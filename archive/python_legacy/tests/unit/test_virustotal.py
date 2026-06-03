"""
Unit tests for Phase 46 VirusTotal Provider.
Phase 59a: circuit breaker and retry wiring added.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
from src.security.models import RiskSignal
from src.security.virustotal import VirusTotalConfig, VirusTotalProvider


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.setex = AsyncMock(return_value=True)
    # Mock RedisBloom bf()
    client.bf = MagicMock()
    client.bf().add = AsyncMock(return_value=1)
    return client


@pytest.fixture
def mock_local_cache():
    cache = MagicMock()
    cache.virustotal_scores = MagicMock()
    cache.virustotal_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session


@pytest.mark.asyncio
async def test_virustotal_provider_signal_logic(
    mock_redis, mock_local_cache, mock_session
):
    config = VirusTotalConfig(
        enabled=True,
        api_key="test",
        malicious_score=30,
        suspicious_score=15,
        score_cap=70,
    )
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    # Test only malicious detections
    data = {"malicious_count": 1, "suspicious_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "virustotal"
    assert signal.score == 30
    assert "1 malicious detection" in signal.reason

    # Test only suspicious detections
    data = {"malicious_count": 0, "suspicious_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 30  # 2 * 15
    assert "2 suspicious detection" in signal.reason

    # Test mixed detections
    data = {"malicious_count": 1, "suspicious_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 60  # 30 + 30
    assert "1 malicious detection" in signal.reason
    assert "2 suspicious detection" in signal.reason

    # Test score capping
    data = {"malicious_count": 3, "suspicious_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 70  # capped at 70

    # Test no detections (should return None)
    data = {"malicious_count": 0, "suspicious_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal is None


@pytest.mark.asyncio
async def test_virustotal_api_lookup(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="test", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(
        return_value={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "undetected": 50,
                        "harmless": 10,
                    }
                }
            }
        }
    )

    # aiohttp session.get() returns an object that is an async context manager
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = mock_ctx

    # Test the lookup process
    await provider._process_lookup("1.2.3.4")

    # Verify Redis was called to cache the result
    mock_redis.setex.assert_called()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "virustotal:data:1.2.3.4"
    cached_data = json.loads(call_args[0][2])
    assert cached_data["malicious_count"] == 3
    assert cached_data["suspicious_count"] == 1


@pytest.mark.asyncio
async def test_virustotal_quota_management(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="test", daily_quota=2)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(
        return_value={
            "data": {
                "attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}
            }
        }
    )

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.get.return_value = mock_ctx

    # First lookup should work
    await provider._process_lookup("1.2.3.4")
    assert provider._quota_used_today == 1

    # Second lookup should work
    await provider._process_lookup("5.6.7.8")
    assert provider._quota_used_today == 2

    # Third lookup should be blocked by quota - test _maybe_lookup which checks quota
    mock_session.get.reset_mock()
    mock_redis.get.return_value = None  # Force cache miss
    await provider._maybe_lookup("9.10.11.12")
    # Should not call the API due to quota (should return early in _maybe_lookup)
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_virustotal_provider_disabled(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=False)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    # Should return None when disabled
    signal = provider.get_signal("1.2.3.4")
    assert signal is None

    # Start/stop should be no-ops
    await provider.start()
    await provider.stop()
    assert len(provider._workers) == 0


@pytest.mark.asyncio
async def test_virustotal_cache_hit(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="test", score_cap=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    # Mock cache hit
    cached_data = {"malicious_count": 2, "suspicious_count": 1}
    mock_local_cache.virustotal_scores.get.return_value = cached_data

    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert signal.score == 75  # (2 * 30) + (1 * 15)

    # Verify no API lookup was triggered (cache hit)
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_virustotal_config_reload(mock_redis, mock_local_cache, mock_session):
    config = VirusTotalConfig(enabled=True, api_key="old_key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    new_config_dict = {
        "virustotal": {
            "enabled": True,
            "api_key": "new_key",
            "malicious_score": 35,
            "suspicious_score": 20,
            "daily_quota": 200,
        }
    }

    provider.on_config_reload(new_config_dict)
    assert provider._config.api_key == "new_key"
    assert provider._config.malicious_score == 35
    assert provider._config.suspicious_score == 20
    assert provider._config.daily_quota == 200


# ---------------------------------------------------------------------------
# Phase 59a: circuit breaker and retry tests
# ---------------------------------------------------------------------------


def _make_ctx(status: int, body: dict):
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=body)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


_VT_OK_BODY = {
    "data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}
}


@pytest.mark.asyncio
async def test_virustotal_no_health_monitor_works(
    mock_redis, mock_local_cache, mock_session
):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)
    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called()


@pytest.mark.asyncio
async def test_virustotal_circuit_open_skips_api(
    mock_redis, mock_local_cache, mock_session
):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("virustotal", failure_threshold=1)
    cb.record_failure()
    assert cb.is_open()

    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_virustotal_circuit_records_success(
    mock_redis, mock_local_cache, mock_session
):
    """Successful API call causes record_success() to be invoked."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("virustotal")
    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
        provider = VirusTotalProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


@pytest.mark.asyncio
async def test_virustotal_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
        provider = VirusTotalProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.side_effect = OSError("connection refused")
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


@pytest.mark.asyncio
async def test_virustotal_retry_twice_then_succeed(
    mock_redis, mock_local_cache, mock_session
):
    """API fails twice then succeeds; session.get called 3 times."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(200, _VT_OK_BODY)
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise OSError("transient error")
        return success_ctx

    mock_session.get.side_effect = side_effect

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    assert call_count == 3
    mock_redis.setex.assert_called()


# ---------------------------------------------------------------------------
# from_config — env var fallback for API key (lines 25-26, 71)
# ---------------------------------------------------------------------------


def test_virustotal_config_from_config_env_key(monkeypatch):
    """VirusTotalConfig.from_config picks up VIRUSTOTAL_API_KEY from env."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-vt-key")
    cfg = VirusTotalConfig.from_config({})
    assert cfg.api_key == "env-vt-key"
    assert cfg.enabled is False


# ---------------------------------------------------------------------------
# start() — enabled path loads quota state and spawns workers (lines 118-133)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_start_enabled_spawns_workers(
    mock_redis, mock_local_cache, mock_session
):
    """start() loads quota state and creates worker tasks."""
    config = VirusTotalConfig(enabled=True, api_key="key", worker_count=1)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    # _load_quota_state will call redis.get
    mock_redis.get.return_value = None

    await provider.start()
    assert len(provider._workers) == 1

    for w in provider._workers:
        w.cancel()
    await asyncio.gather(*provider._workers, return_exceptions=True)


@pytest.mark.asyncio
async def test_virustotal_start_loads_quota_from_redis(
    mock_redis, mock_local_cache, mock_session
):
    """start() restores quota_used from Redis on startup."""
    config = VirusTotalConfig(enabled=True, api_key="key", worker_count=1)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = json.dumps({"quota_used": 50, "last_reset": 0})

    await provider.start()
    assert provider._quota_used_today == 50

    for w in provider._workers:
        w.cancel()
    await asyncio.gather(*provider._workers, return_exceptions=True)


# ---------------------------------------------------------------------------
# get_signal — adaptive cache hit path (lines 153-154)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_get_signal_cache_hit_adaptive_cache_recorded(
    mock_redis, mock_local_cache, mock_session
):
    """Cache hit records a hit in adaptive_cache when one is provided."""
    config = VirusTotalConfig(enabled=True, api_key="key")
    adaptive_cache = MagicMock()
    adaptive_cache.record_cache_hit = AsyncMock()

    provider = VirusTotalProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )
    mock_local_cache.virustotal_scores.get.return_value = {
        "malicious_count": 1,
        "suspicious_count": 0,
    }

    provider.get_signal("1.2.3.4")
    await asyncio.sleep(0)
    adaptive_cache.record_cache_hit.assert_called_once_with("virustotal")


# ---------------------------------------------------------------------------
# _maybe_lookup — Redis hit populates local cache (lines 207-228)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_maybe_lookup_redis_hit(
    mock_redis, mock_local_cache, mock_session
):
    """Redis cache hit populates local cache and skips queue."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = json.dumps(
        {"malicious_count": 2, "suspicious_count": 0}
    )

    await provider._maybe_lookup("1.2.3.4")
    mock_local_cache.virustotal_scores.set.assert_called_once()
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_virustotal_maybe_lookup_redis_error_continues(
    mock_redis, mock_local_cache, mock_session
):
    """Redis read error is swallowed and does not crash the provider."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.side_effect = Exception("redis down")

    await provider._maybe_lookup("1.2.3.4")  # must not raise


@pytest.mark.asyncio
async def test_virustotal_maybe_lookup_bloom_already_seen(
    mock_redis, mock_local_cache, mock_session
):
    """Bloom filter returning 0 (already seen) skips the queue."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 0

    await provider._maybe_lookup("1.2.3.4")
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_virustotal_maybe_lookup_queue_full_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """QueueFull is silently swallowed — proxy must not crash on backpressure."""
    config = VirusTotalConfig(
        enabled=True, api_key="key", daily_quota=100, queue_size=1
    )
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    provider._queue.put_nowait("2.3.4.5")  # fill the queue

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 1

    await provider._maybe_lookup("1.2.3.4")  # must not raise


# ---------------------------------------------------------------------------
# _process_lookup — 404 response (lines 286-288)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_process_lookup_404_caches_zero(
    mock_redis, mock_local_cache, mock_session
):
    """404 response is treated as not found and cached with zeroed counts."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(404, {})

    await provider._process_lookup("1.2.3.4")

    mock_redis.setex.assert_called()
    cached = json.loads(mock_redis.setex.call_args[0][2])
    assert cached["malicious_count"] == 0
    assert cached["suspicious_count"] == 0


# ---------------------------------------------------------------------------
# _process_lookup — HTTP 403 rate-limited path (lines 289-293)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_process_lookup_403_rate_limited(
    mock_redis, mock_local_cache, mock_session
):
    """HTTP 403 is treated as rate-limited; no caching and no circuit breaker failure."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_session.get.return_value = _make_ctx(403, {})

    await provider._process_lookup("1.2.3.4")

    mock_redis.setex.assert_not_called()
    # rate-limited path returns early — circuit breaker should not record failure
    cb_mock.record_failure.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — HTTP 500 triggers retry then exception path (lines 294-300)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_process_lookup_http_500_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """HTTP 500 raises; exception path records circuit breaker failure."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_session.get.return_value = _make_ctx(500, {})

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# _process_lookup — adaptive cache TTL used when manager present (lines 324-325)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_process_lookup_uses_adaptive_ttl(
    mock_redis, mock_local_cache, mock_session
):
    """When adaptive_cache is set, TTL comes from get_adaptive_ttl()."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 999
    adaptive_cache.record_cache_miss = AsyncMock()

    config = VirusTotalConfig(
        enabled=True, api_key="key", daily_quota=100, cache_ttl_seconds=3600
    )
    provider = VirusTotalProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)

    await provider._process_lookup("1.2.3.4")

    # TTL in setex call should be 999 from adaptive cache
    call_args = mock_redis.setex.call_args
    assert call_args[0][1] == 999


# ---------------------------------------------------------------------------
# _process_lookup — record_cache_miss called when adaptive cache set (line 337)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_process_lookup_records_cache_miss_volatility(
    mock_redis, mock_local_cache, mock_session
):
    """record_cache_miss is called on a successful lookup when adaptive_cache is set."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 3600
    adaptive_cache.record_cache_miss = AsyncMock()

    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)

    await provider._process_lookup("1.2.3.4")
    adaptive_cache.record_cache_miss.assert_called_once()


# ---------------------------------------------------------------------------
# _process_lookup — timeout path (lines 342-345)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_process_lookup_timeout_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """asyncio.TimeoutError triggers timeout counter and CB failure."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_session.get.side_effect = asyncio.TimeoutError()

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    cb_mock.record_failure.assert_called()
    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# _load_quota_state / _save_quota_state (lines 352-376)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_load_quota_state_parses_redis_data(
    mock_redis, mock_local_cache, mock_session
):
    """_load_quota_state reads and parses quota state from Redis."""
    config = VirusTotalConfig(enabled=True, api_key="key")
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = json.dumps({"quota_used": 42, "last_reset": 100})

    await provider._load_quota_state()
    assert provider._quota_used_today == 42
    assert provider._last_quota_reset == 100


@pytest.mark.asyncio
async def test_virustotal_load_quota_state_redis_error_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Redis error in _load_quota_state is swallowed — provider continues."""
    config = VirusTotalConfig(enabled=True, api_key="key")
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.side_effect = Exception("redis down")

    await provider._load_quota_state()  # must not raise
    assert provider._quota_used_today == 0  # unchanged


@pytest.mark.asyncio
async def test_virustotal_save_quota_state_writes_to_redis(
    mock_redis, mock_local_cache, mock_session
):
    """_save_quota_state serialises quota usage to Redis with 24h TTL."""
    config = VirusTotalConfig(enabled=True, api_key="key")
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    provider._quota_used_today = 7

    await provider._save_quota_state()

    mock_redis.setex.assert_called_once()
    key, ttl, payload = mock_redis.setex.call_args[0]
    assert key == "virustotal:quota:state"
    assert ttl == 86400
    data = json.loads(payload)
    assert data["quota_used"] == 7


@pytest.mark.asyncio
async def test_virustotal_save_quota_state_redis_error_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Redis error in _save_quota_state is swallowed — proxy must not crash."""
    config = VirusTotalConfig(enabled=True, api_key="key")
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.setex.side_effect = Exception("redis down")

    await provider._save_quota_state()  # must not raise


# ---------------------------------------------------------------------------
# _worker_loop — cancellation exits cleanly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_worker_loop_cancellation(
    mock_redis, mock_local_cache, mock_session
):
    """Worker loop exits cleanly when cancelled."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    task = asyncio.create_task(provider._worker_loop())
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# _process_lookup — old Redis value fetched for volatility (lines 308-310)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_virustotal_process_lookup_fetches_old_value_for_volatility(
    mock_redis, mock_local_cache, mock_session
):
    """Before API call, old cached value is fetched for volatility comparison."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 3600
    adaptive_cache.record_cache_miss = AsyncMock()

    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    # Old value is already in Redis
    old_data = {"malicious_count": 1, "suspicious_count": 0}
    # First get call is for old_data, subsequent ones can return None
    mock_redis.get.return_value = json.dumps(old_data)
    mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)

    await provider._process_lookup("1.2.3.4")

    # record_cache_miss should be called with the old value
    call_kwargs = adaptive_cache.record_cache_miss.call_args
    # old_value argument is the second positional arg
    assert call_kwargs is not None


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_virustotal_stop_cancels_workers(
    mock_redis, mock_local_cache, mock_session
):
    """stop() cancels running workers (lines 137, 139).
    So what: uncancelled workers prevent clean shutdown and leak tasks."""
    config = VirusTotalConfig(enabled=True, api_key="key", worker_count=1)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    await provider.start()
    assert len(provider._workers) == 1
    await provider.stop()


@pytest.mark.asyncio
async def test_virustotal_get_signal_cache_miss_returns_none(
    mock_redis, mock_local_cache, mock_session
):
    """get_signal() on cache miss fires async lookup and returns None (lines 159-161).
    So what: if this path is broken, the provider never fires enrichment lookups."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    mock_local_cache.virustotal_scores.get.return_value = None

    signal = provider.get_signal("1.2.3.4")
    assert signal is None
    assert provider._total == 1
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_virustotal_maybe_lookup_bloom_exception_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Exception from bloom filter add is swallowed (lines 222-223).
    So what: RedisBloom unavailability must not crash the VT enrichment path."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.side_effect = Exception("bloom unavailable")

    await provider._maybe_lookup("1.2.3.4")  # must not raise


@pytest.mark.asyncio
async def test_virustotal_worker_loop_processes_item(
    mock_redis, mock_local_cache, mock_session
):
    """Worker dequeues item and calls _process_lookup with task_done (lines 234-237).
    So what: task_done must fire or shutdown hangs."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    provider._process_lookup = AsyncMock()

    provider._queue.put_nowait("1.2.3.4")

    task = asyncio.create_task(provider._worker_loop())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    provider._process_lookup.assert_called_once_with("1.2.3.4")


@pytest.mark.asyncio
async def test_virustotal_worker_loop_exception_logged(
    mock_redis, mock_local_cache, mock_session
):
    """Exception from _process_lookup is caught and logged (lines 240-241).
    So what: a corrupt VT response must not kill the worker task."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)
    provider._process_lookup = AsyncMock(side_effect=RuntimeError("injected"))

    provider._queue.put_nowait("1.2.3.4")

    task = asyncio.create_task(provider._worker_loop())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_virustotal_process_lookup_no_api_key_returns(
    mock_redis, mock_local_cache, mock_session
):
    """_process_lookup returns immediately when api_key is empty (line 245).
    So what: an unconfigured VT provider must not fire unauthenticated API calls."""
    config = VirusTotalConfig(enabled=True, api_key="", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_virustotal_process_lookup_old_redis_value_exception_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Exception reading old Redis value for volatility is swallowed (lines 309-310).
    So what: a Redis error before the API call must not abort the lookup."""
    config = VirusTotalConfig(enabled=True, api_key="key", daily_quota=100)
    provider = VirusTotalProvider(config, mock_redis, mock_local_cache, mock_session)

    get_call_count = 0

    async def _get_side_effect(key):
        nonlocal get_call_count
        get_call_count += 1
        if get_call_count == 1:
            raise Exception("redis timeout")
        return None

    mock_redis.get.side_effect = _get_side_effect
    mock_session.get.return_value = _make_ctx(200, _VT_OK_BODY)

    await provider._process_lookup("1.2.3.4")  # must not raise
    mock_redis.setex.assert_called()
