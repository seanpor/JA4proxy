"""
Unit tests for Phase 46 ThreatFox Provider.
Phase 59a: circuit breaker and retry wiring added.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
from src.security.models import RiskSignal
from src.security.threatfox import ThreatFoxConfig, ThreatFoxProvider


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
    cache.threatfox_scores = MagicMock()
    cache.threatfox_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session


@pytest.mark.asyncio
async def test_threatfox_provider_signal_logic(
    mock_redis, mock_local_cache, mock_session
):
    config = ThreatFoxConfig(enabled=True, api_key="test", ioc_score=25, score_cap=60)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    # Test 1 IOC
    data = {"ioc_count": 1}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "threatfox"
    assert signal.score == 25
    assert "1 IOC" in signal.reason

    # Test multiple IOCs
    data = {"ioc_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 50

    # Test score capping
    data = {"ioc_count": 3}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 60  # capped at 60

    # Test no IOCs (should return None)
    data = {"ioc_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal is None


@pytest.mark.asyncio
async def test_threatfox_api_lookup(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=True, api_key="test")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(
        return_value={
            "query": "search_ioc",
            "data": [
                {"id": "1", "ioc": "1.2.3.4", "threat_type": "malware"},
                {"id": "2", "ioc": "1.2.3.4", "threat_type": "botnet"},
            ],
        }
    )

    # aiohttp session.post() returns an object that is an async context manager
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    # Test the lookup process
    await provider._process_lookup("1.2.3.4")

    # Verify Redis was called to cache the result
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args
    assert call_args[0][0] == "threatfox:data:1.2.3.4"
    cached_data = json.loads(call_args[0][2])
    assert cached_data["ioc_count"] == 2


@pytest.mark.asyncio
async def test_threatfox_provider_disabled(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=False)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    # Should return None when disabled
    signal = provider.get_signal("1.2.3.4")
    assert signal is None

    # Start/stop should be no-ops
    await provider.start()
    await provider.stop()
    assert len(provider._workers) == 0


@pytest.mark.asyncio
async def test_threatfox_cache_hit(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=True, api_key="test", score_cap=100)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    # Mock cache hit
    cached_data = {"ioc_count": 2}
    mock_local_cache.threatfox_scores.get.return_value = cached_data

    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert signal.score == 50  # 2 * 25

    # Verify no API lookup was triggered (cache hit)
    mock_session.post.assert_not_called()


@pytest.mark.asyncio
async def test_threatfox_config_reload(mock_redis, mock_local_cache, mock_session):
    config = ThreatFoxConfig(enabled=True, api_key="old_key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    new_config_dict = {
        "threatfox": {"enabled": True, "api_key": "new_key", "ioc_score": 30}
    }

    provider.on_config_reload(new_config_dict)
    assert provider._config.api_key == "new_key"
    assert provider._config.ioc_score == 30


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


_TF_OK_BODY = {
    "data": [
        {"id": "1", "ioc": "1.2.3.4", "threat_type": "malware"},
    ]
}


@pytest.mark.asyncio
async def test_threatfox_no_health_monitor_works(
    mock_redis, mock_local_cache, mock_session
):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.post.return_value = _make_ctx(200, _TF_OK_BODY)
    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called_once()


@pytest.mark.asyncio
async def test_threatfox_circuit_open_skips_api(
    mock_redis, mock_local_cache, mock_session
):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("threatfox", failure_threshold=1)
    cb.record_failure()
    assert cb.is_open()

    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.post.assert_not_called()


@pytest.mark.asyncio
async def test_threatfox_circuit_records_success(
    mock_redis, mock_local_cache, mock_session
):
    """Successful API call causes record_success() to be invoked."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("threatfox")
    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = ThreatFoxConfig(enabled=True, api_key="key")
        provider = ThreatFoxProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.post.return_value = _make_ctx(200, _TF_OK_BODY)
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


@pytest.mark.asyncio
async def test_threatfox_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = ThreatFoxConfig(enabled=True, api_key="key")
        provider = ThreatFoxProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.post.side_effect = OSError("connection refused")
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


@pytest.mark.asyncio
async def test_threatfox_retry_twice_then_succeed(
    mock_redis, mock_local_cache, mock_session
):
    """API fails twice then succeeds; session.post called 3 times."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(200, _TF_OK_BODY)
    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise OSError("transient error")
        return success_ctx

    mock_session.post.side_effect = side_effect

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    assert call_count == 3
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# from_config (lines 25-26, 62-73)
# ---------------------------------------------------------------------------


def test_threatfox_config_from_config_defaults():
    """ThreatFoxConfig.from_config uses sensible defaults from empty config."""
    cfg = ThreatFoxConfig.from_config({})
    assert cfg.enabled is False
    assert cfg.ioc_score == 25
    assert cfg.score_cap == 60


# ---------------------------------------------------------------------------
# start() — enabled path spawns workers (lines 104-116)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_start_enabled_spawns_workers(
    mock_redis, mock_local_cache, mock_session
):
    """start() creates worker tasks when enabled."""
    config = ThreatFoxConfig(enabled=True, api_key="key", worker_count=2)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider.start()
    assert len(provider._workers) == 2

    for w in provider._workers:
        w.cancel()
    await asyncio.gather(*provider._workers, return_exceptions=True)


# ---------------------------------------------------------------------------
# stop() with workers (lines 120, 122)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_stop_cancels_workers(
    mock_redis, mock_local_cache, mock_session
):
    """stop() cancels running workers without raising."""
    config = ThreatFoxConfig(enabled=True, api_key="key", worker_count=1)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    await provider.start()
    assert len(provider._workers) == 1
    await provider.stop()


# ---------------------------------------------------------------------------
# get_signal — adaptive cache hit path (lines 137)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_get_signal_cache_hit_adaptive_recorded(
    mock_redis, mock_local_cache, mock_session
):
    """Cache hit records a hit in adaptive_cache when one is provided."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    adaptive_cache = MagicMock()
    adaptive_cache.record_cache_hit = AsyncMock()

    provider = ThreatFoxProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )
    mock_local_cache.threatfox_scores.get.return_value = {"ioc_count": 2}

    provider.get_signal("1.2.3.4")
    await asyncio.sleep(0)
    adaptive_cache.record_cache_hit.assert_called_once_with("threatfox")


# ---------------------------------------------------------------------------
# get_signal — cache miss fires async lookup (lines 142-144)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_get_signal_cache_miss_returns_none(
    mock_redis, mock_local_cache, mock_session
):
    """Cache miss returns None and fires background lookup."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    mock_local_cache.threatfox_scores.get.return_value = None

    signal = provider.get_signal("1.2.3.4")
    assert signal is None
    assert provider._total == 1
    await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# _maybe_lookup — Redis hit, error, bloom seen paths (lines 169-190)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_maybe_lookup_redis_hit(
    mock_redis, mock_local_cache, mock_session
):
    """Redis cache hit populates local cache and skips queue."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = json.dumps({"ioc_count": 1})

    await provider._maybe_lookup("1.2.3.4")
    mock_local_cache.threatfox_scores.set.assert_called_once()
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_threatfox_maybe_lookup_redis_error_continues(
    mock_redis, mock_local_cache, mock_session
):
    """Redis read error is swallowed; lookup proceeds to bloom/queue."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.side_effect = Exception("redis down")

    await provider._maybe_lookup("1.2.3.4")  # must not raise


@pytest.mark.asyncio
async def test_threatfox_maybe_lookup_bloom_already_seen(
    mock_redis, mock_local_cache, mock_session
):
    """Bloom filter returning 0 (already seen) skips queue."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 0

    await provider._maybe_lookup("1.2.3.4")
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_threatfox_maybe_lookup_queue_full_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """QueueFull is silently swallowed — proxy must not crash on backpressure."""
    config = ThreatFoxConfig(enabled=True, api_key="key", queue_size=1)
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
    provider._queue.put_nowait("2.3.4.5")

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 1

    await provider._maybe_lookup("1.2.3.4")  # must not raise


# ---------------------------------------------------------------------------
# _process_lookup — no api_key returns immediately (line 207)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_process_lookup_no_api_key_skips(
    mock_redis, mock_local_cache, mock_session
):
    """When api_key is empty, _process_lookup returns without API call."""
    config = ThreatFoxConfig(enabled=True, api_key="")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider._process_lookup("1.2.3.4")
    mock_session.post.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — 404 response caches zero IOC count (lines 240-242)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_process_lookup_404_caches_zero(
    mock_redis, mock_local_cache, mock_session
):
    """404 response is treated as not found and cached with zero IOC count."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.post.return_value = _make_ctx(404, {})

    await provider._process_lookup("1.2.3.4")

    mock_redis.setex.assert_called_once()
    cached = json.loads(mock_redis.setex.call_args[0][2])
    assert cached["ioc_count"] == 0


# ---------------------------------------------------------------------------
# _process_lookup — HTTP 500 raises; exception path records CB failure (lines 243-249)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_process_lookup_http_500_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """HTTP 500 raises RuntimeError; exception path records CB failure."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_session.post.return_value = _make_ctx(500, {})

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# _process_lookup — adaptive TTL path (lines 270-271)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_process_lookup_uses_adaptive_ttl(
    mock_redis, mock_local_cache, mock_session
):
    """When adaptive_cache is set, TTL comes from get_adaptive_ttl()."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 9999
    adaptive_cache.record_cache_miss = AsyncMock()

    config = ThreatFoxConfig(enabled=True, api_key="key", cache_ttl_seconds=3600)
    provider = ThreatFoxProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    mock_session.post.return_value = _make_ctx(200, _TF_OK_BODY)

    await provider._process_lookup("1.2.3.4")

    call_args = mock_redis.setex.call_args
    assert call_args[0][1] == 9999


# ---------------------------------------------------------------------------
# _process_lookup — record_cache_miss called (line 283)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_process_lookup_records_cache_miss(
    mock_redis, mock_local_cache, mock_session
):
    """record_cache_miss is called after successful lookup when adaptive_cache is set."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 3600
    adaptive_cache.record_cache_miss = AsyncMock()

    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    mock_session.post.return_value = _make_ctx(200, _TF_OK_BODY)

    await provider._process_lookup("1.2.3.4")
    adaptive_cache.record_cache_miss.assert_called_once()


# ---------------------------------------------------------------------------
# _process_lookup — timeout path (lines 288-290)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_process_lookup_timeout_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """asyncio.TimeoutError records CB failure."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_session.post.side_effect = asyncio.TimeoutError()

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await provider._process_lookup("1.2.3.4")

    cb_mock.record_failure.assert_called()
    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — old Redis value fetched for volatility (lines 257-259)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_process_lookup_fetches_old_value(
    mock_redis, mock_local_cache, mock_session
):
    """Before API call, old cached value is fetched for volatility comparison."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 3600
    adaptive_cache.record_cache_miss = AsyncMock()

    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    old_data = {"ioc_count": 1}
    mock_redis.get.return_value = json.dumps(old_data)
    mock_session.post.return_value = _make_ctx(200, _TF_OK_BODY)

    await provider._process_lookup("1.2.3.4")

    adaptive_cache.record_cache_miss.assert_called_once()


# ---------------------------------------------------------------------------
# _worker_loop — cancellation exits cleanly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threatfox_worker_loop_cancellation(
    mock_redis, mock_local_cache, mock_session
):
    """Worker loop exits cleanly when cancelled."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    task = asyncio.create_task(provider._worker_loop())
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_threatfox_maybe_lookup_bloom_exception_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Exception from bloom filter add is swallowed (lines 184-185).
    So what: RedisBloom unavailability must not crash the ThreatFox enrichment path."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.side_effect = Exception("bloom unavailable")

    await provider._maybe_lookup("1.2.3.4")  # must not raise


@pytest.mark.asyncio
async def test_threatfox_worker_loop_processes_item(
    mock_redis, mock_local_cache, mock_session
):
    """Worker dequeues item and calls _process_lookup with task_done (lines 196-199).
    So what: task_done must fire or shutdown hangs."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
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
async def test_threatfox_worker_loop_exception_logged(
    mock_redis, mock_local_cache, mock_session
):
    """Exception from _process_lookup is caught and logged (lines 202-203).
    So what: a corrupt ThreatFox response must not kill the worker task."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)
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
async def test_threatfox_process_lookup_old_redis_value_exception_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Exception reading old Redis value for volatility is swallowed (lines 258-259).
    So what: a Redis error before the API call must not abort the lookup."""
    config = ThreatFoxConfig(enabled=True, api_key="key")
    provider = ThreatFoxProvider(config, mock_redis, mock_local_cache, mock_session)

    get_call_count = 0

    async def _get_side_effect(key):
        nonlocal get_call_count
        get_call_count += 1
        if get_call_count == 1:
            raise Exception("redis timeout")
        return None

    mock_redis.get.side_effect = _get_side_effect

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"data": []})
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")  # must not raise
    mock_redis.setex.assert_called()
