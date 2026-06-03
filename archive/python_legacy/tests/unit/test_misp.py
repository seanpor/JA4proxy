"""
Unit tests for Phase 46 MISP Provider.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.security.misp import MISPConfig, MISPProvider
from src.security.models import RiskSignal


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
    cache.misp_scores = MagicMock()
    cache.misp_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    session = MagicMock()
    return session


@pytest.mark.asyncio
async def test_misp_provider_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(
        enabled=True,
        api_key="test",
        base_url="https://misp.test",
        attribute_score=20,
        score_cap=50,
    )
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    # Test 1 attribute
    data = {"attribute_count": 1}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.name == "misp"
    assert signal.score == 20
    assert "1 attribute" in signal.reason

    # Test multiple attributes
    data = {"attribute_count": 2}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 40

    # Test score capping
    data = {"attribute_count": 10}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal.score == 50  # capped at 50

    # Test no attributes (should return None)
    data = {"attribute_count": 0}
    signal = provider._to_signal("1.2.3.4", data)
    assert signal is None


@pytest.mark.asyncio
async def test_misp_api_lookup(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=True, api_key="test", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    # Mock successful response
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(
        return_value={
            "response": [
                {"id": "1", "value": "1.2.3.4", "type": "ip-dst"},
                {"id": "2", "value": "1.2.3.4", "type": "ip-dst"},
            ]
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
    assert call_args[0][0] == "misp:data:1.2.3.4"
    cached_data = json.loads(call_args[0][2])
    assert cached_data["attribute_count"] == 2


@pytest.mark.asyncio
async def test_misp_provider_disabled(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=False)
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    # Should return None when disabled
    signal = provider.get_signal("1.2.3.4")
    assert signal is None

    # Start/stop should be no-ops
    await provider.start()
    await provider.stop()
    assert len(provider._workers) == 0


@pytest.mark.asyncio
async def test_misp_cache_hit(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(
        enabled=True, api_key="test", base_url="https://misp.test", score_cap=100
    )
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    # Mock cache hit
    cached_data = {"attribute_count": 3}
    mock_local_cache.misp_scores.get.return_value = cached_data

    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert signal.score == 60  # 3 * 20

    # Verify no API lookup was triggered (cache hit)
    mock_session.post.assert_not_called()


@pytest.mark.asyncio
async def test_misp_config_reload(mock_redis, mock_local_cache, mock_session):
    config = MISPConfig(enabled=True, api_key="old_key", base_url="https://old.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    new_config_dict = {
        "misp": {
            "enabled": True,
            "api_key": "new_key",
            "base_url": "https://new.test",
            "attribute_score": 25,
        }
    }

    provider.on_config_reload(new_config_dict)
    assert provider._config.api_key == "new_key"
    assert provider._config.base_url == "https://new.test"
    assert provider._config.attribute_score == 25


# ---------------------------------------------------------------------------
# from_config — env var fallback (lines 25-26, 65-66)
# ---------------------------------------------------------------------------


def test_misp_config_from_config_env_vars(monkeypatch):
    """MISPConfig.from_config picks up env vars when config dict is empty."""
    monkeypatch.setenv("MISP_API_KEY", "env-misp-key")
    monkeypatch.setenv("MISP_BASE_URL", "https://env.misp.test")
    cfg = MISPConfig.from_config({})
    assert cfg.api_key == "env-misp-key"
    assert cfg.base_url == "https://env.misp.test"
    assert cfg.enabled is False


# ---------------------------------------------------------------------------
# start() — enabled path spawns workers (lines 108-120)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_start_enabled_spawns_workers(
    mock_redis, mock_local_cache, mock_session
):
    """start() creates worker tasks when enabled."""
    config = MISPConfig(
        enabled=True, api_key="key", base_url="https://misp.test", worker_count=2
    )
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider.start()
    assert len(provider._workers) == 2

    for w in provider._workers:
        w.cancel()
    await asyncio.gather(*provider._workers, return_exceptions=True)


# ---------------------------------------------------------------------------
# stop() with workers (lines 124, 126)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_stop_cancels_workers(mock_redis, mock_local_cache, mock_session):
    """stop() cancels running workers without raising."""
    config = MISPConfig(
        enabled=True, api_key="key", base_url="https://misp.test", worker_count=1
    )
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    await provider.start()
    assert len(provider._workers) == 1
    await provider.stop()


# ---------------------------------------------------------------------------
# get_signal — adaptive cache hit path (lines 141)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_get_signal_cache_hit_adaptive_cache_recorded(
    mock_redis, mock_local_cache, mock_session
):
    """Cache hit records a hit in adaptive_cache when one is provided."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    adaptive_cache = MagicMock()
    adaptive_cache.record_cache_hit = AsyncMock()

    provider = MISPProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )
    mock_local_cache.misp_scores.get.return_value = {"attribute_count": 1}

    provider.get_signal("1.2.3.4")
    await asyncio.sleep(0)
    adaptive_cache.record_cache_hit.assert_called_once_with("misp")


# ---------------------------------------------------------------------------
# get_signal — cache miss fires async lookup (lines 146-148)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_get_signal_cache_miss_returns_none(
    mock_redis, mock_local_cache, mock_session
):
    """Cache miss returns None and fires background lookup."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    mock_local_cache.misp_scores.get.return_value = None

    signal = provider.get_signal("1.2.3.4")
    assert signal is None
    assert provider._total == 1
    await asyncio.sleep(0)


# ---------------------------------------------------------------------------
# _maybe_lookup — Redis hit, error, bloom seen paths (lines 173-194)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_maybe_lookup_redis_hit(mock_redis, mock_local_cache, mock_session):
    """Redis cache hit populates local cache and skips queue."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = json.dumps({"attribute_count": 3})

    await provider._maybe_lookup("1.2.3.4")
    mock_local_cache.misp_scores.set.assert_called_once()
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_misp_maybe_lookup_redis_error_continues(
    mock_redis, mock_local_cache, mock_session
):
    """Redis read error is swallowed; lookup proceeds to bloom/queue."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.side_effect = Exception("redis down")

    await provider._maybe_lookup("1.2.3.4")  # must not raise


@pytest.mark.asyncio
async def test_misp_maybe_lookup_bloom_already_seen(
    mock_redis, mock_local_cache, mock_session
):
    """Bloom filter returning 0 (already seen) skips queue."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 0

    await provider._maybe_lookup("1.2.3.4")
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_misp_maybe_lookup_queue_full_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """QueueFull is silently swallowed."""
    config = MISPConfig(
        enabled=True, api_key="key", base_url="https://misp.test", queue_size=1
    )
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
    provider._queue.put_nowait("2.3.4.5")

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 1

    await provider._maybe_lookup("1.2.3.4")  # must not raise


# ---------------------------------------------------------------------------
# _process_lookup — no api_key or no base_url returns immediately (line 211)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_no_api_key_skips(
    mock_redis, mock_local_cache, mock_session
):
    """When api_key is empty, _process_lookup returns immediately."""
    config = MISPConfig(enabled=True, api_key="", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider._process_lookup("1.2.3.4")
    mock_session.post.assert_not_called()


@pytest.mark.asyncio
async def test_misp_process_lookup_no_base_url_skips(
    mock_redis, mock_local_cache, mock_session
):
    """When base_url is empty, _process_lookup returns immediately."""
    config = MISPConfig(enabled=True, api_key="key", base_url="")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider._process_lookup("1.2.3.4")
    mock_session.post.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — circuit breaker skips (lines 216-219)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_circuit_open_skips(
    mock_redis, mock_local_cache, mock_session
):
    """When circuit is open, _process_lookup returns without calling the API."""
    from src.security.feed_health import FeedHealthMonitor

    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("misp", failure_threshold=1)
    cb.record_failure()
    assert cb.is_open()

    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.post.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — 404 response (lines 260-261)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_404_caches_zero(
    mock_redis, mock_local_cache, mock_session
):
    """404 response is treated as not found and cached with zero attributes."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_resp = AsyncMock()
    mock_resp.status = 404
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")

    mock_redis.setex.assert_called_once()
    cached = json.loads(mock_redis.setex.call_args[0][2])
    assert cached["attribute_count"] == 0


# ---------------------------------------------------------------------------
# _process_lookup — HTTP error path triggers CB failure (lines 262-271)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_http_error_records_cb_failure(
    mock_redis, mock_local_cache, mock_session
):
    """Non-200/404 status records CB failure and returns without caching."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_resp = AsyncMock()
    mock_resp.status = 500
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")

    cb_mock.record_failure.assert_called()
    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — adaptive TTL path (lines 275-276)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_uses_adaptive_ttl(
    mock_redis, mock_local_cache, mock_session
):
    """When adaptive_cache is set, TTL comes from get_adaptive_ttl()."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 7200
    adaptive_cache.record_cache_miss = AsyncMock()

    config = MISPConfig(
        enabled=True,
        api_key="key",
        base_url="https://misp.test",
        cache_ttl_seconds=3600,
    )
    provider = MISPProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"response": [{"id": "1"}]})
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")

    call_args = mock_redis.setex.call_args
    assert call_args[0][1] == 7200


# ---------------------------------------------------------------------------
# _process_lookup — adaptive cache miss recorded (line 288)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_records_cache_miss(
    mock_redis, mock_local_cache, mock_session
):
    """record_cache_miss is called after successful lookup when adaptive_cache is set."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 3600
    adaptive_cache.record_cache_miss = AsyncMock()

    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"response": []})
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")
    adaptive_cache.record_cache_miss.assert_called_once()


# ---------------------------------------------------------------------------
# _process_lookup — timeout path (lines 293-296)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_timeout_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """asyncio.TimeoutError records CB failure."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(side_effect=asyncio.TimeoutError())
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")

    cb_mock.record_failure.assert_called()
    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — generic exception path (lines 297-301)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_process_lookup_generic_exception_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """Generic exception records CB failure and is swallowed."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(side_effect=OSError("connection refused"))
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")

    cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# _worker_loop — cancellation exits cleanly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_misp_worker_loop_cancellation(
    mock_redis, mock_local_cache, mock_session
):
    """Worker loop exits cleanly when cancelled."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    task = asyncio.create_task(provider._worker_loop())
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_misp_maybe_lookup_bloom_exception_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Exception from bloom filter add is swallowed (lines 188-189).
    So what: RedisBloom unavailability must not crash the MISP enrichment path."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.side_effect = Exception("bloom unavailable")

    await provider._maybe_lookup("1.2.3.4")  # must not raise


@pytest.mark.asyncio
async def test_misp_worker_loop_processes_item(
    mock_redis, mock_local_cache, mock_session
):
    """Worker dequeues item and calls _process_lookup with task_done (lines 200-203).
    So what: task_done must be called or queue.join() hangs during shutdown."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
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
async def test_misp_worker_loop_exception_logged(
    mock_redis, mock_local_cache, mock_session
):
    """Exception from _process_lookup is caught and logged (lines 206-207).
    So what: a corrupt MISP response must not kill the worker task."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)
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
async def test_misp_process_lookup_old_redis_value_exception_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Exception reading old Redis value for volatility is swallowed (lines 241-243).
    So what: a Redis error before the API call must not abort the lookup."""
    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(config, mock_redis, mock_local_cache, mock_session)

    # First redis.get call raises (for old_data), subsequent calls can return None
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
    mock_resp.json = AsyncMock(return_value={"response": []})
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")  # must not raise


@pytest.mark.asyncio
async def test_misp_process_lookup_cb_record_success_called(
    mock_redis, mock_local_cache, mock_session
):
    """Successful lookup with a circuit breaker calls record_success (line 291).
    So what: if record_success is never called, the circuit breaker cannot reset
    after a transient failure, causing permanent feed blackout."""
    monitor = MagicMock()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False
    monitor.get_circuit_breaker.return_value = cb_mock

    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"response": [{"id": "1"}]})
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")
    cb_mock.record_success.assert_called_once()


@pytest.mark.asyncio
async def test_misp_process_lookup_existing_redis_value_parsed(
    mock_redis, mock_local_cache, mock_session
):
    """Old Redis value is parsed when present before API call (line 241).
    So what: if old_value is never populated, volatility detection in adaptive
    cache is silently disabled — slow-moving threats go undetected."""
    adaptive_cache = MagicMock()
    adaptive_cache.get_adaptive_ttl.return_value = 3600
    adaptive_cache.record_cache_miss = AsyncMock()

    config = MISPConfig(enabled=True, api_key="key", base_url="https://misp.test")
    provider = MISPProvider(
        config,
        mock_redis,
        mock_local_cache,
        mock_session,
        adaptive_cache=adaptive_cache,
    )

    # Redis already has cached data for this IP
    old_data = json.dumps({"attribute_count": 1})
    mock_redis.get.return_value = old_data

    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.json = AsyncMock(return_value={"response": [{"id": "1"}, {"id": "2"}]})
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    mock_ctx.__aexit__ = AsyncMock(return_value=None)
    mock_session.post.return_value = mock_ctx

    await provider._process_lookup("1.2.3.4")

    # record_cache_miss should have been called with the old value
    adaptive_cache.record_cache_miss.assert_called_once()
    call_args = adaptive_cache.record_cache_miss.call_args[0]
    assert call_args[1] == {"attribute_count": 1}  # old_value
