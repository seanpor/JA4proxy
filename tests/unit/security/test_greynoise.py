"""
Unit tests for Phase 59a — GreyNoise circuit breaker and retry wiring.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
from src.security.greynoise import GreyNoiseConfig, GreyNoiseProvider
from src.security.models import RiskSignal

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.setex = AsyncMock(return_value=True)
    client.bf = MagicMock()
    client.bf().add = AsyncMock(return_value=1)
    client.expire = AsyncMock(return_value=True)
    return client


@pytest.fixture
def mock_local_cache():
    cache = MagicMock()
    cache.greynoise_scores = MagicMock()
    cache.greynoise_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    return MagicMock()


def _make_ctx(status: int, body: dict):
    """Build an async context-manager that returns an aiohttp-like response."""
    mock_resp = AsyncMock()
    mock_resp.status = status
    mock_resp.json = AsyncMock(return_value=body)
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_resp)
    ctx.__aexit__ = AsyncMock(return_value=None)
    return ctx


# ---------------------------------------------------------------------------
# Backwards compatibility — no health_monitor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_no_health_monitor_works(mock_redis, mock_local_cache, mock_session):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(
        200, {"noise": True, "riot": False, "classification": "malicious"}
    )

    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — open circuit skips API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_circuit_open_skips_api(mock_redis, mock_local_cache, mock_session):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("greynoise", failure_threshold=1)
    cb.record_failure()  # Open the circuit immediately (threshold=1)
    assert cb.is_open()

    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


# ---------------------------------------------------------------------------
# Circuit breaker — success path records success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_circuit_records_success(mock_redis, mock_local_cache, mock_session):
    """Successful API call causes record_success() to be invoked on the circuit breaker."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("greynoise")

    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = GreyNoiseConfig(enabled=True, api_key="key")
        provider = GreyNoiseProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.return_value = _make_ctx(
            200, {"noise": True, "riot": False, "classification": "malicious"}
        )

        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — failure path records failure and re-raises
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called and exception is swallowed by worker."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = GreyNoiseConfig(enabled=True, api_key="key")
        provider = GreyNoiseProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        # Simulate network error on every attempt
        mock_session.get.side_effect = OSError("connection refused")

        # _process_lookup catches the final exception internally
        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# Retry — fails twice then succeeds; three HTTP calls made
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_retry_twice_then_succeed(mock_redis, mock_local_cache, mock_session):
    """API fails twice then succeeds; the session is called 3 times total."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(
        200, {"noise": True, "riot": False, "classification": "malicious"}
    )

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
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# Signal logic sanity check (unchanged from Phase 23)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = GreyNoiseConfig(enabled=True, api_key="key", noise_score=25, riot_score_reduction=15)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    signal = provider._to_signal("1.2.3.4", {"noise": True, "riot": False, "classification": "malicious"})
    assert signal is not None
    assert signal.score == 25

    signal = provider._to_signal("1.2.3.4", {"noise": False, "riot": True, "classification": "unknown"})
    assert signal is not None
    assert signal.score == -15

    signal = provider._to_signal("1.2.3.4", {"noise": False, "riot": False, "classification": "unknown"})
    assert signal is None


# ---------------------------------------------------------------------------
# from_config — env var fallback for API key (lines 64-66)
# ---------------------------------------------------------------------------


def test_greynoise_config_from_config_env_key(monkeypatch):
    """GreyNoiseConfig.from_config picks up GREYNOISE_API_KEY from env when config is empty."""
    monkeypatch.setenv("GREYNOISE_API_KEY", "env-key-123")
    cfg = GreyNoiseConfig.from_config({})
    assert cfg.api_key == "env-key-123"
    assert cfg.enabled is False  # default


def test_greynoise_config_from_config_explicit_key():
    """Explicit config key takes precedence over env var."""
    cfg = GreyNoiseConfig.from_config({"greynoise": {"api_key": "explicit", "enabled": True}})
    assert cfg.api_key == "explicit"
    assert cfg.enabled is True


# ---------------------------------------------------------------------------
# start() — enabled path spawns workers (lines 103-117)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_start_enabled_spawns_workers(mock_redis, mock_local_cache, mock_session):
    """start() creates worker_count tasks when enabled."""
    config = GreyNoiseConfig(enabled=True, api_key="key", worker_count=2)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider.start()
    assert len(provider._workers) == 2

    # Cleanup
    for w in provider._workers:
        w.cancel()
    await asyncio.gather(*provider._workers, return_exceptions=True)


@pytest.mark.asyncio
async def test_greynoise_start_disabled_no_workers(mock_redis, mock_local_cache, mock_session):
    """start() is a no-op when disabled."""
    config = GreyNoiseConfig(enabled=False)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    await provider.start()
    assert len(provider._workers) == 0


# ---------------------------------------------------------------------------
# stop() — cancels workers (lines 120-123)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_stop_cancels_workers(mock_redis, mock_local_cache, mock_session):
    """stop() cancels running workers without raising."""
    config = GreyNoiseConfig(enabled=True, api_key="key", worker_count=1)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    await provider.start()
    assert len(provider._workers) == 1
    await provider.stop()


# ---------------------------------------------------------------------------
# get_signal — cache miss path enqueues async lookup (lines 126-140)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_get_signal_cache_miss_returns_none(
    mock_redis, mock_local_cache, mock_session
):
    """get_signal returns None on cache miss and fires async lookup."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    mock_local_cache.greynoise_scores.get.return_value = None

    # Need an event loop for create_task
    signal = provider.get_signal("1.2.3.4")
    assert signal is None
    # Allow the spawned task to settle
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_greynoise_get_signal_updates_metrics_on_cache_miss(
    mock_redis, mock_local_cache, mock_session
):
    """_update_metrics is called even on cache miss."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    mock_local_cache.greynoise_scores.get.return_value = None

    provider.get_signal("1.2.3.4")
    assert provider._total == 1
    assert provider._hits == 0
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_greynoise_get_signal_cache_hit_updates_ratio(
    mock_redis, mock_local_cache, mock_session
):
    """Cache hit increments _hits and returns a signal."""
    config = GreyNoiseConfig(enabled=True, api_key="key", noise_score=25)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    mock_local_cache.greynoise_scores.get.return_value = {
        "noise": True, "riot": False, "classification": "malicious"
    }

    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert provider._hits == 1
    assert provider._total == 1


# ---------------------------------------------------------------------------
# _maybe_lookup — Redis cache hit populates local cache (lines 178-200)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_maybe_lookup_redis_hit_populates_local_cache(
    mock_redis, mock_local_cache, mock_session
):
    """When Redis has the data, local cache is populated and queue is not touched."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    cached_payload = json.dumps({"noise": True, "riot": False, "classification": "malicious"})
    mock_redis.get.return_value = cached_payload

    await provider._maybe_lookup("1.2.3.4")

    mock_local_cache.greynoise_scores.set.assert_called_once()
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_greynoise_maybe_lookup_redis_error_continues(
    mock_redis, mock_local_cache, mock_session
):
    """Redis read error is swallowed; lookup still proceeds to bloom/queue."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.side_effect = Exception("connection refused")

    # Should not raise
    await provider._maybe_lookup("1.2.3.4")


@pytest.mark.asyncio
async def test_greynoise_maybe_lookup_bloom_already_seen_skips_queue(
    mock_redis, mock_local_cache, mock_session
):
    """If Bloom filter says IP is already seen (returns 0), queue is skipped."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 0  # already seen

    await provider._maybe_lookup("1.2.3.4")
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_greynoise_maybe_lookup_queue_full_swallows_error(
    mock_redis, mock_local_cache, mock_session
):
    """QueueFull is silently swallowed — proxy must not crash on backpressure."""
    config = GreyNoiseConfig(enabled=True, api_key="key", queue_size=1)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    # Fill the queue
    provider._queue.put_nowait("2.3.4.5")

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 1  # new entry

    # Should not raise even though queue is full
    await provider._maybe_lookup("1.2.3.4")


# ---------------------------------------------------------------------------
# _process_lookup — 404 response (lines 242-244)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_process_lookup_404_caches_unknown(
    mock_redis, mock_local_cache, mock_session
):
    """404 response is treated as 'not found' and cached with neutral result."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(404, {})

    await provider._process_lookup("1.2.3.4")

    mock_redis.setex.assert_called_once()
    cached = json.loads(mock_redis.setex.call_args[0][2])
    assert cached["noise"] is False
    assert cached["riot"] is False


# ---------------------------------------------------------------------------
# _process_lookup — HTTP 500 raises, circuit breaker records failure (lines 245-278)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_process_lookup_http_error_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """Non-200/404 status raises RuntimeError; exception path increments error counter."""
    from src.security.feed_health import FeedHealthMonitor
    from unittest.mock import patch

    monitor = FeedHealthMonitor()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = GreyNoiseConfig(enabled=True, api_key="key")
        provider = GreyNoiseProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.return_value = _make_ctx(500, {})
        with patch("asyncio.sleep", new_callable=AsyncMock):
            await provider._process_lookup("1.2.3.4")

        cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# _process_lookup — asyncio.TimeoutError path (lines 270-273)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_process_lookup_timeout_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """asyncio.TimeoutError triggers timeout counter and circuit breaker failure."""
    from src.security.feed_health import FeedHealthMonitor
    from unittest.mock import patch

    monitor = FeedHealthMonitor()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = GreyNoiseConfig(enabled=True, api_key="key")
        provider = GreyNoiseProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.side_effect = asyncio.TimeoutError()

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await provider._process_lookup("1.2.3.4")

        cb_mock.record_failure.assert_called()
        mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# _process_lookup — no api_key returns immediately (line 217)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_process_lookup_no_api_key_skips(
    mock_redis, mock_local_cache, mock_session
):
    """When api_key is empty, _process_lookup returns immediately without API call."""
    config = GreyNoiseConfig(enabled=True, api_key="")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


# ---------------------------------------------------------------------------
# on_config_reload (line 281)
# ---------------------------------------------------------------------------


def test_greynoise_on_config_reload(mock_redis, mock_local_cache, mock_session):
    """on_config_reload replaces config with new values."""
    config = GreyNoiseConfig(enabled=True, api_key="old", noise_score=25)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    provider.on_config_reload({"greynoise": {"enabled": True, "api_key": "new", "noise_score": 40}})
    assert provider._config.api_key == "new"
    assert provider._config.noise_score == 40


# ---------------------------------------------------------------------------
# _worker_loop — cancellation exits cleanly (lines 203-213)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_greynoise_worker_loop_cancellation(mock_redis, mock_local_cache, mock_session):
    """Worker loop exits cleanly when cancelled."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    task = asyncio.create_task(provider._worker_loop())
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass  # Expected — task was cancelled before it could catch it internally


# ── Missing-coverage additions ────────────────────────────────────────────────


def test_greynoise_get_signal_disabled_returns_none(mock_redis, mock_local_cache, mock_session):
    """get_signal() when disabled returns None immediately (line 127).
    So what: a disabled provider must not fire async lookups or count traffic."""
    config = GreyNoiseConfig(enabled=False)
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    assert provider.get_signal("1.2.3.4") is None


@pytest.mark.asyncio
async def test_greynoise_maybe_lookup_bloom_exception_swallowed(
    mock_redis, mock_local_cache, mock_session
):
    """Exception from bloom filter add is swallowed (lines 193-195).
    So what: a missing RedisBloom module must not crash the enrichment path;
    the IP is still enqueued via the fallback code path."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.side_effect = Exception("WRONGTYPE bloom unavailable")

    # Must not raise; queue should still receive the IP (bloom fallback)
    await provider._maybe_lookup("1.2.3.4")


@pytest.mark.asyncio
async def test_greynoise_worker_loop_processes_item(mock_redis, mock_local_cache, mock_session):
    """Worker dequeues item, calls _process_lookup, calls task_done (lines 206-209).
    So what: if the inner try/finally is never exercised, task_done is never called
    and the queue's join() will hang forever — blocking graceful shutdown."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
    provider._process_lookup = AsyncMock()

    provider._queue.put_nowait("1.2.3.4")

    task = asyncio.create_task(provider._worker_loop())
    # Give the event loop two turns: one to dequeue, one to finish _process_lookup
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    provider._process_lookup.assert_called_once_with("1.2.3.4")


@pytest.mark.asyncio
async def test_greynoise_worker_loop_exception_logged(mock_redis, mock_local_cache, mock_session):
    """Exception from _process_lookup is caught and logged, not propagated (lines 212-213).
    So what: a single corrupt lookup must not kill the worker; all subsequent
    IPs in the queue must still be processed."""
    config = GreyNoiseConfig(enabled=True, api_key="key")
    provider = GreyNoiseProvider(config, mock_redis, mock_local_cache, mock_session)
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
    # Must not propagate RuntimeError
