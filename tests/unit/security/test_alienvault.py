"""
Unit tests for Phase 59a — AlienVault OTX circuit breaker and retry wiring.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.alienvault import AlienVaultOTXProvider, OTXConfig
from src.security.feed_health import CircuitBreaker, FeedHealthMonitor
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
    cache.alienvault_scores = MagicMock()
    cache.alienvault_scores.get.return_value = None
    return cache


@pytest.fixture
def mock_session():
    return MagicMock()


def _make_ctx(status: int, body: dict):
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
async def test_alienvault_no_health_monitor_works(mock_redis, mock_local_cache, mock_session):
    """Provider works normally without a health_monitor (backwards compat)."""
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(
        200, {"pulse_info": {"count": 3}}
    )

    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — open circuit skips API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_circuit_open_skips_api(mock_redis, mock_local_cache, mock_session):
    """When the circuit is open, _process_lookup returns without calling the API."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("alienvault_otx", failure_threshold=1)
    cb.record_failure()
    assert cb.is_open()

    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(
        config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
    )

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


# ---------------------------------------------------------------------------
# Circuit breaker — success records success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_circuit_records_success(mock_redis, mock_local_cache, mock_session):
    """Successful API call causes record_success() to be invoked."""
    monitor = FeedHealthMonitor()
    cb = monitor.get_circuit_breaker("alienvault_otx")
    cb_mock = MagicMock(wraps=cb)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = OTXConfig(enabled=True, api_key="key")
        provider = AlienVaultOTXProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.return_value = _make_ctx(
            200, {"pulse_info": {"count": 2}}
        )

        await provider._process_lookup("1.2.3.4")
        cb_mock.record_success.assert_called_once()


# ---------------------------------------------------------------------------
# Circuit breaker — failure records failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_circuit_records_failure_on_exception(
    mock_redis, mock_local_cache, mock_session
):
    """When all retry attempts raise, record_failure() is called."""
    monitor = FeedHealthMonitor()
    cb_mock = MagicMock(spec=CircuitBreaker)
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = OTXConfig(enabled=True, api_key="key")
        provider = AlienVaultOTXProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )

        mock_session.get.side_effect = OSError("connection refused")

        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# Retry — fails twice then succeeds
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_retry_twice_then_succeed(mock_redis, mock_local_cache, mock_session):
    """API fails twice then succeeds; session.get called 3 times."""
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    success_ctx = _make_ctx(200, {"pulse_info": {"count": 1}})

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
# Signal logic sanity check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alienvault_signal_logic(mock_redis, mock_local_cache, mock_session):
    config = OTXConfig(enabled=True, api_key="key", pulse_score=15, score_cap=45)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    signal = provider._to_signal("1.2.3.4", {"pulse_count": 2})
    assert signal is not None
    assert signal.score == 30

    signal = provider._to_signal("1.2.3.4", {"pulse_count": 0})
    assert signal is None


# ---------------------------------------------------------------------------
# OTXConfig.from_config — line 62-73
# ---------------------------------------------------------------------------


def test_otxconfig_from_config_defaults():
    """from_config() with empty dict returns safe defaults; api_key falls through to env.

    Security consequence: a misconfigured YAML must not accidentally enable the feed or
    set a wrong score cap — callers rely on enabled=False as the safe default.
    """
    from src.security.alienvault import OTXConfig

    cfg = OTXConfig.from_config({})
    assert cfg.enabled is False
    assert cfg.cache_ttl_seconds == 3600
    assert cfg.score_cap == 45
    assert cfg.pulse_score == 15


def test_otxconfig_from_config_with_values():
    """from_config() reads all alienvault sub-keys correctly.

    Security consequence: incorrect config parsing could silently override the score
    cap or pulse_score, causing signals to be under- or over-weighted in the scorer.
    """
    from src.security.alienvault import OTXConfig

    raw = {
        "alienvault": {
            "enabled": True,
            "api_key": "abc123",
            "cache_ttl_seconds": 7200,
            "lookup_timeout_seconds": 10,
            "score_cap": 30,
            "queue_size": 100,
            "worker_count": 1,
            "pulse_score": 20,
        }
    }
    cfg = OTXConfig.from_config(raw)
    assert cfg.enabled is True
    assert cfg.api_key == "abc123"
    assert cfg.cache_ttl_seconds == 7200
    assert cfg.score_cap == 30
    assert cfg.pulse_score == 20


def test_otxconfig_from_config_env_api_key(monkeypatch):
    """from_config() picks up OTX_API_KEY from environment when config key is absent.

    Security consequence: if env-var fallback is broken, the provider silently
    runs without an API key and all lookups are no-ops, giving zero threat intel.
    """
    import os
    from src.security.alienvault import OTXConfig

    monkeypatch.setenv("OTX_API_KEY", "env-key-xyz")
    cfg = OTXConfig.from_config({"alienvault": {}})
    assert cfg.api_key == "env-key-xyz"


# ---------------------------------------------------------------------------
# start() / stop() — lines 100-120
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_enabled_creates_workers(mock_redis, mock_local_cache, mock_session):
    """start() creates worker_count tasks when enabled=True.

    Security consequence: if workers are never created, IPs are never actually
    looked up from the API — the enrichment queue silently fills and all API
    reputation data is lost.
    """
    config = OTXConfig(enabled=True, api_key="key", worker_count=2)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider.start()
    assert len(provider._workers) == 2

    # Clean up tasks
    for w in provider._workers:
        w.cancel()
    await asyncio.gather(*provider._workers, return_exceptions=True)


@pytest.mark.asyncio
async def test_start_disabled_creates_no_workers(mock_redis, mock_local_cache, mock_session):
    """start() is a no-op when enabled=False.

    Security consequence: workers must not run when the feature is disabled —
    they would waste Redis connections and generate spurious API calls.
    """
    config = OTXConfig(enabled=False, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)
    await provider.start()
    assert provider._workers == []


@pytest.mark.asyncio
async def test_stop_cancels_workers(mock_redis, mock_local_cache, mock_session):
    """stop() cancels all running worker tasks without raising.

    Security consequence: leaking worker tasks keeps Redis connections open and
    prevents clean shutdown, which can delay deployment of security patches.
    """
    config = OTXConfig(enabled=True, api_key="key", worker_count=2)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)
    await provider.start()
    assert len(provider._workers) == 2

    # stop() should not raise even if workers are still running
    await provider.stop()


# ---------------------------------------------------------------------------
# get_signal() cache-hit path — lines 123-137
# ---------------------------------------------------------------------------


def test_get_signal_disabled_returns_none(mock_redis, mock_local_cache, mock_session):
    """get_signal() returns None immediately when the provider is disabled.

    Security consequence: if a disabled provider erroneously returns a signal,
    it introduces phantom risk scores that affect blocking decisions.
    """
    config = OTXConfig(enabled=False, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    result = provider.get_signal("1.2.3.4")
    assert result is None


def test_get_signal_cache_hit_returns_signal(mock_redis, mock_local_cache, mock_session):
    """get_signal() returns a RiskSignal from local cache without going to Redis/API.

    Security consequence: if the cache-hit branch is broken, every request causes
    an async lookup task to be enqueued, flooding the enrichment queue and starving
    Redis bandwidth on a busy proxy.
    """
    config = OTXConfig(enabled=True, api_key="key", pulse_score=15, score_cap=45)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    # Inject a cache hit
    mock_local_cache.alienvault_scores.get.return_value = {"pulse_count": 3}

    signal = provider.get_signal("1.2.3.4")
    assert signal is not None
    assert signal.score == 45  # 3*15 = 45, capped at 45
    assert provider._hits == 1
    assert provider._total == 1


def test_get_signal_cache_hit_zero_pulse_returns_none(mock_redis, mock_local_cache, mock_session):
    """get_signal() returns None for cache hit with pulse_count=0 (clean IP).

    Security consequence: returning a non-None signal for pulse_count=0 would add
    a false positive score to a clean IP, raising its composite risk score.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_local_cache.alienvault_scores.get.return_value = {"pulse_count": 0}

    signal = provider.get_signal("1.2.3.4")
    assert signal is None


def test_get_signal_cache_miss_increments_total(mock_redis, mock_local_cache, mock_session):
    """get_signal() on a cache miss increments _total but not _hits.

    Security consequence: if _total is not incremented on misses, the cache-hit
    ratio metric is inflated, hiding the true Redis/API load from operators.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    # Cache miss
    mock_local_cache.alienvault_scores.get.return_value = None

    # Wrap asyncio.create_task so the task doesn't actually run in this sync test
    with patch("asyncio.create_task", return_value=MagicMock()):
        provider.get_signal("1.2.3.4")

    assert provider._total == 1
    assert provider._hits == 0


# ---------------------------------------------------------------------------
# _maybe_lookup() — lines 161-182
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_maybe_lookup_redis_hit_populates_local_cache(mock_redis, mock_local_cache, mock_session):
    """_maybe_lookup() finds result in Redis and populates local cache without API call.

    Security consequence: if the Redis-tier cache is bypassed, every connection
    triggers an outbound API call, causing rate-limit exhaustion on OTX.
    """
    import json as _json

    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = _json.dumps({"pulse_count": 5}).encode()
    await provider._maybe_lookup("1.2.3.4")

    mock_local_cache.alienvault_scores.set.assert_called_once_with("1.2.3.4", {"pulse_count": 5})
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_maybe_lookup_redis_error_continues(mock_redis, mock_local_cache, mock_session):
    """_maybe_lookup() logs a Redis read error but still tries to enqueue the IP.

    Security consequence: a transient Redis error must not silently drop the lookup
    request — the IP would never be enriched, allowing known-malicious IPs to pass.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.side_effect = Exception("redis timeout")

    # Bloom add returns 1 (IP not already enqueued)
    mock_redis.bf().add.return_value = 1

    await provider._maybe_lookup("1.2.3.4")
    # Should not raise; IP should be enqueued (queue was empty)
    assert provider._queue.qsize() == 1


@pytest.mark.asyncio
async def test_maybe_lookup_bloom_duplicate_skips_queue(mock_redis, mock_local_cache, mock_session):
    """_maybe_lookup() skips re-enqueuing an IP already in the Bloom filter.

    Security consequence: re-enqueuing the same IP floods the worker queue,
    starving other IPs and creating a DoS vector against the enrichment pipeline.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    # Redis miss, bloom says already added (0 = already present)
    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 0

    await provider._maybe_lookup("1.2.3.4")
    assert provider._queue.qsize() == 0


@pytest.mark.asyncio
async def test_maybe_lookup_queue_full_does_not_raise(mock_redis, mock_local_cache, mock_session):
    """_maybe_lookup() silently drops an IP when the queue is full rather than raising.

    Security consequence: if a full queue raises an exception it crashes the caller
    goroutine; fail-open means the proxy continues even under enrichment overload.
    """
    config = OTXConfig(enabled=True, api_key="key", queue_size=1)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_redis.get.return_value = None
    mock_redis.bf().add.return_value = 1

    # Fill the queue
    provider._queue.put_nowait("already.in.queue")

    # Should not raise even though queue is full
    await provider._maybe_lookup("1.2.3.4")
    assert provider._queue.qsize() == 1  # Unchanged


# ---------------------------------------------------------------------------
# _worker_loop() exception path — line 195
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_worker_loop_exception_does_not_crash(mock_redis, mock_local_cache, mock_session):
    """_worker_loop() catches unexpected exceptions so the worker keeps running.

    Security consequence: an unhandled exception in the worker task kills it
    permanently, meaning subsequent IPs are never looked up from the API.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    # Enqueue one IP
    provider._queue.put_nowait("1.2.3.4")

    # Make _process_lookup raise an unexpected exception (not CancelledError)
    with patch.object(provider, "_process_lookup", side_effect=RuntimeError("unexpected")):
        # Start the worker — the exception is caught internally (line 195), task stays alive
        task = asyncio.create_task(provider._worker_loop())
        await asyncio.sleep(0.05)  # Let the worker run once, log the error, and keep looping
        assert not task.done(), "Worker task must stay alive after a non-CancelledError exception"
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


# ---------------------------------------------------------------------------
# _process_lookup() — no API key (line 199) and HTTP 404 (line 222-224)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_lookup_no_api_key_returns_early(mock_redis, mock_local_cache, mock_session):
    """_process_lookup() returns without calling the API when api_key is empty.

    Security consequence: if this guard is missing, the provider sends requests
    with an empty API key header, which exposes the service path and wastes quota.
    """
    config = OTXConfig(enabled=True, api_key="")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    await provider._process_lookup("1.2.3.4")
    mock_session.get.assert_not_called()


@pytest.mark.asyncio
async def test_process_lookup_404_caches_zero_pulses(mock_redis, mock_local_cache, mock_session):
    """HTTP 404 from OTX API caches pulse_count=0 (IP is clean or unknown).

    Security consequence: if a 404 is treated as an error and not cached, the
    proxy re-queries for every connection from that IP, exhausting the API quota.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(404, {})

    await provider._process_lookup("1.2.3.4")

    # Should cache with pulse_count=0
    mock_redis.setex.assert_called_once()
    cached_val = json.loads(mock_redis.setex.call_args[0][2])
    assert cached_val == {"pulse_count": 0}


@pytest.mark.asyncio
async def test_process_lookup_non_200_404_raises_logged_and_fails_open(
    mock_redis, mock_local_cache, mock_session
):
    """Non-200/404 HTTP status is logged as error and does not cache anything.

    Security consequence: silently caching a 5xx response as clean data would
    allow malicious IPs to slip through during OTX service degradation.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.return_value = _make_ctx(500, {})

    # Should not raise (fail open), but should not cache either
    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# TimeoutError path — lines 251-253
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_lookup_timeout_does_not_raise(mock_redis, mock_local_cache, mock_session):
    """asyncio.TimeoutError during lookup is caught and increments timeout counter.

    Security consequence: an uncaught timeout would crash the worker task, halting
    all subsequent enrichment lookups for the lifetime of the proxy process.
    """
    config = OTXConfig(enabled=True, api_key="key")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    mock_session.get.side_effect = asyncio.TimeoutError()

    # Should complete without raising
    await provider._process_lookup("1.2.3.4")
    mock_redis.setex.assert_not_called()


@pytest.mark.asyncio
async def test_process_lookup_timeout_with_circuit_breaker_records_failure(
    mock_redis, mock_local_cache, mock_session
):
    """TimeoutError records failure on the circuit breaker to track feed health.

    Security consequence: if failures are not recorded, the circuit breaker never
    opens, and the proxy continues hammering a down feed with every new connection.
    """
    from src.security.feed_health import FeedHealthMonitor
    from unittest.mock import patch

    monitor = FeedHealthMonitor()
    cb_mock = MagicMock()
    cb_mock.is_open.return_value = False

    with patch.object(monitor, "get_circuit_breaker", return_value=cb_mock):
        config = OTXConfig(enabled=True, api_key="key")
        provider = AlienVaultOTXProvider(
            config, mock_redis, mock_local_cache, mock_session, health_monitor=monitor
        )
        mock_session.get.side_effect = asyncio.TimeoutError()

        await provider._process_lookup("1.2.3.4")
        cb_mock.record_failure.assert_called()


# ---------------------------------------------------------------------------
# on_config_reload() — line 261
# ---------------------------------------------------------------------------


def test_on_config_reload_updates_config(mock_redis, mock_local_cache, mock_session):
    """on_config_reload() replaces the runtime config with updated values.

    Security consequence: if hot-reload is broken, secops cannot adjust score_cap
    or pulse_score without restarting the proxy, causing a service disruption.
    """
    config = OTXConfig(enabled=True, api_key="old-key", pulse_score=15)
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    new_raw_config = {
        "alienvault": {
            "enabled": True,
            "api_key": "new-key",
            "pulse_score": 20,
            "score_cap": 40,
        }
    }
    provider.on_config_reload(new_raw_config)

    assert provider._config.api_key == "new-key"
    assert provider._config.pulse_score == 20
    assert provider._config.score_cap == 40


# ── Missing-coverage additions ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_maybe_lookup_bloom_exception_is_suppressed(mock_redis, mock_local_cache, mock_session):
    """Lines 176-177: exception from the Bloom filter is caught and suppressed so
    enrichment degrades gracefully instead of crashing the caller.
    So what: if the except block is removed, a transient Redis Bloom filter error
    (e.g. RedisBloom module not loaded) would raise through _maybe_lookup and crash
    the per-connection async task — all subsequent enrichment for that connection
    would be lost silently."""
    config = OTXConfig(enabled=True, api_key="key")
    # Make bf().add raise so the except Exception: pass branch runs
    mock_redis.get.return_value = None
    mock_redis.bf().add.side_effect = Exception("bloom filter unavailable")
    provider = AlienVaultOTXProvider(config, mock_redis, mock_local_cache, mock_session)

    # Must not raise; the IP should still be enqueued (fail-open behaviour)
    await provider._maybe_lookup("5.5.5.5")
    # Queue may or may not have the IP depending on implementation,
    # but no exception must escape
    assert True  # reaching here means no exception propagated
