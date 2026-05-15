#!/usr/bin/env python3
"""
Additional rate_tracker tests for previously uncovered branches.

Covers:
- Lines 125-126: register_script raises redis.RedisError → RedisConnectionError
- Line 164: non-dict rate_limit_strategies raises ValueError
- Lines 175-178: strategy settings not a dict → skipped with warning
- Line 187: unknown strategy name → skipped with warning
- Lines 225-226: invalid window value (TypeError/ValueError) → warning
- Lines 367-368: _track_single_strategy except redis.TimeoutError
- Lines 369-370: _track_single_strategy except redis.RedisError
- Lines 371-372: _track_single_strategy except bare Exception
"""

from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
import redis

from src.security.rate_strategy import RateLimitStrategy
from src.security.rate_tracker import (
    MultiStrategyRateTracker,
    RateTrackerError,
    RedisConnectionError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_redis(ping_ok=True, register_ok=True, register_side_effect=None):
    """Build a mock Redis client."""
    mock = Mock(spec=redis.Redis)
    mock.ping.return_value = (
        True if ping_ok else Mock(side_effect=redis.ConnectionError("down"))
    )
    script = Mock()
    script.return_value = 1
    if register_ok:
        mock.register_script.return_value = script
    elif register_side_effect:
        mock.register_script.side_effect = register_side_effect
    return mock


def _minimal_config(strategy_override=None, windows_override=None):
    """Minimal valid config with one enabled strategy."""
    strategies = (
        strategy_override
        if strategy_override is not None
        else {
            "by_ip": {
                "enabled": True,
                "thresholds": {"suspicious": 5, "block": 20, "ban": 50},
                "action": "block",
                "ban_duration": 3600,
            }
        }
    )
    cfg = {
        "security": {
            "rate_limit_strategies": strategies,
        }
    }
    if windows_override is not None:
        cfg["security"]["rate_windows"] = windows_override
    return cfg


# ---------------------------------------------------------------------------
# Lines 125-126: register_script raises redis.RedisError
# ---------------------------------------------------------------------------


class TestRegisterScriptFailure:
    def test_redis_error_on_register_script_raises_connection_error(self):
        """Lines 125-126: register_script raises RedisError → RedisConnectionError."""
        mock_redis = _make_redis()
        mock_redis.register_script.side_effect = redis.RedisError("script load failed")

        with pytest.raises(RedisConnectionError, match="Failed to register Lua script"):
            MultiStrategyRateTracker(mock_redis, _minimal_config())


# ---------------------------------------------------------------------------
# Line 164: non-dict rate_limit_strategies raises ValueError
# ---------------------------------------------------------------------------


class TestNonDictStrategies:
    def test_list_strategies_raises_value_error(self):
        """Line 164: rate_limit_strategies is a list → ValueError."""
        mock_redis = _make_redis()
        config = {"security": {"rate_limit_strategies": ["by_ip", "by_ja4"]}}

        with pytest.raises(
            ValueError, match="rate_limit_strategies must be a dictionary"
        ):
            MultiStrategyRateTracker(mock_redis, config)

    def test_string_strategies_raises_value_error(self):
        """rate_limit_strategies is a string → ValueError."""
        mock_redis = _make_redis()
        config = {"security": {"rate_limit_strategies": "by_ip"}}

        with pytest.raises(
            ValueError, match="rate_limit_strategies must be a dictionary"
        ):
            MultiStrategyRateTracker(mock_redis, config)


# ---------------------------------------------------------------------------
# Lines 175-178: strategy settings not a dict → warning + skip
# ---------------------------------------------------------------------------


class TestInvalidStrategySettings:
    def test_string_settings_skipped_with_warning(self, caplog):
        """Lines 175-178: settings is a string → warning logged, strategy skipped."""
        import logging

        mock_redis = _make_redis()
        config = _minimal_config(
            strategy_override={
                "by_ip": "not-a-dict",  # invalid settings
            }
        )
        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        assert any("Invalid settings" in r.message for r in caplog.records)
        # Strategy was skipped → enabled_strategies is empty (only by_ip configured)
        assert len(tracker.enabled_strategies) == 0

    def test_none_settings_skipped(self, caplog):
        """None settings → not a dict → warning, strategy skipped."""
        import logging

        mock_redis = _make_redis()
        config = _minimal_config(
            strategy_override={
                "by_ip": None,
            }
        )
        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        assert any("Invalid settings" in r.message for r in caplog.records)
        assert len(tracker.enabled_strategies) == 0


# ---------------------------------------------------------------------------
# Line 187: unknown strategy name → warning
# ---------------------------------------------------------------------------


class TestUnknownStrategyName:
    def test_unknown_enabled_strategy_skipped(self, caplog):
        """Line 187: enabled strategy with unknown name → warning, skipped."""
        import logging

        mock_redis = _make_redis()
        config = _minimal_config(
            strategy_override={
                "completely_unknown_strategy": {
                    "enabled": True,
                    "thresholds": {"suspicious": 5, "block": 20, "ban": 50},
                    "action": "block",
                    "ban_duration": 3600,
                },
            }
        )
        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        assert any("Unknown strategy" in r.message for r in caplog.records)
        assert len(tracker.enabled_strategies) == 0

    def test_disabled_unknown_strategy_not_warned(self, caplog):
        """Disabled unknown strategy doesn't trigger the warning."""
        import logging

        mock_redis = _make_redis()
        config = _minimal_config(
            strategy_override={
                "completely_unknown_strategy": {
                    "enabled": False,  # disabled → not loaded, no warning
                    "thresholds": {"suspicious": 5, "block": 20, "ban": 50},
                },
            }
        )
        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        unknown_warns = [r for r in caplog.records if "Unknown strategy" in r.message]
        assert len(unknown_warns) == 0


# ---------------------------------------------------------------------------
# Lines 225-226: invalid window value → TypeError/ValueError
# ---------------------------------------------------------------------------


class TestInvalidWindowValues:
    def test_non_numeric_window_value_skipped(self, caplog):
        """Lines 225-226: float('list') raises ValueError → warning, default kept."""
        import logging

        mock_redis = _make_redis()
        config = _minimal_config(windows_override={"custom": "not-a-number"})

        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        assert any("Invalid window" in r.message for r in caplog.records)
        # Default window is still used (short=1.0)
        assert tracker.windows["short"] == 1.0

    def test_none_window_value_skipped(self, caplog):
        """None window value → float(None) raises TypeError → warning."""
        import logging

        mock_redis = _make_redis()
        config = _minimal_config(windows_override={"custom": None})

        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        assert any("Invalid window" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Lines 367-372: _track_single_strategy exception hierarchy
# ---------------------------------------------------------------------------


class TestTrackSingleStrategyExceptions:
    @pytest.fixture
    def tracker(self):
        """Build a tracker with a single by_ip strategy."""
        mock_redis = _make_redis()
        return MultiStrategyRateTracker(mock_redis, _minimal_config())

    async def test_timeout_error_raises_rate_tracker_error(self, tracker):
        """Lines 367-368: redis.TimeoutError → RateTrackerError."""
        tracker.rate_script.side_effect = redis.TimeoutError("operation timed out")

        results = await tracker.track_connection("t13d1516h2_abc123_def456", "1.2.3.4")

        # Fail-closed: returns MAX_CONNECTIONS for all strategies
        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW

    async def test_generic_redis_error_raises_rate_tracker_error(self, tracker):
        """Lines 369-370: redis.RedisError (not Connection/Timeout) → RateTrackerError."""
        # redis.DataError is-a RedisError but NOT ConnectionError or TimeoutError
        tracker.rate_script.side_effect = redis.DataError("type error in script")

        results = await tracker.track_connection("t13d1516h2_abc123_def456", "1.2.3.4")

        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW

    async def test_unexpected_exception_raises_rate_tracker_error(self, tracker):
        """Lines 371-372: bare Exception → RateTrackerError."""
        tracker.rate_script.side_effect = RuntimeError("unexpected crash")

        results = await tracker.track_connection("t13d1516h2_abc123_def456", "1.2.3.4")

        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW

    async def test_overflow_error_raises_rate_tracker_error(self, tracker):
        """OverflowError is-a Exception → hits lines 371-372."""
        tracker.rate_script.side_effect = OverflowError("int overflow")

        results = await tracker.track_connection("t13d1516h2_abc123_def456", "1.2.3.4")

        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW


# ── Missing-coverage tests ────────────────────────────────────────────────────


class TestIsAsyncRedis:
    """Cover _is_async_redis() AttributeError path (line 141-142).

    So what: if redis.asyncio doesn't exist on older installs the tracker must
    not crash on init — it must gracefully return False (sync mode).
    """

    def test_is_async_redis_attribute_error_returns_false(self):
        """redis.asyncio missing Redis attr → returns False (lines 141-142).
        So what: environments without redis.asyncio must still initialise safely."""
        from src.security.rate_tracker import MultiStrategyRateTracker

        mock_client = MagicMock()
        # Simulate redis.asyncio not having a Redis attribute at all
        import types

        fake_asyncio = types.ModuleType("redis.asyncio")
        # Do NOT set fake_asyncio.Redis — accessing it raises AttributeError
        with patch("src.security.rate_tracker.redis") as mock_redis_mod:
            mock_redis_mod.asyncio = fake_asyncio
            result = MultiStrategyRateTracker._is_async_redis(mock_client)
        assert result is False


class TestValidateRedisConnectionAsync:
    """Cover _validate_redis_connection() async skip path (line 154).

    So what: for async Redis clients, ping() returns a coroutine that cannot
    be awaited synchronously — skipping validates the connection was already
    established by the caller.
    """

    def test_validate_redis_async_skips_ping(self):
        """Async Redis client → _validate_redis_connection returns early (line 154).
        So what: calling sync ping on async client raises TypeError; must be skipped."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)
        # Patch _is_async_redis to pretend our mock is async
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=True
        ):
            # Should not call ping
            tracker._validate_redis_connection()
        mock_redis.ping.assert_called_once()  # was called in __init__, not in validate


class TestHealthCheckAsync:
    """Cover health_check() for async Redis (line 555).

    So what: if health_check() tries to call sync ping on async Redis it would
    get a coroutine back (not a bool). Must return True immediately for async.
    """

    def test_health_check_returns_true_for_async_client(self):
        """Async Redis client → health_check returns True without calling ping (line 555).
        So what: calling .ping() on async client returns a coroutine, not a bool."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=True
        ):
            result = tracker.health_check()
        assert result is True


class TestTrackWithPipelineBatchingSyncPath:
    """Cover the sync Redis pipeline batching path (lines 404-434).

    So what: the proxy uses pipeline batching to reduce Redis round-trips by 3×.
    If the sync pipeline path never executes, the batching never actually fires for
    sync Redis deployments, reverting to individual calls and tripling latency.
    """

    @pytest.mark.asyncio
    async def test_sync_pipeline_batching_populates_results(self):
        """Sync Redis pipeline batching → results dict populated (lines 404-434).
        So what: pipeline batching must work with sync Redis or rate data is lost."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        # Set up pipeline mock
        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = [5]  # one strategy, count=5
        mock_pipe.__enter__ = MagicMock(return_value=mock_pipe)
        mock_pipe.__exit__ = MagicMock(return_value=False)
        mock_redis.pipeline.return_value = mock_pipe

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=False
        ):
            await tracker._track_with_pipeline_batching(
                "t13d",
                "1.2.3.4",
                window_seconds=60.0,
                now=1700000000.0,
                ttl=60,
                results=results,
            )
        assert len(results) == 1
        for metrics in results.values():
            assert metrics.connections_per_second == 5

    @pytest.mark.asyncio
    async def test_sync_pipeline_batching_clamps_oversized_count(self):
        """Count > MAX_CONNECTIONS_PER_WINDOW is clamped (lines 425-431).
        So what: a malicious Redis returning huge count must not bypass rate limits."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        mock_pipe = MagicMock()
        mock_pipe.execute.return_value = [tracker.MAX_CONNECTIONS_PER_WINDOW + 9999]
        mock_pipe.__enter__ = MagicMock(return_value=mock_pipe)
        mock_pipe.__exit__ = MagicMock(return_value=False)
        mock_redis.pipeline.return_value = mock_pipe

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=False
        ):
            await tracker._track_with_pipeline_batching(
                "t13d",
                "1.2.3.4",
                window_seconds=60.0,
                now=1700000000.0,
                ttl=60,
                results=results,
            )
        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW

    @pytest.mark.asyncio
    async def test_sync_pipeline_batching_connection_error_raises(self):
        """redis.ConnectionError in sync pipeline → RateTrackerError (line 443).
        So what: Redis going down during batch must be surfaced, not silently dropped.
        """
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        mock_pipe = MagicMock()
        mock_pipe.__enter__ = MagicMock(return_value=mock_pipe)
        mock_pipe.__exit__ = MagicMock(return_value=False)
        mock_pipe.execute.side_effect = redis.ConnectionError("down")
        mock_redis.pipeline.return_value = mock_pipe

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=False
        ):
            with pytest.raises(RateTrackerError, match="Redis connection error"):
                await tracker._track_with_pipeline_batching(
                    "t13d",
                    "1.2.3.4",
                    60.0,
                    1700000000.0,
                    60,
                    results,
                )

    @pytest.mark.asyncio
    async def test_sync_pipeline_batching_timeout_error_raises(self):
        """redis.TimeoutError in sync pipeline → RateTrackerError (line 445).
        So what: timeout during batch must propagate so track_connection can fail-closed.
        """
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        mock_pipe = MagicMock()
        mock_pipe.__enter__ = MagicMock(return_value=mock_pipe)
        mock_pipe.__exit__ = MagicMock(return_value=False)
        mock_pipe.execute.side_effect = redis.TimeoutError("timeout")
        mock_redis.pipeline.return_value = mock_pipe

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=False
        ):
            with pytest.raises(RateTrackerError, match="Redis timeout"):
                await tracker._track_with_pipeline_batching(
                    "t13d",
                    "1.2.3.4",
                    60.0,
                    1700000000.0,
                    60,
                    results,
                )

    @pytest.mark.asyncio
    async def test_sync_pipeline_batching_redis_error_raises(self):
        """redis.RedisError in sync pipeline → RateTrackerError (line 447).
        So what: generic Redis error during batch must not silently succeed."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        mock_pipe = MagicMock()
        mock_pipe.__enter__ = MagicMock(return_value=mock_pipe)
        mock_pipe.__exit__ = MagicMock(return_value=False)
        mock_pipe.execute.side_effect = redis.RedisError("generic error")
        mock_redis.pipeline.return_value = mock_pipe

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=False
        ):
            with pytest.raises(RateTrackerError, match="Redis error"):
                await tracker._track_with_pipeline_batching(
                    "t13d",
                    "1.2.3.4",
                    60.0,
                    1700000000.0,
                    60,
                    results,
                )

    @pytest.mark.asyncio
    async def test_no_enabled_strategies_returns_immediately(self):
        """enabled_strategies empty → _track_with_pipeline_batching returns (line 354-355).
        So what: a proxy with all rate strategies disabled must not attempt Redis calls.
        """
        mock_redis = _make_redis()
        tracker = MultiStrategyRateTracker(
            mock_redis, {"security": {"rate_limit_strategies": {}}}
        )
        results = {}
        await tracker._track_with_pipeline_batching(
            "t13d",
            "1.2.3.4",
            60.0,
            1700000000.0,
            60,
            results,
        )
        assert results == {}


class TestTrackWithPipelineBatchingAsyncPath:
    """Cover the async Redis pipeline batching path (lines 360-398).

    So what: async Redis is the default in modern async Python deployments.
    If the async pipeline path never runs, every tracking call is serialised
    (one round-trip per strategy) instead of batched — 3× the Redis latency.
    """

    @pytest.mark.asyncio
    async def test_async_pipeline_batching_populates_results(self):
        """Async Redis pipeline → results populated with connection counts (lines 360-398).
        So what: pipeline must fire all strategy scripts in one round-trip."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        # Build async context manager pipeline mock
        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(return_value=[5])  # one strategy, count=5
        async_cm = MagicMock()
        async_cm.__aenter__ = AsyncMock(return_value=mock_pipe)
        async_cm.__aexit__ = AsyncMock(return_value=False)
        mock_redis.pipeline = MagicMock(return_value=async_cm)

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=True
        ):
            await tracker._track_with_pipeline_batching(
                "t13d",
                "1.2.3.4",
                window_seconds=60.0,
                now=1700000000.0,
                ttl=60,
                results=results,
            )
        assert len(results) == 1
        for metrics in results.values():
            assert metrics.connections_per_second == 5

    @pytest.mark.asyncio
    async def test_async_pipeline_clamps_oversized_count(self):
        """Count > MAX_CONNECTIONS_PER_WINDOW clamped in async path (lines 382-389).
        So what: Redis returning an extreme count must not bypass rate limiting."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(
            return_value=[tracker.MAX_CONNECTIONS_PER_WINDOW + 9999]
        )
        async_cm = MagicMock()
        async_cm.__aenter__ = AsyncMock(return_value=mock_pipe)
        async_cm.__aexit__ = AsyncMock(return_value=False)
        mock_redis.pipeline = MagicMock(return_value=async_cm)

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=True
        ):
            await tracker._track_with_pipeline_batching(
                "t13d",
                "1.2.3.4",
                window_seconds=60.0,
                now=1700000000.0,
                ttl=60,
                results=results,
            )
        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW

    @pytest.mark.asyncio
    async def test_async_pipeline_connection_error_raises(self):
        """redis.ConnectionError in async pipeline → RateTrackerError (line 443)."""
        mock_redis = _make_redis()
        cfg = _minimal_config()
        tracker = MultiStrategyRateTracker(mock_redis, cfg)

        mock_pipe = AsyncMock()
        mock_pipe.execute = AsyncMock(side_effect=redis.ConnectionError("down"))
        async_cm = MagicMock()
        async_cm.__aenter__ = AsyncMock(return_value=mock_pipe)
        async_cm.__aexit__ = AsyncMock(return_value=False)
        mock_redis.pipeline = MagicMock(return_value=async_cm)

        results = {}
        with patch.object(
            MultiStrategyRateTracker, "_is_async_redis", return_value=True
        ):
            with pytest.raises(RateTrackerError, match="Redis connection error"):
                await tracker._track_with_pipeline_batching(
                    "t13d",
                    "1.2.3.4",
                    60.0,
                    1700000000.0,
                    60,
                    results,
                )
