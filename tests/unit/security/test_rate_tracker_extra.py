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

import pytest
from unittest.mock import Mock, patch, MagicMock

import redis

from src.security.rate_tracker import (
    MultiStrategyRateTracker,
    RateTrackerError,
    RedisConnectionError,
)
from src.security.rate_strategy import RateLimitStrategy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_redis(ping_ok=True, register_ok=True, register_side_effect=None):
    """Build a mock Redis client."""
    mock = Mock(spec=redis.Redis)
    mock.ping.return_value = True if ping_ok else Mock(side_effect=redis.ConnectionError("down"))
    script = Mock()
    script.return_value = 1
    if register_ok:
        mock.register_script.return_value = script
    elif register_side_effect:
        mock.register_script.side_effect = register_side_effect
    return mock


def _minimal_config(strategy_override=None, windows_override=None):
    """Minimal valid config with one enabled strategy."""
    strategies = strategy_override if strategy_override is not None else {
        "by_ip": {
            "enabled": True,
            "thresholds": {"suspicious": 5, "block": 20, "ban": 50},
            "action": "block",
            "ban_duration": 3600,
        }
    }
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

        with pytest.raises(ValueError, match="rate_limit_strategies must be a dictionary"):
            MultiStrategyRateTracker(mock_redis, config)

    def test_string_strategies_raises_value_error(self):
        """rate_limit_strategies is a string → ValueError."""
        mock_redis = _make_redis()
        config = {"security": {"rate_limit_strategies": "by_ip"}}

        with pytest.raises(ValueError, match="rate_limit_strategies must be a dictionary"):
            MultiStrategyRateTracker(mock_redis, config)


# ---------------------------------------------------------------------------
# Lines 175-178: strategy settings not a dict → warning + skip
# ---------------------------------------------------------------------------


class TestInvalidStrategySettings:
    def test_string_settings_skipped_with_warning(self, caplog):
        """Lines 175-178: settings is a string → warning logged, strategy skipped."""
        import logging
        mock_redis = _make_redis()
        config = _minimal_config(strategy_override={
            "by_ip": "not-a-dict",  # invalid settings
        })
        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        assert any("Invalid settings" in r.message for r in caplog.records)
        # Strategy was skipped → enabled_strategies is empty (only by_ip configured)
        assert len(tracker.enabled_strategies) == 0

    def test_none_settings_skipped(self, caplog):
        """None settings → not a dict → warning, strategy skipped."""
        import logging
        mock_redis = _make_redis()
        config = _minimal_config(strategy_override={
            "by_ip": None,
        })
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
        config = _minimal_config(strategy_override={
            "completely_unknown_strategy": {
                "enabled": True,
                "thresholds": {"suspicious": 5, "block": 20, "ban": 50},
                "action": "block",
                "ban_duration": 3600,
            },
        })
        with caplog.at_level(logging.WARNING, logger="src.security.rate_tracker"):
            tracker = MultiStrategyRateTracker(mock_redis, config)

        assert any("Unknown strategy" in r.message for r in caplog.records)
        assert len(tracker.enabled_strategies) == 0

    def test_disabled_unknown_strategy_not_warned(self, caplog):
        """Disabled unknown strategy doesn't trigger the warning."""
        import logging
        mock_redis = _make_redis()
        config = _minimal_config(strategy_override={
            "completely_unknown_strategy": {
                "enabled": False,  # disabled → not loaded, no warning
                "thresholds": {"suspicious": 5, "block": 20, "ban": 50},
            },
        })
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
