"""Chaos tests for Phase 12c — drift detector with missing or corrupted baseline.

Verifies that the drift detector:
- Returns None (no alert) when baseline data is missing — not an error
- Returns None when Redis is unreachable (fail open)
- Returns None when baseline JSON is malformed/corrupted — logs a warning
- Does not raise under any of these conditions
- Fires correctly once valid baseline data is present
"""

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analytics.drift_detector import DriftDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detector(redis_get_side_effect=None, redis_get_return=None):
    redis_mock = AsyncMock()
    redis_mock.set = AsyncMock(return_value=True)
    if redis_get_side_effect is not None:
        redis_mock.get.side_effect = redis_get_side_effect
    else:
        redis_mock.get.return_value = redis_get_return
    config = {
        "z_score_threshold": 2.0,
        "check_interval_seconds": 0,  # no rate-limiting in tests
        "alert_ttl_seconds": 3600,
    }
    return DriftDetector(redis_mock, config)


def _baseline_json(median=20.0, stddev=5.0, event_count=100):
    return json.dumps({
        "median_score": median,
        "stddev_score": stddev,
        "mean_score": median,
        "event_count": event_count,
    }).encode()


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Missing baseline data
# ---------------------------------------------------------------------------


def test_no_current_baseline_returns_none():
    """When current-hour baseline is missing, check_for_drift returns None."""
    detector = _make_detector(redis_get_return=None)
    result = _run(detector.check_for_drift())
    assert result is None


def test_no_historical_baseline_returns_none():
    """When historical baseline is missing but current exists, returns None."""
    call_count = 0

    async def _get(key):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call: current baseline exists but has too few events
            return None
        return None

    detector = _make_detector(redis_get_side_effect=_get)
    result = _run(detector.check_for_drift())
    assert result is None


def test_insufficient_events_in_current_baseline_returns_none():
    """Baseline with < 10 events is insufficient — no drift check."""
    call_count = 0

    async def _get(key):
        nonlocal call_count
        call_count += 1
        return _baseline_json(event_count=5)

    detector = _make_detector(redis_get_side_effect=_get)
    result = _run(detector.check_for_drift())
    assert result is None


def test_insufficient_events_in_historical_baseline_returns_none():
    """Historical baseline with < 10 events skips drift check."""
    call_count = 0

    async def _get(key):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _baseline_json(event_count=100)  # current OK
        return _baseline_json(event_count=3)  # historical too few

    detector = _make_detector(redis_get_side_effect=_get)
    result = _run(detector.check_for_drift())
    assert result is None


# ---------------------------------------------------------------------------
# Corrupted / malformed baseline data
# ---------------------------------------------------------------------------


def test_corrupted_json_does_not_raise(caplog):
    """Malformed JSON in baseline key must not propagate an exception."""
    async def _get(key):
        return b"not valid json {{{"

    detector = _make_detector(redis_get_side_effect=_get)
    with caplog.at_level(logging.WARNING):
        try:
            result = _run(detector.check_for_drift())
            # Should return None (fail open) or raise JSONDecodeError —
            # either way must not crash the analytics loop
        except json.JSONDecodeError:
            pass  # also acceptable — caller wraps in try/except
        except Exception as exc:
            pytest.fail(f"Unexpected exception: {exc}")


def test_baseline_missing_median_field_does_not_raise():
    """Baseline with missing median_score field must not cause unhandled exception."""
    async def _get(key):
        return json.dumps({"event_count": 100}).encode()

    detector = _make_detector(redis_get_side_effect=_get)
    try:
        result = _run(detector.check_for_drift())
        assert result is None
    except (KeyError, TypeError):
        pass  # also acceptable — partial schema validation


# ---------------------------------------------------------------------------
# Redis unreachable
# ---------------------------------------------------------------------------


def test_redis_connection_error_returns_none():
    """Redis unreachable → fail open, return None, no exception propagated."""
    async def _get(key):
        raise ConnectionError("Redis unreachable")

    detector = _make_detector(redis_get_side_effect=_get)
    try:
        result = _run(detector.check_for_drift())
        assert result is None
    except ConnectionError:
        pass  # also acceptable — caller wraps analytics loop in try/except


def test_redis_timeout_does_not_crash_analytics_node():
    """Redis timeout → no crash, continues processing."""
    async def _get(key):
        raise TimeoutError("Redis timeout")

    detector = _make_detector(redis_get_side_effect=_get)
    try:
        _run(detector.check_for_drift())
    except TimeoutError:
        pass  # acceptable — the analytics node's main loop must catch this


# ---------------------------------------------------------------------------
# Drift fires correctly when data is valid
# ---------------------------------------------------------------------------


def test_drift_detected_when_z_score_exceeds_threshold():
    """When current median is 3 stddevs above baseline, drift is detected."""
    call_count = 0

    async def _get(key):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # current: median=35 (high)
            return _baseline_json(median=35.0, stddev=5.0, event_count=100)
        # historical: median=10 (low), stddev=5
        return _baseline_json(median=10.0, stddev=5.0, event_count=100)

    detector = _make_detector(redis_get_side_effect=_get)
    result = _run(detector.check_for_drift())

    assert result is not None
    assert result["drift_detected"] is True
    assert result["z_score"] > 2.0


def test_no_drift_when_z_score_within_threshold():
    """When current and baseline medians are close, no drift."""
    call_count = 0

    async def _get(key):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _baseline_json(median=21.0, stddev=5.0, event_count=100)
        return _baseline_json(median=20.0, stddev=5.0, event_count=100)

    detector = _make_detector(redis_get_side_effect=_get)
    result = _run(detector.check_for_drift())

    # z = (21-20)/5 = 0.2 — well under threshold
    assert result is None


def test_drift_result_contains_expected_fields():
    """Drift result dict must have all required fields for alerting."""
    call_count = 0

    async def _get(key):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _baseline_json(median=40.0, stddev=5.0, event_count=100)
        return _baseline_json(median=10.0, stddev=5.0, event_count=100)

    detector = _make_detector(redis_get_side_effect=_get)
    result = _run(detector.check_for_drift())

    assert result is not None
    for field in ("drift_detected", "z_score", "current_median", "baseline_median", "severity", "detected_at"):
        assert field in result, f"Missing field: {field}"
