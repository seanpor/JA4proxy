"""
Unit tests for src/analytics/shadow_scoring.py.

Security consequence: ShadowScoring monitors the scores assigned to known-good
traffic (browser h2/h1 connections).  If known-good traffic receives elevated
scores, the dial is miscalibrated and raising it would block real users.  Bugs
in the calibration checks would either silence the alert (dial raised, mass FP)
or fire spuriously (alert fatigue → operators stop watching).
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.analytics.shadow_scoring import ShadowScoring


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shadow(config=None) -> ShadowScoring:
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock()
    cfg = config or {}
    return ShadowScoring(mock_redis, cfg)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _h2_event(score: float) -> dict:
    return {"src_ip": "1.2.3.4", "alpn": "h2", "score": score, "action": "allow"}


def _h1_event(score: float) -> dict:
    return {"src_ip": "1.2.3.4", "alpn": "h1", "score": score, "action": "allow"}


def _bot_event(score: float) -> dict:
    return {"src_ip": "1.2.3.4", "alpn": "grpc", "score": score, "action": "block"}


# ---------------------------------------------------------------------------
# _is_known_good_traffic
# ---------------------------------------------------------------------------

class TestIsKnownGoodTraffic:
    def test_h2_alpn_is_known_good(self):
        # Security: h2 browser traffic is the canonical known-good population;
        # if it is not identified as such, calibration has no reference set.
        s = _make_shadow()
        assert s._is_known_good_traffic({"alpn": "h2", "score": 0}) is True

    def test_h1_alpn_is_known_good(self):
        s = _make_shadow()
        assert s._is_known_good_traffic({"alpn": "h1", "score": 0}) is True

    def test_grpc_alpn_is_not_known_good(self):
        s = _make_shadow()
        assert s._is_known_good_traffic({"alpn": "grpc", "score": 0}) is False

    def test_missing_alpn_is_not_known_good(self):
        s = _make_shadow()
        assert s._is_known_good_traffic({"score": 0}) is False

    def test_custom_known_good_alpn_honoured(self):
        # Operators can extend the known-good set (e.g. internal gRPC services).
        s = _make_shadow({"known_good_alpn": ["h2", "h1", "grpc"]})
        assert s._is_known_good_traffic({"alpn": "grpc", "score": 0}) is True


# ---------------------------------------------------------------------------
# _calculate_median
# ---------------------------------------------------------------------------

class TestCalculateMedian:
    def test_empty_list_returns_zero(self):
        s = _make_shadow()
        assert s._calculate_median([]) == 0.0

    def test_single_element(self):
        s = _make_shadow()
        assert s._calculate_median([42.0]) == 42.0

    def test_odd_count(self):
        s = _make_shadow()
        assert s._calculate_median([1.0, 3.0, 5.0]) == 3.0

    def test_even_count_averages_middle_two(self):
        s = _make_shadow()
        assert s._calculate_median([2.0, 4.0, 6.0, 8.0]) == 5.0

    def test_all_same_values(self):
        s = _make_shadow()
        assert s._calculate_median([7.0, 7.0, 7.0]) == 7.0


# ---------------------------------------------------------------------------
# _calculate_mean
# ---------------------------------------------------------------------------

class TestCalculateMean:
    def test_empty_list_returns_zero(self):
        s = _make_shadow()
        assert s._calculate_mean([]) == 0.0

    def test_single_value(self):
        s = _make_shadow()
        assert s._calculate_mean([10.0]) == 10.0

    def test_multiple_values(self):
        s = _make_shadow()
        assert s._calculate_mean([10.0, 20.0, 30.0]) == pytest.approx(20.0)


# ---------------------------------------------------------------------------
# _calculate_stddev
# ---------------------------------------------------------------------------

class TestCalculateStddev:
    def test_single_value_returns_zero(self):
        s = _make_shadow()
        assert s._calculate_stddev([5.0]) == 0.0

    def test_empty_list_returns_zero(self):
        s = _make_shadow()
        assert s._calculate_stddev([]) == 0.0

    def test_constant_values_stddev_zero(self):
        s = _make_shadow()
        assert s._calculate_stddev([4.0, 4.0, 4.0]) == pytest.approx(0.0, abs=1e-9)

    def test_known_stddev(self):
        # Population std of [2,4,4,4,5,5,7,9] = 2.0
        s = _make_shadow()
        assert s._calculate_stddev([2, 4, 4, 4, 5, 5, 7, 9]) == pytest.approx(2.0, abs=1e-9)


# ---------------------------------------------------------------------------
# update_with_event — window rotation and score accumulation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestUpdateWithEvent:
    async def test_non_known_good_event_ignored(self):
        # Security: bot traffic must not contaminate the known-good reference
        # population — if it does, high attacker scores push up the shadow median
        # and calibration issues go undetected.
        s = _make_shadow()
        await s.update_with_event(_bot_event(80.0))
        assert s.shadow_scores == []

    async def test_known_good_event_accumulates_score(self):
        s = _make_shadow()
        await s.update_with_event(_h2_event(5.0))
        assert s.shadow_scores == [5.0]

    async def test_multiple_events_accumulate(self):
        s = _make_shadow()
        for score in [1.0, 2.0, 3.0]:
            await s.update_with_event(_h2_event(score))
        assert s.shadow_scores == [1.0, 2.0, 3.0]

    async def test_window_initialized_on_first_event(self):
        s = _make_shadow()
        assert s.current_window is None
        await s.update_with_event(_h2_event(5.0))
        assert s.current_window is not None

    async def test_window_rotation_flushes_scores(self):
        # Security: window rotation stores current scores and resets the list;
        # if scores are not flushed, the previous window bleeds into the next,
        # masking sudden calibration degradation.
        s = _make_shadow()
        s.redis.set = AsyncMock()
        # Force current_window to a past window
        s.current_window = 0
        s.shadow_scores = [1.0, 2.0, 3.0]
        # Now send event that belongs to a different window
        await s.update_with_event(_h2_event(9.0))
        # Scores should have been rotated: new list starts fresh
        assert s.shadow_scores == [9.0]


# ---------------------------------------------------------------------------
# _store_shadow_scores
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestStoreShadowScores:
    async def test_empty_scores_no_redis_write(self):
        # Avoid writing meaningless data to Redis that could confuse downstream reads.
        s = _make_shadow()
        s.shadow_scores = []
        await s._store_shadow_scores()
        s.redis.set.assert_not_called()

    async def test_non_empty_scores_writes_to_redis(self):
        s = _make_shadow()
        s.shadow_scores = [2.0, 5.0, 8.0]
        await s._store_shadow_scores()
        s.redis.set.assert_called_once()
        key = s.redis.set.call_args[0][0]
        assert key == s.shadow_key
        stored = json.loads(s.redis.set.call_args[0][1])
        assert stored["count"] == 3
        assert "median" in stored
        assert "mean" in stored
        assert "stddev" in stored

    async def test_stored_stats_correct(self):
        s = _make_shadow()
        s.shadow_scores = [4.0, 6.0, 8.0]
        await s._store_shadow_scores()
        stored = json.loads(s.redis.set.call_args[0][1])
        assert stored["median"] == pytest.approx(6.0)
        assert stored["mean"] == pytest.approx(6.0)


# ---------------------------------------------------------------------------
# check_calibration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCheckCalibration:
    async def test_rate_limited_on_second_call(self):
        s = _make_shadow({"check_interval_seconds": 9999})
        s.last_check_time = time.time()
        result = await s.check_calibration()
        assert result is None

    async def test_no_shadow_data_returns_none(self):
        s = _make_shadow({"check_interval_seconds": 0})
        s.redis.get = AsyncMock(return_value=None)
        result = await s.check_calibration()
        assert result is None

    async def test_insufficient_count_returns_none(self):
        # Too few samples → calibration check is unreliable; suppress alert.
        s = _make_shadow({"check_interval_seconds": 0})
        shadow_data = json.dumps({"median": 5.0, "mean": 5.0, "stddev": 1.0, "count": 5})
        s.redis.get = AsyncMock(return_value=shadow_data.encode())
        result = await s.check_calibration()
        assert result is None

    async def test_alert_fires_when_median_exceeds_threshold(self):
        # Security: if known-good traffic receives high scores, the scoring model
        # is miscalibrated; operators must be alerted before raising the dial.
        s = _make_shadow({"check_interval_seconds": 0, "calibration_threshold": 10.0})
        shadow_data = json.dumps({"median": 25.0, "mean": 22.0, "stddev": 5.0, "count": 50})
        s.redis.get = AsyncMock(return_value=shadow_data.encode())
        s.redis.set = AsyncMock()
        result = await s.check_calibration()
        assert result is not None
        assert result["type"] == "calibration_issue"
        assert result["severity"] == "high"

    async def test_no_alert_when_median_below_threshold(self):
        s = _make_shadow({"check_interval_seconds": 0, "calibration_threshold": 10.0})
        shadow_data = json.dumps({"median": 3.0, "mean": 3.5, "stddev": 1.0, "count": 50})
        s.redis.get = AsyncMock(return_value=shadow_data.encode())
        result = await s.check_calibration()
        assert result is None

    async def test_calibration_alert_stored_in_redis(self):
        s = _make_shadow({"check_interval_seconds": 0, "calibration_threshold": 10.0})
        shadow_data = json.dumps({"median": 30.0, "mean": 28.0, "stddev": 5.0, "count": 100})
        s.redis.get = AsyncMock(return_value=shadow_data.encode())
        s.redis.set = AsyncMock()
        await s.check_calibration()
        s.redis.set.assert_called()
        # The alert key should be what's written
        call_key = s.redis.set.call_args[0][0]
        assert call_key == s.alert_key


# ---------------------------------------------------------------------------
# get_active_alert / clear_alert
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestShadowAlertManagement:
    async def test_no_alert_when_redis_empty(self):
        s = _make_shadow()
        s.redis.get = AsyncMock(return_value=None)
        result = await s.get_active_alert()
        assert result is None

    async def test_returns_unresolved_alert(self):
        s = _make_shadow()
        alert = {"type": "calibration_issue", "resolved": False, "shadow_median": 30.0}
        s.redis.get = AsyncMock(return_value=json.dumps(alert).encode())
        result = await s.get_active_alert()
        assert result is not None
        assert result["shadow_median"] == 30.0

    async def test_resolved_alert_returns_none(self):
        # Security: a cleared alert must not recur until the condition is
        # re-detected; otherwise the management UI shows ghost alerts.
        s = _make_shadow()
        alert = {"type": "calibration_issue", "resolved": True}
        s.redis.get = AsyncMock(return_value=json.dumps(alert).encode())
        result = await s.get_active_alert()
        assert result is None

    async def test_clear_alert_sets_resolved_true(self):
        s = _make_shadow()
        original = {"type": "calibration_issue", "resolved": False, "shadow_median": 30.0}
        s.redis.get = AsyncMock(return_value=json.dumps(original).encode())
        s.redis.set = AsyncMock()
        await s.clear_alert()
        stored = json.loads(s.redis.set.call_args[0][1])
        assert stored["resolved"] is True
        assert "resolved_at" in stored

    async def test_clear_alert_no_op_when_no_existing_alert(self):
        s = _make_shadow()
        s.redis.get = AsyncMock(return_value=None)
        s.redis.set = AsyncMock()
        await s.clear_alert()
        s.redis.set.assert_not_called()


# ---------------------------------------------------------------------------
# get_calibration_history
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGetCalibrationHistory:
    async def test_empty_history_when_no_redis_data(self):
        s = _make_shadow({"check_interval_seconds": 0})
        s.redis.get = AsyncMock(return_value=None)
        history = await s.get_calibration_history(hours=3)
        assert history == []

    async def test_history_sorted_descending_by_timestamp(self):
        # Security: most recent calibration status first so operators can quickly
        # check whether the model was miscalibrated recently.
        s = _make_shadow()
        shadow_data = json.dumps({"median": 2.0, "mean": 2.0, "stddev": 0.5, "count": 20})
        s.redis.get = AsyncMock(return_value=shadow_data.encode())
        history = await s.get_calibration_history(hours=3)
        if len(history) >= 2:
            assert history[0]["timestamp"] >= history[1]["timestamp"]

    async def test_history_entry_has_expected_keys(self):
        s = _make_shadow()
        shadow_data = json.dumps({"median": 2.0, "mean": 2.0, "stddev": 0.5, "count": 20})
        s.redis.get = AsyncMock(return_value=shadow_data.encode())
        history = await s.get_calibration_history(hours=1)
        if history:
            entry = history[0]
            for key in ("timestamp", "shadow_median", "has_calibration_issue", "severity"):
                assert key in entry

    async def test_history_marks_calibration_issue_when_threshold_exceeded(self):
        s = _make_shadow({"calibration_threshold": 10.0})
        shadow_data = json.dumps({"median": 25.0, "mean": 22.0, "stddev": 5.0, "count": 50})
        s.redis.get = AsyncMock(return_value=shadow_data.encode())
        history = await s.get_calibration_history(hours=1)
        if history:
            assert history[0]["has_calibration_issue"] is True
            assert history[0]["severity"] == "high"
