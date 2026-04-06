"""Unit tests for Phase 9 — Beaconing Detection."""

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import redis

from src.security.beaconing_detector import (
    BeaconingDetector,
    beacon_score,
    coefficient_of_variation,
    compute_iats,
)
from src.security.models import ConnectionContext, RiskSignal

# ---------------------------------------------------------------------------
# Statistical function tests
# ---------------------------------------------------------------------------


class TestCoefficientOfVariation(unittest.TestCase):
    """Tests for coefficient_of_variation()."""

    def test_empty_list_returns_zero(self):
        """Empty list → 0.0 (not an error)."""
        self.assertEqual(coefficient_of_variation([]), 0.0)

    def test_single_value_returns_zero(self):
        """Single value → 0.0 (can't compute variation)."""
        self.assertEqual(coefficient_of_variation([60.0]), 0.0)

    def test_all_equal_values_returns_zero(self):
        """All-equal values → stdev=0 → CV=0.0."""
        self.assertEqual(coefficient_of_variation([60.0, 60.0, 60.0, 60.0]), 0.0)

    def test_typical_values(self):
        """Returns correct CV for typical IAT sequence."""
        # mean=60, stdev≈7, CV≈0.11
        iats = [53.0, 67.0, 60.0, 53.0, 67.0, 60.0, 53.0]
        cv = coefficient_of_variation(iats)
        self.assertGreater(cv, 0.0)
        self.assertLess(cv, 0.15)  # Stays in strong-beacon range


class TestBeaconScore(unittest.TestCase):
    """Tests for beacon_score()."""

    def test_empty_iat_list_returns_zero(self):
        """Empty IAT list → 0.0 (not enough data)."""
        self.assertEqual(beacon_score([]), 0.0)

    def test_single_iat_returns_zero(self):
        """Single IAT → 0.0 (can't compute CV)."""
        self.assertEqual(beacon_score([60.0]), 0.0)

    def test_perfect_beacon_cv_zero_returns_09(self):
        """CV=0 (all equal) → 0.9 (strong beacon)."""
        iats = [60.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0]
        self.assertEqual(beacon_score(iats), 0.9)

    def test_jittered_beacon_cv_012_returns_09(self):
        """CV≈0.10 (±7s jitter around 60s) → 0.9 (still strong beacon)."""
        # mean≈60, stdev≈6, CV≈0.10 < 0.15
        iats = [53.0, 67.0, 60.0, 53.0, 67.0, 60.0, 53.0]
        self.assertEqual(beacon_score(iats), 0.9)

    def test_moderate_cv_025_returns_05(self):
        """CV≈0.22 (±15s around 60s) → 0.5 (moderate)."""
        # mean=60, stdev≈13, CV≈0.22
        iats = [45.0, 75.0, 60.0, 45.0, 75.0, 60.0, 45.0]
        score = beacon_score(iats)
        self.assertEqual(score, 0.5)

    def test_weak_cv_055_returns_02(self):
        """CV≈0.48 (large jitter) → 0.2 (weak signal)."""
        # mean=60, stdev≈29, CV≈0.48
        iats = [27.0, 93.0, 60.0, 27.0, 93.0, 60.0, 27.0]
        score = beacon_score(iats)
        self.assertEqual(score, 0.2)

    def test_human_like_cv_08_returns_00(self):
        """CV≈0.79 (highly irregular) → 0.0 (no signal)."""
        # mean=60, stdev≈47, CV≈0.79 ≥ 0.70
        iats = [5.0, 115.0, 60.0, 5.0, 115.0, 60.0, 5.0]
        self.assertEqual(beacon_score(iats), 0.0)

    def test_custom_thresholds_respected(self):
        """Custom CV thresholds override defaults."""
        # With strong_beacon=0.30, CV=0.22 should now be 0.9
        iats = [45.0, 75.0, 60.0, 45.0, 75.0, 60.0, 45.0]
        self.assertEqual(beacon_score(iats, strong_beacon=0.30), 0.9)


class TestComputeIats(unittest.TestCase):
    """Tests for compute_iats()."""

    def test_empty_returns_empty(self):
        self.assertEqual(compute_iats([]), [])

    def test_single_returns_empty(self):
        self.assertEqual(compute_iats([1000.0]), [])

    def test_regular_spacing(self):
        ts = [1000.0, 1060.0, 1120.0, 1180.0]
        iats = compute_iats(ts)
        self.assertEqual(iats, [60.0, 60.0, 60.0])


# ---------------------------------------------------------------------------
# BeaconingDetector guard tests
# ---------------------------------------------------------------------------


def _make_detector(config=None, redis=None, cache=None):
    """Helper: build a BeaconingDetector with mocked dependencies."""
    cfg = config or {
        "beaconing_detector": {
            "enabled": True,
            "min_observations": 8,
            "window_size": 20,
            "observation_window_seconds": 3600,
            "score": 35,
            "long_window": {"enabled": True, "window_seconds": 86400,
                            "min_observations": 5, "score": 20},
        }
    }
    mock_redis = redis or MagicMock()
    if cache is None:
        mock_cache = MagicMock()
        mock_cache.whitelist_decisions = MagicMock()
        mock_cache.whitelist_decisions.get = MagicMock(return_value=None)
    else:
        mock_cache = cache
    return BeaconingDetector(cfg, mock_redis, mock_cache)


class TestMaybeRecordGuards(unittest.TestCase):
    """Guards must prevent recording specific connection types."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_h2_alpn_not_recorded(self):
        """h2 ALPN connections must never be recorded."""
        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        detector = _make_detector(redis=mock_redis)

        self._run(detector.maybe_record("1.2.3.4", "t13d...", "h2", "allow"))

        mock_redis.pipeline.assert_not_called()

    def test_h1_alpn_not_recorded(self):
        """h1 ALPN connections must never be recorded."""
        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        detector = _make_detector(redis=mock_redis)

        self._run(detector.maybe_record("1.2.3.4", "t13d...", "h1", "allow"))

        mock_redis.pipeline.assert_not_called()

    def test_whitelisted_ip_not_recorded(self):
        """IP present in whitelist_decisions cache must not be recorded."""
        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        mock_cache = MagicMock()
        mock_cache.whitelist_decisions = MagicMock()
        mock_cache.whitelist_decisions.get = MagicMock(return_value=True)
        detector = _make_detector(redis=mock_redis, cache=mock_cache)

        self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "allow"))

        mock_redis.pipeline.assert_not_called()

    def test_blocked_action_not_recorded(self):
        """block action → not recorded (prevents CV distortion)."""
        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        detector = _make_detector(redis=mock_redis)

        self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "block"))

        mock_redis.pipeline.assert_not_called()

    def test_banned_action_not_recorded(self):
        """ban action → not recorded."""
        mock_redis = MagicMock()
        mock_redis.pipeline = MagicMock(return_value=AsyncMock())
        detector = _make_detector(redis=mock_redis)

        self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "ban"))

        mock_redis.pipeline.assert_not_called()

    def test_allowed_connection_recorded(self):
        """Normal allowed connection → write_buffer.enqueue called with zadd."""
        mock_redis = MagicMock()
        detector = _make_detector(redis=mock_redis)
        detector._write_buffer.enqueue = AsyncMock()

        self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "allow"))

        # Verify it was enqueued
        enqueued_ops = [call.args[0] for call in detector._write_buffer.enqueue.call_args_list]
        self.assertIn("zadd", enqueued_ops)

    def test_disabled_detector_skips_all(self):
        """Disabled detector skips recording entirely."""
        cfg = {"beaconing_detector": {"enabled": False}}
        mock_redis = MagicMock()
        detector = _make_detector(config=cfg, redis=mock_redis)

        self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "allow"))

        mock_redis.pipeline.assert_not_called()


class TestUUIDSuffixPreventsDuplication(unittest.TestCase):
    """UUID suffix prevents Sorted Set member collision on same-millisecond arrivals."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_two_calls_produce_distinct_members(self):
        """Two calls at the same time.time() produce different member strings."""
        added_members = []

        async def _capture_enqueue(operation, *args, **kwargs):
            if operation == "zadd" and len(args) >= 2:
                # args[0] = key, args[1] = {member: score}
                added_members.extend(args[1].keys())
            return True

        mock_redis = MagicMock()
        with patch("src.security.beaconing_detector.time.time", return_value=1700000000.0):
            detector = _make_detector(redis=mock_redis)
            detector._write_buffer.enqueue = AsyncMock(side_effect=_capture_enqueue)
            self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "allow"))
            self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "allow"))

        # Both calls recorded at exact same timestamp — UUID suffix must differ.
        # Each maybe_record adds to 2 keys (short + long), so 4 zadd calls total.
        self.assertEqual(len(added_members), 4)
        unique_members = list(dict.fromkeys(added_members))  # preserve order, deduplicate
        self.assertEqual(len(unique_members), 2)
        self.assertNotEqual(unique_members[0], unique_members[1])
        # Both start with the same timestamp prefix
        self.assertTrue(unique_members[0].startswith("1700000000.000000:"))
        self.assertTrue(unique_members[1].startswith("1700000000.000000:"))


class TestGetSignalMinObservations(unittest.TestCase):
    """Signal must not be emitted before min_observations threshold."""

    def _run(self, coro):
        return asyncio.run(coro)

    def test_below_min_observations_returns_none(self):
        """Fewer than min_observations timestamps → no signal."""
        now = time.time()
        # Only 4 timestamps — below short window min_observations=8 AND long window min_observations=5
        timestamps = [(f"ts{i}", now - (8 - i) * 60) for i in range(4)]

        mock_redis = MagicMock()
        mock_redis.zrangebyscore = AsyncMock(return_value=timestamps)

        detector = _make_detector(redis=mock_redis)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d...")

        result = self._run(detector.get_signal(ctx))
        self.assertIsNone(result)

    def test_at_min_observations_returns_signal(self):
        """Exactly min_observations regular timestamps → signal emitted."""
        now = time.time()
        # 8 timestamps at exactly 60s intervals → CV=0 → strong beacon
        timestamps = [(f"ts{i}", now - (8 - i) * 60.0) for i in range(8)]

        mock_redis = MagicMock()
        mock_redis.zrangebyscore = AsyncMock(return_value=timestamps)
        
        # Phase 28a: Use pipeline for suspects update to reduce RTTs
        pipeline = MagicMock()
        pipeline.execute = AsyncMock(return_value=[1, 1])  # zadd=1, zcard=1
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        mock_redis.pipeline.return_value = pipeline

        detector = _make_detector(redis=mock_redis)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d...")

        result = self._run(detector.get_signal(ctx))
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "beaconing")
        self.assertGreater(result.score, 0)
        self.assertIn("cv=0.000", result.reason)
        self.assertIn("strength=strong", result.reason)

    def test_redis_failure_returns_none(self):
        """Redis unavailable during get_signal → returns None silently."""
        mock_redis = MagicMock()
        mock_redis.zrangebyscore = AsyncMock(side_effect=redis.exceptions.ConnectionError("Redis down"))

        detector = _make_detector(redis=mock_redis)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d...")

        result = self._run(detector.get_signal(ctx))
        self.assertIsNone(result)

    def test_signal_output_format(self):
        """Signal has correct name and reason format."""
        now = time.time()
        timestamps = [(f"ts{i}", now - (10 - i) * 60.0) for i in range(10)]

        mock_redis = MagicMock()
        mock_redis.zrangebyscore = AsyncMock(return_value=timestamps)
        
        # Phase 28a: Mock pipeline
        pipeline = MagicMock()
        pipeline.execute = AsyncMock(return_value=[1, 1])
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        mock_redis.pipeline.return_value = pipeline

        detector = _make_detector(redis=mock_redis)
        ctx = ConnectionContext(client_ip="5.6.7.8", ja4="t13d1234")

        result = self._run(detector.get_signal(ctx))
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "beaconing")
        self.assertIsInstance(result.score, int)
        self.assertIn("cv=", result.reason)
        self.assertIn("strength=", result.reason)
        self.assertIn("over 10 observations", result.reason)


# ---------------------------------------------------------------------------
# Phase 14d — beacon:suspects leaderboard cap
# ---------------------------------------------------------------------------


def _make_detector_with_cap(max_suspects: int, zcard_return: int):
    """Return a (detector, mock_redis) pair configured with the given cap.

    The mock_redis is pre-wired so that zrangebyscore returns 10 evenly-spaced
    timestamps (enough to produce a strong beacon signal), and its pipeline
    returns zadd result and zcard result.
    """
    now = time.time()
    timestamps = [(now - i * 60, now - i * 60) for i in range(10)]  # (member, score) pairs

    mock_redis = MagicMock()
    mock_redis.zrangebyscore = AsyncMock(return_value=timestamps)
    
    # Phase 28a: Mock pipeline
    pipeline = MagicMock()
    pipeline.execute = AsyncMock(return_value=[1, zcard_return])
    pipeline.__aenter__ = AsyncMock(return_value=pipeline)
    pipeline.__aexit__ = AsyncMock(return_value=None)
    mock_redis.pipeline.return_value = pipeline
    
    mock_redis.zremrangebyrank = AsyncMock()

    cfg = {
        "beaconing_detector": {
            "enabled": True,
            "min_observations": 8,
            "window_size": 20,
            "observation_window_seconds": 3600,
            "score": 35,
            "max_suspects": max_suspects,
            "long_window": {"enabled": False},
        }
    }
    mock_cache = MagicMock()
    mock_cache.whitelist_decisions.get = MagicMock(return_value=None)
    detector = BeaconingDetector(cfg, mock_redis, mock_cache)
    return detector, mock_redis


class TestSuspectsLeaderboardCap(unittest.TestCase):
    def _run(self, coro):
        return asyncio.run(coro)

    def test_no_trim_when_under_cap(self):
        """When leaderboard count <= max_suspects, ZREMRANGEBYRANK is NOT called."""
        detector, mock_redis = _make_detector_with_cap(max_suspects=100, zcard_return=50)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1234")
        self._run(detector.get_signal(ctx))
        mock_redis.zremrangebyrank.assert_not_called()

    def test_no_trim_when_exactly_at_cap(self):
        """When leaderboard count == max_suspects, ZREMRANGEBYRANK is NOT called."""
        detector, mock_redis = _make_detector_with_cap(max_suspects=100, zcard_return=100)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1234")
        self._run(detector.get_signal(ctx))
        mock_redis.zremrangebyrank.assert_not_called()

    def test_trim_when_one_over_cap(self):
        """When leaderboard is exactly 1 over cap, trim removes 1 entry."""
        detector, mock_redis = _make_detector_with_cap(max_suspects=100, zcard_return=101)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1234")
        self._run(detector.get_signal(ctx))
        mock_redis.zremrangebyrank.assert_called_once_with("beacon:suspects", 0, 0)

    def test_trim_when_many_over_cap(self):
        """When leaderboard is N over cap, trim removes N lowest-scoring entries."""
        detector, mock_redis = _make_detector_with_cap(max_suspects=100, zcard_return=150)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1234")
        self._run(detector.get_signal(ctx))
        # Remove entries 0..49 (50 entries)
        mock_redis.zremrangebyrank.assert_called_once_with("beacon:suspects", 0, 49)

    def test_suspects_gauge_capped_at_max(self):
        """After trimming, the Prometheus gauge must reflect max_suspects, not the raw count."""
        detector, mock_redis = _make_detector_with_cap(max_suspects=100, zcard_return=200)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1234")
        with patch("src.security.beaconing_detector._BEACONING_SUSPECTS") as mock_gauge:
            self._run(detector.get_signal(ctx))
        mock_gauge.set.assert_called_once_with(100)

    def test_trim_error_does_not_propagate(self):
        """An exception from ZREMRANGEBYRANK must be silently swallowed."""
        detector, mock_redis = _make_detector_with_cap(max_suspects=10, zcard_return=20)
        mock_redis.zremrangebyrank = AsyncMock(side_effect=redis.RedisError("redis down"))
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d1234")
        # Must not raise
        result = self._run(detector.get_signal(ctx))
        # Signal still returned (exception is in the non-critical suspects block)
        self.assertIsNotNone(result)

    def test_default_max_suspects_is_10000(self):
        """Without config, max_suspects defaults to 10 000."""
        detector = _make_detector()
        self.assertEqual(detector._max_suspects, 10000)


# ── Missing-coverage additions ─────────────────────────────────────────────────


class TestBeaconingCoverageGaps(unittest.TestCase):
    """Cover lines 100, 201, 205, 255-259, 273-274, 294, 316, 353.

    So what: these paths are the fail-open fallbacks and disabled-detector guards
    that prevent beaconing analysis from crashing the hot path when Redis is
    unavailable or the detector is administratively disabled.
    """

    def _run(self, coro):
        return asyncio.run(coro)

    # Line 100 — coefficient_of_variation with zero-mean input
    def test_coefficient_of_variation_zero_mean_returns_zero(self):
        """CV with all-zero values (mean=0) returns 0.0 (line 100).
        So what: if this returns NaN (0/0), any downstream comparison to 0.15
        raises TypeError, crashing the signal path for that connection."""
        self.assertEqual(coefficient_of_variation([0.0, 0.0, 0.0]), 0.0)

    # Lines 201, 205 — start()/stop() lifecycle
    def test_start_calls_write_buffer_start(self):
        """start() must call _write_buffer.start() (line 201).
        So what: if the write buffer never starts, all beacon records are silently
        dropped — beaconing analysis produces no data."""
        detector = _make_detector()
        detector._write_buffer.start = AsyncMock()
        self._run(detector.start())
        detector._write_buffer.start.assert_called_once()

    def test_stop_calls_write_buffer_stop(self):
        """stop() must call _write_buffer.stop() (line 205).
        So what: without this, the write buffer's flush loop leaks as a zombie
        task, potentially preventing clean process shutdown."""
        detector = _make_detector()
        detector._write_buffer.stop = AsyncMock()
        self._run(detector.stop())
        detector._write_buffer.stop.assert_called_once()

    # Lines 255-259 — short-window enqueue exception in maybe_record
    def test_maybe_record_short_window_enqueue_failure_swallowed(self):
        """Exception in short-window enqueue is swallowed (lines 255-259).
        So what: a write buffer failure must not propagate to the caller — beacon
        recording must always be fire-and-forget from the connection hot path."""
        detector = _make_detector()
        detector._write_buffer.enqueue = AsyncMock(side_effect=RuntimeError("queue full"))
        # Must not raise
        self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "allow"))

    # Lines 273-274 — long-window enqueue exception in maybe_record
    def test_maybe_record_long_window_enqueue_failure_swallowed(self):
        """Exception in long-window enqueue is swallowed independently (lines 273-274).
        So what: if long-window recording fails, the short-window record should
        survive — the two windows are independent error boundaries."""
        short_window_count = [0]

        async def _selective_raise(operation, *args, **kwargs):
            short_window_count[0] += 1
            if short_window_count[0] <= 4:
                return True  # short window succeeds (4 operations)
            raise RuntimeError("long window exploded")

        detector = _make_detector()
        detector._write_buffer.enqueue = AsyncMock(side_effect=_selective_raise)
        # Must not raise — long-window failure is non-fatal
        self._run(detector.maybe_record("1.2.3.4", "t13d...", "", "allow"))
        # Short window succeeded (4 enqueue calls)
        assert short_window_count[0] >= 4

    # Line 294 — get_signal() when disabled
    def test_get_signal_disabled_returns_none(self):
        """get_signal() returns None immediately when disabled (line 294).
        So what: if this guard is missing, a disabled detector still calls Redis,
        wasting connections and potentially causing noise in test environments."""
        cfg = {"beaconing_detector": {"enabled": False}}
        detector = _make_detector(config=cfg)
        ctx = ConnectionContext(client_ip="1.2.3.4", ja4="t13d...")
        result = self._run(detector.get_signal(ctx))
        self.assertIsNone(result)

    # Line 316 — get_signal() returns None when long window disabled + short misses
    def test_get_signal_no_long_window_returns_none_when_short_misses(self):
        """Return None at end of get_signal when long_window is off (line 316).
        So what: if this return is missing, the method falls off the end returning
        None implicitly — but future refactors could introduce a spurious signal."""
        mock_redis = MagicMock()
        # Short window returns fewer than min_observations timestamps
        mock_redis.zrangebyscore = AsyncMock(return_value=[])
        cfg = {
            "beaconing_detector": {
                "enabled": True,
                "min_observations": 8,
                "window_size": 20,
                "observation_window_seconds": 3600,
                "score": 35,
                "long_window": {"enabled": False},
            }
        }
        mock_cache = MagicMock()
        mock_cache.whitelist_decisions.get = MagicMock(return_value=None)
        detector = BeaconingDetector(cfg, mock_redis, mock_cache)
        ctx = ConnectionContext(client_ip="5.5.5.5", ja4="t13d...")
        result = self._run(detector.get_signal(ctx))
        self.assertIsNone(result)

    # Line 353 — _check_window returns None when score_float == 0.0
    def test_check_window_returns_none_when_cv_too_high(self):
        """score_float==0.0 (highly irregular timing) → None returned (line 353).
        So what: if this return is missing, a zero-score signal propagates with
        risk_score=0, polluting the composite scorer with noise."""
        import time as _time
        now = _time.time()
        # 10 timestamps with very high CV (random-ish timing → score_float=0.0)
        # IATs: [300, 1, 500, 2, 400, 1, 600] — extremely irregular
        ts_list = [now - 1800, now - 1500, now - 1499, now - 999, now - 997,
                   now - 597, now - 596, now - 196, now - 195, now - 1]
        mock_members = [(f"m{i}", t) for i, t in enumerate(ts_list)]

        mock_redis = MagicMock()
        mock_redis.zrangebyscore = AsyncMock(return_value=mock_members)
        detector = _make_detector(redis=mock_redis)
        ctx = ConnectionContext(client_ip="6.6.6.6", ja4="t13d...")
        result = self._run(detector.get_signal(ctx))
        # High-CV timing → beacon_score returns 0.0 → _check_window returns None
        self.assertIsNone(result)
