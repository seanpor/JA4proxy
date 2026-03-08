"""Integration tests for Phase 9 — Beaconing Detection in pipeline.

Verifies that a simulated beaconing client accumulates timestamps and
escalates to a strong beacon signal (score ≥ 0.9) via the detector.
"""

import asyncio
import time
import unittest
from unittest.mock import AsyncMock, MagicMock

from src.security.beaconing_detector import BeaconingDetector, beacon_score, compute_iats
from src.security.models import ConnectionContext


def _run(coro):
    return asyncio.run(coro)


def _make_detector(min_obs: int = 10) -> tuple[BeaconingDetector, list]:
    """Return (detector, recorded_timestamps).

    Uses an in-memory list as a fake Redis Sorted Set so the full
    record→retrieve→score pipeline can be exercised without real Redis.
    """
    recorded: list[float] = []

    async def fake_zadd(key, mapping):
        for score in mapping.values():
            recorded.append(score)

    async def fake_zremrangebyscore(key, min_score, max_score):
        recorded[:] = [t for t in recorded if min_score <= t <= max_score]

    async def fake_zremrangebyrank(key, start, stop):
        pass  # Not needed for integration test

    async def fake_expire(key, ttl):
        pass

    async def fake_execute():
        return [1, 0, 0, True]

    async def fake_zrangebyscore(key, min_score, max_score, **kwargs):
        return [(f"ts{i}", t) for i, t in enumerate(sorted(recorded))
                if min_score <= t <= max_score]

    async def fake_zadd_suspects(key, mapping):
        pass

    async def fake_zcard(key):
        return 1

    # Build pipeline mock that executes commands immediately
    pipe = MagicMock()
    pipe.zadd = MagicMock(side_effect=lambda k, m: asyncio.ensure_future(fake_zadd(k, m)))
    pipe.zremrangebyscore = MagicMock(side_effect=lambda k, a, b: asyncio.ensure_future(fake_zremrangebyscore(k, a, b)))
    pipe.zremrangebyrank = MagicMock(side_effect=lambda k, a, b: asyncio.ensure_future(fake_zremrangebyrank(k, a, b)))
    pipe.expire = MagicMock(side_effect=lambda k, t: asyncio.ensure_future(fake_expire(k, t)))
    pipe.execute = AsyncMock(side_effect=fake_execute)
    pipe.__aenter__ = AsyncMock(return_value=pipe)
    pipe.__aexit__ = AsyncMock(return_value=False)

    mock_redis = MagicMock()
    mock_redis.pipeline = MagicMock(return_value=pipe)
    mock_redis.zrangebyscore = AsyncMock(side_effect=fake_zrangebyscore)
    mock_redis.zadd = AsyncMock(side_effect=fake_zadd_suspects)
    mock_redis.zcard = AsyncMock(side_effect=fake_zcard)

    mock_cache = MagicMock()
    mock_cache.whitelist_decisions = MagicMock()
    mock_cache.whitelist_decisions.get = MagicMock(return_value=None)

    config = {
        "beaconing_detector": {
            "enabled": True,
            "min_observations": min_obs,
            "window_size": 50,
            "observation_window_seconds": 3600,
            "score": 35,
            "long_window": {"enabled": False},
        }
    }
    detector = BeaconingDetector(config, mock_redis, mock_cache)
    return detector, recorded


class TestBeaconingPipeline(unittest.TestCase):
    """End-to-end beacon detection: record timestamps, retrieve signal."""

    def test_regular_30s_beacon_escalates_to_strong(self):
        """10 connections at 30s intervals → beacon_score = 0.9 (strong beacon).

        Simulates a C2 implant checking in every 30 seconds.  After
        min_observations timestamps are recorded the detector must return
        a signal with strength 'strong'.
        """
        now = time.time()
        # 10 connections spaced exactly 30 seconds apart → CV = 0 → strong beacon
        timestamps = [(f"ts{i}", now - (9 - i) * 30.0) for i in range(10)]

        # Verify pure-function contract first
        raw_ts = sorted(score for _, score in timestamps)
        iats = compute_iats(raw_ts)
        self.assertEqual(beacon_score(iats), 0.9)

        # Verify detector produces a signal when Redis returns these timestamps
        mock_redis = MagicMock()
        mock_redis.zrangebyscore = AsyncMock(return_value=timestamps)
        mock_redis.zadd = AsyncMock()
        mock_redis.zcard = AsyncMock(return_value=1)

        mock_cache = MagicMock()
        mock_cache.whitelist_decisions = MagicMock()
        mock_cache.whitelist_decisions.get = MagicMock(return_value=None)

        config = {
            "beaconing_detector": {
                "enabled": True,
                "min_observations": 10,
                "window_size": 50,
                "observation_window_seconds": 3600,
                "score": 35,
                "long_window": {"enabled": False},
            }
        }
        detector = BeaconingDetector(config, mock_redis, mock_cache)
        ctx = ConnectionContext(client_ip="10.0.0.1", ja4="t13d1516h2_abc")

        result = _run(detector.get_signal(ctx))
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "beaconing")
        self.assertIn("strength=strong", result.reason)
        self.assertGreater(result.score, 0)
        # Score cap for short window is 35; strong beacon → round(0.9 × 35) = 32
        self.assertEqual(result.score, 32)

    def test_irregular_human_traffic_no_signal(self):
        """Highly irregular timing (high CV) → no signal emitted."""
        # CV > 0.70 → beacon_score = 0.0 → no signal
        # Timestamps with wildly varying inter-arrival times
        now = time.time()
        timestamps = [
            now - 3600,
            now - 3595,  # 5s gap
            now - 3300,  # 295s gap
            now - 3298,  # 2s gap
            now - 2900,  # 398s gap
            now - 2895,  # 5s gap
            now - 2000,  # 895s gap
            now - 1998,  # 2s gap
            now - 1000,  # 998s gap
            now - 998,   # 2s gap
        ]
        iats = compute_iats(timestamps)
        score = beacon_score(iats)
        self.assertEqual(score, 0.0)

    def test_beacon_score_grows_with_more_observations(self):
        """Consistent beaconing pattern: score stays 0.9 with more data."""
        # With regular 60s intervals, more observations don't change the score
        for n in [10, 20, 50]:
            now = time.time()
            timestamps = [now - (n - 1 - i) * 60.0 for i in range(n)]
            iats = compute_iats(timestamps)
            score = beacon_score(iats)
            self.assertEqual(score, 0.9, f"Expected 0.9 with {n} observations")

    def test_long_window_independent_of_short(self):
        """Long window operates independently — different min_observations threshold."""
        config = {
            "beaconing_detector": {
                "enabled": True,
                "min_observations": 20,  # Short window needs 20
                "window_size": 50,
                "observation_window_seconds": 3600,
                "score": 35,
                "long_window": {
                    "enabled": True,
                    "window_seconds": 86400,
                    "min_observations": 5,  # Long window only needs 5
                    "score": 20,
                },
            }
        }

        now = time.time()
        # Only 8 timestamps — below short window (20) but above long window (5)
        timestamps = [(f"ts{i}", now - (8 - i) * 3600.0) for i in range(8)]

        mock_redis = MagicMock()
        mock_redis.zrangebyscore = AsyncMock(return_value=timestamps)
        mock_redis.zadd = AsyncMock()
        mock_redis.zcard = AsyncMock(return_value=1)

        mock_cache = MagicMock()
        mock_cache.whitelist_decisions = MagicMock()
        mock_cache.whitelist_decisions.get = MagicMock(return_value=None)

        detector = BeaconingDetector(config, mock_redis, mock_cache)
        ctx = ConnectionContext(client_ip="192.168.1.1", ja4="t13d_longbeacon")

        result = _run(detector.get_signal(ctx))
        # Short window short-circuits to None (8 < 20), then long window hits (8 ≥ 5)
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "beaconing")
        # Score cap is 20 for long window
        self.assertLessEqual(result.score, 20)
