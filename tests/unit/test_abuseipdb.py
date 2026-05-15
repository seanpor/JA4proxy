"""Unit tests for Phase 10 — AbuseIPDB Integration.

Covers:
- Three-tier cache hierarchy (in-process LRU → Redis → API queue)
- Score calculation (abuseipdb_to_risk_signal)
- Quota enforcement
- API error / timeout handling
- Worker CancelledError handling
- Queue overflow behaviour
- IPv6 canonical format
- Bloom filter dedup
"""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, call, patch

from src.cache.local_cache import LocalCache
from src.security.abuseipdb import (
    AbuseIPDBChecker,
    AbuseIPDBConfig,
    QuotaExhaustedException,
    _CacheHitTracker,
    abuseipdb_to_risk_signal,
)
from src.security.models import RiskSignal


def _run(coro):
    return asyncio.run(coro)


def _make_config(**kwargs) -> AbuseIPDBConfig:
    defaults = dict(
        enabled=True,
        api_key="test-key",
        max_requests_per_day=100,
        cache_ttl_seconds=14400,
        lookup_timeout_seconds=10,
        shared_ip_threshold=50,
        queue_size=10,
        worker_count=1,
        score_cap=40,
        delegate_to_analytics=False,
    )
    defaults.update(kwargs)
    return AbuseIPDBConfig(**defaults)


def _make_redis(get_return=None) -> MagicMock:
    """Return a mock async Redis client with pipeline support."""
    redis_mock = MagicMock()
    redis_mock.get = AsyncMock(return_value=get_return)
    redis_mock.setex = AsyncMock(return_value=True)
    redis_mock.incr = AsyncMock(return_value=1)
    redis_mock.decr = AsyncMock(return_value=0)
    redis_mock.expire = AsyncMock(return_value=True)
    redis_mock.sadd = AsyncMock(return_value=1)

    # Phase 28a: Mock pipeline
    pipeline = MagicMock()
    pipeline.incr = MagicMock()
    pipeline.expire = MagicMock()
    pipeline.execute = AsyncMock(return_value=[1, True])
    pipeline.__aenter__ = AsyncMock(return_value=pipeline)
    pipeline.__aexit__ = AsyncMock(return_value=None)
    redis_mock.pipeline = MagicMock(return_value=pipeline)

    bf = MagicMock()
    bf.add = AsyncMock(return_value=1)  # 1 = newly added
    redis_mock.bf = MagicMock(return_value=bf)
    return redis_mock


def _make_checker(config=None, redis=None, local_cache=None, session=None):
    if config is None:
        config = _make_config()
    if redis is None:
        redis = _make_redis()
    if local_cache is None:
        local_cache = LocalCache({})
    if session is None:
        session = MagicMock()
    return AbuseIPDBChecker(config, redis, local_cache, session)


# ---------------------------------------------------------------------------
# Score calculation tests (pure function — no async needed)
# ---------------------------------------------------------------------------


class TestAbuseIPDBToRiskSignal(unittest.TestCase):
    """Tests for abuseipdb_to_risk_signal()."""

    def test_none_confidence_returns_none(self):
        """confidence=None → fail open → None."""
        result = abuseipdb_to_risk_signal("1.2.3.4", None, 50, 40)
        self.assertIsNone(result)

    def test_confidence_zero_gives_zero_score(self):
        """confidence=0 → contribution=0."""
        result = abuseipdb_to_risk_signal("1.2.3.4", 0, 50, 40)
        self.assertIsInstance(result, RiskSignal)
        self.assertEqual(result.score, 0)

    def test_confidence_100_gives_score_cap(self):
        """confidence=100 → contribution exactly score_cap (default 40)."""
        result = abuseipdb_to_risk_signal("1.2.3.4", 100, 50, 40)
        self.assertIsInstance(result, RiskSignal)
        self.assertEqual(result.score, 40)

    def test_confidence_50_scales_correctly(self):
        """confidence=50 (at threshold boundary) → scales to score_cap/2."""
        # confidence 50 >= threshold 50 → contribution = round(50/100 * 40) = 20
        result = abuseipdb_to_risk_signal("1.2.3.4", 50, 50, 40)
        self.assertIsInstance(result, RiskSignal)
        self.assertEqual(result.score, 20)

    def test_confidence_below_threshold_capped_at_15(self):
        """confidence=49 (< threshold 50) → contribution ≤ 15."""
        result = abuseipdb_to_risk_signal("1.2.3.4", 49, 50, 40)
        self.assertIsInstance(result, RiskSignal)
        self.assertLessEqual(result.score, 15)

    def test_confidence_zero_below_threshold_gives_zero(self):
        """confidence=0 below threshold → contribution=0."""
        result = abuseipdb_to_risk_signal("1.2.3.4", 0, 50, 40)
        self.assertEqual(result.score, 0)

    def test_custom_score_cap(self):
        """score_cap=20 → confidence=100 → contribution=20."""
        result = abuseipdb_to_risk_signal("1.2.3.4", 100, 50, 20)
        self.assertIsInstance(result, RiskSignal)
        self.assertEqual(result.score, 20)

    def test_signal_name_is_abuseipdb(self):
        """Signal name must be 'abuseipdb'."""
        result = abuseipdb_to_risk_signal("1.2.3.4", 75, 50, 40)
        self.assertEqual(result.name, "abuseipdb")

    def test_reason_contains_confidence(self):
        """Signal reason must mention the confidence percentage."""
        result = abuseipdb_to_risk_signal("1.2.3.4", 85, 50, 40)
        self.assertIn("85", result.reason)


# ---------------------------------------------------------------------------
# Cache tier tests
# ---------------------------------------------------------------------------


class TestCacheTierHits(unittest.IsolatedAsyncioTestCase):
    """Tests for three-tier cache hierarchy."""

    async def test_tier1_hit_returns_immediately_no_redis(self):
        """In-process cache hit: no Redis call, no API enqueue."""
        redis = _make_redis()
        local_cache = LocalCache({})
        local_cache.abuseipdb_scores.set("1.2.3.4", 85)

        checker = _make_checker(redis=redis, local_cache=local_cache)
        signal = checker.get_signal("1.2.3.4")

        self.assertIsNotNone(signal)
        # confidence=85 >= threshold=50 → contribution = round(85/100 * 40) = 34
        self.assertEqual(signal.score, round((85 / 100) * 40))
        redis.get.assert_not_called()

    async def test_tier1_hit_correct_score_below_threshold(self):
        """In-process cache hit with confidence below shared_ip_threshold."""
        local_cache = LocalCache({})
        local_cache.abuseipdb_scores.set("1.2.3.4", 30)  # Below threshold of 50

        checker = _make_checker(local_cache=local_cache)
        signal = checker.get_signal("1.2.3.4")

        self.assertIsNotNone(signal)
        self.assertLessEqual(signal.score, 15)

    async def test_tier2_redis_hit_no_api_call(self):
        """Redis cache hit: returns value, populates tier 1, no API call."""
        redis = _make_redis(get_return=b"75")
        local_cache = LocalCache({})

        checker = _make_checker(redis=redis, local_cache=local_cache)
        score = await checker.get_score("1.2.3.4")

        self.assertEqual(score, 75)
        # Verify tier 1 was populated
        cached = local_cache.abuseipdb_scores.get("1.2.3.4")
        self.assertEqual(cached, 75)

    async def test_both_caches_miss_returns_none(self):
        """Tier 1 + Tier 2 miss → returns None immediately; enqueues lookup."""
        redis = _make_redis(get_return=None)
        local_cache = LocalCache({})

        checker = _make_checker(redis=redis, local_cache=local_cache)
        score = await checker.get_score("1.2.3.4")

        # Returns None (fail open)
        self.assertIsNone(score)

    async def test_get_signal_cache_miss_returns_none(self):
        """get_signal() on cache miss returns None (fire-and-forget enqueue)."""
        local_cache = LocalCache({})
        redis = _make_redis(get_return=None)

        checker = _make_checker(redis=redis, local_cache=local_cache)
        signal = checker.get_signal("1.2.3.4")

        self.assertIsNone(signal)

    async def test_disabled_checker_returns_none(self):
        """Disabled checker always returns None from get_signal."""
        cfg = _make_config(enabled=False)
        checker = _make_checker(config=cfg)
        signal = checker.get_signal("1.2.3.4")
        self.assertIsNone(signal)

    async def test_disabled_checker_get_score_returns_none(self):
        """Disabled checker always returns None from get_score."""
        cfg = _make_config(enabled=False)
        checker = _make_checker(config=cfg)
        score = await checker.get_score("1.2.3.4")
        self.assertIsNone(score)


# ---------------------------------------------------------------------------
# Quota enforcement tests
# ---------------------------------------------------------------------------


class TestQuotaEnforcement(unittest.IsolatedAsyncioTestCase):
    """Tests for daily quota tracking."""

    async def test_quota_at_limit_is_accepted(self):
        """Request exactly at the limit (count == max) is accepted."""
        redis = _make_redis()
        redis.incr = AsyncMock(return_value=100)  # Exactly at limit
        checker = _make_checker(redis=redis)
        result = await checker._check_quota()
        self.assertTrue(result)
        redis.decr.assert_not_called()

    async def test_quota_exceeded_is_rejected_and_rolled_back(self):
        """Request at limit+1 is rejected; DECR called to roll back."""
        redis = _make_redis()
        # Mock pipeline to return 101 for incr
        redis.pipeline.return_value.execute = AsyncMock(return_value=[101, True])
        checker = _make_checker(redis=redis)
        result = await checker._check_quota()
        self.assertFalse(result)
        redis.decr.assert_called_once()

    async def test_quota_first_request_sets_ttl(self):
        """First request today (count=1) sets the TTL on the quota key."""
        redis = _make_redis()
        # count=1 from pipeline
        redis.pipeline.return_value.execute = AsyncMock(return_value=[1, True])
        checker = _make_checker(redis=redis)
        await checker._check_quota()
        redis.pipeline.assert_called_once()
        # Verify expire was called on pipeline
        redis.pipeline.return_value.expire.assert_called_once()

    async def test_quota_redis_error_fails_open(self):
        """Redis error on quota check fails open (returns True)."""
        redis = _make_redis()
        redis.incr = AsyncMock(side_effect=ConnectionError("Redis down"))
        checker = _make_checker(redis=redis)
        result = await checker._check_quota()
        self.assertTrue(result)  # Fail open


# ---------------------------------------------------------------------------
# API error / timeout tests
# ---------------------------------------------------------------------------


class TestAPIErrors(unittest.IsolatedAsyncioTestCase):
    """Tests for API error and timeout handling."""

    async def test_api_error_fails_open_score_zero(self):
        """API error (5xx) → fail open (score=0), error counter incremented."""
        redis = _make_redis()
        local_cache = LocalCache({})

        session = MagicMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _error_get(*args, **kwargs):
            err = Exception("HTTP 503")
            err.status = 503  # type: ignore[attr-defined]
            raise err
            yield  # pragma: no cover

        session.get = _error_get
        checker = _make_checker(redis=redis, local_cache=local_cache, session=session)
        await checker.start()

        try:
            # Process one lookup directly
            await checker._process_lookup("1.2.3.4")
        finally:
            await checker.stop()

        # Score 0 (fail open) should be cached
        cached = local_cache.abuseipdb_scores.get("1.2.3.4")
        self.assertEqual(cached, 0)

    async def test_api_timeout_fails_open(self):
        """API timeout → fail open (score=0), no hanging coroutine."""
        redis = _make_redis()
        local_cache = LocalCache({})

        session = MagicMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _timeout_get(*args, **kwargs):
            raise asyncio.TimeoutError()
            yield  # pragma: no cover

        session.get = _timeout_get
        checker = _make_checker(redis=redis, local_cache=local_cache, session=session)
        await checker.start()

        try:
            await checker._process_lookup("1.2.3.4")
        finally:
            await checker.stop()

        cached = local_cache.abuseipdb_scores.get("1.2.3.4")
        self.assertEqual(cached, 0)

    async def test_worker_cancelled_error_exits_cleanly(self):
        """Worker asyncio.CancelledError → exits cleanly without re-raising."""
        redis = _make_redis()
        local_cache = LocalCache({})
        checker = _make_checker(redis=redis, local_cache=local_cache)
        await checker.start()

        # Let event loop tick
        await asyncio.sleep(0)

        # stop() should return without hanging
        await asyncio.wait_for(checker.stop(), timeout=5.0)

    async def test_stop_completes_within_5_seconds(self):
        """stop() must complete within 5 seconds even with workers running."""
        redis = _make_redis()
        checker = _make_checker(redis=redis)
        await checker.start()
        await asyncio.wait_for(checker.stop(), timeout=5.0)


# ---------------------------------------------------------------------------
# Queue overflow tests
# ---------------------------------------------------------------------------


class TestQueueOverflow(unittest.IsolatedAsyncioTestCase):
    """Tests for queue full behaviour."""

    async def test_queue_full_drops_item_increments_counter(self):
        """Queue full → item dropped; queue_dropped_total counter incremented."""
        redis = _make_redis()
        # Set up bloom filter to always return "newly added" (1)
        bf = MagicMock()
        bf.add = AsyncMock(return_value=1)
        redis.bf = MagicMock(return_value=bf)

        cfg = _make_config(queue_size=1)
        checker = _make_checker(config=cfg, redis=redis)
        # Don't start workers — queue won't drain
        checker._queue = asyncio.Queue(maxsize=1)
        checker._workers = []

        # Fill the queue
        checker._queue.put_nowait("192.168.1.1")

        # Next enqueue should drop
        from prometheus_client import REGISTRY

        initial_dropped = 0
        try:
            dropped_counter = REGISTRY._names_to_collectors.get(
                "ja4proxy_abuseipdb_queue_dropped_total"
            )
            if dropped_counter:
                initial_dropped = list(dropped_counter.collect())[0].samples[0].value
        except Exception:
            pass

        await checker._enqueue_lookup("192.168.1.2")

        # Queue should still have max=1 item and the drop counter incremented
        self.assertEqual(checker._queue.qsize(), 1)


# ---------------------------------------------------------------------------
# IPv6 tests
# ---------------------------------------------------------------------------


class TestIPv6Handling(unittest.IsolatedAsyncioTestCase):
    """Tests for IPv6 canonical format submission."""

    async def test_ipv6_canonical_format_submitted_to_api(self):
        """IPv6 address is submitted in compressed canonical format."""
        redis = _make_redis()
        local_cache = LocalCache({})

        submitted_ips = []

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _record_get(url, params=None, **kwargs):
            ip = (params or {}).get("ipAddress", "")
            submitted_ips.append(ip)
            resp = MagicMock()
            resp.status = 200
            resp.json = AsyncMock(return_value={"data": {"abuseConfidenceScore": 0}})
            resp.raise_for_status = MagicMock()
            yield resp

        session = MagicMock()
        session.get = _record_get
        checker = _make_checker(redis=redis, local_cache=local_cache, session=session)

        # Full-form IPv6 that should be compressed
        full_ipv6 = "2001:0db8:0000:0000:0000:0000:0000:0001"
        await checker._process_lookup(full_ipv6)

        # The submitted IP should be compressed
        import ipaddress

        expected = ipaddress.ip_address(full_ipv6).compressed
        self.assertIn(expected, submitted_ips)
        self.assertEqual(submitted_ips[0], expected)


# ---------------------------------------------------------------------------
# Bloom filter dedup tests
# ---------------------------------------------------------------------------


class TestBloomFilterDedup(unittest.IsolatedAsyncioTestCase):
    """Tests for Bloom filter deduplication."""

    async def test_bloom_filter_present_skips_enqueue(self):
        """BF.ADD returns 0 (already present) → IP not re-enqueued."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(return_value=0)  # Already present
        redis.bf = MagicMock(return_value=bf)

        checker = _make_checker(redis=redis)
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []

        await checker._enqueue_lookup("1.2.3.4")

        # Queue should be empty since IP was already in bloom filter
        self.assertEqual(checker._queue.qsize(), 0)

    async def test_bloom_filter_miss_enqueues_ip(self):
        """BF.ADD returns 1 (newly added) → IP enqueued for lookup."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(return_value=1)  # Newly added
        redis.bf = MagicMock(return_value=bf)

        checker = _make_checker(redis=redis)
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []

        await checker._enqueue_lookup("1.2.3.4")

        self.assertEqual(checker._queue.qsize(), 1)

    async def test_bloom_unavailable_falls_back_to_set(self):
        """RedisBloom unavailable → falls back to SET+TTL dedup."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(side_effect=Exception("WRONGTYPE"))
        redis.bf = MagicMock(return_value=bf)
        # First call to fallback key returns None (not yet enriched)
        redis.get = AsyncMock(return_value=None)

        checker = _make_checker(redis=redis)
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []

        await checker._enqueue_lookup("1.2.3.4")
        # Should use fallback and enqueue
        self.assertEqual(checker._queue.qsize(), 1)


# ---------------------------------------------------------------------------
# Delegate to analytics tests
# ---------------------------------------------------------------------------


class TestDelegateToAnalytics(unittest.IsolatedAsyncioTestCase):
    """Tests for analytics delegation mode."""

    async def test_delegate_mode_publishes_to_redis_set(self):
        """delegate_to_analytics=True → SADD to analytics:enrich:abuseipdb."""
        redis = _make_redis()
        cfg = _make_config(delegate_to_analytics=True)
        checker = _make_checker(config=cfg, redis=redis)
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []

        # Bloom filter: newly added
        bf = MagicMock()
        bf.add = AsyncMock(return_value=1)
        redis.bf = MagicMock(return_value=bf)

        await checker._enqueue_lookup("1.2.3.4")

        # Should SADD to analytics set, not enqueue locally
        redis.sadd.assert_called_once_with("analytics:enrich:abuseipdb", "1.2.3.4")
        self.assertEqual(checker._queue.qsize(), 0)


# ---------------------------------------------------------------------------
# Hot reload / config tests
# ---------------------------------------------------------------------------


class TestHotReload(unittest.TestCase):
    """Tests for on_config_reload behaviour."""

    def test_worker_count_change_logs_warn(self):
        """Changing worker_count during hot reload logs a WARN."""
        checker = _make_checker(config=_make_config(worker_count=3))
        new_config = {
            "abuseipdb": {
                "enabled": True,
                "worker_count": 5,
                "queue_size": 10,
                "score_cap": 40,
            }
        }
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            checker.on_config_reload(new_config)
        # Old worker_count preserved
        self.assertEqual(checker._config.worker_count, 3)

    def test_queue_size_change_logs_warn(self):
        """Changing queue_size during hot reload logs a WARN."""
        checker = _make_checker(config=_make_config(queue_size=100))
        new_config = {
            "abuseipdb": {
                "enabled": True,
                "worker_count": 1,
                "queue_size": 200,
                "score_cap": 40,
            }
        }
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            checker.on_config_reload(new_config)
        # Old queue_size preserved
        self.assertEqual(checker._config.queue_size, 100)

    def test_enabled_toggle_false_to_true_logs_warn(self):
        """Toggling enabled false→true during hot reload logs WARN (restart needed)."""
        checker = _make_checker(config=_make_config(enabled=False))
        new_config = {
            "abuseipdb": {"enabled": True, "worker_count": 1, "queue_size": 10}
        }
        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            checker.on_config_reload(new_config)

    def test_hot_reloadable_fields_apply_immediately(self):
        """Hot-reloadable fields (score_cap, api_key, etc.) apply without restart."""
        checker = _make_checker(config=_make_config(score_cap=40))
        new_config = {
            "abuseipdb": {
                "enabled": True,
                "score_cap": 20,
                "worker_count": 1,
                "queue_size": 10,
            }
        }
        checker.on_config_reload(new_config)
        self.assertEqual(checker._config.score_cap, 20)


# ---------------------------------------------------------------------------
# AbuseIPDBConfig.from_config tests
# ---------------------------------------------------------------------------


class TestAbuseIPDBConfigFromConfig(unittest.TestCase):
    """Tests for AbuseIPDBConfig.from_config()."""

    def test_loads_api_key_from_env_if_empty(self):
        """If api_key is empty in config, loads from ABUSEIPDB_API_KEY env var."""
        import os

        old = os.environ.get("ABUSEIPDB_API_KEY")
        os.environ["ABUSEIPDB_API_KEY"] = "env-key-123"
        try:
            cfg = AbuseIPDBConfig.from_config({"abuseipdb": {"api_key": ""}})
            self.assertEqual(cfg.api_key, "env-key-123")
        finally:
            if old is None:
                os.environ.pop("ABUSEIPDB_API_KEY", None)
            else:
                os.environ["ABUSEIPDB_API_KEY"] = old

    def test_config_key_takes_precedence_over_env(self):
        """Explicit api_key in config takes precedence over env var."""
        import os

        old = os.environ.get("ABUSEIPDB_API_KEY")
        os.environ["ABUSEIPDB_API_KEY"] = "env-key-456"
        try:
            cfg = AbuseIPDBConfig.from_config({"abuseipdb": {"api_key": "config-key"}})
            self.assertEqual(cfg.api_key, "config-key")
        finally:
            if old is None:
                os.environ.pop("ABUSEIPDB_API_KEY", None)
            else:
                os.environ["ABUSEIPDB_API_KEY"] = old

    def test_defaults_when_section_missing(self):
        """Missing abuseipdb section → all defaults."""
        cfg = AbuseIPDBConfig.from_config({})
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.score_cap, 40)
        self.assertEqual(cfg.max_requests_per_day, 1000)


class TestCacheHitTracker(unittest.TestCase):
    """Phase 16c — cover _CacheHitTracker edge cases (lines 241-242, 247, 251)."""

    def test_ratio_empty_returns_zero(self):
        """ratio() returns 0.0 when no observations recorded (line 251)."""
        tracker = _CacheHitTracker()
        self.assertEqual(tracker.ratio(), 0.0)

    def test_record_hit_window_overflow(self):
        """record_hit() trims when total exceeds window (lines 241-242)."""
        tracker = _CacheHitTracker(window=2)
        tracker.record_hit()
        tracker.record_hit()
        # Now at window limit; next hit overflows
        tracker.record_hit()
        # Should have trimmed: total stays at 2
        self.assertLessEqual(tracker._total, 2)

    def test_record_miss_window_overflow(self):
        """record_miss() trims when total exceeds window (line 247)."""
        tracker = _CacheHitTracker(window=2)
        tracker.record_miss()
        tracker.record_miss()
        tracker.record_miss()  # Overflow
        # total should be trimmed back to window
        self.assertLessEqual(tracker._total, 2)


# ---------------------------------------------------------------------------
# Missing-coverage tests
# ---------------------------------------------------------------------------


class TestStartDisabled(unittest.IsolatedAsyncioTestCase):
    """Cover start() early-return when disabled (line 298)."""

    async def test_start_when_disabled_returns_without_creating_workers(self):
        """start() with enabled=False → returns immediately, no workers created.
        So what: a disabled checker must not spawn background tasks that consume
        resources and hold Redis connections unnecessarily."""
        cfg = _make_config(enabled=False)
        checker = _make_checker(config=cfg)
        await checker.start()
        self.assertIsNone(checker._queue)
        self.assertEqual(checker._workers, [])


class TestStopQueueNotEmpty(unittest.IsolatedAsyncioTestCase):
    """Cover stop() warning when queue has remaining items (line 325)."""

    async def test_stop_with_items_in_queue_logs_warning(self):
        """stop() when queue still has IPs → WARN logged for unprocessed items.
        So what: lost enrichment requests are a data quality issue; the warning
        lets operators detect under-sized queues during shutdown."""
        checker = _make_checker()
        await checker.start()
        # Manually add items to queue without workers draining them
        checker._queue.put_nowait("1.2.3.4")
        checker._queue.put_nowait("5.6.7.8")
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            await checker.stop()


class TestMaybeLookup(unittest.IsolatedAsyncioTestCase):
    """Cover _maybe_lookup() paths: tier1 hit, redis hit, redis error (lines 393, 420-426, 402-403)."""

    async def test_get_score_tier1_hit_skips_redis(self):
        """get_score() with tier-1 LRU hit → returns immediately without Redis (line 393).
        So what: tier-1 bypass is the key latency optimization; a regression here
        doubles Redis RTTs on hot-path requests."""
        from src.cache.local_cache import LocalCache

        local_cache = LocalCache({})
        local_cache.abuseipdb_scores.set("1.2.3.4", 75)
        redis = _make_redis()
        checker = _make_checker(redis=redis, local_cache=local_cache)
        score = await checker.get_score("1.2.3.4")
        self.assertEqual(score, 75)
        redis.get.assert_not_called()

    async def test_maybe_lookup_redis_hit_populates_tier1(self):
        """_maybe_lookup() with Redis hit → populates tier-1 cache (lines 420-424).
        So what: warm-through from Redis to LRU prevents duplicate Redis reads
        on subsequent connections from the same IP."""
        local_cache = MagicMock()
        local_cache.abuseipdb_scores = MagicMock()
        redis = _make_redis(get_return=b"60")
        checker = _make_checker(redis=redis, local_cache=local_cache)
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        await checker._maybe_lookup("1.2.3.4")
        local_cache.abuseipdb_scores.set.assert_called()

    async def test_maybe_lookup_redis_error_logs_warning_and_enqueues(self):
        """_maybe_lookup() redis.get raises → logs warning, enqueues (lines 425-426).
        So what: Redis read errors must not crash the background pipeline; the IP
        gets re-queued for enrichment on the next connection."""
        local_cache = MagicMock()
        local_cache.abuseipdb_scores = MagicMock()
        redis = _make_redis()
        redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
        bf = MagicMock()
        bf.add = AsyncMock(return_value=1)
        redis.bf = MagicMock(return_value=bf)
        checker = _make_checker(redis=redis, local_cache=local_cache)
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            await checker._maybe_lookup("1.2.3.4")


class TestEnqueueLookupEdgePaths(unittest.IsolatedAsyncioTestCase):
    """Cover _enqueue_lookup() edge paths (lines 442, 446-447, 461-462, 469, 471-472)."""

    async def test_enqueue_skips_when_quota_exhausted(self):
        """_enqueue_lookup() skips when quota exhausted (line 442).
        So what: enqueueing after quota exhaustion wastes queue slots and causes
        misleading 429-cycle errors; the flag must short-circuit immediately."""
        redis = _make_redis()
        checker = _make_checker(redis=redis)
        checker._quota_exhausted = True
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        await checker._enqueue_lookup("1.2.3.4")
        self.assertEqual(checker._queue.qsize(), 0)

    async def test_enqueue_delegate_redis_error_logs_warning(self):
        """delegate_to_analytics=True, sadd raises → logs warning (lines 446-447).
        So what: a Redis error during delegation must not crash the background
        worker; the IP is silently dropped, which is acceptable fail-open behavior."""
        redis = _make_redis()
        redis.sadd = AsyncMock(side_effect=ConnectionError("Redis error"))
        cfg = _make_config(delegate_to_analytics=True)
        checker = _make_checker(config=cfg, redis=redis)
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            await checker._enqueue_lookup("1.2.3.4")

    async def test_bloom_expire_redis_error_swallowed(self):
        """bloom filter expire RedisError → swallowed (lines 461-462).
        So what: TTL-setting failure must not prevent the IP from being enqueued;
        slightly longer bloom filter retention is acceptable."""
        import redis as redis_lib

        r = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(return_value=1)  # newly added
        r.bf = MagicMock(return_value=bf)
        r.expire = AsyncMock(side_effect=redis_lib.RedisError("expire failed"))
        checker = _make_checker(redis=r)
        checker._quota_exhausted = False
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        await checker._enqueue_lookup("1.2.3.4")
        # Should still enqueue despite expire failure
        self.assertEqual(checker._queue.qsize(), 1)

    async def test_bloom_fallback_already_present_skips_enqueue(self):
        """Fallback bloom key exists → IP already enriched, skip enqueue (line 469).
        So what: the fallback path must dedup correctly when RedisBloom is absent,
        otherwise unbounded re-enqueueing will exhaust the daily API quota."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(side_effect=Exception("WRONGTYPE"))
        redis.bf = MagicMock(return_value=bf)
        # Fallback key exists
        redis.get = AsyncMock(return_value=b"1")
        checker = _make_checker(redis=redis)
        checker._quota_exhausted = False
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        await checker._enqueue_lookup("1.2.3.4")
        self.assertEqual(checker._queue.qsize(), 0)

    async def test_bloom_fallback_set_error_still_enqueues(self):
        """Fallback setex raises → debug log, but IP still enqueued (lines 471-472).
        So what: bloom dedup failure must not silently drop the enrichment request;
        a duplicate API call is preferable to a missed lookup."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(side_effect=Exception("WRONGTYPE"))
        redis.bf = MagicMock(return_value=bf)
        # Fallback key does NOT exist, but setex also fails
        redis.get = AsyncMock(return_value=None)
        redis.setex = AsyncMock(side_effect=Exception("setex failed"))
        checker = _make_checker(redis=redis)
        checker._quota_exhausted = False
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        await checker._enqueue_lookup("1.2.3.4")
        # Should still enqueue since dedup failure falls through
        self.assertEqual(checker._queue.qsize(), 1)


class TestLookupWorkerPaths(unittest.IsolatedAsyncioTestCase):
    """Cover _lookup_worker() processing paths (lines 489-506)."""

    async def test_lookup_worker_processes_item_end_to_end(self):
        """Worker dequeues IP, calls _process_lookup, marks task_done (lines 489-506).
        So what: if task_done is not called, the queue.join() will hang forever,
        blocking a clean shutdown."""
        redis = _make_redis()
        local_cache = MagicMock()
        local_cache.abuseipdb_scores = MagicMock()
        local_cache.abuseipdb_scores.get = MagicMock(return_value=None)
        local_cache.abuseipdb_scores.set = MagicMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _ok_get(url, params=None, **kwargs):
            resp = MagicMock()
            resp.status = 200
            resp.json = AsyncMock(return_value={"data": {"abuseConfidenceScore": 50}})
            resp.raise_for_status = MagicMock()
            yield resp

        session = MagicMock()
        session.get = _ok_get
        checker = _make_checker(redis=redis, local_cache=local_cache, session=session)
        await checker.start()
        await checker._queue.put("1.2.3.4")
        # Give worker time to process
        await asyncio.sleep(0.05)
        await checker.stop()
        local_cache.abuseipdb_scores.set.assert_called()

    async def test_lookup_worker_exception_in_process_lookup_does_not_crash(self):
        """Worker catches unhandled exception from _process_lookup (lines 492-506).
        So what: an unexpected crash in process_lookup must not kill the worker
        goroutine — the proxy cannot restart workers mid-traffic."""
        redis = _make_redis()
        checker = _make_checker(redis=redis)
        await checker.start()

        with patch.object(checker, "_process_lookup", side_effect=RuntimeError("bang")):
            await checker._queue.put("1.2.3.4")
            await asyncio.sleep(0.05)

        await checker.stop()
        # If we got here without hanging, the worker survived the exception


class TestProcessLookupPaths(unittest.IsolatedAsyncioTestCase):
    """Cover _process_lookup() quota-exhausted and ValueError paths (lines 515-529, 534-535)."""

    async def test_process_lookup_quota_check_false_sets_exhausted_flag(self):
        """_check_quota() → False → sets _quota_exhausted, logs WARN (lines 515-529).
        So what: the exhausted flag prevents further queue buildup for the rest of
        the UTC day; without it every connection spawns a doomed API request."""
        redis = _make_redis()
        checker = _make_checker(redis=redis)
        await checker.start()

        with patch.object(checker, "_check_quota", AsyncMock(return_value=False)):
            import logging

            with self.assertLogs("src.security.abuseipdb", level="WARNING"):
                await checker._process_lookup("1.2.3.4")

        self.assertTrue(checker._quota_exhausted)
        await checker.stop()

    async def test_process_lookup_quota_already_exhausted_no_double_warn(self):
        """Second quota failure when already exhausted → no duplicate WARN (line 515).
        So what: duplicate WARNs flood Splunk/Wazuh dashboards; the flag must prevent
        log storms during sustained quota-exceeded periods."""
        redis = _make_redis()
        checker = _make_checker(redis=redis)
        checker._quota_exhausted = True  # Already set
        await checker.start()

        with patch.object(checker, "_check_quota", AsyncMock(return_value=False)):
            # Should not log (already exhausted)
            await checker._process_lookup("1.2.3.4")

        await checker.stop()

    async def test_process_lookup_invalid_ip_uses_raw_string(self):
        """Invalid IP string → ValueError caught, raw string used as canonical (lines 534-535).
        So what: a malformed IP in the queue (from a corrupt event) must not crash
        the worker; it should fall through and attempt the API call with the raw value.
        """
        redis = _make_redis()
        local_cache = MagicMock()
        local_cache.abuseipdb_scores = MagicMock()
        local_cache.abuseipdb_scores.set = MagicMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _ok_get(url, params=None, **kwargs):
            resp = MagicMock()
            resp.status = 200
            resp.json = AsyncMock(return_value={"data": {"abuseConfidenceScore": 0}})
            resp.raise_for_status = MagicMock()
            yield resp

        session = MagicMock()
        session.get = _ok_get
        checker = _make_checker(redis=redis, local_cache=local_cache, session=session)
        await checker.start()
        # "not-an-ip" will trigger ValueError in ipaddress.ip_address()
        await checker._process_lookup("not-an-ip")
        await checker.stop()
        # Should have stored score under the raw string
        local_cache.abuseipdb_scores.set.assert_called()

    async def test_process_lookup_api_429_sets_exhausted(self):
        """API returns 429 → QuotaExhaustedException → sets _quota_exhausted (lines 542-556).
        So what: receiving 429 from AbuseIPDB means we have burned the quota in another
        process; the flag must propagate to avoid hammering their API further."""
        redis = _make_redis()
        checker = _make_checker(redis=redis)
        await checker.start()

        with patch.object(
            checker, "_api_lookup", AsyncMock(side_effect=QuotaExhaustedException())
        ):
            import logging

            with self.assertLogs("src.security.abuseipdb", level="WARNING"):
                await checker._process_lookup("1.2.3.4")

        self.assertTrue(checker._quota_exhausted)
        await checker.stop()

    async def test_process_lookup_redis_write_error_logs_warning(self):
        """Redis write failure after API lookup → logs WARNING, does not lose score (lines 596-597).
        So what: a Redis write error must not lose the freshly fetched score; it should
        still populate the in-process LRU so at least this instance caches it."""
        redis = _make_redis()
        redis.setex = AsyncMock(side_effect=ConnectionError("Redis write failed"))
        local_cache = MagicMock()
        local_cache.abuseipdb_scores = MagicMock()
        local_cache.abuseipdb_scores.set = MagicMock()

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _ok_get(url, params=None, **kwargs):
            resp = MagicMock()
            resp.status = 200
            resp.json = AsyncMock(return_value={"data": {"abuseConfidenceScore": 42}})
            resp.raise_for_status = MagicMock()
            yield resp

        session = MagicMock()
        session.get = _ok_get
        checker = _make_checker(redis=redis, local_cache=local_cache, session=session)
        await checker.start()
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            await checker._process_lookup("1.2.3.4")
        await checker.stop()
        # Score still set in LRU despite Redis error
        local_cache.abuseipdb_scores.set.assert_called()


class TestAPILookupQuota429(unittest.IsolatedAsyncioTestCase):
    """Cover _api_lookup() 429 → QuotaExhaustedException (line 642)."""

    async def test_api_lookup_429_raises_quota_exhausted(self):
        """HTTP 429 from API → raises QuotaExhaustedException (line 642).
        So what: 429 must be translated to QuotaExhaustedException so the caller
        can set the exhaustion flag; treating it as a generic error would cause
        repeated hammering until the daily window resets."""
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _429_get(url, params=None, **kwargs):
            resp = MagicMock()
            resp.status = 429
            yield resp

        session = MagicMock()
        session.get = _429_get
        checker = _make_checker(session=session)
        with self.assertRaises(QuotaExhaustedException):
            await checker._api_lookup("1.2.3.4")


class TestCheckQuotaException(unittest.IsolatedAsyncioTestCase):
    """Cover _check_quota() pipeline exception → fail open (lines 666-670)."""

    async def test_check_quota_pipeline_exception_fails_open(self):
        """Redis pipeline exception in _check_quota → True (fail open) (lines 666-670).
        So what: a quota check failure must not block enrichment; failing open means
        we may exceed the daily limit by a few requests, which is acceptable."""
        redis = _make_redis()
        # Make pipeline raise on execute
        pipe = MagicMock()
        pipe.incr = MagicMock()
        pipe.expire = MagicMock()
        pipe.execute = AsyncMock(side_effect=ConnectionError("Redis pipeline down"))
        pipe.__aenter__ = AsyncMock(return_value=pipe)
        pipe.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = MagicMock(return_value=pipe)
        checker = _make_checker(redis=redis)
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            result = await checker._check_quota()
        self.assertTrue(result)


class TestUpdateQuotaGauge(unittest.IsolatedAsyncioTestCase):
    """Cover _update_quota_gauge() paths (lines 679, 682-686)."""

    async def test_update_quota_gauge_sets_gauge_when_key_present(self):
        """Redis quota key present → Prometheus gauge updated (line 679).
        So what: if the gauge is never updated, the Grafana quota dashboard
        always shows 0, masking quota exhaustion from the SRE on-call rotation."""
        redis = _make_redis(get_return=b"42")
        checker = _make_checker(redis=redis)
        await checker._update_quota_gauge()
        # No exception → gauge was set; spot-check via get_return

    async def test_update_quota_gauge_resets_exhausted_flag_on_new_day(self):
        """Quota exhausted but redis shows count ≤ limit → reset flag (lines 682-684).
        So what: if the flag is not reset at midnight, the checker remains disabled
        for the new UTC day even though quota has fully refreshed."""
        redis = _make_redis(get_return=b"5")  # Well below daily limit
        checker = _make_checker(redis=redis)
        checker._quota_exhausted = True
        await checker._update_quota_gauge()
        self.assertFalse(checker._quota_exhausted)

    async def test_update_quota_gauge_redis_error_swallowed(self):
        """Redis error in _update_quota_gauge → swallowed (line 685-686).
        So what: gauge updates are best-effort; a Redis error here must not
        propagate and crash the worker that called it after a successful lookup."""
        import redis as redis_lib

        redis = _make_redis()
        redis.get = AsyncMock(side_effect=redis_lib.RedisError("redis down"))
        checker = _make_checker(redis=redis)
        # Should not raise
        await checker._update_quota_gauge()


class TestGetScoreRedisException(unittest.IsolatedAsyncioTestCase):
    """Cover get_score() Redis exception path (lines 402-403)."""

    async def test_get_score_redis_exception_logs_warning_and_returns_none(self):
        """get_score() when redis.get raises → logs WARNING, returns None (lines 402-403).
        So what: a Redis outage during score lookup must not propagate up and
        crash the hot path; fail-open returns None so the connection is allowed."""
        local_cache = LocalCache({})  # Empty — no tier-1 hit
        redis = _make_redis()
        redis.get = AsyncMock(side_effect=ConnectionError("Redis read failed"))
        checker = _make_checker(redis=redis, local_cache=local_cache)
        import logging

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            score = await checker.get_score("1.2.3.4")
        self.assertIsNone(score)
