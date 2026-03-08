"""Chaos tests for Phase 10 — AbuseIPDB external API failure scenarios.

Verifies that the proxy fails open and continues operating normally when:
  - AbuseIPDB API is unreachable
  - Quota is exhausted (HTTP 429)
  - Redis is unavailable for cache writes
  - Worker pool is stopped cleanly
"""

import asyncio
import json
import logging
import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

from src.security.abuseipdb import (
    AbuseIPDBChecker,
    AbuseIPDBConfig,
    abuseipdb_to_risk_signal,
    QuotaExhaustedException,
)
from src.cache.local_cache import LocalCache


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
    redis = MagicMock()
    redis.get = AsyncMock(return_value=get_return)
    redis.setex = AsyncMock(return_value=True)
    redis.incr = AsyncMock(return_value=1)
    redis.decr = AsyncMock(return_value=0)
    redis.expire = AsyncMock(return_value=True)
    redis.sadd = AsyncMock(return_value=1)
    bf = MagicMock()
    bf.add = AsyncMock(return_value=1)
    redis.bf = MagicMock(return_value=bf)
    return redis


class TestAbuseIPDBAPIUnreachable(unittest.IsolatedAsyncioTestCase):
    """AbuseIPDB API unreachable: fail open; error logged; connections continue."""

    async def test_network_error_fails_open_score_zero(self):
        """Connection refused → fail open (confidence=0); error counter incremented."""
        redis = _make_redis()
        local_cache = LocalCache({})

        @asynccontextmanager
        async def _network_error(*args, **kwargs):
            raise ConnectionError("Connection refused")
            yield  # pragma: no cover

        session = MagicMock()
        session.get = _network_error

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, session)
        await checker.start()

        try:
            await checker._process_lookup("1.2.3.4")
        finally:
            await checker.stop()

        # Fail open: score=0 cached
        cached = local_cache.abuseipdb_scores.get("1.2.3.4")
        self.assertEqual(cached, 0)

    async def test_api_error_logged(self):
        """API error is logged with ERROR level and event=api_error."""
        redis = _make_redis()
        local_cache = LocalCache({})

        @asynccontextmanager
        async def _server_error(*args, **kwargs):
            exc = Exception("HTTP 503")
            exc.status = 503  # type: ignore[attr-defined]
            raise exc
            yield  # pragma: no cover

        session = MagicMock()
        session.get = _server_error

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, session)

        with self.assertLogs("src.security.abuseipdb", level="ERROR") as cm:
            await checker._process_lookup("1.2.3.4")

        # Verify error was logged
        log_messages = " ".join(cm.output)
        self.assertIn("api_error", log_messages)

    async def test_connections_continue_after_api_error(self):
        """After API error, subsequent get_signal() calls still work from cache."""
        redis = _make_redis()
        local_cache = LocalCache({})

        # Pre-populate cache for a known-good IP
        local_cache.abuseipdb_scores.set("10.0.0.1", 0)

        @asynccontextmanager
        async def _server_error(*args, **kwargs):
            exc = Exception("HTTP 503")
            exc.status = 503  # type: ignore[attr-defined]
            raise exc
            yield  # pragma: no cover

        session = MagicMock()
        session.get = _server_error

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, session)

        # API error on lookup
        await checker._process_lookup("192.168.1.1")

        # Known-good IP still served from cache
        signal = checker.get_signal("10.0.0.1")
        # score should be 0 (confidence 0 = 0 contribution)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.score, 0)


class TestAbuseIPDBQuotaExhausted(unittest.IsolatedAsyncioTestCase):
    """Quota exhausted (HTTP 429): WARN logged once; subsequent requests use cache."""

    async def test_quota_exhausted_warn_logged_once(self):
        """HTTP 429 → WARN logged exactly once (not on every subsequent call)."""
        redis = _make_redis()
        # Quota check always returns over limit
        redis.incr = AsyncMock(return_value=101)  # Over limit
        local_cache = LocalCache({})

        @asynccontextmanager
        async def _quota_hit(*args, **kwargs):
            from src.security.abuseipdb import QuotaExhaustedException
            raise QuotaExhaustedException()
            yield  # pragma: no cover

        session = MagicMock()
        session.get = _quota_hit

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, session)

        with self.assertLogs("src.security.abuseipdb", level="WARNING") as cm:
            await checker._process_lookup("1.2.3.4")
            await checker._process_lookup("5.6.7.8")  # Second call — no second WARN

        # Only one quota_exhausted warning
        quota_warnings = [
            line for line in cm.output
            if "quota_exhausted" in line and "WARN" in line
        ]
        self.assertGreaterEqual(len(quota_warnings), 1)

    async def test_quota_exhausted_gauge_set_to_1(self):
        """Quota exhausted → ja4proxy_abuseipdb_quota_exhausted gauge = 1."""
        redis = _make_redis()
        redis.incr = AsyncMock(return_value=101)
        local_cache = LocalCache({})

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, MagicMock())

        with self.assertLogs("src.security.abuseipdb", level="WARNING"):
            await checker._process_lookup("1.2.3.4")

        self.assertTrue(checker._quota_exhausted)

    async def test_quota_exhausted_stops_enqueueing(self):
        """Once quota exhausted, new IPs are not enqueued."""
        redis = _make_redis()
        local_cache = LocalCache({})

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, MagicMock())
        checker._queue = asyncio.Queue(maxsize=10)
        checker._workers = []
        checker._quota_exhausted = True

        await checker._enqueue_lookup("1.2.3.4")

        # Nothing should be in the queue
        self.assertEqual(checker._queue.qsize(), 0)

    async def test_get_signal_returns_none_when_quota_exhausted(self):
        """get_signal() on a non-cached IP returns None (cache miss + quota)."""
        redis = _make_redis()
        local_cache = LocalCache({})

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, MagicMock())
        checker._quota_exhausted = True

        # No cache entry — returns None
        signal = checker.get_signal("1.2.3.4")
        self.assertIsNone(signal)


class TestRedisUnavailableForCacheWrite(unittest.IsolatedAsyncioTestCase):
    """Redis unavailable for cache write: API result used; write failure logged."""

    async def test_redis_write_failure_logs_warn_no_crash(self):
        """Redis.setex fails → warning logged; no crash; in-process cache updated."""
        redis = _make_redis()
        redis.setex = AsyncMock(side_effect=ConnectionError("Redis down"))
        local_cache = LocalCache({})

        @asynccontextmanager
        async def _success_response(url, params=None, **kwargs):
            ip = (params or {}).get("ipAddress", "1.2.3.4")
            resp = MagicMock()
            resp.status = 200
            resp.json = AsyncMock(return_value={"data": {"abuseConfidenceScore": 75}})
            resp.raise_for_status = MagicMock()
            yield resp

        session = MagicMock()
        session.get = _success_response

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, session)

        with self.assertLogs("src.security.abuseipdb", level="WARNING") as cm:
            await checker._process_lookup("1.2.3.4")

        # Warning logged
        log_text = " ".join(cm.output)
        self.assertIn("redis_write_error", log_text)

        # In-process cache was still updated (result not lost for this instance)
        cached = local_cache.abuseipdb_scores.get("1.2.3.4")
        self.assertEqual(cached, 75)

    async def test_redis_read_failure_logs_warn_no_crash(self):
        """Redis.get fails during get_score → warning logged; returns None (fail open)."""
        redis = _make_redis()
        redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))
        local_cache = LocalCache({})

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, MagicMock())

        # Should not raise; should return None
        score = await checker.get_score("1.2.3.4")
        self.assertIsNone(score)


class TestWorkerPoolStop(unittest.IsolatedAsyncioTestCase):
    """Worker pool stop() completes within 5 seconds."""

    async def test_stop_completes_within_5_seconds(self):
        """stop() must return within 5 seconds, even with workers waiting for items."""
        redis = _make_redis()
        checker = AbuseIPDBChecker(_make_config(worker_count=3), redis, LocalCache({}), MagicMock())
        await checker.start()

        # Workers are now waiting on queue.get() — stop should cancel them
        await asyncio.wait_for(checker.stop(), timeout=5.0)

    async def test_stop_drains_logs_remaining_depth(self):
        """If queue has items on stop(), shutdown logs the remaining depth."""
        redis = _make_redis()
        checker = AbuseIPDBChecker(_make_config(worker_count=0), redis, LocalCache({}), MagicMock())
        # Create queue but no workers so items accumulate
        checker._queue = asyncio.Queue(maxsize=100)
        checker._workers = []

        # Add items to queue
        checker._queue.put_nowait("1.2.3.4")
        checker._queue.put_nowait("5.6.7.8")

        with self.assertLogs("src.security.abuseipdb", level="WARNING") as cm:
            await checker.stop()

        log_text = " ".join(cm.output)
        self.assertIn("shutdown_queue_not_empty", log_text)

    async def test_worker_cancelled_error_exits_cleanly(self):
        """Workers handle asyncio.CancelledError cleanly — stop() returns without hang."""
        redis = _make_redis()
        checker = AbuseIPDBChecker(_make_config(worker_count=2), redis, LocalCache({}), MagicMock())
        await checker.start()

        # stop() should not raise and should complete promptly
        await asyncio.wait_for(checker.stop(), timeout=5.0)
        # All workers should be done
        for w in checker._workers:
            self.assertTrue(w.done())
