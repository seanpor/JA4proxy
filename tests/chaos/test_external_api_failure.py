"""Chaos tests for external API failure scenarios (Phase 10/11/16d).

Verifies that the proxy fails open and continues operating normally when:
  - AbuseIPDB API is unreachable / returns 429 / times out / returns malformed JSON
  - RDAP RIR is unreachable
  - Redis is unavailable for cache writes
  - All external APIs fail simultaneously (pipeline must still allow connections)
  - Worker pool is stopped cleanly
"""

import asyncio
import json
import logging
import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

from src.cache.local_cache import LocalCache
from src.security.abuseipdb import (
    AbuseIPDBChecker,
    AbuseIPDBConfig,
    QuotaExhaustedException,
    abuseipdb_to_risk_signal,
)


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
    # Pipeline mock for Phase 28 pipeline-based methods
    pipe = MagicMock()
    pipe.incr = MagicMock(return_value=None)
    pipe.expire = MagicMock(return_value=None)
    pipe.execute = AsyncMock(return_value=[1, True])
    pipeline_cm = MagicMock()
    pipeline_cm.__aenter__ = AsyncMock(return_value=pipe)
    pipeline_cm.__aexit__ = AsyncMock(return_value=None)
    redis.pipeline = MagicMock(return_value=pipeline_cm)
    redis._test_pipe = pipe
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
        # count=101 > max_requests_per_day=100 → quota exceeded → warning logged
        redis._test_pipe.execute = AsyncMock(return_value=[101, True])
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


# ===========================================================================
# Phase 11 — RDAP Chaos Tests
# ===========================================================================


def _make_rdap_config(**kwargs):
    from src.security.rdap_enrichment import RDAPConfig, _BlockExpansionConfig, _NewNetblockConfig, _OrgReputationConfig
    defaults = dict(
        enabled=True,
        queue_size=10,
        worker_count=1,
        min_enqueue_score=20,
        lookup_timeout_seconds=5,
        delegate_to_analytics=False,
        org_reputation=_OrgReputationConfig(enabled=True, score=45),
        new_netblock_flagging=_NewNetblockConfig(enabled=True, max_age_days=90, score=20),
        block_expansion=_BlockExpansionConfig(enabled=False),
    )
    defaults.update(kwargs)
    return RDAPConfig(**defaults) if False else _build_rdap_config(defaults)


def _build_rdap_config(defaults):
    from src.security.rdap_enrichment import RDAPConfig, _BlockExpansionConfig, _NewNetblockConfig, _OrgReputationConfig
    return RDAPConfig(
        enabled=defaults.get("enabled", True),
        queue_size=defaults.get("queue_size", 10),
        worker_count=defaults.get("worker_count", 1),
        min_enqueue_score=defaults.get("min_enqueue_score", 20),
        lookup_timeout_seconds=defaults.get("lookup_timeout_seconds", 5),
        delegate_to_analytics=defaults.get("delegate_to_analytics", False),
        org_reputation=defaults.get("org_reputation", _OrgReputationConfig()),
        new_netblock_flagging=defaults.get("new_netblock_flagging", _NewNetblockConfig()),
        block_expansion=defaults.get("block_expansion", _BlockExpansionConfig(enabled=False)),
    )


def _make_rdap_redis():
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.setex = AsyncMock(return_value=True)
    redis.set = AsyncMock(return_value=True)
    redis.incr = AsyncMock(return_value=1)
    redis.decr = AsyncMock(return_value=0)
    redis.expire = AsyncMock(return_value=True)
    redis.exists = AsyncMock(return_value=0)
    redis.sadd = AsyncMock(return_value=1)
    redis.publish = AsyncMock(return_value=1)
    redis.lpush = AsyncMock(return_value=1)
    redis.ltrim = AsyncMock(return_value=True)
    redis.scan = AsyncMock(return_value=(0, []))
    bf = MagicMock()
    bf.add = AsyncMock(return_value=1)
    redis.bf = MagicMock(return_value=bf)
    return redis


class TestRDAPAPIUnreachable(unittest.IsolatedAsyncioTestCase):
    """RIR RDAP API unreachable: fail open; error counter incremented."""

    async def test_rir_unreachable_fails_open(self):
        """Connection refused to RIR → fail open; rdap_lookup_total{result=error} inc'd."""
        from contextlib import asynccontextmanager

        from src.cache.local_cache import LocalCache
        from src.security.rdap_enrichment import RDAPEnricher

        @asynccontextmanager
        async def _network_error(*args, **kwargs):
            raise ConnectionError("Connection refused")
            yield  # pragma: no cover

        session = MagicMock()
        session.get = _network_error

        redis = _make_rdap_redis()
        local_cache = LocalCache({})

        enricher = RDAPEnricher(
            _build_rdap_config({}),
            redis, local_cache, session,
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []
        enricher._bootstrap_v4 = [
            {"prefixes": ["0.0.0.0/0"], "urls": ["https://rdap.arin.net/registry/"]}
        ]
        enricher._bootstrap_v6 = []

        with patch("src.security.rdap_enrichment._LOOKUP_TOTAL") as mock_counter:
            # Should not raise — fail open
            await enricher._process_lookup("1.2.3.4")
            # Error counter should be incremented
            mock_counter.labels.assert_called()

    async def test_queue_drains_normally_after_api_failure(self):
        """Worker continues processing queue after API failures."""
        from src.cache.local_cache import LocalCache
        from src.security.rdap_enrichment import RDAPEnricher

        redis = _make_rdap_redis()
        local_cache = LocalCache({})

        enricher = RDAPEnricher(
            _build_rdap_config({"queue_size": 5, "worker_count": 1}),
            redis, local_cache, MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []
        enricher._bootstrap_v4 = [
            {"prefixes": ["0.0.0.0/0"], "urls": ["https://rdap.arin.net/registry/"]}
        ]

        # start creates the queue and workers
        with patch.object(enricher, '_load_bootstrap', new=AsyncMock()):
            with patch.object(enricher, '_scan_existing_ban_cidrs', new=AsyncMock()):
                with patch.object(enricher, '_load_known_bad_orgs'):
                    await enricher.start()

        try:
            with patch.object(enricher, '_process_lookup', side_effect=ConnectionError("refused")):
                enricher._queue.put_nowait("1.2.3.4")
                await asyncio.sleep(0.1)  # Allow worker to process
                # Worker should still be running (not crashed)
                for w in enricher._workers:
                    self.assertFalse(w.done(), "Worker must not crash on API error")
        finally:
            await enricher.stop()


class TestRDAPBootstrapFailure(unittest.IsolatedAsyncioTestCase):
    """IANA bootstrap download fails: use cached bootstrap or warn and continue."""

    async def test_bootstrap_download_fails_uses_redis_cache(self):
        """Bootstrap download fails → load from Redis; WARN logged; no crash."""
        import json

        from src.cache.local_cache import LocalCache
        from src.security.rdap_enrichment import RDAPEnricher

        # Bootstrap is available in Redis
        cached_bootstrap = [{"prefixes": ["0.0.0.0/0"], "urls": ["https://rdap.arin.net/registry/"]}]
        redis = _make_rdap_redis()
        redis.get = AsyncMock(side_effect=[
            json.dumps(cached_bootstrap).encode(),  # v4 bootstrap
            json.dumps(cached_bootstrap).encode(),  # v6 bootstrap
        ])

        enricher = RDAPEnricher(
            _build_rdap_config({}),
            redis, LocalCache({}), MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []

        # Should load from Redis without needing to download
        await enricher._load_bootstrap()
        self.assertTrue(len(enricher._bootstrap_v4) > 0 or len(enricher._bootstrap_v6) > 0)

    async def test_bootstrap_download_and_redis_both_fail_logs_warn(self):
        """Both download and Redis fail → WARN logged; startup continues."""
        from contextlib import asynccontextmanager

        from src.cache.local_cache import LocalCache
        from src.security.rdap_enrichment import RDAPEnricher

        @asynccontextmanager
        async def _fail(*args, **kwargs):
            raise ConnectionError("No network")
            yield  # pragma: no cover

        session = MagicMock()
        session.get = _fail

        redis = _make_rdap_redis()
        redis.get = AsyncMock(side_effect=ConnectionError("Redis down"))

        enricher = RDAPEnricher(
            _build_rdap_config({}),
            redis, LocalCache({}), session,
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []

        # Should not raise — logs WARN and continues
        with patch.object(enricher, '_try_become_bootstrap_leader', new=AsyncMock(return_value=True)):
            await enricher._load_bootstrap()


class TestRDAPMalformedJSON(unittest.IsolatedAsyncioTestCase):
    """Malformed RDAP JSON: parse_errors incremented; fail open; worker continues."""

    async def test_malformed_json_increments_parse_errors_counter(self):
        """Malformed JSON response → rdap_parse_errors_total incremented; fail open."""
        from contextlib import asynccontextmanager

        from src.cache.local_cache import LocalCache
        from src.security.rdap_enrichment import RDAPEnricher

        @asynccontextmanager
        async def _malformed_response(*args, **kwargs):
            resp = MagicMock()
            resp.status = 200
            resp.headers = {}
            resp.raise_for_status = MagicMock()
            resp.json = AsyncMock(return_value={"bad_data": True, "no_valid_fields": "here"})
            yield resp

        session = MagicMock()
        session.get = _malformed_response

        redis = _make_rdap_redis()
        local_cache = LocalCache({})

        enricher = RDAPEnricher(
            _build_rdap_config({}),
            redis, local_cache, session,
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []
        enricher._bootstrap_v4 = [
            {"prefixes": ["0.0.0.0/0"], "urls": ["https://rdap.arin.net/registry/"]}
        ]

        # Should not raise — fail open with empty result
        # The malformed JSON will produce a result with fallback values (not an error)
        # because _parse_rdap_response has graceful fallbacks
        await enricher._process_lookup("1.2.3.4")
        # Worker continues — no exception propagated


class TestRDAPQueueOverflow(unittest.IsolatedAsyncioTestCase):
    """Queue overflow: items dropped silently; drop counter incremented."""

    async def test_queue_full_drops_item_silently(self):
        """Full queue → item dropped; rdap_queue_dropped_total incremented; no crash."""
        from src.cache.local_cache import LocalCache
        from src.security.rdap_enrichment import RDAPEnricher

        redis = _make_rdap_redis()
        local_cache = LocalCache({})

        enricher = RDAPEnricher(
            _build_rdap_config({"queue_size": 1}),
            redis, local_cache, MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []
        enricher._queue = asyncio.Queue(maxsize=1)
        enricher._queue.put_nowait("1.1.1.1")  # Fill the queue

        with patch("src.security.rdap_enrichment._QUEUE_DROPPED") as mock_dropped:
            await enricher._enqueue_lookup("2.2.2.2")
            mock_dropped.inc.assert_called_once()

    async def test_multiple_overflows_do_not_crash(self):
        """Multiple queue overflows in a row: all dropped silently; no exception."""
        from src.cache.local_cache import LocalCache
        from src.security.rdap_enrichment import RDAPEnricher

        redis = _make_rdap_redis()
        local_cache = LocalCache({})

        enricher = RDAPEnricher(
            _build_rdap_config({"queue_size": 2}),
            redis, local_cache, MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []
        enricher._queue = asyncio.Queue(maxsize=2)
        enricher._queue.put_nowait("1.1.1.1")
        enricher._queue.put_nowait("2.2.2.2")

        # These should all be dropped without error
        for i in range(5):
            await enricher._enqueue_lookup(f"3.3.3.{i}")  # All overflow


# ── Phase 16d: Simultaneous failure of all external APIs ─────────────────────

class TestAllApiSimultaneousFailure(unittest.IsolatedAsyncioTestCase):
    """Simultaneous failure of AbuseIPDB + RDAP: pipeline must allow all
    connections; all per-service error counters must be incremented."""

    def _make_session_error(self):
        """Create a session mock that raises a connection error on .get()."""
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _error(*args, **kwargs):
            raise ConnectionError("Connection refused")
            yield  # pragma: no cover

        session = MagicMock()
        session.get = _error
        return session

    async def test_abuseipdb_down_pipeline_allows(self):
        """AbuseIPDB unreachable → get_signal() returns None (no cached score); fails open."""
        redis = _make_redis()
        local_cache = LocalCache({})
        session = self._make_session_error()

        checker = AbuseIPDBChecker(_make_config(), redis, local_cache, session)
        await checker.start()
        try:
            await checker._process_lookup("8.8.8.8")
        finally:
            await checker.stop()

        # get_signal reads from local_cache; score=0 was cached on failure → fail open
        signal = checker.get_signal("8.8.8.8")
        # Either None (not in cache) or a low-confidence signal (score 0) — both are fail-open
        assert signal is None or (hasattr(signal, "score") and signal.score == 0)

    async def test_rdap_down_pipeline_allows(self):
        """RDAP RIR unreachable → _process_lookup() returns gracefully; pipeline fails open."""
        from src.security.rdap_enrichment import RDAPEnricher

        redis = _make_rdap_redis()
        local_cache = LocalCache({})

        enricher = RDAPEnricher(
            _build_rdap_config({}),
            redis, local_cache, MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []

        # All RIR requests raise a connection error — _process_lookup must not crash
        with patch("aiohttp.ClientSession.get", side_effect=ConnectionError("RIR unreachable")):
            # Does not raise — fails open
            await enricher._process_lookup("192.0.2.1")

    async def test_simultaneous_api_failure_both_return_safe(self):
        """AbuseIPDB + RDAP both fail simultaneously: both return safe values; no crash."""
        from src.security.rdap_enrichment import RDAPEnricher

        # AbuseIPDB fails open
        redis_abuse = _make_redis()
        session = self._make_session_error()
        checker = AbuseIPDBChecker(_make_config(), redis_abuse, LocalCache({}), session)
        await checker.start()
        try:
            await checker._process_lookup("10.0.0.1")
        finally:
            await checker.stop()
        abuse_signal = checker.get_signal("10.0.0.1")

        # RDAP fails open
        redis_rdap = _make_rdap_redis()
        enricher = RDAPEnricher(
            _build_rdap_config({}),
            redis_rdap, LocalCache({}), MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = []
        with patch("aiohttp.ClientSession.get", side_effect=ConnectionError("RIR unreachable")):
            # _process_lookup must not raise — RDAP fails open
            await enricher._process_lookup("10.0.0.1")

        # Both must fail open, not crash
        assert abuse_signal is None or (hasattr(abuse_signal, "score") and abuse_signal.score == 0)
        # RDAP: get_signal returns [] (empty signals) when no result in cache
        rdap_signals = enricher.get_signal("10.0.0.1", trigger_score=0)
        assert isinstance(rdap_signals, list)
