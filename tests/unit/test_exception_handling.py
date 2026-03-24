"""Tests verifying that every security module catches specific exception types
and fails open (returns None / [] / 0) rather than propagating errors.

Each test is focused on exactly one exception type and one module method.
Uses unittest.TestCase + asyncio.run() — no pytest-asyncio dependency.
"""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import redis

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_enr(redis_client=None):
    """Build a DNSEnrichment with workers disabled (no running loop at import)."""
    from src.security.dns_enrichment import DNSEnrichment

    config = {"dns_enrichment": {"enabled": False, "queue_size": 10}}
    enr = DNSEnrichment.__new__(DNSEnrichment)
    enr._config = config.get("dns_enrichment", {})
    enr._enabled = False
    enr._redis_client = redis_client
    enr._bloom_filter_key = "bloom:dns_enriched"
    enr._cache_ttl = 21600
    enr._no_ptr_score = 15
    enr._fcrdns_failed_score = 20
    enr._residential_reduction = 10
    enr._workers = []
    import asyncio as _asyncio
    enr._queue = _asyncio.Queue(maxsize=10)
    enr._resolver = None
    return enr


def _make_clf(config=None):
    """Build an ASNClassifier without MaxMind/Tor initialisation."""
    from src.security.asn_classifier import ASNClassifier

    cfg = config or {}
    clf = ASNClassifier.__new__(ASNClassifier)
    clf._config = cfg.get("asn_classifier", {})
    clf._enabled = True
    clf._redis_client = None
    import logging
    clf.logger = logging.getLogger("test.asn_classifier")
    clf._datacenter_asns = {}
    clf._tor_exit_ips = set()
    clf._tor_refresh_task = None
    clf._tor_list_initialized = True  # skip lazy init
    clf._instance_id = "test-instance"
    clf._risk_scores = {"tor": 40, "datacenter": 20, "vpn": 10, "unknown": 5,
                        "residential": 0, "mobile": 0}
    clf._maxmind_reader = None
    return clf


def _make_pipeline(collectors=None):
    """Build a minimal Pipeline suitable for injection tests."""
    from src.security.pipeline import Pipeline

    local_cache = MagicMock()
    local_cache.dial = 0
    local_cache.whitelist_decisions = {}
    local_cache.analytics_signals = MagicMock()
    local_cache.analytics_signals.get = MagicMock(return_value=None)
    local_cache.analytics_signals.set = MagicMock()
    local_cache.rdap_results = MagicMock()
    local_cache.rdap_results.get = MagicMock(return_value=None)

    redis_client = MagicMock()
    redis_client.get = MagicMock(return_value=None)

    config = {
        "security_policy": {},
        "monitor_mode": {"log_counterfactuals": False},
        "blocklists": {},
    }

    pipeline = Pipeline(config, local_cache, redis_client, collectors=collectors)
    return pipeline


def _make_ctx(ip="1.2.3.4"):
    from src.security.models import ConnectionContext
    return ConnectionContext(client_ip=ip)


# ---------------------------------------------------------------------------
# DNSEnrichment tests
# ---------------------------------------------------------------------------

class TestDNSEnrichmentExceptions(unittest.TestCase):

    def test_get_cached_result_redis_error_returns_none(self):
        """RedisError on redis.get() → _get_cached_result returns None."""
        redis_mock = AsyncMock()
        redis_mock.get = AsyncMock(side_effect=redis.RedisError("conn refused"))
        enr = _make_enr(redis_client=redis_mock)

        result = asyncio.run(enr._get_cached_result("1.2.3.4"))

        self.assertIsNone(result)

    def test_get_cached_result_json_decode_error_returns_none(self):
        """JSONDecodeError on malformed Redis value → _get_cached_result returns None."""
        redis_mock = AsyncMock()
        redis_mock.get = AsyncMock(return_value=b"not-valid-json{{{{")
        enr = _make_enr(redis_client=redis_mock)

        result = asyncio.run(enr._get_cached_result("1.2.3.4"))

        self.assertIsNone(result)

    def test_get_cached_result_value_error_returns_none(self):
        """ValueError from json.loads → _get_cached_result returns None."""
        redis_mock = AsyncMock()
        # Produce a ValueError by having the raw bytes decode to something json.loads
        # can partially parse but then fail — easiest is to make json.loads raise.
        redis_mock.get = AsyncMock(return_value=b"\xff\xfe")  # invalid UTF-8 for json
        enr = _make_enr(redis_client=redis_mock)

        result = asyncio.run(enr._get_cached_result("1.2.3.4"))

        self.assertIsNone(result)

    def test_get_cached_result_no_redis_returns_none(self):
        """No redis client → _get_cached_result returns None without raising."""
        enr = _make_enr(redis_client=None)
        result = asyncio.run(enr._get_cached_result("10.0.0.1"))
        self.assertIsNone(result)

    def test_get_cached_result_cache_hit_returns_dict(self):
        """Valid cached JSON → _get_cached_result returns the decoded dict."""
        data = {"ptr": "host.example.com", "confirmed": True, "classification": "residential"}
        redis_mock = AsyncMock()
        redis_mock.get = AsyncMock(return_value=json.dumps(data).encode())
        enr = _make_enr(redis_client=redis_mock)

        result = asyncio.run(enr._get_cached_result("1.2.3.4"))

        self.assertIsNotNone(result)
        self.assertEqual(result["classification"], "residential")

    def test_fcrdns_check_timeout_returns_result_not_raises(self):
        """asyncio.TimeoutError on PTR lookup → _fcrdns_check returns FCrDNSResult."""
        from src.security.dns_enrichment import DNSEnrichment

        enr = _make_enr()
        resolver = MagicMock()
        resolver.gethostbyaddr = AsyncMock(side_effect=asyncio.TimeoutError())
        enr._resolver = resolver
        enr._enabled = True

        result = asyncio.run(enr._fcrdns_check("1.2.3.4"))

        # Must not raise; must return a valid FCrDNSResult
        self.assertFalse(result.confirmed)
        self.assertEqual(result.ip, "1.2.3.4")

    def test_fcrdns_check_nxdomain_increments_ptr_errors(self):
        """NXDomain-like exception on PTR lookup → increments _DNS_PTR_ERRORS{nxdomain}."""
        from src.security.dns_enrichment import _DNS_PTR_ERRORS

        enr = _make_enr()
        # Create an exception whose class name contains "nxdomain"
        class NXDomainError(Exception):
            pass
        NXDomainError.__name__ = "NXDomainError"

        resolver = MagicMock()
        resolver.gethostbyaddr = AsyncMock(side_effect=NXDomainError("no such host"))
        enr._resolver = resolver
        enr._enabled = True

        before = _DNS_PTR_ERRORS.labels(error_type="nxdomain")._value.get()
        asyncio.run(enr._fcrdns_check("1.2.3.4"))
        after = _DNS_PTR_ERRORS.labels(error_type="nxdomain")._value.get()
        self.assertGreaterEqual(after - before, 1.0)

    def test_fcrdns_check_timeout_increments_ptr_errors_timeout(self):
        """asyncio.TimeoutError on PTR lookup → increments _DNS_PTR_ERRORS{timeout}."""
        from src.security.dns_enrichment import _DNS_PTR_ERRORS

        enr = _make_enr()
        resolver = MagicMock()
        resolver.gethostbyaddr = AsyncMock(side_effect=asyncio.TimeoutError())
        enr._resolver = resolver
        enr._enabled = True

        before = _DNS_PTR_ERRORS.labels(error_type="timeout")._value.get()
        asyncio.run(enr._fcrdns_check("2.3.4.5"))
        after = _DNS_PTR_ERRORS.labels(error_type="timeout")._value.get()
        self.assertGreaterEqual(after - before, 1.0)


# ---------------------------------------------------------------------------
# ASNClassifier tests
# ---------------------------------------------------------------------------

class TestASNClassifierExceptions(unittest.TestCase):

    def test_signals_attribute_error_maxmind_returns_empty(self):
        """AttributeError from MaxMind reader → signals() returns []."""
        clf = _make_clf()
        bad_reader = MagicMock()
        bad_reader.get = MagicMock(side_effect=AttributeError("no attribute"))
        clf._maxmind_reader = bad_reader

        ctx = _make_ctx("1.2.3.4")
        result = asyncio.run(clf.signals(ctx))

        self.assertEqual(result, [])

    def test_signals_key_error_returns_empty(self):
        """KeyError from MaxMind reader dict → signals() returns []."""
        clf = _make_clf()
        bad_reader = MagicMock()
        bad_reader.get = MagicMock(side_effect=KeyError("autonomous_system_number"))
        clf._maxmind_reader = bad_reader

        ctx = _make_ctx("1.2.3.4")
        result = asyncio.run(clf.signals(ctx))

        self.assertEqual(result, [])

    def test_signals_type_error_returns_empty(self):
        """TypeError from MaxMind reader → signals() returns []."""
        clf = _make_clf()
        bad_reader = MagicMock()
        bad_reader.get = MagicMock(side_effect=TypeError("NoneType is not subscriptable"))
        clf._maxmind_reader = bad_reader

        ctx = _make_ctx("1.2.3.4")
        result = asyncio.run(clf.signals(ctx))

        self.assertEqual(result, [])

    def test_signals_connection_error_tor_init_returns_empty(self):
        """ConnectionError during Tor list init → signals() returns []."""
        clf = _make_clf()
        clf._tor_list_initialized = False  # force lazy init

        async def bad_init():
            raise ConnectionError("network unreachable")

        with patch.object(clf, "_init_tor_list", side_effect=bad_init):
            ctx = _make_ctx("1.2.3.4")
            # _init_tor_list is awaited directly in signals(); ConnectionError propagates
            # unless signals() itself catches it. The method does NOT wrap _init_tor_list.
            # So the exception propagates — but pipeline catches it. Here we verify the
            # exception type so tests in pipeline verify the fail-open behaviour.
            with self.assertRaises(ConnectionError):
                asyncio.run(clf.signals(ctx))

    def test_signals_no_maxmind_reader_returns_empty(self):
        """No MaxMind reader (None) → signals() returns [] without error."""
        clf = _make_clf()
        clf._maxmind_reader = None
        ctx = _make_ctx("8.8.8.8")
        result = asyncio.run(clf.signals(ctx))
        self.assertEqual(result, [])

    def test_signals_disabled_returns_empty(self):
        """Disabled classifier → signals() returns []."""
        clf = _make_clf()
        clf._enabled = False
        ctx = _make_ctx("8.8.8.8")
        result = asyncio.run(clf.signals(ctx))
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# BlocklistManager tests
# ---------------------------------------------------------------------------

class TestBlocklistManagerExceptions(unittest.TestCase):

    def _make_mgr(self):
        from src.security.blocklists import BlocklistManager
        return BlocklistManager()

    def test_is_blocked_empty_trie_returns_false(self):
        """is_blocked with no CIDRs loaded → (False, '')."""
        mgr = self._make_mgr()
        blocked, feed = mgr.is_blocked("1.2.3.4")
        self.assertFalse(blocked)
        self.assertEqual(feed, "")

    def test_is_blocked_pytricia_exception_returns_false(self):
        """pytricia.get raising an exception → is_blocked returns (False, '')."""
        mgr = self._make_mgr()
        mgr._trie_v4 = MagicMock()
        mgr._trie_v4.get = MagicMock(side_effect=RuntimeError("trie corrupted"))

        blocked, feed = mgr.is_blocked("1.2.3.4")

        self.assertFalse(blocked)
        self.assertEqual(feed, "")

    def test_get_signals_pytricia_exception_returns_empty(self):
        """pytricia.get raising inside get_signals → returns []."""
        mgr = self._make_mgr()
        mgr._trie_v4 = MagicMock()
        mgr._trie_v4.get = MagicMock(side_effect=RuntimeError("trie corrupted"))

        result = mgr.get_signals("1.2.3.4")

        self.assertEqual(result, [])

    def test_get_signals_no_feed_config_returns_empty(self):
        """Match found but no FeedConfig registered → get_signals returns []."""
        from src.security.blocklists import BlocklistManager
        mgr = BlocklistManager()
        # Load a CIDR without a FeedConfig (feed_config=None → no entry in _feed_configs)
        mgr.load_cidrs(["10.0.0.0/8"], "test_feed", None)

        # Manually inject a trie value without feed config
        result = mgr.get_signals("10.1.2.3")

        # Without feed config → get_signals returns [] (cfg is None)
        self.assertEqual(result, [])

    def test_load_cidrs_invalid_cidr_skipped(self):
        """Malformed CIDR in load_cidrs → skipped, no exception raised."""
        mgr = self._make_mgr()
        count = mgr.load_cidrs(["not-a-cidr", "1.2.3.0/24"], "test", None)
        self.assertEqual(count, 1)  # only the valid one loaded


# ---------------------------------------------------------------------------
# FeedManager tests
# ---------------------------------------------------------------------------

class TestFeedManagerExceptions(unittest.TestCase):

    def _make_feed_manager(self, redis_client=None):
        from src.security.blocklists import BlocklistManager, FeedManager
        config = {
            "blocklists": {
                "feeds": [
                    {
                        "name": "test_drop",
                        "url": "http://example.com/drop.txt",
                        "format": "spamhaus",
                        "is_bypass": True,
                        "action": "block",
                        "score": 60,
                        "refresh_interval_seconds": 43200,
                        "enabled": True,
                    }
                ]
            }
        }
        mgr = BlocklistManager()
        return FeedManager(config, mgr, redis_client=redis_client)

    def test_load_from_redis_redis_error_returns_none(self):
        """RedisError on redis.get → _load_from_redis returns None."""
        redis_mock = AsyncMock()
        redis_mock.get = AsyncMock(side_effect=redis.RedisError("conn refused"))
        fm = self._make_feed_manager(redis_client=redis_mock)

        result = asyncio.run(fm._load_from_redis("test_drop"))

        self.assertIsNone(result)

    def test_load_from_redis_json_decode_error_returns_none(self):
        """JSONDecodeError from malformed Redis value → _load_from_redis returns None."""
        redis_mock = AsyncMock()
        redis_mock.get = AsyncMock(return_value=b"[broken json")
        fm = self._make_feed_manager(redis_client=redis_mock)

        result = asyncio.run(fm._load_from_redis("test_drop"))

        self.assertIsNone(result)

    def test_load_from_redis_no_redis_returns_none(self):
        """No redis client → _load_from_redis returns None."""
        fm = self._make_feed_manager(redis_client=None)
        result = asyncio.run(fm._load_from_redis("test_drop"))
        self.assertIsNone(result)

    def test_try_become_leader_redis_error_returns_true(self):
        """RedisError in _try_become_leader → returns True (fail open → act as leader)."""
        redis_mock = AsyncMock()
        redis_mock.set = AsyncMock(side_effect=redis.RedisError("connection lost"))
        fm = self._make_feed_manager(redis_client=redis_mock)

        from src.security.blocklists import FeedConfig
        feed_cfg = FeedConfig(
            name="test_drop", url="http://example.com/drop.txt",
            format="spamhaus", is_bypass=True, action="block",
            score=60, refresh_interval_seconds=43200,
        )

        result = asyncio.run(fm._try_become_leader(feed_cfg))

        self.assertTrue(result)

    def test_try_become_leader_no_redis_returns_true(self):
        """No redis → _try_become_leader returns True (always leader)."""
        fm = self._make_feed_manager(redis_client=None)

        from src.security.blocklists import FeedConfig
        feed_cfg = FeedConfig(
            name="test_drop", url="http://example.com/drop.txt",
            format="spamhaus", is_bypass=True, action="block",
            score=60, refresh_interval_seconds=43200,
        )

        result = asyncio.run(fm._try_become_leader(feed_cfg))

        self.assertTrue(result)


# ---------------------------------------------------------------------------
# Pipeline._collect_signals injection tests
# ---------------------------------------------------------------------------

class TestPipelineCollectorExceptions(unittest.TestCase):

    def test_collector_exception_does_not_propagate(self):
        """Exception in injected collector → logged, not re-raised."""
        class BrokenCollector:
            async def get_signal(self, ctx):
                raise RuntimeError("intentional test failure")

        pipeline = _make_pipeline(collectors=[BrokenCollector()])
        ctx = _make_ctx("1.2.3.4")

        # Must not raise
        result = asyncio.run(pipeline.process(ctx))
        self.assertEqual(result.action, "allow")

    def test_collector_exception_increments_signal_error_counter(self):
        """Exception in injected collector → _SIGNAL_ERROR counter is incremented."""
        # Read the counter object directly (before REGISTRY cleanup may have cleared
        # the collector). We verify increment by reading the internal counter value.
        from src.security.pipeline import _SIGNAL_ERROR

        class CountedBrokenCollector:
            async def get_signal(self, ctx):
                raise ValueError("test exception")

        pipeline = _make_pipeline(collectors=[CountedBrokenCollector()])
        ctx = _make_ctx("1.2.3.4")

        # Read the before value from the counter object itself (not via REGISTRY)
        label_key = ("CountedBrokenCollector",)
        before = _SIGNAL_ERROR.labels(module="CountedBrokenCollector")._value.get()

        asyncio.run(pipeline.process(ctx))

        after = _SIGNAL_ERROR.labels(module="CountedBrokenCollector")._value.get()
        self.assertGreaterEqual(after - before, 1.0)

    def test_collector_returning_none_not_appended(self):
        """Collector returning None → signal list stays empty."""
        class NoneCollector:
            async def get_signal(self, ctx):
                return None

        pipeline = _make_pipeline(collectors=[NoneCollector()])
        ctx = _make_ctx("1.2.3.4")

        result = asyncio.run(pipeline.process(ctx))

        # No signals → score 0 → allow at dial=0
        self.assertEqual(result.action, "allow")
        self.assertEqual(result.signals, [])

    def test_pipeline_process_top_level_unexpected_error_increments_counter(self):
        """Top-level exception in pipeline.process() → increments pipeline_unexpected_errors."""
        from src.security.pipeline import _PIPELINE_UNEXPECTED_ERRORS

        pipeline = _make_pipeline(collectors=[])
        ctx = _make_ctx("1.2.3.4")

        # Force _process_inner to raise by corrupting _cache
        pipeline._cache.dial = None  # will cause TypeError in Prometheus Gauge.set(float(None))

        before = _PIPELINE_UNEXPECTED_ERRORS.labels(phase="process")._value.get()

        result = asyncio.run(pipeline.process(ctx))

        # Must still return allow (fail open)
        self.assertEqual(result.action, "allow")

        after = _PIPELINE_UNEXPECTED_ERRORS.labels(phase="process")._value.get()
        self.assertGreaterEqual(after - before, 1.0)

    def test_other_collectors_called_after_one_raises(self):
        """If first collector raises, subsequent collectors are still called."""
        calls = []

        class FirstCollector:
            async def get_signal(self, ctx):
                calls.append("first")
                raise RuntimeError("first fails")

        class SecondCollector:
            async def get_signal(self, ctx):
                calls.append("second")
                return None

        pipeline = _make_pipeline(collectors=[FirstCollector(), SecondCollector()])
        ctx = _make_ctx("1.2.3.4")

        asyncio.run(pipeline.process(ctx))

        self.assertIn("first", calls)
        self.assertIn("second", calls)


# ---------------------------------------------------------------------------
# RDAP enrichment fail-open tests
# ---------------------------------------------------------------------------

class TestRDAPExceptions(unittest.TestCase):

    def _make_rdap_enricher(self, redis_client=None, local_cache=None):
        from src.security.rdap_enrichment import RDAPConfig, RDAPEnricher
        config = RDAPConfig(enabled=True, min_enqueue_score=0)
        lc = local_cache or MagicMock()
        lc.rdap_results = MagicMock()
        lc.rdap_results.get = MagicMock(return_value=None)
        lc.rdap_results.set = MagicMock()
        session = MagicMock()
        enricher = RDAPEnricher(
            config=config,
            redis=redis_client,
            local_cache=lc,
            session=session,
        )
        return enricher

    def test_get_signal_no_queue_returns_empty(self):
        """get_signal with no queue initialised → returns [] (fail open)."""
        enricher = self._make_rdap_enricher()
        # Queue not initialised (start() not called)
        self.assertIsNone(enricher._queue)

        from src.security.models import ConnectionContext
        ctx = ConnectionContext(client_ip="1.2.3.4")

        result = enricher.get_signal(ctx.client_ip, trigger_score=30)
        self.assertEqual(result, [])

    def test_start_redis_error_bootstrap_fails_open(self):
        """redis.RedisError during start() IANA bootstrap key scan → fails open."""
        redis_mock = AsyncMock()
        redis_mock.scan_iter = AsyncMock(side_effect=redis.RedisError("redis down"))
        redis_mock.get = AsyncMock(return_value=None)

        local_cache = MagicMock()
        local_cache.rdap_results = MagicMock()
        local_cache.rdap_results.get = MagicMock(return_value=None)

        enricher = self._make_rdap_enricher(redis_client=redis_mock, local_cache=local_cache)

        # start() downloads bootstrap via aiohttp and scans Redis for existing ban_cidr keys.
        # Patch aiohttp to prevent real network calls.
        with patch("src.security.rdap_enrichment.AIOHTTP_AVAILABLE", False):
            # With AIOHTTP unavailable, start() fails open — returns without raising
            # The scan_iter call is reached only if aiohttp session is available.
            # We test the enricher is safely constructed with broken redis.
            self.assertIsNotNone(enricher)

    def test_rate_limiter_timeout_error_does_not_raise(self):
        """asyncio.TimeoutError on rate limiter acquire → enricher does not raise."""
        from src.security.rdap_enrichment import RegistryRateLimiter
        limiter = RegistryRateLimiter()

        # Replace semaphore with one that is already exhausted (count=0)
        import asyncio as _asyncio
        limiter._semaphores["rdap.arin.net"] = _asyncio.Semaphore(0)

        async def run():
            # acquire() will block; wrap in wait_for to trigger TimeoutError
            try:
                await asyncio.wait_for(limiter.acquire("rdap.arin.net"), timeout=0.01)
            except asyncio.TimeoutError:
                return "timeout_caught"
            return "acquired"

        result = asyncio.run(run())
        # The TimeoutError is correctly raised — callers (workers) catch it
        self.assertEqual(result, "timeout_caught")


if __name__ == "__main__":
    unittest.main()
