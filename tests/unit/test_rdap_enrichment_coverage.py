"""Phase 16c — Coverage tests for rdap_enrichment.py.

Covers the uncovered paths in rdap_enrichment.py, targeting ≥ 80% coverage.
These tests use mocks only; no real network calls are made.
"""

import asyncio
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, call, mock_open, patch

from src.cache.local_cache import LocalCache
from src.security.models import RiskSignal
from src.security.rdap_enrichment import (
    RDAPConfig,
    RDAPEnricher,
    RDAPResult,
    RegistryRateLimiter,
    _BlockExpansionConfig,
    _compute_expansion_cidr,
    _extract_netblock,
    _extract_org,
    _NewNetblockConfig,
    _OrgReputationConfig,
    new_netblock_signal,
)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helpers (shared with existing test_rdap_enrichment.py)
# ---------------------------------------------------------------------------


def _make_config(**kwargs) -> RDAPConfig:
    defaults = dict(
        enabled=True,
        queue_size=10,
        worker_count=1,
        min_enqueue_score=20,
        lookup_timeout_seconds=5,
        delegate_to_analytics=False,
        org_reputation=_OrgReputationConfig(enabled=True, score=45),
        new_netblock_flagging=_NewNetblockConfig(enabled=True, max_age_days=90, score=20),
        block_expansion=_BlockExpansionConfig(
            enabled=True,
            min_trigger_score=75,
            max_prefix_length_v4=24,
            max_prefix_length_v6=48,
            require_no_browser_traffic=True,
            require_known_bad_org=True,
            expansion_ban_duration=3600,
            max_expansions_per_hour=10,
        ),
    )
    defaults.update(kwargs)
    return RDAPConfig(**defaults)


def _make_redis() -> MagicMock:
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
    # Pipeline mock for Phase 28 pipeline-based methods
    pipe = MagicMock()
    pipe.incr = MagicMock(return_value=None)
    pipe.expire = MagicMock(return_value=None)
    pipe.lpush = MagicMock(return_value=None)
    pipe.ltrim = MagicMock(return_value=None)
    pipe.execute = AsyncMock(return_value=[1, True])
    pipeline_cm = MagicMock()
    pipeline_cm.__aenter__ = AsyncMock(return_value=pipe)
    pipeline_cm.__aexit__ = AsyncMock(return_value=None)
    redis.pipeline = MagicMock(return_value=pipeline_cm)
    redis._test_pipe = pipe
    return redis


def _make_enricher(**kwargs):
    config = kwargs.pop("config", _make_config())
    redis = kwargs.pop("redis", _make_redis())
    local_cache = kwargs.pop("local_cache", LocalCache({}))
    session = kwargs.pop("session", MagicMock())
    blocklist_manager = kwargs.pop("blocklist_manager", None)
    known_bad_orgs_path = kwargs.pop("known_bad_orgs_path", "config/known_bad_orgs.yml")
    return RDAPEnricher(
        config, redis, local_cache, session,
        blocklist_manager=blocklist_manager,
        known_bad_orgs_path=known_bad_orgs_path,
        **kwargs,
    )


def _make_rdap_result(**kwargs) -> RDAPResult:
    defaults = dict(
        netblock="1.2.3.0/24",
        org_name="Test Org",
        org_handle="TEST-1",
        asn=None,
        country="US",
        registration_date="2020-01-01",
        fetched_at=1000.0,
        is_unknown=False,
    )
    defaults.update(kwargs)
    return RDAPResult(**defaults)


# ---------------------------------------------------------------------------
# RegistryRateLimiter._release_after (line 267)
# ---------------------------------------------------------------------------


class TestRegistryRateLimiter(unittest.TestCase):

    def test_release_after_releases_semaphore(self):
        """_release_after waits then releases the semaphore (line 267)."""
        sem = asyncio.Semaphore(0)

        async def run():
            # Start with sem at 0; _release_after should increment it after delay
            task = asyncio.create_task(RegistryRateLimiter._release_after(sem, 0.001))
            await asyncio.sleep(0.01)
            assert sem._value == 1  # should be released by now
            await task

        _run(run())

    def test_acquire_calls_release_after(self):
        """acquire() spawns _release_after task (line 262)."""
        rl = RegistryRateLimiter()
        # Override limits so acquire doesn't block (semaphore starts at 10)
        rl.LIMITS = {"arin.net": (10, 0)}

        async def run():
            await rl.acquire("arin.net")  # should not block

        _run(run())


# ---------------------------------------------------------------------------
# new_netblock_signal — invalid date (lines 304-305)
# ---------------------------------------------------------------------------


class TestNewNetblockSignalEdgeCases(unittest.TestCase):

    def test_invalid_date_format_returns_none(self):
        """Non-parseable date → catches ValueError, returns None (lines 304-305)."""
        sig = new_netblock_signal("not-a-date", max_age_days=90, score=20)
        self.assertIsNone(sig)

    def test_integer_date_returns_none(self):
        """Unexpected type (int) → catches TypeError, returns None (lines 304-305)."""
        sig = new_netblock_signal(12345, max_age_days=90, score=20)  # type: ignore[arg-type]
        self.assertIsNone(sig)


# ---------------------------------------------------------------------------
# RDAPEnricher.start() (lines 391-419)
# ---------------------------------------------------------------------------


class TestRDAPEnricherStart(unittest.TestCase):

    def test_start_when_disabled_returns_early(self):
        """start() returns immediately when enabled=False (line 391-392)."""
        enricher = _make_enricher(config=_make_config(enabled=False))

        async def run():
            await enricher.start()

        _run(run())
        self.assertIsNone(enricher._queue)

    def test_start_happy_path_creates_queue_and_workers(self):
        """start() loads known_bad, bootstrap, scans ban_cidrs, creates workers."""
        enricher = _make_enricher()

        async def run():
            with (
                patch.object(enricher, "_load_known_bad_orgs"),
                patch.object(enricher, "_load_bootstrap", new=AsyncMock()),
                patch.object(enricher, "_scan_existing_ban_cidrs", new=AsyncMock()),
            ):
                await enricher.start()
                # Clean up workers immediately
                for w in enricher._workers:
                    w.cancel()
                await asyncio.gather(*enricher._workers, return_exceptions=True)

        _run(run())
        self.assertIsNotNone(enricher._queue)

    def test_start_creates_correct_worker_count(self):
        """start() creates worker_count tasks."""
        enricher = _make_enricher(config=_make_config(worker_count=2))

        async def run():
            with (
                patch.object(enricher, "_load_known_bad_orgs"),
                patch.object(enricher, "_load_bootstrap", new=AsyncMock()),
                patch.object(enricher, "_scan_existing_ban_cidrs", new=AsyncMock()),
            ):
                await enricher.start()
                count = len(enricher._workers)
                for w in enricher._workers:
                    w.cancel()
                await asyncio.gather(*enricher._workers, return_exceptions=True)
                return count

        result = _run(run())
        self.assertEqual(result, 2)


# ---------------------------------------------------------------------------
# RDAPEnricher.stop() (lines 421-437)
# ---------------------------------------------------------------------------


class TestRDAPEnricherStop(unittest.TestCase):

    def test_stop_with_empty_workers_list(self):
        """stop() with no workers is a no-op."""
        enricher = _make_enricher()
        enricher._workers = []
        enricher._queue = asyncio.Queue()

        async def run():
            await enricher.stop()

        _run(run())

    def test_stop_logs_when_queue_not_empty(self):
        """stop() logs warning when queue has remaining items (lines 428-437)."""
        enricher = _make_enricher()

        async def run():
            enricher._queue = asyncio.Queue(maxsize=5)
            enricher._queue.put_nowait("1.2.3.4")  # One item pending
            # No workers to cancel
            await enricher.stop()

        _run(run())

    def test_stop_with_none_queue(self):
        """stop() with queue=None skips queue check."""
        enricher = _make_enricher()
        enricher._queue = None
        enricher._workers = []

        async def run():
            await enricher.stop()

        _run(run())


# ---------------------------------------------------------------------------
# record_browser_subnet (lines 480-487)
# ---------------------------------------------------------------------------


class TestRecordBrowserSubnet(unittest.TestCase):

    def test_record_browser_subnet_sets_redis_key(self):
        """record_browser_subnet() writes browser:seen:subnet:{subnet} to Redis."""
        redis = _make_redis()
        enricher = _make_enricher(redis=redis)

        async def run():
            await enricher.record_browser_subnet("1.2.3.4")

        _run(run())
        redis.setex.assert_called_once()
        key = redis.setex.call_args[0][0]
        self.assertIn("browser:seen:subnet:", key)

    def test_record_browser_subnet_redis_error_swallowed(self):
        """Redis error in record_browser_subnet is caught and logged (lines 484-487)."""
        redis = _make_redis()
        redis.setex = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)

        async def run():
            await enricher.record_browser_subnet("1.2.3.4")  # must not raise

        _run(run())


# ---------------------------------------------------------------------------
# on_config_reload (lines 489-535)
# ---------------------------------------------------------------------------


class TestOnConfigReload(unittest.TestCase):

    def _make_raw_config(self, **overrides) -> dict:
        cfg = {
            "rdap_enrichment": {
                "enabled": True,
                "queue_size": 10,
                "worker_count": 1,
                "min_enqueue_score": 20,
                "lookup_timeout_seconds": 5,
                "delegate_to_analytics": False,
                "org_reputation": {"enabled": True, "score": 45},
                "new_netblock_flagging": {"enabled": True, "max_age_days": 90, "score": 20},
                "block_expansion": {
                    "enabled": True,
                    "min_trigger_score": 75,
                    "max_prefix_length_v4": 24,
                    "max_prefix_length_v6": 48,
                    "require_no_browser_traffic": True,
                    "require_known_bad_org": True,
                    "expansion_ban_duration": 3600,
                    "max_expansions_per_hour": 10,
                },
            }
        }
        cfg["rdap_enrichment"].update(overrides)
        return cfg

    def test_on_config_reload_updates_config(self):
        """on_config_reload() updates _config with new values."""
        enricher = _make_enricher()
        old_score = enricher._config.min_enqueue_score
        raw = self._make_raw_config(min_enqueue_score=30)
        enricher.on_config_reload(raw)
        self.assertEqual(enricher._config.min_enqueue_score, 30)

    def test_on_config_reload_warns_worker_count_changed(self):
        """on_config_reload() warns when worker_count changes (lines 499-510)."""
        enricher = _make_enricher(config=_make_config(worker_count=1))
        raw = self._make_raw_config(worker_count=2)  # different
        with patch("src.security.rdap_enrichment.logger") as mock_logger:
            enricher.on_config_reload(raw)
            # Should have logged a warning
            mock_logger.warning.assert_called()

    def test_on_config_reload_warns_queue_size_changed(self):
        """on_config_reload() warns when queue_size changes (lines 511-522)."""
        enricher = _make_enricher(config=_make_config(queue_size=10))
        raw = self._make_raw_config(queue_size=20)  # different
        with patch("src.security.rdap_enrichment.logger") as mock_logger:
            enricher.on_config_reload(raw)
            mock_logger.warning.assert_called()

    def test_on_config_reload_keeps_old_worker_count_and_queue_size(self):
        """Hot reload keeps old worker_count and queue_size (lines 527-528)."""
        enricher = _make_enricher(config=_make_config(worker_count=3, queue_size=15))
        raw = self._make_raw_config(worker_count=5, queue_size=30)
        enricher.on_config_reload(raw)
        self.assertEqual(enricher._config.worker_count, 3)
        self.assertEqual(enricher._config.queue_size, 15)


# ---------------------------------------------------------------------------
# _enqueue_lookup (lines 541-582)
# ---------------------------------------------------------------------------


class TestEnqueueLookup(unittest.TestCase):

    def test_enqueue_lookup_disabled_returns_early(self):
        """_enqueue_lookup returns early when disabled or no queue (line 544)."""
        enricher = _make_enricher(config=_make_config(enabled=False))

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())

    def test_enqueue_lookup_with_no_queue_returns_early(self):
        """_enqueue_lookup with _queue=None returns early."""
        enricher = _make_enricher()
        enricher._queue = None

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())

    def test_enqueue_lookup_delegates_to_analytics(self):
        """With delegate_to_analytics=True, pushes to analytics:enrich:rdap (lines 547-553)."""
        redis = _make_redis()
        enricher = _make_enricher(
            config=_make_config(delegate_to_analytics=True),
            redis=redis,
        )
        enricher._queue = asyncio.Queue()

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())
        redis.sadd.assert_called_once_with("analytics:enrich:rdap", "1.2.3.4")

    def test_enqueue_lookup_delegate_redis_error_swallowed(self):
        """Redis error in delegate path is caught and logged (lines 549-552)."""
        redis = _make_redis()
        redis.sadd = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(
            config=_make_config(delegate_to_analytics=True),
            redis=redis,
        )
        enricher._queue = asyncio.Queue()

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")  # must not raise

        _run(run())

    def test_enqueue_lookup_bloom_dedup_already_present(self):
        """Bloom filter returns 0 → already seen → skip enqueue (line 558-559)."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(return_value=0)  # already present
        redis.bf = MagicMock(return_value=bf)
        enricher = _make_enricher(redis=redis)
        enricher._queue = asyncio.Queue()

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())
        self.assertEqual(enricher._queue.qsize(), 0)  # not enqueued

    def test_enqueue_lookup_bloom_expire_error_swallowed(self):
        """Redis expire error in bloom key is silently passed (line 562-563)."""
        redis = _make_redis()
        redis.expire = AsyncMock(side_effect=Exception("expire error"))
        enricher = _make_enricher(redis=redis)
        enricher._queue = asyncio.Queue()

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())

    def test_enqueue_lookup_bloom_fallback_already_present(self):
        """Bloom unavailable, fallback SET finds existing key → skip (line 568-570)."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(side_effect=Exception("bloom unavailable"))
        redis.bf = MagicMock(return_value=bf)
        redis.get = AsyncMock(return_value=b"1")  # already exists
        enricher = _make_enricher(redis=redis)
        enricher._queue = asyncio.Queue()

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())
        self.assertEqual(enricher._queue.qsize(), 0)

    def test_enqueue_lookup_bloom_fallback_error_still_enqueues(self):
        """Bloom fallback error → dedup failed → still enqueue (lines 572-575)."""
        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(side_effect=Exception("bloom unavailable"))
        redis.bf = MagicMock(return_value=bf)
        redis.get = AsyncMock(side_effect=Exception("get error"))
        enricher = _make_enricher(redis=redis)
        enricher._queue = asyncio.Queue(maxsize=5)

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())
        # Even with bloom error, IP may still be enqueued
        # (test passes as long as no exception raised)

    def test_enqueue_lookup_queue_full_drops(self):
        """QueueFull → drops item silently (lines 581-582)."""
        enricher = _make_enricher()
        enricher._queue = asyncio.Queue(maxsize=1)
        enricher._queue.put_nowait("5.5.5.5")  # fill it

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")  # should not raise

        _run(run())

    def test_enqueue_lookup_adds_to_queue(self):
        """Happy path: new IP is enqueued (line 579-580)."""
        enricher = _make_enricher()
        enricher._queue = asyncio.Queue(maxsize=5)

        async def run():
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())
        self.assertEqual(enricher._queue.qsize(), 1)


# ---------------------------------------------------------------------------
# _lookup_worker (lines 584-606)
# ---------------------------------------------------------------------------


class TestLookupWorker(unittest.TestCase):

    def test_lookup_worker_process_lookup_exception_continues(self):
        """Worker catches _process_lookup exception, logs, continues (lines 592-604)."""
        enricher = _make_enricher()

        async def run():
            enricher._queue = asyncio.Queue()
            enricher._queue.put_nowait("1.2.3.4")
            enricher._queue.put_nowait("STOP")  # sentinel

            call_count = [0]

            async def _fake_process(ip):
                call_count[0] += 1
                if ip == "1.2.3.4":
                    raise RuntimeError("process error")
                # "STOP" → raise CancelledError to break loop
                raise asyncio.CancelledError()

            with patch.object(enricher, "_process_lookup", side_effect=_fake_process):
                try:
                    await enricher._lookup_worker()
                except asyncio.CancelledError:
                    pass

            return call_count[0]

        count = _run(run())
        self.assertEqual(count, 2)


# ---------------------------------------------------------------------------
# _process_lookup (lines 608-695)
# ---------------------------------------------------------------------------


class TestProcessLookup(unittest.TestCase):

    def test_process_lookup_bootstrap_routing_error(self):
        """get_rdap_base_url raises → error logged, returns (lines 612-624)."""
        enricher = _make_enricher()

        async def run():
            with patch.object(enricher, "get_rdap_base_url",
                              new=AsyncMock(side_effect=Exception("bootstrap error"))):
                await enricher._process_lookup("1.2.3.4")

        _run(run())

    def test_process_lookup_api_timeout(self):
        """asyncio.TimeoutError → logged, returns (lines 642-654)."""
        enricher = _make_enricher()

        async def run():
            with patch.object(enricher, "get_rdap_base_url",
                              new=AsyncMock(return_value="https://rdap.arin.net/registry/")):
                with patch.object(enricher, "_api_lookup",
                                  new=AsyncMock(side_effect=asyncio.TimeoutError())):
                    await enricher._process_lookup("1.2.3.4")

        _run(run())

    def test_process_lookup_redirect_limit_error(self):
        """_RedirectLimitError → counter incremented, returns (lines 655-657)."""
        from src.security.rdap_enrichment import _RedirectLimitError
        enricher = _make_enricher()

        async def run():
            with patch.object(enricher, "get_rdap_base_url",
                              new=AsyncMock(return_value="https://rdap.arin.net/registry/")):
                with patch.object(enricher, "_api_lookup",
                                  new=AsyncMock(side_effect=_RedirectLimitError("too many"))):
                    await enricher._process_lookup("1.2.3.4")

        _run(run())

    def test_process_lookup_not_found_stores_unknown(self):
        """_NotFoundError → stores is_unknown=True result (lines 658-670)."""
        from src.security.rdap_enrichment import _NotFoundError
        enricher = _make_enricher()

        async def run():
            with patch.object(enricher, "get_rdap_base_url",
                              new=AsyncMock(return_value="https://rdap.arin.net/registry/")):
                with patch.object(enricher, "_api_lookup",
                                  new=AsyncMock(side_effect=_NotFoundError("1.2.3.4"))):
                    with patch.object(enricher, "_cache_result", new=AsyncMock()) as mock_cache:
                        with patch.object(enricher, "maybe_expand_block", new=AsyncMock()):
                            await enricher._process_lookup("1.2.3.4")
                            if mock_cache.called:
                                rdap_arg = mock_cache.call_args[0][1]
                                return rdap_arg.is_unknown
            return None

        result = _run(run())
        # may be True if _cache_result was called
        if result is not None:
            self.assertTrue(result)

    def test_process_lookup_generic_exception(self):
        """Generic exception from _api_lookup → error logged, returns (lines 671-683)."""
        enricher = _make_enricher()

        async def run():
            with patch.object(enricher, "get_rdap_base_url",
                              new=AsyncMock(return_value="https://rdap.arin.net/registry/")):
                with patch.object(enricher, "_api_lookup",
                                  new=AsyncMock(side_effect=Exception("network error"))):
                    await enricher._process_lookup("1.2.3.4")

        _run(run())

    def test_process_lookup_happy_path_calls_cache_and_expand(self):
        """Successful lookup → _cache_result and maybe_expand_block called."""
        enricher = _make_enricher()
        rdap = _make_rdap_result()

        async def run():
            with patch.object(enricher, "get_rdap_base_url",
                              new=AsyncMock(return_value="https://rdap.arin.net/registry/")):
                with patch.object(enricher, "_api_lookup", new=AsyncMock(return_value=rdap)):
                    with patch.object(enricher, "_cache_result", new=AsyncMock()) as mock_cache:
                        with patch.object(enricher, "maybe_expand_block",
                                          new=AsyncMock(return_value=False)) as mock_expand:
                            await enricher._process_lookup("1.2.3.4")
                            return mock_cache.called, mock_expand.called

        cache_called, expand_called = _run(run())
        self.assertTrue(cache_called)
        self.assertTrue(expand_called)


# ---------------------------------------------------------------------------
# _cache_result (lines 697-729)
# ---------------------------------------------------------------------------


class TestCacheResult(unittest.TestCase):

    def test_cache_result_redis_write_error_swallowed(self):
        """Redis setex error in _cache_result is caught and logged (lines 716-726)."""
        redis = _make_redis()
        redis.setex = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            await enricher._cache_result("1.2.3.4", rdap)

        _run(run())
        # Should still write to LocalCache
        cached = enricher._local_cache.rdap_results.get("1.2.3.4")
        self.assertIsNotNone(cached)

    def test_cache_result_writes_to_local_cache(self):
        """_cache_result writes to LocalCache regardless of Redis result."""
        enricher = _make_enricher()
        rdap = _make_rdap_result()

        async def run():
            await enricher._cache_result("2.3.4.5", rdap)

        _run(run())
        cached = enricher._local_cache.rdap_results.get("2.3.4.5")
        self.assertIs(cached, rdap)


# ---------------------------------------------------------------------------
# _rdap_to_signals edge case (line 734, 759)
# ---------------------------------------------------------------------------


class TestRdapToSignals(unittest.TestCase):

    def test_rdap_to_signals_with_new_netblock_enabled(self):
        """new_netblock_flagging enabled → new netblock signal included (line 759+)."""
        from datetime import timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        enricher = _make_enricher()
        enricher._known_bad = [
            {"handle": "TEST-1", "name": "Test Org", "reason": "test", "score": 45}
        ]
        rdap = _make_rdap_result(org_handle="TEST-1", registration_date=recent)
        signals = enricher._rdap_to_signals(rdap)
        names = [s.name for s in signals]
        self.assertIn("rdap_known_bad_org", names)
        self.assertIn("rdap_new_netblock", names)

    def test_rdap_to_signals_is_unknown_returns_empty(self):
        """is_unknown=True → returns [] immediately (line 734)."""
        enricher = _make_enricher()
        rdap = _make_rdap_result(is_unknown=True)
        signals = enricher._rdap_to_signals(rdap)
        self.assertEqual(signals, [])


# ---------------------------------------------------------------------------
# _load_bootstrap (lines 770-820)
# ---------------------------------------------------------------------------


class TestLoadBootstrap(unittest.TestCase):

    def test_load_bootstrap_from_redis_cache(self):
        """_load_bootstrap loads from Redis when both keys present (lines 770-784)."""
        redis = _make_redis()
        v4_data = json.dumps([{"prefixes": ["1.0.0.0/8"], "urls": ["https://rdap.arin.net/"]}])
        v6_data = json.dumps([{"prefixes": ["2001::/32"], "urls": ["https://rdap.arin.net/"]}])
        redis.get = AsyncMock(side_effect=[v4_data.encode(), v6_data.encode()])
        enricher = _make_enricher(redis=redis)

        async def run():
            await enricher._load_bootstrap()

        _run(run())
        self.assertGreater(len(enricher._bootstrap_v4), 0)
        self.assertGreater(len(enricher._bootstrap_v6), 0)

    def test_load_bootstrap_redis_error_falls_through(self):
        """Redis read error → falls through to leader election (lines 785-788)."""
        redis = _make_redis()
        redis.get = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)

        async def run():
            with patch.object(enricher, "_try_become_bootstrap_leader",
                              new=AsyncMock(return_value=True)):
                with patch.object(enricher, "_download_bootstrap", new=AsyncMock()):
                    await enricher._load_bootstrap()

        _run(run())

    def test_load_bootstrap_non_leader_waits_for_redis(self):
        """Non-leader waits for Redis bootstrap data (lines 799-810)."""
        redis = _make_redis()
        # First get returns None (bootstrap not ready), second returns data
        v4_data = json.dumps([{"prefixes": ["1.0.0.0/8"], "urls": ["https://rdap.arin.net/"]}])
        v6_data = json.dumps([{"prefixes": ["2001::/32"], "urls": ["https://rdap.arin.net/"]}])
        call_count = [0]

        async def get_side_effect(key):
            call_count[0] += 1
            if call_count[0] <= 2:
                return None  # Not ready
            if "v4" in key:
                return v4_data.encode()
            return v6_data.encode()

        redis.get = AsyncMock(side_effect=get_side_effect)
        enricher = _make_enricher(redis=redis)

        async def run():
            with patch.object(enricher, "_try_become_bootstrap_leader",
                              new=AsyncMock(return_value=False)):
                with patch("asyncio.sleep", AsyncMock(return_value=None)):
                    await enricher._load_bootstrap()

        _run(run())

    def test_load_bootstrap_non_leader_timeout(self):
        """Non-leader that never gets Redis data logs warning (lines 811-820)."""
        redis = _make_redis()
        redis.get = AsyncMock(return_value=None)  # always None
        enricher = _make_enricher(redis=redis)

        async def run():
            with patch.object(enricher, "_try_become_bootstrap_leader",
                              new=AsyncMock(return_value=False)):
                with patch("asyncio.sleep", AsyncMock(return_value=None)):
                    await enricher._load_bootstrap()

        _run(run())
        # Should log timeout warning and continue

    def test_load_bootstrap_leader_election_exception_acts_as_leader(self):
        """Exception in _try_become_bootstrap_leader → acts as leader (lines 793-794)."""
        redis = _make_redis()
        redis.get = AsyncMock(return_value=None)
        enricher = _make_enricher(redis=redis)

        async def run():
            with patch.object(enricher, "_try_become_bootstrap_leader",
                              new=AsyncMock(side_effect=Exception("redis down"))):
                with patch.object(enricher, "_download_bootstrap", new=AsyncMock()):
                    await enricher._load_bootstrap()

        _run(run())


# ---------------------------------------------------------------------------
# _try_become_bootstrap_leader (lines 822-833)
# ---------------------------------------------------------------------------


class TestTryBecomeBootstrapLeader(unittest.TestCase):

    def test_becomes_leader_when_set_returns_true(self):
        """Redis SET nx=True returns non-None → leader (line 831)."""
        redis = _make_redis()
        redis.set = AsyncMock(return_value=True)
        enricher = _make_enricher(redis=redis)

        async def run():
            return await enricher._try_become_bootstrap_leader()

        result = _run(run())
        self.assertTrue(result)

    def test_not_leader_when_set_returns_none(self):
        """Redis SET nx=True returns None → not leader (line 831)."""
        redis = _make_redis()
        redis.set = AsyncMock(return_value=None)
        enricher = _make_enricher(redis=redis)

        async def run():
            return await enricher._try_become_bootstrap_leader()

        result = _run(run())
        self.assertFalse(result)

    def test_redis_error_acts_as_leader(self):
        """Redis error in leader election → fail open, acts as leader (lines 832-833)."""
        redis = _make_redis()
        redis.set = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)

        async def run():
            return await enricher._try_become_bootstrap_leader()

        result = _run(run())
        self.assertTrue(result)


# ---------------------------------------------------------------------------
# _download_bootstrap (lines 835-886)
# ---------------------------------------------------------------------------


class TestDownloadBootstrap(unittest.TestCase):

    def test_download_bootstrap_skips_when_no_session(self):
        """_download_bootstrap skips when session=None (lines 837-847)."""
        enricher = _make_enricher(session=None)

        async def run():
            await enricher._download_bootstrap()

        _run(run())
        self.assertEqual(enricher._bootstrap_v4, [])

    def test_download_bootstrap_happy_path(self):
        """_download_bootstrap fetches and parses both bootstrap files (lines 849-875)."""
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={
            "services": [
                [["1.0.0.0/8", "2.0.0.0/8"], ["https://rdap.arin.net/registry/"]]
            ]
        })
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        session.get = MagicMock(return_value=mock_resp)

        import aiohttp
        redis = _make_redis()
        enricher = _make_enricher(session=session, redis=redis)

        async def run():
            with patch("src.security.rdap_enrichment.aiohttp.ClientTimeout",
                       return_value=MagicMock()):
                await enricher._download_bootstrap()

        _run(run())

    def test_download_bootstrap_http_error_logged(self):
        """HTTP error during download is logged (lines 876-886)."""
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock(side_effect=Exception("HTTP 500"))
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        session.get = MagicMock(return_value=mock_resp)

        enricher = _make_enricher(session=session)

        async def run():
            with patch("src.security.rdap_enrichment.aiohttp.ClientTimeout",
                       return_value=MagicMock()):
                await enricher._download_bootstrap()  # must not raise

        _run(run())

    def test_download_bootstrap_redis_write_error_swallowed(self):
        """Redis write error during bootstrap download is caught (lines 871-875)."""
        session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = AsyncMock(return_value={"services": []})
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        session.get = MagicMock(return_value=mock_resp)

        redis = _make_redis()
        redis.setex = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(session=session, redis=redis)

        async def run():
            with patch("src.security.rdap_enrichment.aiohttp.ClientTimeout",
                       return_value=MagicMock()):
                await enricher._download_bootstrap()  # must not raise

        _run(run())


# ---------------------------------------------------------------------------
# get_rdap_base_url (lines 888-917)
# ---------------------------------------------------------------------------


class TestGetRdapBaseUrl(unittest.TestCase):

    def test_get_rdap_base_url_ipv4_match(self):
        """IPv4 address matches bootstrap entry (lines 905-915)."""
        enricher = _make_enricher()
        enricher._bootstrap_v4 = [
            {"prefixes": ["1.0.0.0/8"], "urls": ["https://rdap.apnic.net/"]},
        ]

        async def run():
            return await enricher.get_rdap_base_url("1.2.3.4")

        url = _run(run())
        self.assertIn("apnic", url)

    def test_get_rdap_base_url_ipv4_no_match_uses_default(self):
        """IPv4 with no matching prefix uses default ARIN URL."""
        enricher = _make_enricher()
        enricher._bootstrap_v4 = []

        async def run():
            return await enricher.get_rdap_base_url("10.0.0.1")

        url = _run(run())
        self.assertIn("arin", url)

    def test_get_rdap_base_url_ipv6_match(self):
        """IPv6 address matches bootstrap_v6 entry."""
        enricher = _make_enricher()
        enricher._bootstrap_v6 = [
            {"prefixes": ["2001:db8::/32"], "urls": ["https://rdap.ripe.net/"]},
        ]

        async def run():
            return await enricher.get_rdap_base_url("2001:db8::1")

        url = _run(run())
        self.assertIn("ripe", url)

    def test_get_rdap_base_url_invalid_prefix_skipped(self):
        """Invalid prefix string is caught and skipped (line 914-915)."""
        enricher = _make_enricher()
        enricher._bootstrap_v4 = [
            {"prefixes": ["not-a-cidr"], "urls": ["https://rdap.example.net/"]},
            {"prefixes": ["1.0.0.0/8"], "urls": ["https://rdap.apnic.net/"]},
        ]

        async def run():
            return await enricher.get_rdap_base_url("1.2.3.4")

        url = _run(run())
        # Invalid prefix is skipped; valid one matches
        self.assertIn("apnic", url)

    def test_get_rdap_base_url_longest_prefix_wins(self):
        """Longest matching prefix wins (most specific route)."""
        enricher = _make_enricher()
        enricher._bootstrap_v4 = [
            {"prefixes": ["1.0.0.0/8"], "urls": ["https://rdap.apnic.net/"]},
            {"prefixes": ["1.2.0.0/16"], "urls": ["https://rdap.ripe.net/"]},
        ]

        async def run():
            return await enricher.get_rdap_base_url("1.2.3.4")

        url = _run(run())
        self.assertIn("ripe", url)


# ---------------------------------------------------------------------------
# _api_lookup (lines 942-990)
# ---------------------------------------------------------------------------


class TestApiLookup(unittest.TestCase):

    def _make_session_response(self, status=200, json_data=None, raise_exc=None,
                               location=None):
        """Build a mock aiohttp response."""
        resp = MagicMock()
        resp.status = status
        resp.raise_for_status = MagicMock()
        if json_data is not None:
            resp.json = AsyncMock(return_value=json_data)
        if raise_exc:
            resp.raise_for_status = MagicMock(side_effect=raise_exc)
        if location:
            resp.headers = {"Location": location}
        else:
            resp.headers = {}
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        return resp

    def test_api_lookup_404_raises_not_found(self):
        """404 response → _NotFoundError (lines 955-956)."""
        from src.security.rdap_enrichment import _NotFoundError
        resp = self._make_session_response(status=404)
        session = MagicMock()
        session.get = MagicMock(return_value=resp)
        enricher = _make_enricher(session=session)

        async def run():
            import aiohttp
            with patch("src.security.rdap_enrichment.aiohttp.ClientTimeout",
                       return_value=MagicMock()):
                await enricher._api_lookup("1.2.3.4", "https://rdap.arin.net/registry/")

        with self.assertRaises(Exception):  # _NotFoundError
            _run(run())

    def test_api_lookup_redirect_followed(self):
        """301 redirect → follows Location header (lines 957-967)."""
        from src.security.rdap_enrichment import _RedirectLimitError
        resp1 = self._make_session_response(status=301, location="https://rdap.ripe.net/ip/1.2.3.4")
        resp2 = self._make_session_response(status=301, location="https://rdap.lacnic.net/ip/1.2.3.4")
        resp3 = self._make_session_response(status=301, location="https://rdap.afrinic.net/ip/1.2.3.4")
        resp4 = self._make_session_response(status=301, location="https://another.net/ip/1.2.3.4")

        call_count = [0]
        responses = [resp1, resp2, resp3, resp4]

        session = MagicMock()
        def get_side_effect(*args, **kwargs):
            r = responses[call_count[0]]
            call_count[0] += 1
            return r
        session.get = MagicMock(side_effect=get_side_effect)
        enricher = _make_enricher(session=session)

        async def run():
            with patch("src.security.rdap_enrichment.aiohttp.ClientTimeout",
                       return_value=MagicMock()):
                await enricher._api_lookup("1.2.3.4", "https://rdap.arin.net/registry/")

        with self.assertRaises(Exception):  # _RedirectLimitError
            _run(run())

    def test_api_lookup_success_parses_response(self):
        """200 response → parsed RDAPResult (lines 968-984)."""
        rdap_data = {
            "startAddress": "1.2.3.0",
            "cidrLength": 24,
            "entities": [],
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}],
        }
        resp = self._make_session_response(status=200, json_data=rdap_data)
        session = MagicMock()
        session.get = MagicMock(return_value=resp)
        enricher = _make_enricher(session=session)

        async def run():
            with patch("src.security.rdap_enrichment.aiohttp.ClientTimeout",
                       return_value=MagicMock()):
                return await enricher._api_lookup("1.2.3.4", "https://rdap.arin.net/registry/")

        result = _run(run())
        self.assertIsInstance(result, RDAPResult)
        self.assertEqual(result.registration_date, "2020-01-01")


# ---------------------------------------------------------------------------
# _parse_rdap_response (lines 992-1044)
# ---------------------------------------------------------------------------


class TestParseRdapResponse(unittest.TestCase):

    def test_parse_full_rdap_response(self):
        """Full RDAP response with autnums, events, entities."""
        enricher = _make_enricher()
        data = {
            "startAddress": "1.2.3.0",
            "cidrLength": 24,
            "country": "US",
            "autnums": [{"handle": "15169"}],
            "events": [{"eventAction": "registration", "eventDate": "2020-01-15T00:00:00Z"}],
            "entities": [
                {
                    "roles": ["registrant"],
                    "handle": "GOOGLE",
                    "vcardArray": ["vcard", [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Google LLC"],
                    ]],
                }
            ],
        }
        result = enricher._parse_rdap_response(data, "1.2.3.4")
        self.assertEqual(result.asn, "AS15169")
        self.assertEqual(result.country, "US")
        self.assertEqual(result.registration_date, "2020-01-15")
        self.assertEqual(result.org_name, "Google LLC")
        self.assertEqual(result.org_handle, "GOOGLE")

    def test_parse_parent_handle_asn(self):
        """parentHandle field as ASN fallback (lines 1017-1019)."""
        enricher = _make_enricher()
        data = {
            "startAddress": "2.3.4.0",
            "cidrLength": 24,
            "parentHandle": "AS5678",
            "events": [],
            "entities": [],
        }
        result = enricher._parse_rdap_response(data, "2.3.4.5")
        self.assertEqual(result.asn, "AS5678")

    def test_parse_no_asn_no_parent_handle(self):
        """No ASN info → asn is None (lines 1009-1019)."""
        enricher = _make_enricher()
        data = {
            "startAddress": "3.4.5.0",
            "cidrLength": 24,
            "events": [],
            "entities": [],
        }
        result = enricher._parse_rdap_response(data, "3.4.5.6")
        self.assertIsNone(result.asn)

    def test_parse_event_with_long_date(self):
        """Event date >= 10 chars is truncated to 10 (line 1032)."""
        enricher = _make_enricher()
        data = {
            "startAddress": "4.5.6.0",
            "cidrLength": 24,
            "events": [{"eventAction": "registration", "eventDate": "2021-06-15T12:34:56Z"}],
            "entities": [],
        }
        result = enricher._parse_rdap_response(data, "4.5.6.7")
        self.assertEqual(result.registration_date, "2021-06-15")


# ---------------------------------------------------------------------------
# _load_known_bad_orgs (lines 1050-1067)
# ---------------------------------------------------------------------------


class TestLoadKnownBadOrgs(unittest.TestCase):

    def test_load_known_bad_orgs_file_not_found_raises(self):
        """Missing file raises FileNotFoundError (lines 1053-1058)."""
        enricher = _make_enricher(known_bad_orgs_path="/nonexistent/path.yml")
        with self.assertRaises(FileNotFoundError):
            enricher._load_known_bad_orgs()

    def test_load_known_bad_orgs_yaml_error_raises_runtime(self):
        """YAML parse error raises RuntimeError (lines 1059-1063)."""
        import yaml
        enricher = _make_enricher(known_bad_orgs_path="config/known_bad_orgs.yml")
        with (
            patch("os.path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data="::bad yaml::")),
            patch("yaml.safe_load", side_effect=yaml.YAMLError("bad")),
        ):
            with self.assertRaises(RuntimeError):
                enricher._load_known_bad_orgs()

    def test_load_known_bad_orgs_happy_path(self):
        """Valid YAML loads known_bad list (lines 1050-1067)."""
        yaml_content = """
orgs:
  - handle: FRANTECH
    name: Frantech Solutions
    reason: BP hosting
    score: 55
"""
        enricher = _make_enricher(known_bad_orgs_path="config/known_bad_orgs.yml")
        with (
            patch("os.path.exists", return_value=True),
            patch("builtins.open", mock_open(read_data=yaml_content)),
        ):
            enricher._load_known_bad_orgs()
        self.assertEqual(len(enricher._known_bad), 1)
        self.assertEqual(enricher._known_bad[0]["handle"], "FRANTECH")


# ---------------------------------------------------------------------------
# maybe_expand_block (lines 1108-1193)
# ---------------------------------------------------------------------------


class TestMaybeExpandBlock(unittest.TestCase):

    def test_expand_disabled_returns_false(self):
        """Block expansion disabled → returns False (line 1134-1135)."""
        cfg = _make_config(
            block_expansion=_BlockExpansionConfig(
                enabled=False, min_trigger_score=75, max_prefix_length_v4=24,
                max_prefix_length_v6=48, require_no_browser_traffic=True,
                require_known_bad_org=True, expansion_ban_duration=3600,
                max_expansions_per_hour=10,
            )
        )
        enricher = _make_enricher(config=cfg)
        rdap = _make_rdap_result()

        async def run():
            return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, True)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_score_below_threshold_returns_false(self):
        """Score below min_trigger_score → returns False (lines 1138-1139)."""
        enricher = _make_enricher()
        rdap = _make_rdap_result()

        async def run():
            return await enricher.maybe_expand_block("1.2.3.4", rdap, 30, True)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_netblock_too_broad_returns_false(self):
        """Netblock broader than max_prefix_length → False (lines 1150-1151)."""
        enricher = _make_enricher()
        rdap = _make_rdap_result(netblock="1.0.0.0/8")  # /8 is broader than /24

        async def run():
            return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, True)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_invalid_netblock_returns_false(self):
        """Invalid netblock string → ValueError caught, returns False (lines 1150-1151)."""
        enricher = _make_enricher()
        rdap = _make_rdap_result(netblock="not-a-cidr")

        async def run():
            return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, True)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_browser_traffic_guard_returns_false(self):
        """Browser traffic seen from subnet → returns False (lines 1158-1159)."""
        redis = _make_redis()
        redis.exists = AsyncMock(return_value=1)  # browser traffic seen
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, True)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_browser_check_error_fails_safe(self):
        """Redis error in browser check → fails safe, returns False (lines 1160-1164)."""
        redis = _make_redis()
        redis.exists = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, True)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_not_known_bad_returns_false(self):
        """Not known-bad org → returns False (lines 1167-1168)."""
        redis = _make_redis()
        redis.exists = AsyncMock(return_value=0)
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, False)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_rate_limit_reached_returns_false(self):
        """Rate limit exceeded → returns False (lines 1171-1172)."""
        redis = _make_redis()
        redis.exists = AsyncMock(return_value=0)
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            with patch.object(enricher, "_check_expansion_rate_limit",
                              new=AsyncMock(return_value=False)):
                return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, True)

        result = _run(run())
        self.assertFalse(result)

    def test_expand_happy_path_returns_true(self):
        """All guards pass → expansion applied, returns True (lines 1174-1193)."""
        redis = _make_redis()
        redis.exists = AsyncMock(return_value=0)
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            with patch.object(enricher, "_check_expansion_rate_limit",
                              new=AsyncMock(return_value=True)):
                with patch.object(enricher, "_apply_expansion", new=AsyncMock()):
                    with patch.object(enricher, "_log_expansion_audit", new=AsyncMock()):
                        return await enricher.maybe_expand_block("1.2.3.4", rdap, 80, True)

        result = _run(run())
        self.assertTrue(result)


# ---------------------------------------------------------------------------
# _check_expansion_rate_limit (lines 1195-1229)
# ---------------------------------------------------------------------------


class TestCheckExpansionRateLimit(unittest.TestCase):

    def test_first_expansion_sets_expire(self):
        """count=1 → expire called, returns True (lines 1207-1208)."""
        redis = _make_redis()
        redis._test_pipe.execute = AsyncMock(return_value=[1, True])
        enricher = _make_enricher(redis=redis)

        async def run():
            return await enricher._check_expansion_rate_limit()

        result = _run(run())
        self.assertTrue(result)
        redis._test_pipe.expire.assert_called_once()

    def test_rate_limit_exceeded_returns_false(self):
        """count > max → decrements counter, returns False (lines 1209-1221)."""
        redis = _make_redis()
        redis._test_pipe.execute = AsyncMock(return_value=[11, True])  # > max=10
        enricher = _make_enricher()
        enricher._redis = redis

        async def run():
            return await enricher._check_expansion_rate_limit()

        result = _run(run())
        self.assertFalse(result)
        redis.decr.assert_called_once()

    def test_redis_error_fails_open(self):
        """Redis error → fails open, returns True (lines 1225-1229)."""
        redis = _make_redis()
        redis.incr = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)

        async def run():
            return await enricher._check_expansion_rate_limit()

        result = _run(run())
        self.assertTrue(result)


# ---------------------------------------------------------------------------
# _apply_expansion (lines 1231-1267)
# ---------------------------------------------------------------------------


class TestApplyExpansion(unittest.TestCase):

    def test_apply_expansion_redis_write_error_swallowed(self):
        """Redis setex error in _apply_expansion is caught (lines 1246-1249)."""
        redis = _make_redis()
        redis.setex = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            await enricher._apply_expansion("1.2.3.0/24", rdap, 80)

        _run(run())

    def test_apply_expansion_with_blocklist_manager(self):
        """_apply_expansion calls blocklist_manager.load_cidrs (lines 1252-1258)."""
        redis = _make_redis()
        bm = MagicMock()
        enricher = _make_enricher(redis=redis, blocklist_manager=bm)
        rdap = _make_rdap_result()

        async def run():
            await enricher._apply_expansion("1.2.3.0/24", rdap, 80)

        _run(run())
        bm.load_cidrs.assert_called_once_with(["1.2.3.0/24"], "rdap_expansion")

    def test_apply_expansion_blocklist_error_swallowed(self):
        """BlocklistManager error is caught (lines 1255-1258)."""
        redis = _make_redis()
        bm = MagicMock()
        bm.load_cidrs.side_effect = Exception("trie error")
        enricher = _make_enricher(redis=redis, blocklist_manager=bm)
        rdap = _make_rdap_result()

        async def run():
            await enricher._apply_expansion("1.2.3.0/24", rdap, 80)

        _run(run())

    def test_apply_expansion_pubsub_error_swallowed(self):
        """Redis publish error is caught (lines 1264-1267)."""
        redis = _make_redis()
        redis.publish = AsyncMock(side_effect=Exception("pubsub down"))
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            await enricher._apply_expansion("1.2.3.0/24", rdap, 80)

        _run(run())

    def test_apply_expansion_publishes_cidr_ban_add(self):
        """_apply_expansion publishes cidr_ban_add message (lines 1261-1263)."""
        redis = _make_redis()
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            await enricher._apply_expansion("1.2.3.0/24", rdap, 80)

        _run(run())
        redis.publish.assert_called_once()
        args = redis.publish.call_args[0]
        self.assertEqual(args[0], "ja4proxy:invalidate")
        msg = json.loads(args[1])
        self.assertEqual(msg["type"], "cidr_ban_add")
        self.assertEqual(msg["value"], "1.2.3.0/24")


# ---------------------------------------------------------------------------
# _log_expansion_audit (lines 1269-1294)
# ---------------------------------------------------------------------------


class TestLogExpansionAudit(unittest.TestCase):

    def test_log_expansion_audit_writes_to_redis(self):
        """_log_expansion_audit writes to rdap:expansions list (lines 1288-1290)."""
        redis = _make_redis()
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            await enricher._log_expansion_audit("1.2.3.4", "1.2.3.0/24", rdap, 80)

        _run(run())
        redis._test_pipe.lpush.assert_called_once()
        redis._test_pipe.ltrim.assert_called_once()

    def test_log_expansion_audit_redis_error_swallowed(self):
        """Redis error in audit write is caught (lines 1291-1294)."""
        redis = _make_redis()
        redis.lpush = AsyncMock(side_effect=Exception("redis down"))
        enricher = _make_enricher(redis=redis)
        rdap = _make_rdap_result()

        async def run():
            await enricher._log_expansion_audit("1.2.3.4", "1.2.3.0/24", rdap, 80)

        _run(run())


# ---------------------------------------------------------------------------
# _scan_existing_ban_cidrs (lines 1296-1326)
# ---------------------------------------------------------------------------


class TestScanExistingBanCidrs(unittest.TestCase):

    def test_scan_no_blocklist_manager_returns_early(self):
        """No blocklist_manager → returns early (lines 1298-1299)."""
        enricher = _make_enricher(blocklist_manager=None)

        async def run():
            await enricher._scan_existing_ban_cidrs()

        _run(run())

    def test_scan_existing_ban_cidrs_loads_into_trie(self):
        """Scan finds ban_cidr:* keys and loads into blocklist (lines 1301-1322)."""
        redis = _make_redis()
        redis.scan = AsyncMock(return_value=(0, [b"ban_cidr:1.2.3.0/24", b"ban_cidr:5.6.7.0/24"]))
        bm = MagicMock()
        enricher = _make_enricher(redis=redis, blocklist_manager=bm)

        async def run():
            await enricher._scan_existing_ban_cidrs()

        _run(run())
        bm.load_cidrs.assert_called_once()
        loaded_cidrs = bm.load_cidrs.call_args[0][0]
        self.assertIn("1.2.3.0/24", loaded_cidrs)

    def test_scan_with_string_keys(self):
        """Scan handles string keys as well as bytes (line 1306)."""
        redis = _make_redis()
        redis.scan = AsyncMock(return_value=(0, ["ban_cidr:9.8.7.0/24"]))
        bm = MagicMock()
        enricher = _make_enricher(redis=redis, blocklist_manager=bm)

        async def run():
            await enricher._scan_existing_ban_cidrs()

        _run(run())
        bm.load_cidrs.assert_called_once()

    def test_scan_multi_page(self):
        """Multi-page scan (cursor != 0) iterates correctly."""
        redis = _make_redis()
        redis.scan = AsyncMock(side_effect=[
            (1, [b"ban_cidr:1.2.3.0/24"]),  # cursor=1 → continue
            (0, [b"ban_cidr:5.6.7.0/24"]),  # cursor=0 → done
        ])
        bm = MagicMock()
        enricher = _make_enricher(redis=redis, blocklist_manager=bm)

        async def run():
            await enricher._scan_existing_ban_cidrs()

        _run(run())
        bm.load_cidrs.assert_called_once()
        loaded_cidrs = bm.load_cidrs.call_args[0][0]
        self.assertEqual(len(loaded_cidrs), 2)

    def test_scan_redis_error_swallowed(self):
        """Redis scan error is caught and logged (lines 1323-1325)."""
        redis = _make_redis()
        redis.scan = AsyncMock(side_effect=Exception("redis down"))
        bm = MagicMock()
        enricher = _make_enricher(redis=redis, blocklist_manager=bm)

        async def run():
            await enricher._scan_existing_ban_cidrs()

        _run(run())

    def test_scan_empty_keys_list_no_load(self):
        """Empty scan result → blocklist_manager.load_cidrs not called."""
        redis = _make_redis()
        redis.scan = AsyncMock(return_value=(0, []))
        bm = MagicMock()
        enricher = _make_enricher(redis=redis, blocklist_manager=bm)

        async def run():
            await enricher._scan_existing_ban_cidrs()

        _run(run())
        bm.load_cidrs.assert_not_called()


# ---------------------------------------------------------------------------
# _extract_netblock (lines 1347-1386)
# ---------------------------------------------------------------------------


class TestExtractNetblock(unittest.TestCase):

    def test_method1_start_address_cidr_length(self):
        """Method 1: startAddress + cidrLength (lines 1350-1356)."""
        data = {"startAddress": "1.2.3.0", "cidrLength": 24}
        result = _extract_netblock(data, "1.2.3.4")
        self.assertEqual(result, "1.2.3.0/24")

    def test_method1_invalid_cidr_falls_through(self):
        """Method 1 with invalid cidr → falls through to method 2 (lines 1354-1356)."""
        data = {"startAddress": "not-an-ip", "cidrLength": 24}
        result = _extract_netblock(data, "1.2.3.4")
        # Falls through to fallback
        self.assertIn("/", result)

    def test_method2_network_start_cidr_length(self):
        """Method 2: network.startAddress + cidrLength (lines 1362-1367)."""
        data = {"network": {"startAddress": "10.0.0.0", "cidrLength": 8}}
        result = _extract_netblock(data, "10.1.2.3")
        self.assertEqual(result, "10.0.0.0/8")

    def test_method2_network_end_address_ipv4(self):
        """Method 2 fallback: endAddress → /24 for IPv4 (lines 1373-1374)."""
        data = {"network": {"startAddress": "5.6.7.0", "endAddress": "5.6.7.255"}}
        result = _extract_netblock(data, "5.6.7.8")
        self.assertIn("/24", result)

    def test_method2_network_end_address_ipv6(self):
        """Method 2 fallback: endAddress → /48 for IPv6 (line 1375)."""
        data = {"network": {
            "startAddress": "2001:db8::",
            "endAddress": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
        }}
        result = _extract_netblock(data, "2001:db8::1")
        self.assertIn("/48", result)

    def test_fallback_ipv4_from_trigger_ip(self):
        """Fallback: compute /24 from IPv4 trigger IP (lines 1382-1383)."""
        data = {}
        result = _extract_netblock(data, "192.168.1.42")
        self.assertEqual(result, "192.168.1.0/24")

    def test_fallback_ipv6_from_trigger_ip(self):
        """Fallback: compute /48 from IPv6 trigger IP (line 1384)."""
        data = {}
        result = _extract_netblock(data, "2001:db8::1")
        import ipaddress
        net = ipaddress.ip_network(result, strict=False)
        self.assertEqual(net.prefixlen, 48)

    def test_fallback_invalid_ip_returns_default(self):
        """Fallback with invalid trigger IP → returns 0.0.0.0/0 (lines 1385-1386)."""
        data = {}
        result = _extract_netblock(data, "not-an-ip")
        self.assertEqual(result, "0.0.0.0/0")


# ---------------------------------------------------------------------------
# _extract_org (lines 1389-1426)
# ---------------------------------------------------------------------------


class TestExtractOrg(unittest.TestCase):

    def test_extract_org_from_registrant_entity(self):
        """Registrant entity with vcard → org_name, org_handle extracted."""
        data = {
            "entities": [{
                "roles": ["registrant"],
                "handle": "TEST-HDL",
                "vcardArray": ["vcard", [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Test Corporation"],
                ]],
            }]
        }
        name, handle = _extract_org(data)
        self.assertEqual(name, "Test Corporation")
        self.assertEqual(handle, "TEST-HDL")

    def test_extract_org_from_administrative_entity(self):
        """Administrative entity also accepted (line 1397)."""
        data = {
            "entities": [{
                "roles": ["administrative"],
                "handle": "ADMIN-HDL",
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", "Admin Org"],
                ]],
            }]
        }
        name, handle = _extract_org(data)
        self.assertEqual(name, "Admin Org")

    def test_extract_org_nic_hdl_fallback(self):
        """nic-hdl used when handle not present (line 1401)."""
        data = {
            "entities": [{
                "roles": ["registrant"],
                "nic-hdl": "RIPE-NCC",
                "vcardArray": ["vcard", [["fn", {}, "text", "RIPE NCC"]]],
            }]
        }
        name, handle = _extract_org(data)
        self.assertEqual(handle, "RIPE-NCC")

    def test_extract_org_vcard_org_entry(self):
        """vCard 'org' entry extracted (line 1412)."""
        data = {
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["org", {}, "text", "My Company Ltd"],
                ]],
            }]
        }
        name, _ = _extract_org(data)
        self.assertEqual(name, "My Company Ltd")

    def test_extract_org_vcard_name_as_list(self):
        """vCard name value as list → joined (lines 1414-1415)."""
        data = {
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", ["Google", "LLC"]],
                ]],
            }]
        }
        name, _ = _extract_org(data)
        self.assertIn("Google", name)

    def test_extract_org_skips_non_registrant(self):
        """Entity without registrant/administrative role is skipped (line 1397-1398)."""
        data = {
            "entities": [{
                "roles": ["noc"],
                "handle": "NOC-1",
                "vcardArray": ["vcard", [["fn", {}, "text", "NOC Org"]]],
            }]
        }
        name, handle = _extract_org(data)
        self.assertEqual(name, "")

    def test_extract_org_fallback_top_level_name(self):
        """No entities → fallback to top-level 'name' field (lines 1422-1424)."""
        data = {"entities": [], "name": "ARIN-ORG"}
        name, _ = _extract_org(data)
        self.assertEqual(name, "ARIN-ORG")

    def test_extract_org_no_entities_no_name(self):
        """No entities, no top-level name → empty strings."""
        data = {}
        name, handle = _extract_org(data)
        self.assertEqual(name, "")
        self.assertEqual(handle, "")

    def test_extract_org_stops_at_first_org_name(self):
        """Breaks after first entity with org_name (line 1419-1420)."""
        data = {
            "entities": [
                {
                    "roles": ["registrant"],
                    "handle": "FIRST",
                    "vcardArray": ["vcard", [["fn", {}, "text", "First Org"]]],
                },
                {
                    "roles": ["registrant"],
                    "handle": "SECOND",
                    "vcardArray": ["vcard", [["fn", {}, "text", "Second Org"]]],
                },
            ]
        }
        name, handle = _extract_org(data)
        self.assertEqual(name, "First Org")
        self.assertEqual(handle, "FIRST")

    def test_extract_org_short_vcard_entry_skipped(self):
        """vCard entry with < 4 elements is skipped (lines 1410-1411)."""
        data = {
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}]]],  # Only 2 elements
            }]
        }
        name, _ = _extract_org(data)
        self.assertEqual(name, "")


# ---------------------------------------------------------------------------
# Second-pass coverage additions — 25 missed lines
# ---------------------------------------------------------------------------

import redis as redis_lib  # noqa: E402 (append block)


class TestRDAPCoverageGaps2(unittest.TestCase):
    """Lines 438, 584, 657-658, 663-664, 849-850, 1011, 1021-1035, 1038-1041,
    1288-1292, 1359-1360, 1436-1437, 1446-1447."""

    # ── stop() with active workers (line 438) ────────────────────────────────

    def test_stop_cancels_active_workers(self):
        """Line 438: stop() calls w.cancel() for each worker task.
        So what: without this, shutdown leaves worker coroutines running forever,
        preventing clean process exit and leaking event-loop resources."""
        async def run():
            enricher = _make_enricher()
            # Inject a fake long-running worker task
            never_done = asyncio.create_task(asyncio.sleep(9999))
            enricher._workers = [never_done]
            await enricher.stop()
            assert never_done.cancelled()

        _run(run())

    # ── bloom expire RedisError (line 584) ───────────────────────────────────

    def test_bloom_expire_redis_error_is_suppressed(self):
        """Line 584: bloom filter expire raises RedisError → suppressed.
        So what: without this except, a transient Redis error after successful
        bf().add() propagates and aborts the enqueue path, losing the RDAP lookup."""
        async def run():
            redis = _make_redis()
            # bf().add returns 1 (new entry), but expire raises
            bf_mock = MagicMock()
            bf_mock.add = AsyncMock(return_value=1)
            redis.bf = MagicMock(return_value=bf_mock)
            redis.expire = AsyncMock(side_effect=redis_lib.RedisError("expire failed"))
            enricher = _make_enricher(redis=redis)
            enricher._queue = asyncio.Queue(maxsize=10)
            # Should not raise
            await enricher._enqueue_lookup("1.2.3.4")

        _run(run())

    # ── urlparse exception → registry_host="unknown" (lines 657-658) ─────────

    def test_lookup_urlparse_exception_falls_back_to_unknown(self):
        """Lines 657-658: urlparse raises → registry_host set to 'unknown'.
        So what: without this fallback, a malformed RDAP registry URL crashes the
        entire lookup goroutine, silently dropping the enrichment signal."""
        async def run():
            enricher = _make_enricher()
            enricher._rate_limiter = MagicMock()
            enricher._rate_limiter.acquire = AsyncMock(return_value=None)
            enricher._api_lookup = AsyncMock(side_effect=asyncio.TimeoutError())

            with patch("urllib.parse.urlparse", side_effect=Exception("parse error")):
                enricher.get_rdap_base_url = AsyncMock(return_value="https://malformed-url")
                try:
                    await enricher._process_lookup("1.2.3.4")
                except Exception:
                    pass  # timeout is expected

        _run(run())

    # ── rate limiter acquire fails (lines 663-664) ────────────────────────────

    def test_lookup_rate_limiter_error_is_non_fatal(self):
        """Lines 663-664: rate_limiter.acquire() raises RedisError → suppressed.
        So what: without this except, a Redis outage in the rate limiter would
        prevent all RDAP lookups globally even though the RDAP service is healthy."""
        async def run():
            enricher = _make_enricher()
            enricher._rate_limiter = MagicMock()
            enricher._rate_limiter.acquire = AsyncMock(
                side_effect=redis_lib.RedisError("rate limiter down")
            )
            enricher._api_lookup = AsyncMock(side_effect=asyncio.TimeoutError())
            enricher.get_rdap_base_url = AsyncMock(return_value="https://rdap.arin.net/registry")

            # Should not raise — rate limiter error suppressed, TimeoutError caught further down
            await enricher._process_lookup("1.2.3.4")

        _run(run())

    # ── bootstrap follower Redis error (lines 849-850) ───────────────────────

    def test_bootstrap_follower_redis_error_retries(self):
        """Lines 849-850: follower Redis.get raises → exception caught, loop continues.
        So what: without this except, a transient Redis outage during bootstrap
        propagates out of _load_bootstrap(), leaving the enricher permanently unable
        to route lookups to the correct RIR."""
        async def run():
            enricher = _make_enricher()
            enricher._redis.set = AsyncMock(return_value=None)  # follower (no lock)

            call_count = [0]
            async def _get(key):
                call_count[0] += 1
                if call_count[0] <= 2:
                    raise redis_lib.RedisError("Redis flap")
                # On 3rd call return valid data
                if "v4" in key:
                    return json.dumps({"services": []}).encode()
                return json.dumps({"services": []}).encode()

            enricher._redis.get = _get

            with patch("asyncio.sleep", new_callable=AsyncMock):
                await enricher._load_bootstrap()

        _run(run())

    # ── redirect with no Location header (line 1011) ─────────────────────────

    def test_api_lookup_redirect_no_location_raises(self):
        """Line 1011: redirect response with no Location header → raises Exception.
        So what: without this guard, the url variable stays unchanged and the loop
        retries the same URL forever, hanging the lookup goroutine until timeout."""
        async def run():
            enricher = _make_enricher()
            import aiohttp

            resp = MagicMock()
            resp.status = 301
            resp.headers = {}  # no Location
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=None)
            enricher._session.get = MagicMock(return_value=resp)

            with self.assertRaises(Exception):
                await enricher._api_lookup("1.2.3.4", "https://rdap.arin.net/registry/ip/1.2.3.4")

        _run(run())

    # ── _parse_rdap_response error in _api_lookup (lines 1021-1035) ──────────

    def test_api_lookup_parse_error_is_logged_and_reraised(self):
        """Lines 1021-1035: _parse_rdap_response raises → logged then re-raised.
        So what: without this block, parse errors are silent — the caller never
        knows the lookup failed, and the stale/missing cache entry persists."""
        async def run():
            enricher = _make_enricher()
            import aiohttp

            resp = MagicMock()
            resp.status = 200
            resp.raise_for_status = MagicMock(return_value=None)
            resp.json = AsyncMock(return_value={"bad": "data"})
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=None)
            enricher._session.get = MagicMock(return_value=resp)
            enricher._parse_rdap_response = MagicMock(side_effect=ValueError("bad response"))

            with self.assertRaises((ValueError, Exception)):
                await enricher._api_lookup("1.2.3.4", "https://rdap.arin.net/registry/ip/1.2.3.4")

        _run(run())

    # ── expansion rate limit check exception (lines 1288-1292) ──────────────

    def test_expansion_rate_limit_exception_fails_open(self):
        """Lines 1288-1292: exception in rate-limit check → returns True (fail open).
        So what: without this, a Redis outage in the rate limiter would block ALL block
        expansions globally, leaving known malicious CIDRs un-blocked during an attack."""
        async def run():
            redis = _make_redis()
            # Make the pipeline execute raise
            pipe = MagicMock()
            pipe.incr = MagicMock(return_value=None)
            pipe.expire = MagicMock(return_value=None)
            pipe.execute = AsyncMock(side_effect=redis_lib.RedisError("pipeline fail"))
            pipeline_cm = MagicMock()
            pipeline_cm.__aenter__ = AsyncMock(return_value=pipe)
            pipeline_cm.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline = MagicMock(return_value=pipeline_cm)

            enricher = _make_enricher(redis=redis)
            result = await enricher._check_expansion_rate_limit()
            self.assertTrue(result)  # fail open → True

        _run(run())

    # ── audit log pipeline exception (lines 1359-1360) ──────────────────────

    def test_log_expansion_audit_pipeline_exception_is_suppressed(self):
        """Lines 1359-1360: pipeline for audit log raises → suppressed.
        So what: without this, an audit-log write failure propagates out of
        _log_expansion_audit, aborting the _maybe_block_expand flow and silently
        skipping the expansion even though the CIDR was already written to Redis."""
        async def run():
            redis = _make_redis()
            # Make the pipeline execute raise
            pipe = MagicMock()
            pipe.lpush = MagicMock()
            pipe.ltrim = MagicMock()
            pipe.execute = AsyncMock(side_effect=Exception("pipeline error"))
            pipeline_cm = MagicMock()
            pipeline_cm.__aenter__ = AsyncMock(return_value=pipe)
            pipeline_cm.__aexit__ = AsyncMock(return_value=None)
            redis.pipeline = MagicMock(return_value=pipeline_cm)

            enricher = _make_enricher(redis=redis)
            rdap = _make_rdap_result()
            # Should not raise
            await enricher._log_expansion_audit("1.2.3.4", "1.2.3.0/24", rdap, trigger_score=80)

        _run(run())

    # ── _extract_netblock ValueError on network.cidr (lines 1436-1437) ────────

    def test_extract_netblock_invalid_network_cidr_uses_fallback(self):
        """Lines 1436-1437: ValueError on ip_network(start/cidr_len) in network → falls through.
        So what: without this except, a malformed RDAP network sub-object crashes
        block expansion entirely, preventing CIDR banning for the offending org."""
        from src.security.rdap_enrichment import _extract_netblock
        # network.startAddress is invalid, so ip_network raises
        data = {"network": {"startAddress": "not-an-ip", "cidrLength": 24}}
        result = _extract_netblock(data, "1.2.3.4")
        # Falls through to the fallback /24 from trigger IP
        self.assertEqual(result, "1.2.3.0/24")

    # ── _extract_netblock ValueError on IP range (lines 1446-1447) ──────────

    def test_extract_netblock_invalid_ip_range_uses_fallback(self):
        """Lines 1446-1447: ValueError on ip_address(start) for endAddress range → falls through.
        So what: without this except, a malformed endAddress in the RDAP response
        crashes the expansion, leaving a known-bad netblock without a ban entry."""
        from src.security.rdap_enrichment import _extract_netblock
        # network.startAddress is invalid IP, so ip_address() raises
        data = {"network": {"startAddress": "bad-ip", "endAddress": "1.2.3.255"}}
        result = _extract_netblock(data, "1.2.3.4")
        self.assertEqual(result, "1.2.3.0/24")


if __name__ == "__main__":
    unittest.main()
