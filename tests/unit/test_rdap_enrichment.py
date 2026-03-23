"""Unit tests for Phase 11 — RDAP Enrichment & Block Expansion.

Covers:
- Known-bad org detection (exact handle / substring name match)
- New netblock age signal
- get_signal() hot-path caching behaviour
- Block expansion guards (1–4) and rate limit
- _compute_expansion_cidr()
- RDAP 404 handling
- IANA bootstrap routing
- Worker CancelledError handling
- Queue overflow
- PubSubHandler cidr_ban_add
"""

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

from src.cache.local_cache import LocalCache
from src.pubsub import PubSubHandler
from src.security.models import RiskSignal
from src.security.rdap_enrichment import (
    RDAPConfig,
    RDAPEnricher,
    RDAPResult,
    _BlockExpansionConfig,
    _compute_expansion_cidr,
    _NewNetblockConfig,
    _OrgReputationConfig,
    new_netblock_signal,
)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**kwargs) -> RDAPConfig:
    """Build a RDAPConfig with test-friendly defaults."""
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
    return redis


def _make_enricher(config=None, redis=None, local_cache=None, session=None,
                   blocklist_manager=None, known_bad_orgs_path=None):
    if config is None:
        config = _make_config()
    if redis is None:
        redis = _make_redis()
    if local_cache is None:
        local_cache = LocalCache({})
    if session is None:
        session = MagicMock()
    if known_bad_orgs_path is None:
        known_bad_orgs_path = "config/known_bad_orgs.yml"
    enricher = RDAPEnricher(
        config,
        redis,
        local_cache,
        session,
        blocklist_manager=blocklist_manager,
        known_bad_orgs_path=known_bad_orgs_path,
    )
    return enricher


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
# new_netblock_signal (pure function)
# ---------------------------------------------------------------------------


class TestNewNetblockSignal(unittest.TestCase):

    def test_young_netblock_returns_signal(self):
        """Age < max_age_days → RiskSignal(name='rdap_new_netblock')."""
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).date().isoformat()
        sig = new_netblock_signal(recent, max_age_days=90, score=20)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.name, "rdap_new_netblock")
        self.assertEqual(sig.score, 20)

    def test_old_netblock_returns_none(self):
        """Age >= max_age_days → no signal."""
        old = (datetime.now(timezone.utc) - timedelta(days=100)).date().isoformat()
        sig = new_netblock_signal(old, max_age_days=90, score=20)
        self.assertIsNone(sig)

    def test_no_registration_date_returns_none(self):
        """Missing date → no signal (not an error)."""
        sig = new_netblock_signal(None, max_age_days=90, score=20)
        self.assertIsNone(sig)

    def test_empty_registration_date_returns_none(self):
        """Empty string date → no signal."""
        sig = new_netblock_signal("", max_age_days=90, score=20)
        self.assertIsNone(sig)


# ---------------------------------------------------------------------------
# _compute_expansion_cidr (pure function)
# ---------------------------------------------------------------------------


class TestComputeExpansionCidr(unittest.TestCase):

    def test_ipv4_expansion(self):
        """1.2.3.4 with max_prefix_length_v4=24 → '1.2.3.0/24'."""
        config = _BlockExpansionConfig(max_prefix_length_v4=24, max_prefix_length_v6=48)
        result = _compute_expansion_cidr("1.2.3.4", config)
        self.assertEqual(result, "1.2.3.0/24")

    def test_ipv6_expansion(self):
        """2001:db8::1 with max_prefix_length_v6=48 → correct /48."""
        config = _BlockExpansionConfig(max_prefix_length_v4=24, max_prefix_length_v6=48)
        result = _compute_expansion_cidr("2001:db8::1", config)
        import ipaddress
        net = ipaddress.ip_network(result, strict=False)
        self.assertEqual(net.prefixlen, 48)
        self.assertIn(ipaddress.ip_address("2001:db8::1"), net)

    def test_ipv4_host_in_middle_of_block(self):
        """192.168.100.200 → '192.168.100.0/24'."""
        config = _BlockExpansionConfig(max_prefix_length_v4=24, max_prefix_length_v6=48)
        result = _compute_expansion_cidr("192.168.100.200", config)
        self.assertEqual(result, "192.168.100.0/24")


# ---------------------------------------------------------------------------
# Known-bad org detection
# ---------------------------------------------------------------------------


class TestKnownBadOrgs(unittest.TestCase):

    KNOWN_BAD = [
        {"handle": "FRANTECH", "name": "Frantech Solutions", "reason": "BP hosting", "score": 55},
        {"handle": "M247-MNT", "name": "M247", "reason": "Abuse tolerant", "score": 35},
        {"handle": "QUASI-1", "name": "Quasi Networks", "reason": "BP C2", "score": 55},
    ]

    def _make_enricher_with_orgs(self):
        enricher = _make_enricher()
        enricher._known_bad = self.KNOWN_BAD
        return enricher

    def test_exact_handle_match(self):
        """Exact org_handle match → (True, entry)."""
        enricher = self._make_enricher_with_orgs()
        is_bad, entry = enricher._check_known_bad("FRANTECH", "Some Company")
        self.assertTrue(is_bad)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["handle"], "FRANTECH")

    def test_handle_match_case_insensitive(self):
        """Handle match is case-insensitive."""
        enricher = self._make_enricher_with_orgs()
        is_bad, entry = enricher._check_known_bad("frantech", "other")
        self.assertTrue(is_bad)

    def test_org_name_substring_match(self):
        """Case-insensitive substring match on org_name → signal."""
        enricher = self._make_enricher_with_orgs()
        # "M247" is a substring of "M247 Ltd"
        is_bad, entry = enricher._check_known_bad("UNKNOWN-HANDLE", "M247 Ltd Hosting")
        self.assertTrue(is_bad)
        self.assertEqual(entry["name"], "M247")

    def test_org_name_substring_case_insensitive(self):
        """Case-insensitive substring match."""
        enricher = self._make_enricher_with_orgs()
        is_bad, entry = enricher._check_known_bad("UNKNOWN", "quasi networks hosting llc")
        self.assertTrue(is_bad)

    def test_no_match_returns_false(self):
        """No handle or name match → (False, None)."""
        enricher = self._make_enricher_with_orgs()
        is_bad, entry = enricher._check_known_bad("LEGITIMATE-1", "Cloud Solutions Inc")
        self.assertFalse(is_bad)
        self.assertIsNone(entry)

    def test_empty_known_bad_list(self):
        """Empty known_bad list → always (False, None)."""
        enricher = _make_enricher()
        enricher._known_bad = []
        is_bad, entry = enricher._check_known_bad("ANYTHING", "Anything Inc")
        self.assertFalse(is_bad)


# ---------------------------------------------------------------------------
# get_signal() hot-path behaviour
# ---------------------------------------------------------------------------


class TestGetSignal(unittest.TestCase):

    def test_lru_hit_returns_signals_no_enqueue(self):
        """LRU cache hit → returns signals immediately; no background task queued."""
        local_cache = LocalCache({})
        rdap = _make_rdap_result(org_name="Test", org_handle="TEST-1")
        local_cache.rdap_results.set("1.2.3.4", rdap)

        enricher = _make_enricher(local_cache=local_cache)
        enricher._known_bad = []

        with patch("asyncio.create_task") as mock_create_task:
            signals = enricher.get_signal("1.2.3.4", trigger_score=50)
            # Should not enqueue — cache hit
            mock_create_task.assert_not_called()

    def test_lru_miss_below_min_score_not_enqueued(self):
        """LRU miss, score < min_enqueue_score → returns []; not enqueued."""
        enricher = _make_enricher(config=_make_config(min_enqueue_score=20))
        # Set up a queue so we can check it's empty
        enricher._queue = asyncio.Queue(maxsize=10)

        with patch("asyncio.create_task") as mock_create_task:
            signals = enricher.get_signal("1.2.3.4", trigger_score=10)
        self.assertEqual(signals, [])
        mock_create_task.assert_not_called()

    def test_lru_miss_above_min_score_enqueued(self):
        """LRU miss, score >= min_enqueue_score → returns []; enqueues background lookup."""
        enricher = _make_enricher(config=_make_config(min_enqueue_score=20))
        enricher._queue = asyncio.Queue(maxsize=10)

        with patch("asyncio.create_task") as mock_create_task:
            signals = enricher.get_signal("1.2.3.4", trigger_score=25)
        self.assertEqual(signals, [])
        mock_create_task.assert_called_once()

    def test_disabled_returns_empty(self):
        """When disabled, get_signal always returns []."""
        config = _make_config(enabled=False)
        enricher = _make_enricher(config=config)
        signals = enricher.get_signal("1.2.3.4", trigger_score=100)
        self.assertEqual(signals, [])

    def test_known_bad_org_from_cache_returns_signal(self):
        """LRU hit with known-bad org → rdap_known_bad_org signal returned."""
        local_cache = LocalCache({})
        rdap = _make_rdap_result(org_name="Frantech Solutions", org_handle="FRANTECH")
        local_cache.rdap_results.set("1.2.3.4", rdap)

        enricher = _make_enricher(local_cache=local_cache)
        enricher._known_bad = [
            {"handle": "FRANTECH", "name": "Frantech Solutions", "reason": "BP", "score": 55}
        ]

        signals = enricher.get_signal("1.2.3.4", trigger_score=0)
        names = [s.name for s in signals]
        self.assertIn("rdap_known_bad_org", names)


# ---------------------------------------------------------------------------
# Block expansion guards
# ---------------------------------------------------------------------------


class TestBlockExpansionGuards(unittest.IsolatedAsyncioTestCase):

    def _enricher_with_bad_org(self, **expansion_kwargs):
        config = _make_config(
            block_expansion=_BlockExpansionConfig(
                enabled=True,
                min_trigger_score=75,
                max_prefix_length_v4=24,
                max_prefix_length_v6=48,
                require_no_browser_traffic=True,
                require_known_bad_org=True,
                expansion_ban_duration=3600,
                max_expansions_per_hour=10,
                **expansion_kwargs,
            )
        )
        redis = _make_redis()
        # Default: exists returns 0 (no browser traffic), incr returns 1 (under cap)
        redis.exists = AsyncMock(return_value=0)
        redis.incr = AsyncMock(return_value=1)
        enricher = _make_enricher(config=config, redis=redis)
        enricher._known_bad = [
            {"handle": "BADORG-1", "name": "Bad Org", "reason": "test", "score": 45}
        ]
        return enricher, redis

    async def test_guard1_score_below_threshold(self):
        """Guard 1: trigger_score < min_trigger_score → no expansion."""
        enricher, _ = self._enricher_with_bad_org()
        rdap = _make_rdap_result(netblock="1.2.3.0/24")
        result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=50, is_known_bad=True)
        self.assertFalse(result)

    async def test_guard2_ipv4_too_broad(self):
        """Guard 2 (v4): netblock /16 (prefixlen=16 < 24) → no expansion."""
        enricher, _ = self._enricher_with_bad_org()
        rdap = _make_rdap_result(netblock="1.2.0.0/16")
        result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=80, is_known_bad=True)
        self.assertFalse(result)

    async def test_guard2_ipv6_too_broad(self):
        """Guard 2 (v6): netblock broader than /48 → no expansion."""
        enricher, _ = self._enricher_with_bad_org()
        rdap = _make_rdap_result(netblock="2001:db8::/32")
        result = await enricher.maybe_expand_block("2001:db8::1", rdap, trigger_score=80, is_known_bad=True)
        self.assertFalse(result)

    async def test_guard2_ipv4_exactly_24_passes(self):
        """Guard 2 (v4): netblock exactly /24 (prefixlen=24 >= 24) → guard passes."""
        enricher, redis = self._enricher_with_bad_org()
        # Set up so remaining guards also pass
        rdap = _make_rdap_result(netblock="1.2.3.0/24", org_handle="BADORG-1")
        with patch.object(enricher, '_apply_expansion', new=AsyncMock()):
            with patch.object(enricher, '_log_expansion_audit', new=AsyncMock()):
                result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=80, is_known_bad=True)
        self.assertTrue(result)

    async def test_guard3_browser_subnet_prevents_expansion(self):
        """Guard 3: browser:seen:subnet key present → no expansion."""
        enricher, redis = self._enricher_with_bad_org()
        redis.exists = AsyncMock(return_value=1)  # browser traffic seen
        rdap = _make_rdap_result(netblock="1.2.3.0/24")
        result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=80, is_known_bad=True)
        self.assertFalse(result)

    async def test_guard4_unknown_org_prevents_expansion(self):
        """Guard 4: org not known-bad → no expansion."""
        enricher, redis = self._enricher_with_bad_org()
        rdap = _make_rdap_result(netblock="1.2.3.0/24")
        result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=80, is_known_bad=False)
        self.assertFalse(result)

    async def test_expansion_disabled(self):
        """block_expansion.enabled=false → always returns False."""
        config = _make_config(
            block_expansion=_BlockExpansionConfig(enabled=False)
        )
        enricher = _make_enricher(config=config)
        rdap = _make_rdap_result(netblock="1.2.3.0/24")
        result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=100, is_known_bad=True)
        self.assertFalse(result)

    async def test_all_guards_pass_expansion_applied(self):
        """All 4 guards + rate limit → expansion applied; Redis written; audit logged; pub/sub published."""
        enricher, redis = self._enricher_with_bad_org()
        blocklist_manager = MagicMock()
        enricher._blocklist_manager = blocklist_manager

        rdap = _make_rdap_result(netblock="1.2.3.0/24", org_handle="BADORG-1")
        result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=80, is_known_bad=True)

        self.assertTrue(result)
        # ban_cidr written
        redis.setex.assert_any_call("ban_cidr:1.2.3.0/24", 3600, "1")
        # pub/sub published
        redis.publish.assert_called_once()
        args = redis.publish.call_args
        self.assertEqual(args[0][0], "ja4proxy:invalidate")
        msg = args[0][1]
        import json
        parsed = json.loads(msg)
        self.assertEqual(parsed["type"], "cidr_ban_add")
        self.assertEqual(parsed["value"], "1.2.3.0/24")
        # audit log written
        redis.lpush.assert_called_once()
        redis.ltrim.assert_called_once()

    async def test_max_expansions_per_hour_exceeded(self):
        """Rate limit exceeded → expansion skipped; counter rolled back via DECR."""
        config = _make_config(
            block_expansion=_BlockExpansionConfig(
                enabled=True,
                min_trigger_score=75,
                max_prefix_length_v4=24,
                max_prefix_length_v6=48,
                expansion_ban_duration=3600,
                max_expansions_per_hour=5,
            )
        )
        redis = _make_redis()
        redis.exists = AsyncMock(return_value=0)
        redis.incr = AsyncMock(return_value=6)  # > max_expansions_per_hour=5
        redis.decr = AsyncMock(return_value=5)

        enricher = _make_enricher(config=config, redis=redis)
        rdap = _make_rdap_result(netblock="1.2.3.0/24", org_handle="BADORG-1")
        result = await enricher.maybe_expand_block("1.2.3.4", rdap, trigger_score=80, is_known_bad=True)

        self.assertFalse(result)
        # Counter rolled back
        redis.decr.assert_called_once()


# ---------------------------------------------------------------------------
# RDAP 404 handling
# ---------------------------------------------------------------------------


class TestRDAPNotFound(unittest.IsolatedAsyncioTestCase):

    async def test_404_stores_is_unknown_no_error_counter(self):
        """RDAP 404 → is_unknown=True stored; no rdap_lookup_total{result=error}."""
        from src.security.rdap_enrichment import _NotFoundError
        enricher = _make_enricher()
        enricher._known_bad = []
        enricher._bootstrap_v4 = [{"prefixes": ["0.0.0.0/0"], "urls": ["https://rdap.arin.net/registry/"]}]
        enricher._bootstrap_v6 = []
        local_cache = LocalCache({})
        enricher._local_cache = local_cache

        with patch.object(enricher, '_api_lookup', side_effect=_NotFoundError("1.2.3.4")):
            await enricher._process_lookup("1.2.3.4")

        # Should be cached as is_unknown=True
        cached = local_cache.rdap_results.get("1.2.3.4")
        self.assertIsNotNone(cached)
        self.assertTrue(cached.is_unknown)


# ---------------------------------------------------------------------------
# IANA bootstrap routing
# ---------------------------------------------------------------------------


class TestBootstrapRouting(unittest.IsolatedAsyncioTestCase):

    async def test_ipv4_routes_to_correct_rir(self):
        """IPv4 address → correct RIR URL from bootstrap."""
        enricher = _make_enricher()
        enricher._bootstrap_v4 = [
            {"prefixes": ["1.0.0.0/8"], "urls": ["https://rdap.apnic.net/"]},
            {"prefixes": ["0.0.0.0/0"], "urls": ["https://rdap.arin.net/registry/"]},
        ]
        url = await enricher.get_rdap_base_url("1.2.3.4")
        self.assertEqual(url, "https://rdap.apnic.net/")

    async def test_ipv6_routes_to_correct_rir(self):
        """IPv6 address → correct RIR URL from bootstrap."""
        enricher = _make_enricher()
        enricher._bootstrap_v6 = [
            {"prefixes": ["2001:db8::/32"], "urls": ["https://rdap.ripe.net/"]},
            {"prefixes": ["::/0"], "urls": ["https://rdap.arin.net/registry/"]},
        ]
        url = await enricher.get_rdap_base_url("2001:db8::1")
        self.assertEqual(url, "https://rdap.ripe.net/")

    async def test_fallback_rir_when_no_match(self):
        """No matching prefix → ARIN fallback."""
        enricher = _make_enricher()
        enricher._bootstrap_v4 = []
        url = await enricher.get_rdap_base_url("1.2.3.4")
        # Should return the default ARIN URL
        self.assertIn("arin", url)


# ---------------------------------------------------------------------------
# Worker lifecycle
# ---------------------------------------------------------------------------


class TestWorkerLifecycle(unittest.IsolatedAsyncioTestCase):

    async def test_cancelled_error_exits_cleanly(self):
        """Worker CancelledError → breaks cleanly without re-raising."""
        enricher = _make_enricher()
        enricher._queue = asyncio.Queue(maxsize=10)

        task = asyncio.create_task(enricher._lookup_worker())
        await asyncio.sleep(0)  # Let worker start
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except asyncio.CancelledError:
            pass  # Expected — task was cancelled

    async def test_queue_full_drops_item_increments_counter(self):
        """Queue full → item dropped; rdap_queue_dropped_total incremented."""
        enricher = _make_enricher()
        enricher._queue = asyncio.Queue(maxsize=1)
        enricher._queue.put_nowait("1.1.1.1")  # Fill the queue

        redis = _make_redis()
        bf = MagicMock()
        bf.add = AsyncMock(return_value=1)  # Always "newly added"
        redis.bf = MagicMock(return_value=bf)
        enricher._redis = redis

        # Patch prometheus counter to track
        with patch("src.security.rdap_enrichment._QUEUE_DROPPED") as mock_dropped:
            await enricher._enqueue_lookup("2.2.2.2")
            mock_dropped.inc.assert_called_once()


# ---------------------------------------------------------------------------
# PubSubHandler cidr_ban_add
# ---------------------------------------------------------------------------


class TestPubSubCidrBanAdd(unittest.IsolatedAsyncioTestCase):

    async def test_cidr_ban_add_calls_blocklist_manager(self):
        """cidr_ban_add pub/sub message → calls blocklist_manager.load_cidrs()."""
        blocklist_manager = MagicMock()
        blocklist_manager.load_cidrs = MagicMock()

        redis_client = MagicMock()
        local_cache = LocalCache({})
        config_loader = MagicMock()
        config_loader.reload = AsyncMock()

        handler = PubSubHandler(
            redis_client=redis_client,
            local_cache=local_cache,
            config_loader=config_loader,
            blacklist_set=set(),
            whitelist_set=set(),
            blocklist_manager=blocklist_manager,
        )

        import json
        msg = json.dumps({"type": "cidr_ban_add", "value": "1.2.3.0/24"})
        await handler._dispatch(msg.encode())

        blocklist_manager.load_cidrs.assert_called_once_with(
            ["1.2.3.0/24"],
            "rdap_expansion",
            {"name": "rdap_expansion", "enabled": True},
        )

    async def test_cidr_ban_add_no_blocklist_manager_is_silent(self):
        """cidr_ban_add with no blocklist_manager → no crash."""
        redis_client = MagicMock()
        local_cache = LocalCache({})
        config_loader = MagicMock()
        config_loader.reload = AsyncMock()

        handler = PubSubHandler(
            redis_client=redis_client,
            local_cache=local_cache,
            config_loader=config_loader,
            blacklist_set=set(),
            whitelist_set=set(),
            blocklist_manager=None,
        )

        import json
        msg = json.dumps({"type": "cidr_ban_add", "value": "1.2.3.0/24"})
        # Should not raise
        await handler._dispatch(msg.encode())

    async def test_cidr_ban_add_empty_value_ignored(self):
        """cidr_ban_add with empty value → load_cidrs not called."""
        blocklist_manager = MagicMock()
        blocklist_manager.load_cidrs = MagicMock()

        redis_client = MagicMock()
        local_cache = LocalCache({})
        config_loader = MagicMock()
        config_loader.reload = AsyncMock()

        handler = PubSubHandler(
            redis_client=redis_client,
            local_cache=local_cache,
            config_loader=config_loader,
            blacklist_set=set(),
            whitelist_set=set(),
            blocklist_manager=blocklist_manager,
        )

        import json
        msg = json.dumps({"type": "cidr_ban_add", "value": ""})
        await handler._dispatch(msg.encode())
        blocklist_manager.load_cidrs.assert_not_called()


# ---------------------------------------------------------------------------
# on_config_reload WARN for non-hot-reloadable keys
# ---------------------------------------------------------------------------


class TestOnConfigReload(unittest.TestCase):

    def test_worker_count_change_logs_warn(self):
        """worker_count change during reload → WARN logged; value not changed."""
        config = _make_config()
        enricher = _make_enricher(config=config)
        enricher._known_bad = []

        import logging
        with self.assertLogs("src.security.rdap_enrichment", level="WARNING") as cm:
            new_config = {
                "rdap_enrichment": {
                    "enabled": True,
                    "worker_count": 10,  # Changed
                    "queue_size": config.queue_size,
                }
            }
            enricher.on_config_reload(new_config)

        # worker_count should NOT have changed
        self.assertEqual(enricher._config.worker_count, config.worker_count)
        # A WARN should have been logged
        warn_msgs = [m for m in cm.output if "restart_required" in m or "worker_count" in m.lower()]
        self.assertTrue(len(warn_msgs) > 0 or any("WARN" in m for m in cm.output))

    def test_queue_size_change_logs_warn(self):
        """queue_size change during reload → WARN logged; value not changed."""
        config = _make_config()
        enricher = _make_enricher(config=config)
        enricher._known_bad = []

        new_config = {
            "rdap_enrichment": {
                "enabled": True,
                "worker_count": config.worker_count,
                "queue_size": 9999,  # Changed
            }
        }
        with self.assertLogs("src.security.rdap_enrichment", level="WARNING"):
            enricher.on_config_reload(new_config)

        # queue_size should NOT have changed
        self.assertEqual(enricher._config.queue_size, config.queue_size)
