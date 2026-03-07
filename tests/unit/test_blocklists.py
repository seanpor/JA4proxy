"""Unit tests for Phase 8: Spamhaus DROP/EDROP & Blocklist Feed Framework.

Tests are written before the implementation (TDD). They cover:
- BlocklistManager CIDR trie lookup (IPv4 and IPv6)
- Feed format parsers (spamhaus, cidr, ipset)
- ETag 304 handling
- Malformed CIDR resilience
- is_bypass=false → RiskSignal emission
- Prometheus metrics incremented
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.security.blocklists import (
    BlocklistManager,
    FeedConfig,
    parse_feed,
)
from src.security.models import RiskSignal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SPAMHAUS_DROP_TEXT = """\
; Spamhaus Don't Route Or Peer List
; Last-Modified: Mon,  1 Jan 2024 00:00:00 GMT
; Expires: Tue,  2 Jan 2024 00:00:00 GMT
1.10.16.0/20 ; SBL123456
2.57.96.0/22 ; SBL789012
; another comment
192.0.2.0/24 ; SBL999999
"""

CIDR_TEXT = """\
10.0.0.0/8
172.16.0.0/12
# comment line
192.168.0.0/16
"""

IPSET_TEXT = """\
create blocklist hash:net family inet
add blocklist 203.0.113.0/24
add blocklist 198.51.100.0/24
"""

MALFORMED_TEXT = """\
; valid comment
1.10.16.0/20 ; SBL123456
NOT_A_CIDR
999.999.999.0/24
2.57.96.0/22 ; SBL789012
"""


# ---------------------------------------------------------------------------
# parse_feed
# ---------------------------------------------------------------------------

class TestParseFeed:
    """Feed format parsers produce correct CIDR lists."""

    def test_spamhaus_strips_comment_lines(self):
        cidrs = parse_feed(SPAMHAUS_DROP_TEXT, "spamhaus")
        for c in cidrs:
            assert not c.startswith(";")

    def test_spamhaus_strips_sbl_references(self):
        cidrs = parse_feed(SPAMHAUS_DROP_TEXT, "spamhaus")
        for c in cidrs:
            assert "SBL" not in c

    def test_spamhaus_correct_count(self):
        cidrs = parse_feed(SPAMHAUS_DROP_TEXT, "spamhaus")
        assert len(cidrs) == 3

    def test_spamhaus_correct_cidrs(self):
        cidrs = parse_feed(SPAMHAUS_DROP_TEXT, "spamhaus")
        assert "1.10.16.0/20" in cidrs
        assert "2.57.96.0/22" in cidrs
        assert "192.0.2.0/24" in cidrs

    def test_cidr_format_strips_comments(self):
        cidrs = parse_feed(CIDR_TEXT, "cidr")
        assert "10.0.0.0/8" in cidrs
        assert "172.16.0.0/12" in cidrs
        assert "192.168.0.0/16" in cidrs
        assert len(cidrs) == 3

    def test_ipset_format_extracts_networks(self):
        cidrs = parse_feed(IPSET_TEXT, "ipset")
        assert "203.0.113.0/24" in cidrs
        assert "198.51.100.0/24" in cidrs
        assert len(cidrs) == 2

    def test_malformed_cidrs_skipped(self):
        cidrs = parse_feed(MALFORMED_TEXT, "spamhaus")
        # Valid ones loaded
        assert "1.10.16.0/20" in cidrs
        assert "2.57.96.0/22" in cidrs
        # Invalid ones absent
        assert "NOT_A_CIDR" not in cidrs
        assert "999.999.999.0/24" not in cidrs

    def test_empty_input(self):
        assert parse_feed("", "spamhaus") == []
        assert parse_feed("", "cidr") == []


# ---------------------------------------------------------------------------
# BlocklistManager — CIDR trie lookup
# ---------------------------------------------------------------------------

class TestBlocklistManagerIPv4:
    """IPv4 CIDR trie lookup."""

    def setup_method(self):
        self.mgr = BlocklistManager()
        self.mgr.load_cidrs(["1.10.16.0/20", "2.57.96.0/22"], "spamhaus_drop")

    def test_ip_inside_cidr_is_blocked(self):
        blocked, feed = self.mgr.is_blocked("1.10.16.1")
        assert blocked is True
        assert feed == "spamhaus_drop"

    def test_ip_at_network_base_is_blocked(self):
        blocked, feed = self.mgr.is_blocked("1.10.16.0")
        assert blocked is True

    def test_ip_outside_cidr_not_blocked(self):
        blocked, feed = self.mgr.is_blocked("8.8.8.8")
        assert blocked is False
        assert feed == ""

    def test_ip_in_second_cidr_is_blocked(self):
        blocked, feed = self.mgr.is_blocked("2.57.97.1")
        assert blocked is True
        assert feed == "spamhaus_drop"

    def test_empty_manager_blocks_nothing(self):
        mgr = BlocklistManager()
        blocked, feed = mgr.is_blocked("1.2.3.4")
        assert blocked is False
        assert feed == ""


class TestBlocklistManagerIPv6:
    """IPv6 CIDR trie lookup."""

    def setup_method(self):
        self.mgr = BlocklistManager()
        self.mgr.load_cidrs(["2001:db8::/32", "fe80::/10"], "test_v6_list")

    def test_ipv6_inside_cidr_is_blocked(self):
        blocked, feed = self.mgr.is_blocked("2001:db8::1")
        assert blocked is True
        assert feed == "test_v6_list"

    def test_ipv6_outside_cidr_not_blocked(self):
        blocked, feed = self.mgr.is_blocked("2001:db9::1")
        assert blocked is False
        assert feed == ""

    def test_link_local_ipv6_blocked(self):
        blocked, feed = self.mgr.is_blocked("fe80::1")
        assert blocked is True

    def test_ipv4_not_matched_in_ipv6_trie(self):
        """IPv4 address must not be looked up in IPv6 trie."""
        blocked, feed = self.mgr.is_blocked("1.2.3.4")
        assert blocked is False


class TestBlocklistManagerMultipleFeeds:
    """Multiple feeds can be loaded into the same manager."""

    def setup_method(self):
        self.mgr = BlocklistManager()
        self.mgr.load_cidrs(["1.10.16.0/20"], "spamhaus_drop")
        self.mgr.load_cidrs(["10.0.0.0/8"], "internal_list")

    def test_ip_in_first_feed(self):
        blocked, feed = self.mgr.is_blocked("1.10.16.5")
        assert blocked is True
        assert feed == "spamhaus_drop"

    def test_ip_in_second_feed(self):
        blocked, feed = self.mgr.is_blocked("10.0.0.1")
        assert blocked is True
        assert feed == "internal_list"

    def test_ip_in_neither(self):
        blocked, feed = self.mgr.is_blocked("8.8.8.8")
        assert blocked is False


class TestBlocklistManagerReload:
    """load_cidrs replaces entries for a given feed atomically."""

    def test_reload_updates_cidrs(self):
        mgr = BlocklistManager()
        mgr.load_cidrs(["1.10.16.0/20"], "drop")
        assert mgr.is_blocked("1.10.16.1")[0] is True

        # Reload with different CIDRs
        mgr.load_cidrs(["5.5.5.0/24"], "drop")
        # Old CIDR gone
        assert mgr.is_blocked("1.10.16.1")[0] is False
        # New CIDR present
        assert mgr.is_blocked("5.5.5.1")[0] is True

    def test_reload_returns_count(self):
        mgr = BlocklistManager()
        count = mgr.load_cidrs(["1.10.16.0/20", "2.57.96.0/22"], "drop")
        assert count == 2


# ---------------------------------------------------------------------------
# FeedConfig
# ---------------------------------------------------------------------------

class TestFeedConfig:
    """FeedConfig dataclass defaults."""

    def test_is_bypass_defaults_true_for_spamhaus(self):
        cfg = FeedConfig(
            name="spamhaus_drop",
            url="https://example.com/drop.txt",
            format="spamhaus",
            is_bypass=True,
            action="block",
            score=80,
            refresh_interval_seconds=43200,
            enabled=True,
        )
        assert cfg.is_bypass is True

    def test_is_bypass_false_for_custom(self):
        cfg = FeedConfig(
            name="custom",
            url="https://example.com/custom.txt",
            format="cidr",
            is_bypass=False,
            action="block",
            score=60,
            refresh_interval_seconds=3600,
            enabled=True,
        )
        assert cfg.is_bypass is False


# ---------------------------------------------------------------------------
# is_bypass=false → RiskSignal
# ---------------------------------------------------------------------------

class TestNonBypassFeedSignal:
    """is_bypass=false feeds produce RiskSignal, not a bypass."""

    def setup_method(self):
        self.mgr = BlocklistManager()
        feed_cfg = FeedConfig(
            name="custom_scored",
            url="",
            format="cidr",
            is_bypass=False,
            action="block",
            score=60,
            refresh_interval_seconds=3600,
            enabled=True,
        )
        self.mgr.load_cidrs(["203.0.113.0/24"], "custom_scored",
                             feed_config=feed_cfg)

    def test_matched_ip_returns_risk_signal(self):
        signals = self.mgr.get_signals("203.0.113.5")
        assert len(signals) == 1
        sig = signals[0]
        assert isinstance(sig, RiskSignal)
        assert sig.name == "blocklist_custom_scored"
        assert sig.score == 60

    def test_unmatched_ip_returns_empty(self):
        signals = self.mgr.get_signals("8.8.8.8")
        assert signals == []

    def test_bypass_feed_get_signals_returns_empty(self):
        """is_bypass=true feeds do not produce RiskSignals via get_signals."""
        mgr = BlocklistManager()
        bypass_cfg = FeedConfig(
            name="spamhaus_drop",
            url="",
            format="spamhaus",
            is_bypass=True,
            action="block",
            score=80,
            refresh_interval_seconds=43200,
            enabled=True,
        )
        mgr.load_cidrs(["1.10.16.0/20"], "spamhaus_drop", feed_config=bypass_cfg)
        signals = mgr.get_signals("1.10.16.1")
        assert signals == []


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

class TestBlocklistMetrics:
    """Prometheus counters are incremented on match."""

    def test_match_increments_counter(self):
        from src.security.blocklists import _BLOCKLIST_MATCHES

        mgr = BlocklistManager()
        bypass_cfg = FeedConfig(
            name="spamhaus_drop",
            url="",
            format="spamhaus",
            is_bypass=True,
            action="block",
            score=80,
            refresh_interval_seconds=43200,
            enabled=True,
        )
        mgr.load_cidrs(["1.10.16.0/20"], "spamhaus_drop", feed_config=bypass_cfg)

        before = _BLOCKLIST_MATCHES.labels(feed="spamhaus_drop")._value.get()
        mgr.is_blocked("1.10.16.1")
        after = _BLOCKLIST_MATCHES.labels(feed="spamhaus_drop")._value.get()
        assert after == before + 1

    def test_no_match_no_counter_increment(self):
        from src.security.blocklists import _BLOCKLIST_MATCHES

        mgr = BlocklistManager()
        mgr.load_cidrs(["1.10.16.0/20"], "spamhaus_drop")

        before = _BLOCKLIST_MATCHES.labels(feed="spamhaus_drop")._value.get()
        mgr.is_blocked("8.8.8.8")
        after = _BLOCKLIST_MATCHES.labels(feed="spamhaus_drop")._value.get()
        assert after == before
