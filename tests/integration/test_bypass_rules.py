"""Integration tests: blocklist bypass rules (Phase 8).

Verifies that IPs matching is_bypass=true feeds are hard-blocked before
the scorer is called, and that is_bypass=false feeds add RiskSignals.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider
from src.security.blocklists import BlocklistManager, FeedConfig
from src.security.pipeline import ConnectionContext, Pipeline
from src.security.risk_scorer import RiskScorer

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def _run(coro):
    return asyncio.run(coro)


def _make_pipeline(dial: int = 75) -> Pipeline:
    config = {
        "security_policy": {
            "alpn_browser_bypass": {"enabled": True},
            "ja4_whitelist_bypass": {"enabled": True},
            "mtls_bypass": {"enabled": True},
            "static_ip_allowlist": {"enabled": True},
            "ja4_blacklist_bypass": {"enabled": True},
            "country_blacklist_bypass": {"enabled": True},
            "spamhaus_bypass": {"enabled": True},
        }
    }
    cache = LocalCache({})
    cache.dial = dial
    pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
    scorer = RiskScorer(THRESHOLDS)
    decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
    pipeline.update_scorer(scorer, decider)
    return pipeline


def _ctx(**kwargs) -> ConnectionContext:
    defaults = {"client_ip": "1.10.16.1", "ja4": "t13d_test_fingerprint_aa"}
    defaults.update(kwargs)
    return ConnectionContext(**defaults)


def _load_bypass_feed(
    pipeline: Pipeline, cidrs: list[str], feed_name: str = "spamhaus_drop"
):
    cfg = FeedConfig(
        name=feed_name,
        url="",
        format="spamhaus",
        is_bypass=True,
        action="block",
        score=80,
        refresh_interval_seconds=43200,
    )
    pipeline._blocklist_manager.load_cidrs(cidrs, feed_name, cfg)


def _load_scored_feed(
    pipeline: Pipeline, cidrs: list[str], feed_name: str = "custom_list"
):
    cfg = FeedConfig(
        name=feed_name,
        url="",
        format="cidr",
        is_bypass=False,
        action="block",
        score=60,
        refresh_interval_seconds=3600,
    )
    pipeline._blocklist_manager.load_cidrs(cidrs, feed_name, cfg)


# ---------------------------------------------------------------------------
# Bypass feed: blocked before scorer
# ---------------------------------------------------------------------------


class TestBypassFeedHardBlock:
    """is_bypass=true feed: connection rejected before scorer is called."""

    def test_spamhaus_ip_is_hard_blocked(self):
        """IP in bypass feed returns block bypass, never scores."""
        pipeline = _make_pipeline()
        _load_bypass_feed(pipeline, ["1.10.16.0/20"])

        result = _run(pipeline.process(_ctx(client_ip="1.10.16.5")))

        assert result.action == "block"
        assert result.bypassed is True
        assert "spamhaus" in result.bypass_reason

    def test_bypass_block_has_no_score(self):
        """Bypass block result has no score (scorer was not called)."""
        pipeline = _make_pipeline()
        _load_bypass_feed(pipeline, ["1.10.16.0/20"])

        result = _run(pipeline.process(_ctx(client_ip="1.10.16.1")))

        assert result.score is None

    def test_clean_ip_not_blocked(self):
        """IP outside all CIDRs passes through normally."""
        pipeline = _make_pipeline(dial=0)
        _load_bypass_feed(pipeline, ["1.10.16.0/20"])

        result = _run(pipeline.process(_ctx(client_ip="8.8.8.8")))

        assert result.action == "allow"
        assert result.bypassed is False

    def test_ipv6_bypass_feed_blocks_ipv6(self):
        """IPv6 address in bypass feed is hard-blocked."""
        pipeline = _make_pipeline()
        cfg = FeedConfig(
            name="v6_list",
            url="",
            format="cidr",
            is_bypass=True,
            action="block",
            score=80,
            refresh_interval_seconds=43200,
        )
        pipeline._blocklist_manager.load_cidrs(["2001:db8::/32"], "v6_list", cfg)

        result = _run(pipeline.process(_ctx(client_ip="2001:db8::1")))

        assert result.action == "block"
        assert result.bypassed is True

    def test_bypass_disabled_routes_to_scorer(self):
        """When spamhaus_bypass disabled, Spamhaus IPs go through scorer."""
        config = {
            "security_policy": {
                "alpn_browser_bypass": {"enabled": True},
                "ja4_whitelist_bypass": {"enabled": True},
                "mtls_bypass": {"enabled": True},
                "static_ip_allowlist": {"enabled": True},
                "ja4_blacklist_bypass": {"enabled": True},
                "country_blacklist_bypass": {"enabled": True},
                "spamhaus_bypass": {"enabled": False},  # disabled
            }
        }
        cache = LocalCache({})
        cache.dial = 75
        pipeline = Pipeline(config=config, local_cache=cache, redis_client=MagicMock())
        scorer = RiskScorer(THRESHOLDS)
        decider = ActionDecider(THRESHOLDS, ban_duration_seconds=300)
        pipeline.update_scorer(scorer, decider)
        _load_bypass_feed(pipeline, ["1.10.16.0/20"])

        result = _run(pipeline.process(_ctx(client_ip="1.10.16.1")))

        # Not a bypass — goes through scorer
        assert result.bypassed is False


# ---------------------------------------------------------------------------
# Scored feed: RiskSignal emitted
# ---------------------------------------------------------------------------


class TestScoredFeedSignal:
    """is_bypass=false feed: RiskSignal emitted; connection scored normally."""

    def test_matched_ip_emits_risk_signal(self):
        """IP in scored feed appears as a signal in the result."""
        pipeline = _make_pipeline(dial=0)  # monitor mode — score but don't block
        _load_scored_feed(pipeline, ["203.0.113.0/24"])

        result = _run(pipeline.process(_ctx(client_ip="203.0.113.5")))

        signal_names = [s.name for s in result.signals]
        assert "blocklist_custom_list" in signal_names

    def test_scored_signal_contributes_to_score(self):
        """RiskSignal from scored feed raises the final risk score."""
        pipeline = _make_pipeline(dial=0)
        _load_scored_feed(pipeline, ["203.0.113.0/24"])

        clean_result = _run(pipeline.process(_ctx(client_ip="8.8.8.8")))
        dirty_result = _run(pipeline.process(_ctx(client_ip="203.0.113.5")))

        assert dirty_result.score > clean_result.score

    def test_scored_feed_not_a_bypass(self):
        """Scored feed match does not produce bypassed=True."""
        pipeline = _make_pipeline(dial=0)
        _load_scored_feed(pipeline, ["203.0.113.0/24"])

        result = _run(pipeline.process(_ctx(client_ip="203.0.113.5")))

        assert result.bypassed is False
