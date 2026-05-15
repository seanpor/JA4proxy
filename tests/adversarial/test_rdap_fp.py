"""Adversarial / False Positive tests for Phase 11 — RDAP Enrichment.

Verifies that:
1. Legitimate org names with common words don't match bad-org list unexpectedly
2. Block expansion guard 3 (browser traffic) fires even for confirmed bad orgs
3. One attacker in a /24 with legit IPs doesn't trigger expansion
4. RDAP signals alone (org=45 + new_netblock=20 = 65) cannot exceed block threshold (70)
"""

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from src.cache.local_cache import LocalCache
from src.security.action_decider import ActionDecider
from src.security.models import RiskSignal
from src.security.rdap_enrichment import (
    RDAPConfig,
    RDAPEnricher,
    RDAPResult,
    _BlockExpansionConfig,
    _NewNetblockConfig,
    _OrgReputationConfig,
    new_netblock_signal,
)
from src.security.risk_scorer import RiskScorer

# Action thresholds from risk_scorer defaults
_THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


def _make_config(**kwargs) -> RDAPConfig:
    defaults = dict(
        enabled=True,
        queue_size=10,
        worker_count=1,
        min_enqueue_score=20,
        lookup_timeout_seconds=5,
        delegate_to_analytics=False,
        org_reputation=_OrgReputationConfig(enabled=True, score=45),
        new_netblock_flagging=_NewNetblockConfig(
            enabled=True, max_age_days=90, score=20
        ),
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


class TestRDAPFalsePositiveBounds(unittest.TestCase):
    """Verify RDAP score contributions cannot trigger false hard-blocks."""

    def test_rdap_signals_alone_cannot_reach_block_threshold(self):
        """org_reputation (45) + new_netblock (20) = 65 < block threshold (70).

        Even the worst combination of RDAP-only signals cannot push a connection
        past the block threshold without corroboration from other signals.
        This is by design (PHASE_11.md §11g constraint).
        """
        max_rdap_org_score = 45  # From _OrgReputationConfig default
        max_new_netblock_score = 20  # From _NewNetblockConfig default

        total_rdap_max = max_rdap_org_score + max_new_netblock_score
        block_threshold = _THRESHOLDS["block"]

        # RDAP alone must NOT reach the block threshold
        self.assertLess(
            total_rdap_max,
            block_threshold,
            f"RDAP max ({total_rdap_max}) must be < block threshold ({block_threshold})",
        )

    def test_rdap_signals_alone_cannot_reach_block_through_scorer(self):
        """Verify via actual RiskScorer: RDAP signals produce score < 70."""
        scorer = RiskScorer(_THRESHOLDS)
        signals = [
            RiskSignal(name="rdap_known_bad_org", score=45, reason="test"),
            RiskSignal(name="rdap_new_netblock", score=20, reason="test"),
        ]
        assessment = scorer.score(signals)
        self.assertLess(
            assessment.total_score,
            _THRESHOLDS["block"],
            f"RDAP-only score {assessment.total_score} must be < block threshold 70",
        )

    def test_known_bad_org_alone_below_block(self):
        """Known-bad org signal (45) alone < block threshold (70)."""
        scorer = RiskScorer(_THRESHOLDS)
        signals = [RiskSignal(name="rdap_known_bad_org", score=45, reason="test")]
        assessment = scorer.score(signals)
        self.assertLess(assessment.total_score, _THRESHOLDS["block"])

    def test_new_netblock_alone_below_flag(self):
        """New netblock signal (20) alone just hits flag threshold (20) — not rate_limit."""
        scorer = RiskScorer(_THRESHOLDS)
        signals = [RiskSignal(name="rdap_new_netblock", score=20, reason="test")]
        assessment = scorer.score(signals)
        # Should be exactly at or just above flag (20), well below rate_limit (35)
        self.assertLess(assessment.total_score, _THRESHOLDS["rate_limit"])


class TestLegitimateOrgNameFalsePositives(unittest.TestCase):
    """Verify substring matching doesn't fire on legitimate org names."""

    KNOWN_BAD_ORGS = [
        {
            "handle": "FRANTECH",
            "name": "Frantech Solutions",
            "reason": "BP",
            "score": 55,
        },
        {"handle": "M247-MNT", "name": "M247", "reason": "Abuse tolerant", "score": 35},
        {"handle": "QUASI-1", "name": "Quasi Networks", "reason": "BP", "score": 55},
    ]

    def _make_enricher_with_orgs(self):
        enricher = RDAPEnricher(
            _make_config(),
            _make_redis(),
            LocalCache({}),
            MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = self.KNOWN_BAD_ORGS
        return enricher

    def test_legitimate_org_solutions_does_not_match(self):
        """'Solutions' as common word does NOT match 'Frantech Solutions' via substring.

        The substring match checks if the KNOWN-BAD name is a substring of the
        LOOKUP org name — not if any word in the lookup name appears anywhere.
        This means 'Cloud Solutions Inc' does NOT match 'Frantech Solutions'
        because 'Frantech Solutions' is not a substring of 'Cloud Solutions Inc'.
        """
        enricher = self._make_enricher_with_orgs()
        # "Frantech Solutions" is not a substring of "Cloud Solutions Inc"
        is_bad, entry = enricher._check_known_bad("CLOUDCORP-1", "Cloud Solutions Inc")
        self.assertFalse(
            is_bad,
            "Legitimate org 'Cloud Solutions Inc' should not match 'Frantech Solutions'",
        )

    def test_legitimate_org_networks_does_not_match(self):
        """'Networks' as common word does NOT match 'Quasi Networks'."""
        enricher = self._make_enricher_with_orgs()
        # "Quasi Networks" is not a substring of "Virtuous Networks LLC"
        is_bad, entry = enricher._check_known_bad("VIRTUOUS-1", "Virtuous Networks LLC")
        self.assertFalse(is_bad)

    def test_legitimate_isp_does_not_match_m247(self):
        """Generic datacenter name does NOT match 'M247'."""
        enricher = self._make_enricher_with_orgs()
        # "M247" is not a substring of "MainCloud Hosting"
        is_bad, entry = enricher._check_known_bad(
            "MAINCLOUD-1", "MainCloud Hosting Inc"
        )
        self.assertFalse(is_bad)

    def test_actual_bad_org_still_matches(self):
        """Real bad org substring IS detected: 'M247' IS a substring of 'M247 Ltd'."""
        enricher = self._make_enricher_with_orgs()
        is_bad, entry = enricher._check_known_bad("UNKNOWN", "M247 Ltd")
        self.assertTrue(is_bad)


class TestBrowserSubnetGuardFalsePositives(unittest.IsolatedAsyncioTestCase):
    """Guard 3: browser traffic in subnet prevents expansion even for confirmed bad orgs."""

    async def test_browser_ip_in_bad_org_subnet_no_expansion(self):
        """Browser traffic seen → guard 3 blocks expansion even when org is confirmed bad."""
        config = _make_config(
            block_expansion=_BlockExpansionConfig(
                enabled=True,
                min_trigger_score=75,
                max_prefix_length_v4=24,
                max_prefix_length_v6=48,
                expansion_ban_duration=3600,
                max_expansions_per_hour=10,
            )
        )
        redis = _make_redis()
        # Simulate browser traffic seen in the subnet
        redis.exists = AsyncMock(return_value=1)

        enricher = RDAPEnricher(
            config,
            redis,
            LocalCache({}),
            MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = [
            {"handle": "BADORG-1", "name": "Bad Org", "reason": "test", "score": 45}
        ]

        rdap = _make_rdap_result(netblock="1.2.3.0/24", org_handle="BADORG-1")
        # is_known_bad=True, score=100 — all other guards pass, but guard 3 should block
        result = await enricher.maybe_expand_block(
            "1.2.3.4", rdap, trigger_score=100, is_known_bad=True
        )
        self.assertFalse(
            result, "Guard 3 must prevent expansion when browser traffic seen in subnet"
        )

    async def test_one_attacker_in_shared_subnet_no_expansion(self):
        """/24 shared by attacker and legit IPs: guard 3 prevents expansion."""
        config = _make_config(
            block_expansion=_BlockExpansionConfig(
                enabled=True,
                min_trigger_score=75,
                max_prefix_length_v4=24,
                max_prefix_length_v6=48,
                expansion_ban_duration=3600,
                max_expansions_per_hour=10,
            )
        )
        redis = _make_redis()
        # Legit browser traffic was seen somewhere in this /24
        redis.exists = AsyncMock(return_value=1)

        enricher = RDAPEnricher(
            config,
            redis,
            LocalCache({}),
            MagicMock(),
            known_bad_orgs_path="config/known_bad_orgs.yml",
        )
        enricher._known_bad = [
            {"handle": "BADORG-1", "name": "Bad Org", "reason": "test", "score": 45}
        ]

        # The attacker IP is in 5.6.7.0/24, which also has legit users
        rdap = _make_rdap_result(netblock="5.6.7.0/24", org_handle="BADORG-1")
        result = await enricher.maybe_expand_block(
            "5.6.7.200", rdap, trigger_score=90, is_known_bad=True
        )
        self.assertFalse(result, "Guard 3 must protect legit users in shared /24")
