"""Adversarial / False Positive tests for Phase 10 — AbuseIPDB.

Verifies that no single AbuseIPDB score, regardless of value, can cause
a hard block or push a legitimate-looking connection past the ban threshold.

These tests focus on the math of score contribution to verify the design
constraints from PHASE_10.md:
  - score_cap=40 bounds maximum contribution (confidence=100 → 40 pts)
  - ban threshold is 85 (from risk_scorer defaults)
  - score_cap=40 < ban threshold=85, so AbuseIPDB alone can never ban
  - Confidence below shared_ip_threshold (50) → contribution ≤ 15
  - CGN/shared IP at confidence=49 should not push past flag threshold (20) alone

"""

import unittest

from src.security.abuseipdb import abuseipdb_to_risk_signal

# Default thresholds from risk_scorer.py
_THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}

_DEFAULT_SCORE_CAP = 40
_DEFAULT_THRESHOLD = 50


class TestAbuseIPDBFalsePositiveBounds(unittest.TestCase):
    """Verify AbuseIPDB contribution bounds for false positive protection."""

    def test_confidence_100_contribution_below_ban_threshold(self):
        """confidence=100 → contribution=score_cap (40) < ban threshold (85).

        Even if an IP has the highest possible AbuseIPDB confidence, the
        contribution (40) is less than half the ban threshold (85). AbuseIPDB
        alone can never cause a ban.
        """
        signal = abuseipdb_to_risk_signal(
            "1.2.3.4", 100, _DEFAULT_THRESHOLD, _DEFAULT_SCORE_CAP
        )
        self.assertIsNotNone(signal)
        self.assertEqual(signal.score, _DEFAULT_SCORE_CAP)
        # Must be below ban threshold
        self.assertLess(signal.score, _THRESHOLDS["ban"])
        # Must be below block threshold
        self.assertLess(signal.score, _THRESHOLDS["block"])

    def test_confidence_100_contribution_below_block_threshold(self):
        """confidence=100 → contribution cannot reach block threshold (70).

        score_cap=40 < block_threshold=70. AbuseIPDB alone can never cause
        a hard block.
        """
        signal = abuseipdb_to_risk_signal(
            "1.2.3.4", 100, _DEFAULT_THRESHOLD, _DEFAULT_SCORE_CAP
        )
        self.assertLess(signal.score, _THRESHOLDS["block"])

    def test_cgn_ip_confidence_49_stays_below_flag_threshold(self):
        """CGN/shared IP (confidence=49, below threshold=50) → contribution ≤ 15.

        A typical CGN or corporate NAT gateway might have AbuseIPDB confidence
        up to 49 due to other users on the same IP. The contribution must stay
        ≤ 15 so it cannot push a legitimate connection past the flag threshold (20)
        without additional signals.
        """
        signal = abuseipdb_to_risk_signal(
            "100.64.0.1", 49, _DEFAULT_THRESHOLD, _DEFAULT_SCORE_CAP
        )
        self.assertIsNotNone(signal)
        self.assertLessEqual(signal.score, 15)
        # Alone, should stay below flag threshold
        self.assertLess(signal.score, _THRESHOLDS["flag"])

    def test_cgn_ip_confidence_30_contribution_low(self):
        """confidence=30 (clearly shared) → very small contribution."""
        signal = abuseipdb_to_risk_signal(
            "100.64.0.1", 30, _DEFAULT_THRESHOLD, _DEFAULT_SCORE_CAP
        )
        self.assertIsNotNone(signal)
        # round(30/50 * 15) = round(9.0) = 9
        self.assertLessEqual(signal.score, 15)
        # Should not trigger flag alone
        self.assertLess(signal.score, _THRESHOLDS["flag"])

    def test_no_single_score_causes_hard_block(self):
        """No confidence value 0–100 alone produces a composite score ≥ block threshold.

        This test exhaustively verifies that for confidence in [0, 100],
        the AbuseIPDB signal score alone never reaches the block threshold (70)
        or ban threshold (85).
        """
        for confidence in range(0, 101):
            signal = abuseipdb_to_risk_signal(
                "1.2.3.4", confidence, _DEFAULT_THRESHOLD, _DEFAULT_SCORE_CAP
            )
            self.assertIsNotNone(signal)
            self.assertLess(
                signal.score,
                _THRESHOLDS["block"],
                f"confidence={confidence} produced score={signal.score} "
                f"≥ block threshold {_THRESHOLDS['block']}",
            )

    def test_score_cap_upper_bound_enforced(self):
        """Contribution never exceeds score_cap regardless of confidence."""
        for confidence in range(50, 101):
            signal = abuseipdb_to_risk_signal(
                "1.2.3.4", confidence, _DEFAULT_THRESHOLD, _DEFAULT_SCORE_CAP
            )
            self.assertLessEqual(
                signal.score,
                _DEFAULT_SCORE_CAP,
                f"confidence={confidence} exceeded score_cap={_DEFAULT_SCORE_CAP}",
            )

    def test_custom_score_cap_respected(self):
        """custom score_cap=20 is respected at confidence=100."""
        signal = abuseipdb_to_risk_signal("1.2.3.4", 100, _DEFAULT_THRESHOLD, 20)
        self.assertEqual(signal.score, 20)
        self.assertLess(signal.score, _THRESHOLDS["block"])

    def test_browser_alpn_ip_score_bounded(self):
        """Even if a browser-ALPN IP has AbuseIPDB confidence=100, score stays below block.

        Browser ALPN connections are bypassed before scoring in production. This
        test verifies the math: if they were scored, they still wouldn't be blocked
        by AbuseIPDB alone.
        """
        # Simulate: h2 browser IP with confidence=100
        signal = abuseipdb_to_risk_signal(
            "8.8.8.8",  # e.g. Google DNS, might have high AbuseIPDB score
            100,
            _DEFAULT_THRESHOLD,
            _DEFAULT_SCORE_CAP,
        )
        self.assertIsNotNone(signal)
        # Score must be ≤ score_cap and < block threshold
        self.assertLessEqual(signal.score, _DEFAULT_SCORE_CAP)
        self.assertLess(signal.score, _THRESHOLDS["block"])

    def test_threshold_boundary_confidence_50_exactly(self):
        """confidence=50 (exactly at threshold) → contribution uses full formula."""
        # At threshold: contribution = round(50/100 * 40) = 20
        signal = abuseipdb_to_risk_signal("1.2.3.4", 50, 50, 40)
        self.assertIsNotNone(signal)
        self.assertEqual(signal.score, 20)
        # At exactly flag threshold — but alone, just a flag, not a block
        self.assertLess(signal.score, _THRESHOLDS["rate_limit"])
