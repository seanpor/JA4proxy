"""Unit tests for src/security/risk_scorer.py — RiskScorer and RiskSignal."""

import pytest

from src.security.risk_scorer import (
    RiskAssessment,
    RiskScorer,
    RiskSignal,
    _build_explanation,
    _derive_action,
)

# Default thresholds matching proxy.yml
THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


@pytest.fixture
def scorer():
    return RiskScorer(THRESHOLDS)


# ---------------------------------------------------------------------------
# RiskSignal
# ---------------------------------------------------------------------------


class TestRiskSignal:
    def test_basic_construction(self):
        sig = RiskSignal(name="missing_sni", score=30, reason="No SNI")
        assert sig.name == "missing_sni"
        assert sig.score == 30
        assert sig.reason == "No SNI"
        assert sig.weight == 1.0

    def test_custom_weight(self):
        sig = RiskSignal(name="abuseipdb", score=40, reason="test", weight=0.5)
        assert sig.weight == 0.5

    def test_negative_score_allowed(self):
        sig = RiskSignal(name="return_visitor", score=-20, reason="trust")
        assert sig.score == -20


# ---------------------------------------------------------------------------
# RiskScorer.score — empty signals
# ---------------------------------------------------------------------------


class TestRiskScorerEmpty:
    def test_empty_signals_score_zero(self, scorer):
        result = scorer.score([])
        assert result.total_score == 0

    def test_empty_signals_action_allow(self, scorer):
        result = scorer.score([])
        assert result.recommended_action == "allow"

    def test_empty_signals_empty_explanation(self, scorer):
        result = scorer.score([])
        assert result.explanation == ""

    def test_empty_signals_empty_signals_list(self, scorer):
        result = scorer.score([])
        assert result.signals == []

    def test_returns_risk_assessment(self, scorer):
        result = scorer.score([])
        assert isinstance(result, RiskAssessment)


# ---------------------------------------------------------------------------
# RiskScorer.score — single signal
# ---------------------------------------------------------------------------


class TestRiskScorerSingleSignal:
    def test_score_matches_signal(self, scorer):
        result = scorer.score([RiskSignal("missing_sni", 30, "no sni")])
        assert result.total_score == 30

    def test_action_flag_at_20(self, scorer):
        result = scorer.score([RiskSignal("dga", 20, "test")])
        assert result.recommended_action == "flag"

    def test_action_rate_limit_at_35(self, scorer):
        result = scorer.score([RiskSignal("asn_datacenter", 35, "test")])
        assert result.recommended_action == "rate_limit"

    def test_action_tarpit_at_55(self, scorer):
        result = scorer.score([RiskSignal("beaconing", 55, "test")])
        assert result.recommended_action == "tarpit"

    def test_action_block_at_70(self, scorer):
        result = scorer.score([RiskSignal("rdap_known_bad_org", 70, "test")])
        assert result.recommended_action == "block"

    def test_action_ban_at_85(self, scorer):
        result = scorer.score([RiskSignal("asn_tor", 85, "test")])
        assert result.recommended_action == "ban"

    def test_action_allow_below_flag(self, scorer):
        result = scorer.score([RiskSignal("asn_unknown", 5, "test")])
        assert result.recommended_action == "allow"

    def test_explanation_contains_signal_name(self, scorer):
        result = scorer.score([RiskSignal("missing_sni", 30, "no sni")])
        assert "missing_sni" in result.explanation


# ---------------------------------------------------------------------------
# RiskScorer.score — multiple signals
# ---------------------------------------------------------------------------


class TestRiskScorerMultipleSignals:
    def test_scores_summed(self, scorer):
        sigs = [
            RiskSignal("missing_sni", 30, "no sni"),
            RiskSignal("asn_tor", 40, "tor"),
        ]
        result = scorer.score(sigs)
        assert result.total_score == 70

    def test_score_clamped_at_100(self, scorer):
        sigs = [
            RiskSignal("rdap_known_bad_org", 45, "bad org"),
            RiskSignal("missing_sni", 30, "no sni"),
            RiskSignal("asn_tor", 40, "tor"),
            RiskSignal("beaconing", 35, "beacon"),
        ]
        result = scorer.score(sigs)
        assert result.total_score == 100

    def test_negative_signal_reduces_score(self, scorer):
        sigs = [
            RiskSignal("asn_datacenter", 30, "dc"),
            RiskSignal("return_visitor", -20, "trusted"),
        ]
        result = scorer.score(sigs)
        assert result.total_score == 10

    def test_negative_signal_never_below_zero(self, scorer):
        sigs = [
            RiskSignal("return_visitor", -20, "trusted"),
            RiskSignal("residential_ptr", -10, "residential"),
        ]
        result = scorer.score(sigs)
        assert result.total_score == 0

    def test_negative_signal_does_not_crash(self, scorer):
        result = scorer.score([RiskSignal("return_visitor", -20, "test")])
        assert isinstance(result, RiskAssessment)

    def test_signals_preserved_in_assessment(self, scorer):
        sigs = [RiskSignal("missing_sni", 30, "test")]
        result = scorer.score(sigs)
        assert len(result.signals) == 1

    def test_weight_applied_to_contribution(self, scorer):
        sig = RiskSignal("abuseipdb", 40, "test", weight=0.5)
        result = scorer.score([sig])
        assert result.total_score == 20  # 40 × 0.5

    def test_explanation_shows_top_3(self, scorer):
        sigs = [
            RiskSignal("sig1", 40, ""),
            RiskSignal("sig2", 30, ""),
            RiskSignal("sig3", 20, ""),
            RiskSignal("sig4", 10, ""),
        ]
        result = scorer.score(sigs)
        assert "sig1" in result.explanation
        assert "sig2" in result.explanation
        assert "sig3" in result.explanation
        assert "sig4" not in result.explanation  # Only top 3

    def test_explanation_sorted_descending(self, scorer):
        sigs = [
            RiskSignal("low", 10, ""),
            RiskSignal("high", 45, ""),
            RiskSignal("mid", 30, ""),
        ]
        result = scorer.score(sigs)
        idx_high = result.explanation.index("high")
        idx_mid = result.explanation.index("mid")
        idx_low = result.explanation.index("low")
        assert idx_high < idx_mid < idx_low


# ---------------------------------------------------------------------------
# Signal clamping
# ---------------------------------------------------------------------------


class TestSignalClamping:
    def test_individual_signal_over_100_clamped(self, scorer):
        result = scorer.score([RiskSignal("bad", 150, "test")])
        assert result.total_score == 100  # Clamped at composite level too

    def test_individual_signal_under_minus_100_clamped(self, scorer):
        result = scorer.score(
            [
                RiskSignal("good", 50, "test"),
                RiskSignal("very_trusted", -200, "test"),
            ]
        )
        assert result.total_score == 0  # Clamped to 0


# ---------------------------------------------------------------------------
# Threshold boundary tests
# ---------------------------------------------------------------------------


class TestThresholdBoundaries:
    @pytest.mark.parametrize(
        "score,expected_action",
        [
            (0, "allow"),
            (19, "allow"),
            (20, "flag"),
            (34, "flag"),
            (35, "rate_limit"),
            (54, "rate_limit"),
            (55, "tarpit"),
            (69, "tarpit"),
            (70, "block"),
            (84, "block"),
            (85, "ban"),
            (100, "ban"),
        ],
    )
    def test_threshold_boundary(self, score, expected_action):
        result = _derive_action(score, THRESHOLDS)
        assert (
            result == expected_action
        ), f"score={score}: expected {expected_action}, got {result}"


# ---------------------------------------------------------------------------
# _build_explanation
# ---------------------------------------------------------------------------


class TestBuildExplanation:
    def test_empty_signals(self):
        assert _build_explanation([]) == ""

    def test_single_positive_signal(self):
        sigs = [RiskSignal("missing_sni", 30, "")]
        assert "missing_sni(+30)" in _build_explanation(sigs)

    def test_single_negative_signal(self):
        sigs = [RiskSignal("return_visitor", -20, "")]
        assert "return_visitor(-20)" in _build_explanation(sigs)

    def test_max_three_signals_shown(self):
        sigs = [RiskSignal(f"sig{i}", i * 10, "") for i in range(1, 6)]
        result = _build_explanation(sigs)
        assert result.count("sig") == 3


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestRiskScorerFromConfig:
    """Cover lines 112-113: RiskScorer.from_config() classmethod."""

    def test_from_config_returns_instance(self):
        """Lines 112-113: from_config() reads risk_scorer.thresholds from config
        and constructs a RiskScorer instance.
        So what: if from_config() is broken, the proxy falls back to a default
        RiskScorer with no thresholds, silently ignoring operator-configured
        scoring policy — all traffic scores would use the hardcoded defaults."""
        config = {
            "risk_scorer": {
                "thresholds": {"flag": 30, "rate_limit": 50, "block": 75, "ban": 90}
            }
        }
        scorer = RiskScorer.from_config(config)
        assert isinstance(scorer, RiskScorer)
        # The thresholds should be loaded from config
        assert scorer._thresholds.get("flag") == 30

    def test_from_config_empty_config_uses_defaults(self):
        """from_config({}) constructs RiskScorer with empty thresholds (uses defaults).
        So what: a missing config key must not raise KeyError — the proxy must
        start cleanly with default scoring even without a risk_scorer config block."""
        scorer = RiskScorer.from_config({})
        assert isinstance(scorer, RiskScorer)
