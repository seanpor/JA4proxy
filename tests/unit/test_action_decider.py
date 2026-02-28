"""Unit tests for src/security/action_decider.py — ActionDecider with dial."""

import pytest

from src.security.action_decider import ActionDecider

THRESHOLDS = {
    "flag": 20,
    "rate_limit": 35,
    "tarpit": 55,
    "block": 70,
    "ban": 85,
}


@pytest.fixture
def decider():
    return ActionDecider(thresholds=THRESHOLDS, ban_duration_seconds=300)


# ---------------------------------------------------------------------------
# dial=0 → always allow (monitor mode)
# ---------------------------------------------------------------------------


class TestDialZeroMonitorMode:
    def test_dial_zero_score_0_allows(self, decider):
        assert decider.decide(score=0, dial=0) == "allow"

    def test_dial_zero_score_50_allows(self, decider):
        assert decider.decide(score=50, dial=0) == "allow"

    def test_dial_zero_score_100_allows(self, decider):
        assert decider.decide(score=100, dial=0) == "allow"

    def test_dial_zero_score_85_allows_not_ban(self, decider):
        """Even ban-level score must be allowed at dial=0."""
        assert decider.decide(score=85, dial=0) == "allow"


# ---------------------------------------------------------------------------
# dial=100 → thresholds apply as configured
# ---------------------------------------------------------------------------


class TestDialHundredFullBlocking:
    @pytest.mark.parametrize(
        "score,expected",
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
    def test_at_dial_100(self, decider, score, expected):
        result = decider.decide(score=score, dial=100)
        assert result == expected, (
            f"dial=100, score={score}: expected {expected}, got {result}"
        )


# ---------------------------------------------------------------------------
# One below each threshold → previous action
# ---------------------------------------------------------------------------


class TestOneBelowThreshold:
    def test_one_below_flag(self, decider):
        assert decider.decide(score=19, dial=100) == "allow"

    def test_one_below_rate_limit(self, decider):
        assert decider.decide(score=34, dial=100) == "flag"

    def test_one_below_tarpit(self, decider):
        assert decider.decide(score=54, dial=100) == "rate_limit"

    def test_one_below_block(self, decider):
        assert decider.decide(score=69, dial=100) == "tarpit"

    def test_one_below_ban(self, decider):
        assert decider.decide(score=84, dial=100) == "block"


# ---------------------------------------------------------------------------
# Intermediate dial values — scaled thresholds
# ---------------------------------------------------------------------------


class TestIntermediateDial:
    def test_low_dial_allows_moderate_score(self):
        """At dial=10, thresholds are 10× higher — score=70 should allow."""
        decider = ActionDecider(thresholds=THRESHOLDS)
        # effective_ban = 85 × 100/10 = 850 → never triggered at score 70
        result = decider.decide(score=70, dial=10)
        assert result == "allow"

    def test_dial_50_mid_threshold(self):
        """At dial=50, effective thresholds are doubled."""
        decider = ActionDecider(thresholds=THRESHOLDS)
        # effective_flag = 20 × 100/50 = 40 → need score ≥ 40 for flag
        assert decider.decide(score=39, dial=50) == "allow"
        assert decider.decide(score=40, dial=50) == "flag"

    def test_score_zero_always_allows_at_any_dial(self, decider):
        for dial in [0, 10, 50, 75, 100]:
            assert decider.decide(score=0, dial=dial) == "allow"


# ---------------------------------------------------------------------------
# from_config factory
# ---------------------------------------------------------------------------


class TestFromConfig:
    def test_from_config_reads_thresholds(self):
        config = {
            "risk_scorer": {
                "thresholds": {
                    "flag": 15,
                    "rate_limit": 30,
                    "tarpit": 50,
                    "block": 65,
                    "ban": 80,
                },
                "ban_duration_seconds": 600,
            }
        }
        decider = ActionDecider.from_config(config)
        assert decider.decide(score=15, dial=100) == "flag"
        assert decider.decide(score=80, dial=100) == "ban"
        assert decider.ban_duration_seconds == 600

    def test_from_config_empty_uses_defaults(self):
        decider = ActionDecider.from_config({})
        assert decider.decide(score=70, dial=100) == "block"
        assert decider.ban_duration_seconds == 300

    def test_from_config_partial_thresholds(self):
        config = {
            "risk_scorer": {
                "thresholds": {"ban": 90},  # Only ban overridden
            }
        }
        decider = ActionDecider.from_config(config)
        # block threshold still at default 70
        assert decider.decide(score=70, dial=100) == "block"
        # ban now at 90
        assert decider.decide(score=89, dial=100) == "block"
        assert decider.decide(score=90, dial=100) == "ban"


# ---------------------------------------------------------------------------
# ban_duration_seconds attribute
# ---------------------------------------------------------------------------


class TestBanDuration:
    def test_default_ban_duration(self, decider):
        assert decider.ban_duration_seconds == 300

    def test_custom_ban_duration(self):
        d = ActionDecider(ban_duration_seconds=900)
        assert d.ban_duration_seconds == 900
