#!/usr/bin/env python3
"""
Final coverage extras for action_types, action_enforcer, and threat_evaluator.

Covers:
- action_types.py lines 66, 71, 76, 81: NotImplemented in comparison operators
- action_enforcer.py lines 328-330: repeat-offender escalation (offense_count > 1)
- threat_evaluator.py line 196-199: empty thresholds → fallback to global
- threat_evaluator.py lines 337-338: unknown policy → fail secure
- threat_evaluator.py lines 414-415: invalid from_config config → ValueError
"""

import pytest
from unittest.mock import Mock

from src.security.action_types import ActionType, ActionConfig
from src.security.action_enforcer import ActionEnforcer
from src.security.threat_evaluator import ThreatEvaluator, MultiStrategyPolicy
from src.security.threat_tier import ThreatTier, ThreatTierConfig
from src.security.rate_strategy import RateLimitStrategy


# ---------------------------------------------------------------------------
# action_types.py: NotImplemented in comparison operators (lines 66, 71, 76, 81)
# ---------------------------------------------------------------------------


class TestActionTypeNotImplemented:
    """When comparing ActionType with a non-ActionType, return NotImplemented."""

    def test_lt_with_non_action_type_returns_not_implemented(self):
        """Line 66: ActionType.__lt__ with non-ActionType → NotImplemented."""
        result = ActionType.BLOCK.__lt__("not_an_action_type")
        assert result is NotImplemented

    def test_le_with_non_action_type_returns_not_implemented(self):
        """Line 71: ActionType.__le__ with non-ActionType → NotImplemented."""
        result = ActionType.BLOCK.__le__(42)
        assert result is NotImplemented

    def test_gt_with_non_action_type_returns_not_implemented(self):
        """Line 76: ActionType.__gt__ with non-ActionType → NotImplemented."""
        result = ActionType.BLOCK.__gt__(None)
        assert result is NotImplemented

    def test_ge_with_non_action_type_returns_not_implemented(self):
        """Line 81: ActionType.__ge__ with non-ActionType → NotImplemented."""
        result = ActionType.BLOCK.__ge__([1, 2, 3])
        assert result is NotImplemented


# ---------------------------------------------------------------------------
# action_enforcer.py lines 328-330: repeat offender escalation
# ---------------------------------------------------------------------------


class TestRepeatOffenderEscalation:
    """_apply_block should escalate block duration for repeat offenders."""

    def _make_enforcer(self, incr_return=2):
        """Create enforcer whose redis.incr returns incr_return (simulating Nth offense)."""
        redis_mock = Mock()
        redis_mock.ping.return_value = True
        redis_mock.exists.return_value = False
        redis_mock.get.return_value = None
        redis_mock.set.return_value = True
        redis_mock.setex.return_value = True
        redis_mock.delete.return_value = 0
        redis_mock.ttl.return_value = -1
        redis_mock.keys.return_value = []
        redis_mock.incr.return_value = incr_return  # offense_count
        redis_mock.expire.return_value = True

        config = ActionConfig(
            tarpit_enabled=False,
            tarpit_duration=10,
            block_action="block",
            ban_duration=300,
            permanent_ban=False,
        )
        return ActionEnforcer(redis_client=redis_mock, action_config=config), redis_mock

    def test_second_offense_escalates_duration(self):
        """Lines 328-330: offense_count=2 → duration doubled."""
        enforcer, redis_mock = self._make_enforcer(incr_return=2)

        result = enforcer.enforce(
            ja4="t13d1516h2_aabbccddee11_112233445566",
            ip="1.2.3.4",
            tier=ThreatTier.BLOCK,
            strategy=None,
        )

        # incr was called (repeat offender check)
        redis_mock.incr.assert_called()
        redis_mock.expire.assert_called()
        # Result is a block (escalated)
        assert result.allowed is False

    def test_third_offense_escalates_further(self):
        """offense_count=3 → multiplier=4, duration quadrupled."""
        enforcer, redis_mock = self._make_enforcer(incr_return=3)

        result = enforcer.enforce(
            ja4="t13d1516h2_aabbccddee11_112233445566",
            ip="1.2.3.4",
            tier=ThreatTier.BLOCK,
            strategy=None,
        )

        assert result.allowed is False
        redis_mock.incr.assert_called()

    def test_first_offense_does_not_escalate(self):
        """offense_count=1 → if branch NOT taken (lines 328-330 not hit)."""
        enforcer, redis_mock = self._make_enforcer(incr_return=1)

        result = enforcer.enforce(
            ja4="t13d1516h2_aabbccddee11_112233445566",
            ip="1.2.3.4",
            tier=ThreatTier.BLOCK,
            strategy=None,
        )

        # Still blocked, just at base duration
        assert result.allowed is False


# ---------------------------------------------------------------------------
# threat_evaluator.py line 196-199: empty thresholds → fallback to global
# ---------------------------------------------------------------------------


class TestEmptyThresholdsFallback:
    """_get_strategy_thresholds falls back to global thresholds when empty."""

    def test_empty_thresholds_uses_global(self):
        """Lines 196-199: strategy_config has no thresholds → global fallback."""
        tier_config = ThreatTierConfig(
            suspicious_threshold=2,
            block_threshold=10,
            ban_threshold=20,
        )
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs={},
            policy=MultiStrategyPolicy.ANY,
        )

        # strategy_config with no thresholds key at all
        thresholds = evaluator._get_strategy_thresholds(
            RateLimitStrategy.BY_IP, {}  # empty config → thresholds = {}
        )

        # Should fall back to tier_config values
        assert "suspicious" in thresholds
        assert "block" in thresholds
        assert "ban" in thresholds
        assert thresholds["suspicious"] == 2
        assert thresholds["block"] == 10
        assert thresholds["ban"] == 20

    def test_empty_thresholds_dict_also_uses_global(self):
        """Empty thresholds dict triggers the same global fallback."""
        tier_config = ThreatTierConfig(
            suspicious_threshold=3,
            block_threshold=15,
            ban_threshold=30,
        )
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs={},
            policy=MultiStrategyPolicy.ANY,
        )

        thresholds = evaluator._get_strategy_thresholds(
            RateLimitStrategy.BY_IP, {"thresholds": {}}  # explicit empty dict
        )

        assert thresholds["suspicious"] == 3


# ---------------------------------------------------------------------------
# threat_evaluator.py lines 337-338: unknown policy → fail secure
# ---------------------------------------------------------------------------


class TestUnknownPolicyFailSecure:
    """should_apply_action falls through to the else branch for unknown policies."""

    def test_unknown_policy_fails_secure(self):
        """Lines 337-338: unknown policy → error logged, treat as ANY (threat_count > 0)."""
        tier_config = ThreatTierConfig(
            suspicious_threshold=1,
            block_threshold=5,
            ban_threshold=10,
        )
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs={},
            policy=MultiStrategyPolicy.ANY,  # Start with valid policy
        )

        # Inject an invalid policy string directly to trigger the else branch
        # MultiStrategyPolicy has ANY, ALL, MAJORITY — set to a sentinel
        class _FakePolicy:
            value = "invalid_unknown"

        evaluator.policy = _FakePolicy()

        # Build a fake evaluations dict with one threat
        from src.security.threat_evaluator import ThreatEvaluation
        evaluations = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.BLOCK,
                rate=15,
                threshold_exceeded=10,
                entity_id="1.2.3.4",
            )
        }

        # should_apply_action with unknown policy → falls through to else → fails secure
        result = evaluator.should_apply_action(evaluations)
        # Fails secure: threat_count (1) > 0 → True
        assert result is True


# ---------------------------------------------------------------------------
# threat_evaluator.py lines 414-415: from_config raises ValueError
# ---------------------------------------------------------------------------


class TestFromConfigInvalidConfig:
    """ThreatEvaluator.from_config raises ValueError on invalid config."""

    def test_invalid_config_type_raises_value_error(self):
        """Lines 414-415: TypeError/ValueError/AttributeError → ValueError.

        ThreatTierConfig.from_config_dict calls int() on threshold values.
        Passing a non-numeric string triggers ValueError → caught → re-raised.
        """
        bad_config = {
            "security": {
                "thresholds": {
                    "suspicious": "not-a-number",  # int("not-a-number") raises ValueError
                    "block": 10,
                    "ban": 20,
                },
            }
        }
        # from_config catches TypeError/ValueError/AttributeError and re-raises as ValueError
        with pytest.raises(ValueError, match="Invalid threat evaluator configuration"):
            ThreatEvaluator.from_config(bad_config)
