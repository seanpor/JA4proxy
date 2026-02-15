#!/usr/bin/env python3
"""
Unit tests for multi-strategy threat evaluator.

Tests threat evaluation across multiple strategies, policy enforcement,
and evaluation result handling.
"""

import pytest
from unittest.mock import Mock

from src.security.rate_strategy import RateLimitStrategy, RateMetrics
from src.security.threat_tier import ThreatTier, ThreatTierConfig
from src.security.threat_evaluator import (
    ThreatEvaluator,
    ThreatEvaluation,
    MultiStrategyPolicy,
)


class TestMultiStrategyPolicy:
    """Test MultiStrategyPolicy enum."""
    
    def test_policy_values(self):
        """Test policy enum values."""
        assert MultiStrategyPolicy.ANY.value == "any"
        assert MultiStrategyPolicy.ALL.value == "all"
        assert MultiStrategyPolicy.MAJORITY.value == "majority"
    
    def test_from_string_valid(self):
        """Test conversion from valid string."""
        assert MultiStrategyPolicy.from_string("any") == MultiStrategyPolicy.ANY
        assert MultiStrategyPolicy.from_string("all") == MultiStrategyPolicy.ALL
        assert MultiStrategyPolicy.from_string("majority") == MultiStrategyPolicy.MAJORITY
    
    def test_from_string_case_insensitive(self):
        """Test case-insensitive string conversion."""
        assert MultiStrategyPolicy.from_string("ANY") == MultiStrategyPolicy.ANY
        assert MultiStrategyPolicy.from_string("All") == MultiStrategyPolicy.ALL
        assert MultiStrategyPolicy.from_string("MAJORITY") == MultiStrategyPolicy.MAJORITY
    
    def test_from_string_invalid(self):
        """Test invalid string returns None."""
        assert MultiStrategyPolicy.from_string("invalid") is None
        assert MultiStrategyPolicy.from_string("") is None
        assert MultiStrategyPolicy.from_string(None) is None


class TestThreatEvaluation:
    """Test ThreatEvaluation dataclass."""
    
    def test_creation_valid(self):
        """Test creating valid evaluation."""
        eval = ThreatEvaluation(
            strategy=RateLimitStrategy.BY_IP,
            tier=ThreatTier.SUSPICIOUS,
            rate=2,
            threshold_exceeded=1,
            entity_id="192.168.1.100",
        )
        
        assert eval.strategy == RateLimitStrategy.BY_IP
        assert eval.tier == ThreatTier.SUSPICIOUS
        assert eval.rate == 2
        assert eval.threshold_exceeded == 1
        assert eval.entity_id == "192.168.1.100"
    
    def test_immutability(self):
        """Test that evaluation is immutable."""
        eval = ThreatEvaluation(
            strategy=RateLimitStrategy.BY_IP,
            tier=ThreatTier.NORMAL,
            rate=0,
            threshold_exceeded=0,
            entity_id="test",
        )
        
        with pytest.raises(AttributeError):
            eval.tier = ThreatTier.BANNED
    
    def test_validation_invalid_strategy(self):
        """Test validation rejects invalid strategy."""
        with pytest.raises(ValueError, match="Strategy must be"):
            ThreatEvaluation(
                strategy="invalid",
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="test",
            )
    
    def test_validation_invalid_tier(self):
        """Test validation rejects invalid tier."""
        with pytest.raises(ValueError, match="Tier must be"):
            ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier="invalid",
                rate=0,
                threshold_exceeded=0,
                entity_id="test",
            )
    
    def test_validation_negative_rate(self):
        """Test validation rejects negative rate."""
        with pytest.raises(ValueError, match="Rate cannot be negative"):
            ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=-1,
                threshold_exceeded=0,
                entity_id="test",
            )
    
    def test_validation_negative_threshold(self):
        """Test validation rejects negative threshold."""
        with pytest.raises(ValueError, match="Threshold cannot be negative"):
            ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=-1,
                entity_id="test",
            )
    
    def test_validation_empty_entity_id(self):
        """Test validation rejects empty entity ID."""
        with pytest.raises(ValueError, match="Entity ID cannot be empty"):
            ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="",
            )
    
    def test_to_dict(self):
        """Test serialization to dictionary."""
        eval = ThreatEvaluation(
            strategy=RateLimitStrategy.BY_IP,
            tier=ThreatTier.SUSPICIOUS,
            rate=2,
            threshold_exceeded=1,
            entity_id="192.168.1.100",
        )
        
        result = eval.to_dict()
        
        assert result['strategy'] == "by_ip"
        assert result['tier'] == "SUSPICIOUS"
        assert result['rate'] == 2
        assert result['threshold_exceeded'] == 1
        assert 'entity_id_hash' in result
        assert len(result['entity_id_hash']) == 16  # SHA256 truncated to 16 chars


class TestThreatEvaluator:
    """Test ThreatEvaluator class."""
    
    @pytest.fixture
    def tier_config(self):
        """Create test tier configuration."""
        return ThreatTierConfig(
            suspicious_threshold=1,
            block_threshold=5,
            ban_threshold=10,
        )
    
    @pytest.fixture
    def strategy_configs(self):
        """Create test strategy configurations."""
        return {
            RateLimitStrategy.BY_IP: {
                'enabled': True,
                'thresholds': {'suspicious': 2, 'block': 10, 'ban': 20},
            },
            RateLimitStrategy.BY_JA4: {
                'enabled': True,
                'thresholds': {'suspicious': 5, 'block': 25, 'ban': 50},
            },
            RateLimitStrategy.BY_IP_JA4_PAIR: {
                'enabled': True,
                'thresholds': {'suspicious': 1, 'block': 5, 'ban': 10},
            },
        }
    
    @pytest.fixture
    def evaluator(self, tier_config, strategy_configs):
        """Create test evaluator."""
        return ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs=strategy_configs,
            policy=MultiStrategyPolicy.ANY,
        )
    
    def test_initialization(self, tier_config, strategy_configs):
        """Test evaluator initialization."""
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs=strategy_configs,
            policy=MultiStrategyPolicy.ANY,
        )
        
        assert evaluator.tier_config == tier_config
        assert evaluator.strategy_configs == strategy_configs
        assert evaluator.policy == MultiStrategyPolicy.ANY
    
    def test_evaluate_single_normal(self, evaluator):
        """Test evaluating normal traffic."""
        tier, threshold = evaluator._evaluate_single(
            connections_per_second=0,
            thresholds={'suspicious': 1, 'block': 5, 'ban': 10}
        )
        
        assert tier == ThreatTier.NORMAL
        assert threshold == 0
    
    def test_evaluate_single_suspicious(self, evaluator):
        """Test evaluating suspicious traffic."""
        tier, threshold = evaluator._evaluate_single(
            connections_per_second=2,
            thresholds={'suspicious': 1, 'block': 5, 'ban': 10}
        )
        
        assert tier == ThreatTier.SUSPICIOUS
        assert threshold == 1
    
    def test_evaluate_single_block(self, evaluator):
        """Test evaluating block-level traffic."""
        tier, threshold = evaluator._evaluate_single(
            connections_per_second=7,
            thresholds={'suspicious': 1, 'block': 5, 'ban': 10}
        )
        
        assert tier == ThreatTier.BLOCK
        assert threshold == 5
    
    def test_evaluate_single_banned(self, evaluator):
        """Test evaluating ban-level traffic."""
        tier, threshold = evaluator._evaluate_single(
            connections_per_second=15,
            thresholds={'suspicious': 1, 'block': 5, 'ban': 10}
        )
        
        assert tier == ThreatTier.BANNED
        assert threshold == 10
    
    def test_evaluate_multi_strategy(self, evaluator):
        """Test multi-strategy evaluation."""
        rate_results = {
            RateLimitStrategy.BY_IP: RateMetrics(
                connections_per_second=0,
                strategy=RateLimitStrategy.BY_IP,
                entity_id="192.168.1.100",
                timestamp=1234567890.0,
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: RateMetrics(
                connections_per_second=6,
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                entity_id="192.168.1.100|t13d1516h2_abc_def",
                timestamp=1234567890.0,
            ),
        }
        
        evaluations = evaluator.evaluate_multi_strategy(rate_results)
        
        assert len(evaluations) == 2
        assert evaluations[RateLimitStrategy.BY_IP].tier == ThreatTier.NORMAL
        assert evaluations[RateLimitStrategy.BY_IP_JA4_PAIR].tier == ThreatTier.BLOCK
    
    def test_get_most_severe_tier(self, evaluator):
        """Test getting most severe tier."""
        evaluations = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="192.168.1.100",
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                tier=ThreatTier.BLOCK,
                rate=6,
                threshold_exceeded=5,
                entity_id="192.168.1.100|t13d",
            ),
        }
        
        most_severe = evaluator.get_most_severe_tier(evaluations)
        assert most_severe == ThreatTier.BLOCK
    
    def test_get_most_severe_tier_empty(self, evaluator):
        """Test getting most severe tier with no evaluations."""
        most_severe = evaluator.get_most_severe_tier({})
        assert most_severe == ThreatTier.NORMAL
    
    def test_get_triggering_strategy(self, evaluator):
        """Test identifying which strategy triggered a tier."""
        evaluations = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="192.168.1.100",
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                tier=ThreatTier.BLOCK,
                rate=6,
                threshold_exceeded=5,
                entity_id="192.168.1.100|t13d",
            ),
        }
        
        strategy = evaluator.get_triggering_strategy(
            evaluations,
            ThreatTier.BLOCK
        )
        assert strategy == RateLimitStrategy.BY_IP_JA4_PAIR
    
    def test_get_triggering_strategy_none(self, evaluator):
        """Test getting triggering strategy when none match."""
        evaluations = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="192.168.1.100",
            ),
        }
        
        strategy = evaluator.get_triggering_strategy(
            evaluations,
            ThreatTier.BLOCK
        )
        assert strategy is None
    
    def test_should_apply_action_policy_any(self, tier_config, strategy_configs):
        """Test action application with ANY policy."""
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs=strategy_configs,
            policy=MultiStrategyPolicy.ANY,
        )
        
        # One threat should trigger action
        evaluations = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="test",
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                tier=ThreatTier.SUSPICIOUS,
                rate=2,
                threshold_exceeded=1,
                entity_id="test",
            ),
        }
        
        assert evaluator.should_apply_action(evaluations) is True
    
    def test_should_apply_action_policy_all(self, tier_config, strategy_configs):
        """Test action application with ALL policy."""
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs=strategy_configs,
            policy=MultiStrategyPolicy.ALL,
        )
        
        # All must be threats
        evaluations_one_normal = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="test",
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                tier=ThreatTier.SUSPICIOUS,
                rate=2,
                threshold_exceeded=1,
                entity_id="test",
            ),
        }
        
        assert evaluator.should_apply_action(evaluations_one_normal) is False
        
        # All threats should trigger
        evaluations_all_threats = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.SUSPICIOUS,
                rate=3,
                threshold_exceeded=2,
                entity_id="test",
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                tier=ThreatTier.BLOCK,
                rate=6,
                threshold_exceeded=5,
                entity_id="test",
            ),
        }
        
        assert evaluator.should_apply_action(evaluations_all_threats) is True
    
    def test_should_apply_action_policy_majority(self, tier_config, strategy_configs):
        """Test action application with MAJORITY policy."""
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs=strategy_configs,
            policy=MultiStrategyPolicy.MAJORITY,
        )
        
        # 2 out of 3 is majority
        evaluations = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="test",
            ),
            RateLimitStrategy.BY_JA4: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_JA4,
                tier=ThreatTier.SUSPICIOUS,
                rate=6,
                threshold_exceeded=5,
                entity_id="test",
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                tier=ThreatTier.BLOCK,
                rate=6,
                threshold_exceeded=5,
                entity_id="test",
            ),
        }
        
        assert evaluator.should_apply_action(evaluations) is True
    
    def test_should_apply_action_empty(self, evaluator):
        """Test action application with no evaluations."""
        assert evaluator.should_apply_action({}) is False
    
    def test_get_evaluation_summary(self, evaluator):
        """Test evaluation summary generation."""
        evaluations = {
            RateLimitStrategy.BY_IP: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP,
                tier=ThreatTier.NORMAL,
                rate=0,
                threshold_exceeded=0,
                entity_id="test",
            ),
            RateLimitStrategy.BY_IP_JA4_PAIR: ThreatEvaluation(
                strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
                tier=ThreatTier.BLOCK,
                rate=6,
                threshold_exceeded=5,
                entity_id="test",
            ),
        }
        
        summary = evaluator.get_evaluation_summary(evaluations)
        
        assert summary['total_strategies'] == 2
        assert summary['threats_detected'] == 1
        assert summary['most_severe_tier'] == "BLOCK"
        assert summary['policy'] == "any"
        assert summary['action_triggered'] is True
        assert len(summary['evaluations']) == 2
    
    def test_from_config(self):
        """Test creation from configuration dictionary."""
        config = {
            'security': {
                'thresholds': {
                    'suspicious': 1,
                    'block': 5,
                    'ban': 10,
                },
                'ban_durations': {
                    'suspicious': 300,
                    'block': 3600,
                    'ban': 604800,
                },
                'rate_limit_strategies': {
                    'by_ip': {
                        'enabled': True,
                        'thresholds': {'suspicious': 2, 'block': 10, 'ban': 20},
                    },
                    'by_ip_ja4_pair': {
                        'enabled': True,
                        'thresholds': {'suspicious': 1, 'block': 5, 'ban': 10},
                    },
                },
                'multi_strategy_policy': 'any',
            }
        }
        
        evaluator = ThreatEvaluator.from_config(config)
        
        assert evaluator.policy == MultiStrategyPolicy.ANY
        assert RateLimitStrategy.BY_IP in evaluator.strategy_configs
        assert RateLimitStrategy.BY_IP_JA4_PAIR in evaluator.strategy_configs
    
    def test_from_config_invalid_policy(self):
        """Test creation with invalid policy falls back to ANY."""
        config = {
            'security': {
                'multi_strategy_policy': 'invalid',
                'rate_limit_strategies': {},
            }
        }
        
        evaluator = ThreatEvaluator.from_config(config)
        assert evaluator.policy == MultiStrategyPolicy.ANY
    
    def test_from_config_missing_sections(self):
        """Test creation with missing config sections."""
        config = {}
        
        evaluator = ThreatEvaluator.from_config(config)
        assert evaluator.policy == MultiStrategyPolicy.ANY
        assert len(evaluator.strategy_configs) == 0


class TestThreatEvaluatorEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_evaluate_exact_threshold_values(self):
        """Test evaluation at exact threshold boundaries."""
        tier_config = ThreatTierConfig(
            suspicious_threshold=1,
            block_threshold=5,
            ban_threshold=10,
        )
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs={},
            policy=MultiStrategyPolicy.ANY,
        )
        
        # Exactly at suspicious threshold
        tier, _ = evaluator._evaluate_single(
            connections_per_second=1,
            thresholds={'suspicious': 1, 'block': 5, 'ban': 10}
        )
        assert tier == ThreatTier.NORMAL  # Not exceeding
        
        # Just above suspicious threshold
        tier, _ = evaluator._evaluate_single(
            connections_per_second=2,
            thresholds={'suspicious': 1, 'block': 5, 'ban': 10}
        )
        assert tier == ThreatTier.SUSPICIOUS
    
    def test_strategy_with_invalid_thresholds(self):
        """Test handling of invalid threshold configuration."""
        tier_config = ThreatTierConfig()
        evaluator = ThreatEvaluator(
            tier_config=tier_config,
            strategy_configs={
                RateLimitStrategy.BY_IP: {
                    'thresholds': {
                        'suspicious': 10,
                        'block': 5,  # Invalid: block < suspicious
                        'ban': 20,
                    }
                }
            },
            policy=MultiStrategyPolicy.ANY,
        )
        
        # Should fall back to safe defaults
        thresholds = evaluator._get_strategy_thresholds(
            RateLimitStrategy.BY_IP,
            evaluator.strategy_configs[RateLimitStrategy.BY_IP]
        )
        
        assert thresholds['suspicious'] == 1
        assert thresholds['block'] == 5
        assert thresholds['ban'] == 10
