#!/usr/bin/env python3
"""
Multi-strategy threat evaluation for JA4 proxy.

This module evaluates threat levels based on connection patterns across
multiple rate limiting strategies, implementing defense in depth.

Security Considerations:
- Multiple independent strategies prevent bypass
- Configurable policies (any/all/majority) provide flexibility
- Immutable evaluation results prevent tampering
- Comprehensive logging for security audit trail
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from .rate_strategy import RateLimitStrategy, RateMetrics
from .threat_tier import ThreatTier, ThreatTierConfig


class MultiStrategyPolicy(Enum):
    """
    Policy for combining results from multiple rate limiting strategies.
    
    ANY: Apply action if ANY strategy exceeds its threshold
        - Most protective, blocks on first strategy trigger
        - Recommended for high-security environments
        - Defense in depth approach
    
    ALL: Apply action only if ALL enabled strategies exceed thresholds
        - Most permissive, requires consensus
        - Use when false positives are costly
        - May miss coordinated attacks
    
    MAJORITY: Apply action if majority of strategies exceed thresholds
        - Balanced approach
        - Good for normal production environments
        - Reduces false positives while maintaining security
    """
    
    ANY = "any"
    ALL = "all"
    MAJORITY = "majority"
    
    @classmethod
    def from_string(cls, policy_str: str) -> Optional['MultiStrategyPolicy']:
        """Convert string to policy enum with validation."""
        try:
            return cls(policy_str.lower())
        except (ValueError, AttributeError):
            return None


@dataclass(frozen=True)
class ThreatEvaluation:
    """
    Immutable threat evaluation result for a single strategy.
    
    Security: Immutable to prevent tampering after evaluation.
    """
    
    strategy: RateLimitStrategy
    tier: ThreatTier
    rate: int  # connections per second
    threshold_exceeded: int  # which threshold was exceeded
    entity_id: str
    
    def __post_init__(self):
        """Validate evaluation on creation."""
        if not isinstance(self.strategy, RateLimitStrategy):
            raise ValueError("Strategy must be RateLimitStrategy enum")
        if not isinstance(self.tier, ThreatTier):
            raise ValueError("Tier must be ThreatTier enum")
        if self.rate < 0:
            raise ValueError("Rate cannot be negative")
        if self.threshold_exceeded < 0:
            raise ValueError("Threshold cannot be negative")
        if not self.entity_id:
            raise ValueError("Entity ID cannot be empty")
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging/metrics."""
        import hashlib
        return {
            'strategy': self.strategy.value,
            'tier': self.tier.name,
            'rate': self.rate,
            'threshold_exceeded': self.threshold_exceeded,
            'entity_id_hash': hashlib.sha256(
                self.entity_id.encode()
            ).hexdigest()[:16],
        }


class ThreatEvaluator:
    """
    Evaluate threat level based on connection patterns across strategies.
    
    This class implements multi-strategy threat detection, allowing the
    system to detect different attack patterns using complementary strategies.
    """
    
    def __init__(
        self,
        tier_config: ThreatTierConfig,
        strategy_configs: Dict[RateLimitStrategy, Dict],
        policy: MultiStrategyPolicy = MultiStrategyPolicy.ANY,
    ):
        """
        Initialize threat evaluator.
        
        Args:
            tier_config: Global threat tier configuration
            strategy_configs: Per-strategy threshold configurations
            policy: Multi-strategy combination policy
        """
        self.tier_config = tier_config
        self.strategy_configs = strategy_configs
        self.policy = policy
        self.logger = logging.getLogger(__name__)
    
    def evaluate_multi_strategy(
        self,
        rate_results: Dict[RateLimitStrategy, RateMetrics]
    ) -> Dict[RateLimitStrategy, ThreatEvaluation]:
        """
        Evaluate threat tier for each strategy.
        
        Args:
            rate_results: Rate metrics for each active strategy
            
        Returns:
            Dictionary mapping strategy to threat evaluation
            
        Security:
            - Each strategy evaluated independently
            - Results are immutable after creation
            - All evaluations logged for audit trail
        """
        evaluations = {}
        
        for strategy, metrics in rate_results.items():
            # Get strategy-specific configuration
            strategy_config = self.strategy_configs.get(strategy, {})
            
            # Get thresholds for this strategy
            thresholds = self._get_strategy_thresholds(strategy, strategy_config)
            
            # Evaluate tier for this strategy
            tier, threshold = self._evaluate_single(
                metrics.connections_per_second,
                thresholds
            )
            
            # Create immutable evaluation result
            evaluation = ThreatEvaluation(
                strategy=strategy,
                tier=tier,
                rate=metrics.connections_per_second,
                threshold_exceeded=threshold,
                entity_id=metrics.entity_id,
            )
            
            evaluations[strategy] = evaluation
            
            # Log if threat detected
            if tier != ThreatTier.NORMAL:
                self.logger.warning(
                    f"Threat detected - Strategy: {strategy.value}, "
                    f"Entity: {metrics.entity_id[:32]}..., "
                    f"Rate: {metrics.connections_per_second}/sec, "
                    f"Tier: {tier.name}, "
                    f"Threshold: {threshold}/sec"
                )
        
        return evaluations
    
    def _get_strategy_thresholds(
        self,
        strategy: RateLimitStrategy,
        strategy_config: Dict
    ) -> Dict[str, int]:
        """
        Get thresholds for a specific strategy.
        
        Falls back to global thresholds if strategy-specific not configured.
        """
        # Try strategy-specific thresholds first
        thresholds = strategy_config.get('thresholds', {})
        
        if not thresholds:
            # Fall back to global thresholds
            thresholds = {
                'suspicious': self.tier_config.get_threshold(ThreatTier.SUSPICIOUS),
                'block': self.tier_config.get_threshold(ThreatTier.BLOCK),
                'ban': self.tier_config.get_threshold(ThreatTier.BANNED),
            }
        
        # Validate thresholds
        suspicious = int(thresholds.get('suspicious', 1))
        block = int(thresholds.get('block', 5))
        ban = int(thresholds.get('ban', 10))
        
        if not (0 <= suspicious <= block <= ban):
            self.logger.error(
                f"Invalid thresholds for {strategy.value}: "
                f"suspicious={suspicious}, block={block}, ban={ban}"
            )
            # Use safe defaults
            return {'suspicious': 1, 'block': 5, 'ban': 10}
        
        return {'suspicious': suspicious, 'block': block, 'ban': ban}
    
    def _evaluate_single(
        self,
        connections_per_second: int,
        thresholds: Dict[str, int]
    ) -> tuple[ThreatTier, int]:
        """
        Evaluate threat tier for a single metric.
        
        Args:
            connections_per_second: Current connection rate
            thresholds: Threshold values for each tier
            
        Returns:
            Tuple of (tier, threshold_value)
        """
        ban_threshold = thresholds.get('ban', 10)
        block_threshold = thresholds.get('block', 5)
        suspicious_threshold = thresholds.get('suspicious', 1)
        
        if connections_per_second > ban_threshold:
            return ThreatTier.BANNED, ban_threshold
        elif connections_per_second > block_threshold:
            return ThreatTier.BLOCK, block_threshold
        elif connections_per_second > suspicious_threshold:
            return ThreatTier.SUSPICIOUS, suspicious_threshold
        else:
            return ThreatTier.NORMAL, 0
    
    def get_most_severe_tier(
        self,
        evaluations: Dict[RateLimitStrategy, ThreatEvaluation]
    ) -> ThreatTier:
        """
        Get the most severe threat tier across all strategies.
        
        Used when policy is ANY - takes the highest severity tier.
        
        Args:
            evaluations: Threat evaluations for each strategy
            
        Returns:
            Most severe ThreatTier
        """
        if not evaluations:
            return ThreatTier.NORMAL
        
        # ThreatTier is IntEnum, so max() works naturally
        most_severe = max(eval.tier for eval in evaluations.values())
        
        return most_severe
    
    def get_triggering_strategy(
        self,
        evaluations: Dict[RateLimitStrategy, ThreatEvaluation],
        tier: ThreatTier
    ) -> Optional[RateLimitStrategy]:
        """
        Get which strategy triggered a specific tier.
        
        If multiple strategies triggered the tier, returns the first one
        (in order: BY_IP, BY_JA4, BY_IP_JA4_PAIR).
        """
        # Priority order for multiple triggers
        priority_order = [
            RateLimitStrategy.BY_IP_JA4_PAIR,
            RateLimitStrategy.BY_IP,
            RateLimitStrategy.BY_JA4,
        ]
        
        for strategy in priority_order:
            eval = evaluations.get(strategy)
            if eval and eval.tier == tier:
                return strategy
        
        return None
    
    def should_apply_action(
        self,
        evaluations: Dict[RateLimitStrategy, ThreatEvaluation]
    ) -> bool:
        """
        Determine if action should be applied based on policy.
        
        Args:
            evaluations: Threat evaluations for each strategy
            
        Returns:
            True if action should be applied
            
        Policies:
            - ANY: Apply if any strategy detects threat (most protective)
            - ALL: Apply only if all strategies detect threat (most permissive)
            - MAJORITY: Apply if majority detect threat (balanced)
        """
        if not evaluations:
            return False
        
        # Count how many strategies detected threats
        threats = [
            eval for eval in evaluations.values()
            if eval.tier != ThreatTier.NORMAL
        ]
        
        threat_count = len(threats)
        total_count = len(evaluations)
        
        if self.policy == MultiStrategyPolicy.ANY:
            # Any strategy detecting threat triggers action
            return threat_count > 0
        
        elif self.policy == MultiStrategyPolicy.ALL:
            # All strategies must detect threat
            return threat_count == total_count
        
        elif self.policy == MultiStrategyPolicy.MAJORITY:
            # Majority must detect threat
            return threat_count > total_count / 2
        
        else:
            # Unknown policy - fail secure (act on any threat)
            self.logger.error(f"Unknown policy: {self.policy}, failing secure")
            return threat_count > 0
    
    def get_evaluation_summary(
        self,
        evaluations: Dict[RateLimitStrategy, ThreatEvaluation]
    ) -> Dict:
        """
        Get summary of evaluations for logging/metrics.
        
        Returns:
            Dictionary with evaluation summary
        """
        threat_count = sum(
            1 for eval in evaluations.values()
            if eval.tier != ThreatTier.NORMAL
        )
        
        most_severe = self.get_most_severe_tier(evaluations)
        
        return {
            'total_strategies': len(evaluations),
            'threats_detected': threat_count,
            'most_severe_tier': most_severe.name,
            'policy': self.policy.value,
            'action_triggered': self.should_apply_action(evaluations),
            'evaluations': [eval.to_dict() for eval in evaluations.values()],
        }
    
    @classmethod
    def from_config(cls, config: Dict) -> 'ThreatEvaluator':
        """
        Create ThreatEvaluator from configuration dictionary.
        
        Args:
            config: Security configuration dictionary
            
        Returns:
            Configured ThreatEvaluator instance
            
        Raises:
            ValueError: If configuration is invalid
        """
        try:
            # Load global tier configuration
            tier_config = ThreatTierConfig.from_config_dict(
                config.get('security', {})
            )
            
            # Load strategy-specific configurations
            strategy_configs_raw = config.get('security', {}).get(
                'rate_limit_strategies', {}
            )
            
            strategy_configs = {}
            for strategy in RateLimitStrategy:
                config_key = strategy.value
                strategy_config = strategy_configs_raw.get(config_key, {})
                if strategy_config.get('enabled', False):
                    strategy_configs[strategy] = strategy_config
            
            # Load policy
            policy_str = config.get('security', {}).get(
                'multi_strategy_policy', 'any'
            )
            policy = MultiStrategyPolicy.from_string(policy_str)
            if policy is None:
                logging.warning(
                    f"Invalid policy '{policy_str}', using default 'any'"
                )
                policy = MultiStrategyPolicy.ANY
            
            return cls(
                tier_config=tier_config,
                strategy_configs=strategy_configs,
                policy=policy,
            )
        except (TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"Invalid threat evaluator configuration: {e}")
