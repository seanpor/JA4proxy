#!/usr/bin/env python3
"""
Action enforcement for JA4 proxy threat mitigation.

This module enforces actions based on threat tiers, managing blocks,
bans, and TARPIT delays in Redis with appropriate TTLs.

Security Considerations:
- Fail-secure: Errors default to blocking
- Atomic Redis operations prevent race conditions
- GDPR-compliant TTLs with configurable retention
- Audit logging for all enforcement actions
"""

import logging
import time
from typing import Dict, Optional, Tuple

try:
    import redis
except ImportError:
    redis = None

from .action_types import ActionType, ActionResult, ActionConfig
from .rate_strategy import RateLimitStrategy
from .threat_tier import ThreatTier


class ActionEnforcer:
    """
    Enforce security actions based on threat tiers.
    
    This class applies appropriate responses to detected threats:
    - SUSPICIOUS: Log and monitor
    - BLOCK: Apply TARPIT or block
    - BANNED: Apply temporary or permanent ban
    """
    
    def __init__(
        self,
        redis_client,
        action_config: ActionConfig,
        strategy_configs: Optional[Dict[RateLimitStrategy, Dict]] = None,
    ):
        """
        Initialize action enforcer.
        
        Args:
            redis_client: Redis client for state management
            action_config: Action configuration
            strategy_configs: Optional per-strategy configurations
            
        Raises:
            ValueError: If redis_client is None
        """
        if redis_client is None:
            raise ValueError("Redis client is required for action enforcement")
        
        self.redis = redis_client
        self.action_config = action_config
        self.strategy_configs = strategy_configs or {}
        self.logger = logging.getLogger(__name__)
        
        # Verify Redis connection
        try:
            self.redis.ping()
        except Exception as e:
            self.logger.error(f"Redis connection failed: {e}")
            raise
    
    def enforce(
        self,
        ja4: str,
        ip: str,
        tier: ThreatTier,
        strategy: Optional[RateLimitStrategy] = None,
        action_override: Optional[str] = None,
    ) -> ActionResult:
        """
        Enforce action for threat tier.
        
        Args:
            ja4: JA4 fingerprint
            ip: Client IP address
            tier: Threat tier to enforce
            strategy: Strategy that triggered (optional)
            action_override: Override action type (optional)
            
        Returns:
            ActionResult with enforcement details
            
        Security:
            - Fail-secure: Errors result in blocking
            - Atomic Redis operations
            - Comprehensive logging
        """
        # Validate inputs
        if not ja4 or not ip:
            self.logger.error("Invalid ja4 or ip")
            return ActionResult(
                allowed=False,
                action_type=ActionType.BLOCK,
                reason="Invalid request",
                entity_id=ip or "unknown",
                duration=3600,
            )
        
        # Get entity ID based on strategy
        entity_id = self._get_entity_id(ja4, ip, strategy)
        
        # Determine action based on tier
        if tier == ThreatTier.NORMAL:
            return self._allow(entity_id)
        
        elif tier == ThreatTier.SUSPICIOUS:
            return self._log_suspicious(ja4, ip, entity_id, strategy)
        
        elif tier == ThreatTier.BLOCK:
            action_type = self._get_action_type_for_block(strategy, action_override)
            return self._apply_block(ja4, ip, entity_id, action_type)
        
        elif tier == ThreatTier.BANNED:
            return self._apply_ban(ja4, ip, entity_id, strategy)
        
        else:
            # Unknown tier - fail secure
            self.logger.error(f"Unknown threat tier: {tier}")
            return ActionResult(
                allowed=False,
                action_type=ActionType.BLOCK,
                reason="Unknown threat tier",
                entity_id=entity_id,
                duration=3600,
            )
    
    def is_blocked(
        self,
        ja4: str,
        ip: str,
        strategies: Optional[list] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if entity is currently blocked or banned.
        
        Args:
            ja4: JA4 fingerprint
            ip: Client IP address
            strategies: List of strategies to check (optional)
            
        Returns:
            Tuple of (is_blocked, reason)
        """
        if strategies is None:
            strategies = [
                RateLimitStrategy.BY_IP,
                RateLimitStrategy.BY_JA4,
                RateLimitStrategy.BY_IP_JA4_PAIR,
            ]
        
        # Check each strategy
        for strategy in strategies:
            entity_id = self._get_entity_id(ja4, ip, strategy)
            
            # Check blocks
            block_key = f"blocked:{strategy.value}:{entity_id}"
            if self.redis.exists(block_key):
                ttl = self.redis.ttl(block_key)
                return True, f"Blocked by {strategy.value} (expires in {ttl}s)"
            
            # Check bans
            ban_key = f"banned:{strategy.value}:{entity_id}"
            if self.redis.exists(ban_key):
                ttl = self.redis.ttl(ban_key)
                if ttl == -1:
                    return True, f"Permanently banned by {strategy.value}"
                else:
                    return True, f"Banned by {strategy.value} (expires in {ttl}s)"
        
        return False, None
    
    def unban(
        self,
        ja4: str,
        ip: str,
        strategy: Optional[RateLimitStrategy] = None,
    ) -> bool:
        """
        Manually unban an entity.
        
        Args:
            ja4: JA4 fingerprint
            ip: Client IP address
            strategy: Specific strategy to unban (optional, defaults to all)
            
        Returns:
            True if unbanned, False if not banned
            
        Security: Requires manual intervention, logged for audit
        """
        unbanned = False
        
        if strategy:
            strategies = [strategy]
        else:
            strategies = [
                RateLimitStrategy.BY_IP,
                RateLimitStrategy.BY_JA4,
                RateLimitStrategy.BY_IP_JA4_PAIR,
            ]
        
        for strat in strategies:
            entity_id = self._get_entity_id(ja4, ip, strat)
            
            # Remove blocks
            block_key = f"blocked:{strat.value}:{entity_id}"
            if self.redis.delete(block_key):
                self.logger.warning(
                    f"MANUAL UNBAN: Removed block for {strat.value}:{entity_id[:32]}"
                )
                unbanned = True
            
            # Remove bans
            ban_key = f"banned:{strat.value}:{entity_id}"
            if self.redis.delete(ban_key):
                self.logger.warning(
                    f"MANUAL UNBAN: Removed ban for {strat.value}:{entity_id[:32]}"
                )
                unbanned = True
        
        return unbanned
    
    def _get_entity_id(
        self,
        ja4: str,
        ip: str,
        strategy: Optional[RateLimitStrategy],
    ) -> str:
        """Get entity ID based on strategy."""
        if strategy is None:
            strategy = RateLimitStrategy.BY_IP_JA4_PAIR
        
        return strategy.get_entity_id(ja4, ip)
    
    def _get_action_type_for_block(
        self,
        strategy: Optional[RateLimitStrategy],
        action_override: Optional[str],
    ) -> ActionType:
        """Determine action type for BLOCK tier."""
        # Check for override
        if action_override:
            action = ActionType.from_string(action_override)
            if action:
                return action
        
        # Check strategy-specific configuration
        if strategy and strategy in self.strategy_configs:
            strategy_action = self.strategy_configs[strategy].get('action')
            if strategy_action:
                action = ActionType.from_string(strategy_action)
                if action:
                    return action
        
        # Fall back to global configuration
        return self.action_config.get_action_for_block()
    
    def _allow(self, entity_id: str) -> ActionResult:
        """Allow connection (NORMAL tier)."""
        return ActionResult(
            allowed=True,
            action_type=ActionType.LOG,
            reason="Normal traffic",
            entity_id=entity_id,
            duration=0,
        )
    
    def _log_suspicious(
        self,
        ja4: str,
        ip: str,
        entity_id: str,
        strategy: Optional[RateLimitStrategy],
    ) -> ActionResult:
        """Log suspicious activity but allow connection."""
        self.logger.warning(
            f"SUSPICIOUS: IP={ip[:32]} JA4={ja4[:16]} "
            f"strategy={strategy.value if strategy else 'unknown'}"
        )
        
        # Store in Redis with short TTL for investigation
        suspicious_key = f"suspicious:{entity_id}"
        self.redis.setex(suspicious_key, 300, "1")  # 5 minutes
        
        return ActionResult(
            allowed=True,
            action_type=ActionType.LOG,
            reason="Suspicious traffic - monitoring",
            entity_id=entity_id,
            duration=300,
        )
    
    def _apply_block(
        self,
        ja4: str,
        ip: str,
        entity_id: str,
        action_type: ActionType,
    ) -> ActionResult:
        """Apply block or TARPIT."""
        # Get duration from config
        duration = 3600  # Default 1 hour
        
        # Store block in Redis
        if action_type == ActionType.TARPIT:
            # TARPIT: Store with TARPIT duration flag
            block_key = f"blocked:tarpit:{entity_id}"
            self.redis.setex(block_key, duration, str(self.action_config.tarpit_duration))
            
            self.logger.warning(
                f"TARPIT: IP={ip[:32]} JA4={ja4[:16]} "
                f"delay={self.action_config.tarpit_duration}s duration={duration}s"
            )
            
            reason = f"Rate limit exceeded - TARPIT {self.action_config.tarpit_duration}s"
        else:
            # BLOCK: Hard block
            block_key = f"blocked:block:{entity_id}"
            self.redis.setex(block_key, duration, "1")
            
            self.logger.warning(
                f"BLOCK: IP={ip[:32]} JA4={ja4[:16]} duration={duration}s"
            )
            
            reason = "Rate limit exceeded - blocked"
        
        return ActionResult(
            allowed=False,
            action_type=action_type,
            reason=reason,
            entity_id=entity_id,
            duration=duration,
        )
    
    def _apply_ban(
        self,
        ja4: str,
        ip: str,
        entity_id: str,
        strategy: Optional[RateLimitStrategy],
    ) -> ActionResult:
        """Apply temporary or permanent ban."""
        ban_duration = self.action_config.get_ban_duration()
        
        if ban_duration == 0:
            # Permanent ban - no TTL
            ban_key = f"banned:permanent:{entity_id}"
            self.redis.set(ban_key, "1")
            
            self.logger.error(
                f"PERMANENT BAN: IP={ip[:32]} JA4={ja4[:16]} "
                f"strategy={strategy.value if strategy else 'unknown'}"
            )
            
            reason = "Permanently banned for excessive abuse"
            duration = 0
        else:
            # Temporary ban with TTL
            ban_key = f"banned:temporary:{entity_id}"
            self.redis.setex(ban_key, ban_duration, "1")
            
            self.logger.error(
                f"BAN: IP={ip[:32]} JA4={ja4[:16]} "
                f"duration={ban_duration}s strategy={strategy.value if strategy else 'unknown'}"
            )
            
            reason = f"Banned for {ban_duration}s"
            duration = ban_duration
        
        return ActionResult(
            allowed=False,
            action_type=ActionType.BAN,
            reason=reason,
            entity_id=entity_id,
            duration=duration,
        )
    
    def get_enforcement_stats(self) -> Dict:
        """
        Get enforcement statistics from Redis.
        
        Returns:
            Dictionary with current enforcement stats
        """
        try:
            # Count blocks
            blocked_tarpit = len(self.redis.keys("blocked:tarpit:*"))
            blocked_block = len(self.redis.keys("blocked:block:*"))
            
            # Count bans
            banned_temporary = len(self.redis.keys("banned:temporary:*"))
            banned_permanent = len(self.redis.keys("banned:permanent:*"))
            
            # Count suspicious
            suspicious = len(self.redis.keys("suspicious:*"))
            
            return {
                'blocked_tarpit': blocked_tarpit,
                'blocked_block': blocked_block,
                'total_blocked': blocked_tarpit + blocked_block,
                'banned_temporary': banned_temporary,
                'banned_permanent': banned_permanent,
                'total_banned': banned_temporary + banned_permanent,
                'suspicious': suspicious,
            }
        except Exception as e:
            self.logger.error(f"Error getting enforcement stats: {e}")
            return {}
    
    @classmethod
    def from_config(cls, redis_client, config: Dict) -> 'ActionEnforcer':
        """
        Create ActionEnforcer from configuration dictionary.
        
        Args:
            redis_client: Redis client instance
            config: Configuration dictionary
            
        Returns:
            Configured ActionEnforcer instance
        """
        action_config = ActionConfig.from_config_dict(config)
        
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
        
        return cls(
            redis_client=redis_client,
            action_config=action_config,
            strategy_configs=strategy_configs,
        )
