#!/usr/bin/env python3
"""
Integrated security manager for JA4 proxy fail2ban.

This module integrates all security components into a unified interface:
- Multi-strategy rate tracking (Phase 1)
- Multi-strategy threat evaluation (Phase 2)
- Action enforcement (Phase 3)
- GDPR-compliant storage (Phase 4)

Security Considerations:
- Fail-secure: Errors result in blocking
- Comprehensive logging for audit trail
- GDPR compliance by default
- Multi-layer defense in depth
"""

import logging
from typing import Dict, Optional, Tuple

try:
    import redis
except ImportError:
    redis = None

from .rate_tracker import MultiStrategyRateTracker
from .threat_evaluator import ThreatEvaluator, MultiStrategyPolicy
from .action_enforcer import ActionEnforcer
from .gdpr_storage import GDPRStorage, DataCategory
from .threat_tier import ThreatTier
from .action_types import ActionType


class SecurityManager:
    """
    Integrated security manager for comprehensive threat detection and mitigation.
    
    This class coordinates all security components to provide:
    - Multi-strategy rate tracking
    - Intelligent threat evaluation
    - Proportionate action enforcement
    - GDPR-compliant data storage
    
    Usage:
        manager = SecurityManager.from_config(redis_client, config)
        allowed, reason = manager.check_access(ja4, client_ip)
        if not allowed:
            # Connection blocked
            handle_blocked_connection(reason)
    """
    
    def __init__(
        self,
        redis_client,
        config: Dict,
        rate_tracker: Optional[MultiStrategyRateTracker] = None,
        threat_evaluator: Optional[ThreatEvaluator] = None,
        action_enforcer: Optional[ActionEnforcer] = None,
        gdpr_storage: Optional[GDPRStorage] = None,
    ):
        """
        Initialize security manager.
        
        Args:
            redis_client: Redis client for state management
            config: Configuration dictionary
            rate_tracker: Optional pre-configured rate tracker
            threat_evaluator: Optional pre-configured threat evaluator
            action_enforcer: Optional pre-configured action enforcer
            gdpr_storage: Optional pre-configured GDPR storage
            
        Raises:
            ValueError: If redis_client is None
        """
        if redis_client is None:
            raise ValueError("Redis client is required")
        
        self.redis = redis_client
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize or use provided components
        self.rate_tracker = rate_tracker or MultiStrategyRateTracker(
            redis_client, config
        )
        self.threat_evaluator = threat_evaluator or ThreatEvaluator.from_config(
            config
        )
        self.action_enforcer = action_enforcer or ActionEnforcer.from_config(
            redis_client, config
        )
        self.gdpr_storage = gdpr_storage or GDPRStorage.from_config(
            redis_client, config
        )
        
        # Verify Redis connection
        try:
            self.redis.ping()
            self.logger.info("SecurityManager initialized successfully")
        except Exception as e:
            self.logger.error(f"Redis connection failed: {e}")
            raise
    
    def check_access(self, ja4: str, client_ip: str) -> Tuple[bool, str]:
        """
        Comprehensive access check with multi-strategy threat detection.
        
        This method coordinates all security phases:
        1. Check if already blocked/banned
        2. Track connection rate across strategies
        3. Evaluate threat level
        4. Enforce appropriate action
        5. Store data with GDPR compliance
        
        Args:
            ja4: JA4 fingerprint
            client_ip: Client IP address
            
        Returns:
            Tuple of (allowed, reason)
            - allowed: True if connection should be allowed
            - reason: Human-readable reason for decision
            
        Security:
            - Fail-secure: Errors result in blocking
            - Comprehensive audit logging
            - GDPR-compliant storage
        """
        # Validate inputs
        if not ja4 or not client_ip:
            self.logger.error(
                f"Invalid inputs: ja4={bool(ja4)}, ip={bool(client_ip)}"
            )
            return False, "Invalid request"
        
        try:
            # Step 1: Check if already blocked/banned
            is_blocked, block_reason = self.action_enforcer.is_blocked(ja4, client_ip)
            if is_blocked:
                self.logger.info(
                    f"Pre-blocked: IP={client_ip[:32]} JA4={ja4[:16]} - {block_reason}"
                )
                return False, block_reason
            
            # Step 2: Track connection rate across all enabled strategies
            rate_results = self.rate_tracker.track_connection(ja4, client_ip)
            
            # Step 3: Evaluate threat tier for each strategy
            threat_evaluations = self.threat_evaluator.evaluate_multi_strategy(
                rate_results
            )
            
            # Step 4: Determine if action should be applied
            if not self.threat_evaluator.should_apply_action(threat_evaluations):
                # All strategies show normal behavior
                self.logger.debug(
                    f"Allowed: IP={client_ip[:32]} JA4={ja4[:16]} - Normal traffic"
                )
                return True, "Allowed"
            
            # Step 5: Get most severe tier and triggering strategy
            most_severe_tier = self.threat_evaluator.get_most_severe_tier(
                threat_evaluations
            )
            triggering_strategy = self.threat_evaluator.get_triggering_strategy(
                threat_evaluations, most_severe_tier
            )
            
            # Step 6: Enforce action based on tier
            result = self.action_enforcer.enforce(
                ja4=ja4,
                ip=client_ip,
                tier=most_severe_tier,
                strategy=triggering_strategy,
            )
            
            # Step 7: Store enforcement data with GDPR compliance
            if not result.allowed:
                self._store_enforcement_data(ja4, client_ip, result, most_severe_tier)
            
            # Step 8: Log decision for audit trail
            self._log_decision(
                ja4, client_ip, result, most_severe_tier, triggering_strategy
            )
            
            return result.allowed, result.reason
            
        except Exception as e:
            # Fail secure: Block on error
            self.logger.error(
                f"Error in check_access: {e}", exc_info=True
            )
            return False, "Security check failed"
    
    def get_statistics(self) -> Dict:
        """
        Get comprehensive security statistics.
        
        Returns:
            Dictionary with statistics from all components
        """
        try:
            stats = {
                'enforcement': self.action_enforcer.get_enforcement_stats(),
                'gdpr_compliance': self.gdpr_storage.verify_compliance(),
                'retention_report': self.gdpr_storage.get_retention_report(),
            }
            return stats
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {'error': str(e)}
    
    def manual_unban(
        self,
        ja4: str,
        client_ip: str,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Manually unban an entity (e.g., for false positives).
        
        Args:
            ja4: JA4 fingerprint
            client_ip: Client IP address
            reason: Optional reason for unban (for audit log)
            
        Returns:
            True if entity was unbanned, False if not banned
        """
        try:
            was_unbanned = self.action_enforcer.unban(ja4, client_ip)
            
            if was_unbanned:
                self.logger.warning(
                    f"MANUAL UNBAN: IP={client_ip[:32]} JA4={ja4[:16]} "
                    f"Reason: {reason or 'Not specified'}"
                )
                
                # Store unban event in audit log
                self.gdpr_storage.store(
                    key=f"audit:unban:{int(time.time() * 1000)}",
                    value=f"IP={client_ip} JA4={ja4} Reason={reason}",
                    category=DataCategory.AUDIT_LOGS,
                )
            
            return was_unbanned
        except Exception as e:
            self.logger.error(f"Error in manual_unban: {e}")
            return False
    
    def verify_gdpr_compliance(self) -> Dict:
        """
        Verify GDPR compliance of all stored data.
        
        Returns:
            Compliance report with violations if any
        """
        try:
            return self.gdpr_storage.verify_compliance()
        except Exception as e:
            self.logger.error(f"Error verifying compliance: {e}")
            return {'error': str(e), 'compliance_rate': 0.0}
    
    def _store_enforcement_data(
        self,
        ja4: str,
        client_ip: str,
        result,
        tier: ThreatTier,
    ) -> None:
        """Store enforcement data with GDPR compliance."""
        try:
            # Determine category based on tier
            if tier == ThreatTier.SUSPICIOUS:
                category = DataCategory.SUSPICIOUS
            elif tier == ThreatTier.BLOCK:
                category = DataCategory.TEMP_BLOCKS
            elif tier == ThreatTier.BANNED:
                category = DataCategory.BANS
            else:
                category = DataCategory.FINGERPRINTS
            
            # Store enforcement record
            key = f"enforcement:{client_ip}:{ja4}:{int(time.time() * 1000)}"
            self.gdpr_storage.store(
                key=key,
                value=str(result.to_dict()),
                category=category,
            )
        except Exception as e:
            self.logger.error(f"Error storing enforcement data: {e}")
    
    def _log_decision(
        self,
        ja4: str,
        client_ip: str,
        result,
        tier: ThreatTier,
        strategy,
    ) -> None:
        """Log security decision for audit trail."""
        log_level = logging.INFO if result.allowed else logging.WARNING
        
        self.logger.log(
            log_level,
            f"Security Decision: "
            f"IP={client_ip[:32]} "
            f"JA4={ja4[:16]} "
            f"Tier={tier.name} "
            f"Strategy={strategy.value if strategy else 'N/A'} "
            f"Action={result.action_type.value} "
            f"Allowed={result.allowed} "
            f"Reason={result.reason}"
        )
    
    @classmethod
    def from_config(cls, redis_client, config: Dict) -> 'SecurityManager':
        """
        Create SecurityManager from configuration dictionary.
        
        Args:
            redis_client: Redis client instance
            config: Configuration dictionary
            
        Returns:
            Configured SecurityManager instance
        """
        return cls(redis_client, config)
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"SecurityManager("
            f"rate_tracker={self.rate_tracker.__class__.__name__}, "
            f"threat_evaluator={self.threat_evaluator.__class__.__name__}, "
            f"action_enforcer={self.action_enforcer.__class__.__name__}, "
            f"gdpr_storage={self.gdpr_storage.__class__.__name__})"
        )


# For backwards compatibility and convenience
import time

def create_security_manager(redis_client, config: Dict) -> SecurityManager:
    """
    Convenience function to create a SecurityManager instance.
    
    Args:
        redis_client: Redis client instance
        config: Configuration dictionary
        
    Returns:
        Configured SecurityManager instance
    """
    return SecurityManager.from_config(redis_client, config)
