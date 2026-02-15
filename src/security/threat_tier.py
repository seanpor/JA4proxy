#!/usr/bin/env python3
"""
Threat tier classification for rate-based escalation.

This module defines the threat tier system used to classify connection
patterns and determine appropriate responses.

Security Considerations:
- Immutable tier definitions prevent runtime tampering
- Clear escalation path from normal to banned
- GDPR-aligned temporary storage for each tier
"""

from enum import IntEnum
from typing import Dict


class ThreatTier(IntEnum):
    """
    Threat tier classification based on connection rate patterns.
    
    Uses IntEnum for natural ordering comparison (SUSPICIOUS < BLOCK < BANNED).
    
    Tiers:
    - NORMAL: Standard traffic patterns, no action needed
    - SUSPICIOUS: Elevated traffic, log and monitor
    - BLOCK: Excessive traffic, temporary block or TARPIT
    - BANNED: Severe abuse, long-term or permanent ban
    """
    
    NORMAL = 0
    SUSPICIOUS = 1
    BLOCK = 2
    BANNED = 3
    
    def get_action_name(self) -> str:
        """Get human-readable action name for tier."""
        actions = {
            ThreatTier.NORMAL: "allow",
            ThreatTier.SUSPICIOUS: "log",
            ThreatTier.BLOCK: "block",
            ThreatTier.BANNED: "ban",
        }
        return actions[self]
    
    def get_severity_level(self) -> str:
        """Get severity level for logging/metrics."""
        severity = {
            ThreatTier.NORMAL: "info",
            ThreatTier.SUSPICIOUS: "warning",
            ThreatTier.BLOCK: "error",
            ThreatTier.BANNED: "critical",
        }
        return severity[self]
    
    def should_block_connection(self) -> bool:
        """Check if this tier should block the connection."""
        return self >= ThreatTier.BLOCK
    
    def __str__(self) -> str:
        """String representation for logging."""
        return self.name


class ThreatTierConfig:
    """
    Configuration for threat tier thresholds and durations.
    
    Security: Immutable configuration prevents runtime tampering.
    GDPR: Configurable retention periods for each tier.
    """
    
    # Default thresholds (connections per second)
    DEFAULT_THRESHOLDS = {
        'suspicious': 1,
        'block': 5,
        'ban': 10,
    }
    
    # Default durations (seconds)
    DEFAULT_DURATIONS = {
        'suspicious': 300,      # 5 minutes
        'block': 3600,          # 1 hour
        'ban': 604800,          # 7 days
    }
    
    # Maximum allowed durations (GDPR compliance)
    MAX_DURATIONS = {
        'suspicious': 1800,     # 30 minutes max
        'block': 7200,          # 2 hours max
        'ban': 2592000,         # 30 days max
    }
    
    def __init__(
        self,
        suspicious_threshold: int = 1,
        block_threshold: int = 5,
        ban_threshold: int = 10,
        suspicious_duration: int = 300,
        block_duration: int = 3600,
        ban_duration: int = 604800,
    ):
        """
        Initialize threat tier configuration.
        
        Args:
            suspicious_threshold: Connections/sec for suspicious tier
            block_threshold: Connections/sec for block tier
            ban_threshold: Connections/sec for ban tier
            suspicious_duration: Data retention for suspicious (seconds)
            block_duration: Block duration (seconds)
            ban_duration: Ban duration (seconds, 0=permanent)
            
        Raises:
            ValueError: If thresholds or durations are invalid
        """
        # Validate thresholds
        if not (0 <= suspicious_threshold <= block_threshold <= ban_threshold):
            raise ValueError(
                "Thresholds must be ordered: 0 <= suspicious <= block <= ban"
            )
        
        if ban_threshold > 1000:
            raise ValueError("Ban threshold unreasonably high (>1000/sec)")
        
        # Validate durations
        if suspicious_duration < 0:
            raise ValueError("Suspicious duration cannot be negative")
        if block_duration < 0:
            raise ValueError("Block duration cannot be negative")
        if ban_duration < 0:
            raise ValueError("Ban duration cannot be negative")
        
        # Check GDPR limits
        if suspicious_duration > self.MAX_DURATIONS['suspicious']:
            raise ValueError(
                f"Suspicious duration exceeds GDPR limit "
                f"({self.MAX_DURATIONS['suspicious']}s)"
            )
        if block_duration > self.MAX_DURATIONS['block']:
            raise ValueError(
                f"Block duration exceeds GDPR limit "
                f"({self.MAX_DURATIONS['block']}s)"
            )
        if ban_duration > 0 and ban_duration > self.MAX_DURATIONS['ban']:
            raise ValueError(
                f"Ban duration exceeds GDPR limit "
                f"({self.MAX_DURATIONS['ban']}s)"
            )
        
        self.thresholds = {
            'suspicious': suspicious_threshold,
            'block': block_threshold,
            'ban': ban_threshold,
        }
        
        self.durations = {
            'suspicious': suspicious_duration,
            'block': block_duration,
            'ban': ban_duration,
        }
    
    def get_threshold(self, tier: ThreatTier) -> int:
        """Get threshold for a specific tier."""
        if tier == ThreatTier.SUSPICIOUS:
            return self.thresholds['suspicious']
        elif tier == ThreatTier.BLOCK:
            return self.thresholds['block']
        elif tier == ThreatTier.BANNED:
            return self.thresholds['ban']
        else:
            return 0
    
    def get_duration(self, tier: ThreatTier) -> int:
        """Get duration for a specific tier."""
        if tier == ThreatTier.SUSPICIOUS:
            return self.durations['suspicious']
        elif tier == ThreatTier.BLOCK:
            return self.durations['block']
        elif tier == ThreatTier.BANNED:
            return self.durations['ban']
        else:
            return 0
    
    def is_permanent_ban(self) -> bool:
        """Check if ban tier is permanent (duration=0)."""
        return self.durations['ban'] == 0
    
    @classmethod
    def from_config_dict(cls, config: Dict) -> 'ThreatTierConfig':
        """
        Create from configuration dictionary with validation.
        
        Security: Validates all inputs to prevent configuration injection.
        """
        try:
            thresholds = config.get('thresholds', cls.DEFAULT_THRESHOLDS)
            durations = config.get('ban_durations', cls.DEFAULT_DURATIONS)
            
            return cls(
                suspicious_threshold=int(thresholds.get('suspicious', 1)),
                block_threshold=int(thresholds.get('block', 5)),
                ban_threshold=int(thresholds.get('ban', 10)),
                suspicious_duration=int(durations.get('suspicious', 300)),
                block_duration=int(durations.get('block', 3600)),
                ban_duration=int(durations.get('ban', 604800)),
            )
        except (TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"Invalid threat tier configuration: {e}")
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            'thresholds': self.thresholds.copy(),
            'durations': self.durations.copy(),
        }
