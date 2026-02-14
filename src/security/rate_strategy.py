#!/usr/bin/env python3
"""
Rate limiting strategy definitions and data structures.

This module defines the different rate limiting strategies that can be
applied to detect and mitigate various attack patterns.

Security Considerations:
- Strategy selection affects GDPR compliance (IP+JA4 pair is most minimal)
- Each strategy has different privacy implications
- Data retention policies must align with strategy granularity
"""

import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RateLimitStrategy(Enum):
    """
    Rate limiting strategies for different threat models.
    
    BY_IP: Track all connections from an IP address
        - Use case: Traditional DDoS from single source
        - Privacy: Medium (IP addresses are PII under GDPR)
        - Detection: Broad, may catch NAT/proxy users
    
    BY_JA4: Track all connections with a specific JA4 fingerprint
        - Use case: Botnet detection (many IPs, same tool)
        - Privacy: Low (JA4 fingerprints are not PII)
        - Detection: Tool/library level, good for malware campaigns
    
    BY_IP_JA4_PAIR: Track unique IP+JA4 combinations
        - Use case: Targeted attacks, specific client abuse
        - Privacy: High (most minimal data, specific to threat)
        - Detection: Most granular, recommended default
    """
    
    BY_IP = "by_ip"
    BY_JA4 = "by_ja4"
    BY_IP_JA4_PAIR = "by_ip_ja4_pair"
    
    @classmethod
    def from_string(cls, strategy_str: str) -> Optional['RateLimitStrategy']:
        """
        Convert string to strategy enum with validation.
        
        Security: Prevents enum injection via invalid strings.
        """
        try:
            return cls(strategy_str)
        except ValueError:
            return None
    
    def get_redis_key_prefix(self) -> str:
        """Get Redis key prefix for this strategy."""
        prefixes = {
            RateLimitStrategy.BY_IP: "rate:ip",
            RateLimitStrategy.BY_JA4: "rate:ja4",
            RateLimitStrategy.BY_IP_JA4_PAIR: "rate:ip_ja4_pair",
        }
        return prefixes[self]
    
    def get_entity_id(self, ja4: str, ip: str) -> str:
        """
        Get entity ID for tracking based on strategy.
        
        Security: Validates inputs to prevent key injection.
        
        Args:
            ja4: JA4 fingerprint (validated externally)
            ip: IP address (validated externally)
            
        Returns:
            Entity ID string for Redis key
            
        Raises:
            ValueError: If inputs are invalid
        """
        # Input validation
        if not ja4 or not isinstance(ja4, str):
            raise ValueError("JA4 must be non-empty string")
        if not ip or not isinstance(ip, str):
            raise ValueError("IP must be non-empty string")
        
        # Prevent Redis key injection - no colons or spaces in components
        if ':' in ja4 or ' ' in ja4:
            raise ValueError("JA4 contains invalid characters")
        if ':' in ip or ' ' in ip:
            raise ValueError("IP contains invalid characters")
        
        if self == RateLimitStrategy.BY_IP:
            return ip
        elif self == RateLimitStrategy.BY_JA4:
            return ja4
        else:  # BY_IP_JA4_PAIR
            # Use pipe separator to avoid collision with colons in keys
            return f"{ip}|{ja4}"


@dataclass(frozen=True)
class RateMetrics:
    """
    Immutable rate metrics for a tracked entity.
    
    Security: Immutable to prevent tampering after creation.
    GDPR: Contains minimal data needed for rate calculation.
    """
    
    connections_per_second: int
    strategy: RateLimitStrategy
    entity_id: str
    timestamp: float
    window_seconds: float = 1.0
    
    def __post_init__(self):
        """Validate metrics on creation."""
        if self.connections_per_second < 0:
            raise ValueError("Connections per second cannot be negative")
        if self.window_seconds <= 0:
            raise ValueError("Window must be positive")
        if not self.entity_id:
            raise ValueError("Entity ID cannot be empty")
        if not isinstance(self.strategy, RateLimitStrategy):
            raise ValueError("Strategy must be RateLimitStrategy enum")
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging/metrics."""
        return {
            'connections_per_second': self.connections_per_second,
            'strategy': self.strategy.value,
            'entity_id_hash': self._hash_entity_id(),
            'timestamp': self.timestamp,
            'window_seconds': self.window_seconds,
        }
    
    def _hash_entity_id(self) -> str:
        """
        Hash entity ID for privacy-preserving logging.
        
        GDPR: Pseudonymization of identifiers in logs.
        """
        import hashlib
        return hashlib.sha256(self.entity_id.encode()).hexdigest()[:16]
    
    def exceeds_threshold(self, threshold: int) -> bool:
        """Check if rate exceeds threshold."""
        if threshold < 0:
            raise ValueError("Threshold cannot be negative")
        return self.connections_per_second > threshold


@dataclass
class StrategyConfig:
    """
    Configuration for a single rate limiting strategy.
    
    Security: Immutable configuration prevents runtime tampering.
    """
    
    enabled: bool
    suspicious_threshold: int
    block_threshold: int
    ban_threshold: int
    action: str  # 'log', 'tarpit', 'block'
    ban_duration: int  # seconds
    
    def __post_init__(self):
        """Validate configuration on creation."""
        # Validate thresholds are ordered correctly
        if not (0 <= self.suspicious_threshold <= self.block_threshold <= self.ban_threshold):
            raise ValueError(
                "Thresholds must be ordered: 0 <= suspicious <= block <= ban"
            )
        
        # Validate action
        valid_actions = ['log', 'tarpit', 'block']
        if self.action not in valid_actions:
            raise ValueError(
                f"Action must be one of {valid_actions}, got: {self.action}"
            )
        
        # Validate ban duration
        if self.ban_duration < 0:
            raise ValueError("Ban duration cannot be negative")
        if self.ban_duration > 86400 * 30:  # 30 days max
            raise ValueError("Ban duration too long (max 30 days)")
    
    @classmethod
    def from_config_dict(cls, config: dict) -> 'StrategyConfig':
        """
        Create from configuration dictionary with validation.
        
        Security: Validates all inputs to prevent configuration injection.
        """
        try:
            thresholds = config.get('thresholds', {})
            
            # Validate thresholds is a dictionary
            if not isinstance(thresholds, dict):
                raise TypeError("thresholds must be a dictionary")
            
            return cls(
                enabled=bool(config.get('enabled', False)),
                suspicious_threshold=int(thresholds.get('suspicious', 1)),
                block_threshold=int(thresholds.get('block', 5)),
                ban_threshold=int(thresholds.get('ban', 10)),
                action=str(config.get('action', 'tarpit')),
                ban_duration=int(config.get('ban_duration', 3600)),
            )
        except (TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"Invalid strategy configuration: {e}")
