#!/usr/bin/env python3
"""
Action type definitions for threat enforcement.

This module defines the different types of actions that can be applied
when threats are detected, along with their configurations.

Security Considerations:
- Immutable action definitions prevent runtime tampering
- Clear action hierarchy for escalation
- GDPR-aligned temporary storage durations
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional


class ActionType(Enum):
    """
    Types of actions that can be applied to threats.
    
    LOG: Log the threat but allow connection
        - Use for: Suspicious activity, investigation
        - Impact: None on user
        - GDPR: Minimal data retention
    
    TARPIT: Delay response to slow down attacker
        - Use for: Moderate threats, aggressive clients
        - Impact: Slows down attacker, minimal impact on legitimate users
        - GDPR: No additional data storage
    
    BLOCK: Reject connection immediately
        - Use for: Clear attacks, excessive traffic
        - Impact: Connection refused
        - GDPR: Temporary ban record stored
    
    BAN: Long-term or permanent block
        - Use for: Severe attacks, repeated offenders
        - Impact: Extended blocking period
        - GDPR: Requires justification, configurable duration
    """
    
    LOG = "log"
    TARPIT = "tarpit"
    BLOCK = "block"
    BAN = "ban"
    
    def get_severity(self) -> int:
        """Get numeric severity level (0-3)."""
        severity_map = {
            ActionType.LOG: 0,
            ActionType.TARPIT: 1,
            ActionType.BLOCK: 2,
            ActionType.BAN: 3,
        }
        return severity_map[self]
    
    def is_blocking(self) -> bool:
        """Check if this action blocks the connection."""
        return self in (ActionType.TARPIT, ActionType.BLOCK, ActionType.BAN)
    
    def __lt__(self, other) -> bool:
        """Compare action severity."""
        if not isinstance(other, ActionType):
            return NotImplemented
        return self.get_severity() < other.get_severity()
    
    def __le__(self, other) -> bool:
        if not isinstance(other, ActionType):
            return NotImplemented
        return self.get_severity() <= other.get_severity()
    
    def __gt__(self, other) -> bool:
        if not isinstance(other, ActionType):
            return NotImplemented
        return self.get_severity() > other.get_severity()
    
    def __ge__(self, other) -> bool:
        if not isinstance(other, ActionType):
            return NotImplemented
        return self.get_severity() >= other.get_severity()
    
    @classmethod
    def from_string(cls, action_str: str) -> Optional['ActionType']:
        """Convert string to action type with validation."""
        try:
            return cls(action_str.lower())
        except (ValueError, AttributeError):
            return None


@dataclass(frozen=True)
class ActionResult:
    """
    Immutable result of an action enforcement.
    
    Security: Immutable to prevent tampering after creation.
    """
    
    allowed: bool
    action_type: ActionType
    reason: str
    entity_id: str
    duration: int  # seconds, 0 for immediate/log-only actions
    
    def __post_init__(self):
        """Validate result on creation."""
        if not isinstance(self.action_type, ActionType):
            raise ValueError("action_type must be ActionType enum")
        if not self.reason:
            raise ValueError("Reason cannot be empty")
        if not self.entity_id:
            raise ValueError("Entity ID cannot be empty")
        if self.duration < 0:
            raise ValueError("Duration cannot be negative")
        
        # Validate consistency
        if self.action_type.is_blocking() and self.allowed:
            raise ValueError(
                f"Action {self.action_type.value} is blocking but allowed=True"
            )
        if not self.action_type.is_blocking() and not self.allowed:
            raise ValueError(
                f"Action {self.action_type.value} is non-blocking but allowed=False"
            )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging/metrics."""
        import hashlib
        return {
            'allowed': self.allowed,
            'action_type': self.action_type.value,
            'reason': self.reason,
            'entity_id_hash': hashlib.sha256(
                self.entity_id.encode()
            ).hexdigest()[:16],
            'duration': self.duration,
        }


@dataclass
class ActionConfig:
    """
    Configuration for action enforcement.
    
    Security: Validated configuration prevents misuse.
    """
    
    tarpit_enabled: bool = True
    tarpit_duration: int = 10  # seconds
    block_action: str = "tarpit"  # "tarpit" or "block"
    ban_duration: int = 604800  # 7 days
    permanent_ban: bool = False
    max_ban_duration: int = 2592000  # 30 days max (GDPR)
    
    def __post_init__(self):
        """Validate configuration."""
        # Validate tarpit duration
        if self.tarpit_duration < 0:
            raise ValueError("TARPIT duration cannot be negative")
        if self.tarpit_duration > 300:
            raise ValueError("TARPIT duration too long (max 5 minutes)")
        
        # Validate block action
        if self.block_action not in ("tarpit", "block"):
            raise ValueError(
                f"block_action must be 'tarpit' or 'block', got: {self.block_action}"
            )
        
        # Validate ban duration
        if self.ban_duration < 0:
            raise ValueError("Ban duration cannot be negative")
        if not self.permanent_ban and self.ban_duration > self.max_ban_duration:
            raise ValueError(
                f"Ban duration exceeds GDPR limit ({self.max_ban_duration}s)"
            )
    
    @classmethod
    def from_config_dict(cls, config: Dict) -> 'ActionConfig':
        """
        Create from configuration dictionary with validation.
        
        Security: Validates all inputs to prevent configuration injection.
        """
        try:
            security_config = config.get('security', {})
            
            return cls(
                tarpit_enabled=bool(security_config.get('tarpit_enabled', True)),
                tarpit_duration=int(security_config.get('tarpit_duration', 10)),
                block_action=str(security_config.get('block_action', 'tarpit')),
                ban_duration=int(security_config.get('ban_duration', 604800)),
                permanent_ban=bool(security_config.get('permanent_ban', False)),
                max_ban_duration=int(security_config.get('max_ban_duration', 2592000)),
            )
        except (TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"Invalid action configuration: {e}")
    
    def get_action_for_block(self) -> ActionType:
        """Get the action type to use for BLOCK tier."""
        if self.block_action == "tarpit" and self.tarpit_enabled:
            return ActionType.TARPIT
        else:
            return ActionType.BLOCK
    
    def get_ban_duration(self) -> int:
        """Get ban duration (0 if permanent)."""
        if self.permanent_ban:
            return 0
        return self.ban_duration
