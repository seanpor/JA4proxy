#!/usr/bin/env python3
"""
Unit tests for action types and configurations.

Tests action type enums, action results, and configuration validation.
"""

import pytest

from src.security.action_types import (
    ActionType,
    ActionResult,
    ActionConfig,
)


class TestActionType:
    """Test ActionType enum."""
    
    def test_action_values(self):
        """Test action type values."""
        assert ActionType.LOG.value == "log"
        assert ActionType.TARPIT.value == "tarpit"
        assert ActionType.BLOCK.value == "block"
        assert ActionType.BAN.value == "ban"
    
    def test_get_severity(self):
        """Test severity level retrieval."""
        assert ActionType.LOG.get_severity() == 0
        assert ActionType.TARPIT.get_severity() == 1
        assert ActionType.BLOCK.get_severity() == 2
        assert ActionType.BAN.get_severity() == 3
    
    def test_is_blocking(self):
        """Test blocking action identification."""
        assert not ActionType.LOG.is_blocking()
        assert ActionType.TARPIT.is_blocking()
        assert ActionType.BLOCK.is_blocking()
        assert ActionType.BAN.is_blocking()
    
    def test_comparison_operators(self):
        """Test action type comparison."""
        assert ActionType.LOG < ActionType.TARPIT
        assert ActionType.TARPIT < ActionType.BLOCK
        assert ActionType.BLOCK < ActionType.BAN
        
        assert ActionType.LOG <= ActionType.TARPIT
        assert ActionType.BAN >= ActionType.BLOCK
        
        assert ActionType.BAN > ActionType.BLOCK
        assert ActionType.BLOCK > ActionType.TARPIT
    
    def test_from_string_valid(self):
        """Test conversion from valid string."""
        assert ActionType.from_string("log") == ActionType.LOG
        assert ActionType.from_string("tarpit") == ActionType.TARPIT
        assert ActionType.from_string("block") == ActionType.BLOCK
        assert ActionType.from_string("ban") == ActionType.BAN
    
    def test_from_string_case_insensitive(self):
        """Test case-insensitive string conversion."""
        assert ActionType.from_string("LOG") == ActionType.LOG
        assert ActionType.from_string("TarPit") == ActionType.TARPIT
        assert ActionType.from_string("BLOCK") == ActionType.BLOCK
    
    def test_from_string_invalid(self):
        """Test invalid string returns None."""
        assert ActionType.from_string("invalid") is None
        assert ActionType.from_string("") is None
        assert ActionType.from_string(None) is None


class TestActionResult:
    """Test ActionResult dataclass."""
    
    def test_create_log_result(self):
        """Test creating log action result."""
        result = ActionResult(
            allowed=True,
            action_type=ActionType.LOG,
            reason="Normal traffic",
            entity_id="test",
            duration=0,
        )
        
        assert result.allowed is True
        assert result.action_type == ActionType.LOG
        assert result.reason == "Normal traffic"
        assert result.entity_id == "test"
        assert result.duration == 0
    
    def test_create_block_result(self):
        """Test creating block action result."""
        result = ActionResult(
            allowed=False,
            action_type=ActionType.BLOCK,
            reason="Rate limit exceeded",
            entity_id="192.168.1.100",
            duration=3600,
        )
        
        assert result.allowed is False
        assert result.action_type == ActionType.BLOCK
        assert result.duration == 3600
    
    def test_immutability(self):
        """Test that result is immutable."""
        result = ActionResult(
            allowed=True,
            action_type=ActionType.LOG,
            reason="test",
            entity_id="test",
            duration=0,
        )
        
        with pytest.raises(AttributeError):
            result.allowed = False
    
    def test_validation_invalid_action_type(self):
        """Test validation rejects invalid action type."""
        with pytest.raises(ValueError, match="action_type must be"):
            ActionResult(
                allowed=True,
                action_type="invalid",
                reason="test",
                entity_id="test",
                duration=0,
            )
    
    def test_validation_empty_reason(self):
        """Test validation rejects empty reason."""
        with pytest.raises(ValueError, match="Reason cannot be empty"):
            ActionResult(
                allowed=True,
                action_type=ActionType.LOG,
                reason="",
                entity_id="test",
                duration=0,
            )
    
    def test_validation_empty_entity_id(self):
        """Test validation rejects empty entity ID."""
        with pytest.raises(ValueError, match="Entity ID cannot be empty"):
            ActionResult(
                allowed=True,
                action_type=ActionType.LOG,
                reason="test",
                entity_id="",
                duration=0,
            )
    
    def test_validation_negative_duration(self):
        """Test validation rejects negative duration."""
        with pytest.raises(ValueError, match="Duration cannot be negative"):
            ActionResult(
                allowed=True,
                action_type=ActionType.LOG,
                reason="test",
                entity_id="test",
                duration=-1,
            )
    
    def test_validation_blocking_action_allowed_true(self):
        """Test validation catches blocking action with allowed=True."""
        with pytest.raises(ValueError, match="is blocking but allowed=True"):
            ActionResult(
                allowed=True,
                action_type=ActionType.BLOCK,
                reason="test",
                entity_id="test",
                duration=3600,
            )
    
    def test_validation_non_blocking_action_allowed_false(self):
        """Test validation catches non-blocking action with allowed=False."""
        with pytest.raises(ValueError, match="is non-blocking but allowed=False"):
            ActionResult(
                allowed=False,
                action_type=ActionType.LOG,
                reason="test",
                entity_id="test",
                duration=0,
            )
    
    def test_to_dict(self):
        """Test serialization to dictionary."""
        result = ActionResult(
            allowed=False,
            action_type=ActionType.BLOCK,
            reason="Rate limit exceeded",
            entity_id="192.168.1.100",
            duration=3600,
        )
        
        d = result.to_dict()
        
        assert d['allowed'] is False
        assert d['action_type'] == "block"
        assert d['reason'] == "Rate limit exceeded"
        assert 'entity_id_hash' in d
        assert len(d['entity_id_hash']) == 16
        assert d['duration'] == 3600


class TestActionConfig:
    """Test ActionConfig class."""
    
    def test_default_initialization(self):
        """Test default configuration values."""
        config = ActionConfig()
        
        assert config.tarpit_enabled is True
        assert config.tarpit_duration == 10
        assert config.block_action == "tarpit"
        assert config.ban_duration == 604800
        assert config.permanent_ban is False
    
    def test_custom_initialization(self):
        """Test custom configuration values."""
        config = ActionConfig(
            tarpit_enabled=False,
            tarpit_duration=30,
            block_action="block",
            ban_duration=86400,
            permanent_ban=True,
        )
        
        assert config.tarpit_enabled is False
        assert config.tarpit_duration == 30
        assert config.block_action == "block"
        assert config.ban_duration == 86400
        assert config.permanent_ban is True
    
    def test_validation_negative_tarpit_duration(self):
        """Test validation rejects negative TARPIT duration."""
        with pytest.raises(ValueError, match="cannot be negative"):
            ActionConfig(tarpit_duration=-1)
    
    def test_validation_excessive_tarpit_duration(self):
        """Test validation rejects excessive TARPIT duration."""
        with pytest.raises(ValueError, match="too long"):
            ActionConfig(tarpit_duration=301)
    
    def test_validation_invalid_block_action(self):
        """Test validation rejects invalid block action."""
        with pytest.raises(ValueError, match="must be 'tarpit' or 'block'"):
            ActionConfig(block_action="invalid")
    
    def test_validation_negative_ban_duration(self):
        """Test validation rejects negative ban duration."""
        with pytest.raises(ValueError, match="cannot be negative"):
            ActionConfig(ban_duration=-1)
    
    def test_validation_excessive_ban_duration(self):
        """Test validation rejects excessive ban duration (GDPR)."""
        with pytest.raises(ValueError, match="GDPR limit"):
            ActionConfig(ban_duration=2592001, permanent_ban=False)
    
    def test_permanent_ban_bypasses_duration_check(self):
        """Test permanent ban bypasses duration validation."""
        config = ActionConfig(ban_duration=0, permanent_ban=True)
        assert config.ban_duration == 0
        assert config.permanent_ban is True
    
    def test_from_config_dict(self):
        """Test creation from configuration dictionary."""
        config_dict = {
            'security': {
                'tarpit_enabled': False,
                'tarpit_duration': 30,
                'block_action': 'block',
                'ban_duration': 86400,
                'permanent_ban': True,
            }
        }
        
        config = ActionConfig.from_config_dict(config_dict)
        
        assert config.tarpit_enabled is False
        assert config.tarpit_duration == 30
        assert config.block_action == "block"
        assert config.ban_duration == 86400
        assert config.permanent_ban is True
    
    def test_from_config_dict_with_defaults(self):
        """Test creation from config dict uses defaults for missing values."""
        config_dict = {}
        config = ActionConfig.from_config_dict(config_dict)
        
        # Should use default values
        assert config.tarpit_enabled is True
        assert config.tarpit_duration == 10
    
    def test_from_config_dict_invalid(self):
        """Test that invalid config dict raises error."""
        config_dict = {
            'security': {
                'tarpit_duration': 'invalid',  # Non-integer
            }
        }
        
        with pytest.raises(ValueError, match="Invalid action configuration"):
            ActionConfig.from_config_dict(config_dict)
    
    def test_get_action_for_block_tarpit_enabled(self):
        """Test getting TARPIT action for block tier."""
        config = ActionConfig(tarpit_enabled=True, block_action="tarpit")
        action = config.get_action_for_block()
        assert action == ActionType.TARPIT
    
    def test_get_action_for_block_tarpit_disabled(self):
        """Test getting BLOCK action when TARPIT disabled."""
        config = ActionConfig(tarpit_enabled=False, block_action="tarpit")
        action = config.get_action_for_block()
        assert action == ActionType.BLOCK
    
    def test_get_action_for_block_block_action(self):
        """Test getting BLOCK action when configured."""
        config = ActionConfig(tarpit_enabled=True, block_action="block")
        action = config.get_action_for_block()
        assert action == ActionType.BLOCK
    
    def test_get_ban_duration_temporary(self):
        """Test getting temporary ban duration."""
        config = ActionConfig(ban_duration=86400, permanent_ban=False)
        duration = config.get_ban_duration()
        assert duration == 86400
    
    def test_get_ban_duration_permanent(self):
        """Test getting permanent ban duration (0)."""
        config = ActionConfig(ban_duration=86400, permanent_ban=True)
        duration = config.get_ban_duration()
        assert duration == 0


class TestActionConfigEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_zero_tarpit_duration_allowed(self):
        """Test that zero TARPIT duration is allowed."""
        config = ActionConfig(tarpit_duration=0)
        assert config.tarpit_duration == 0
    
    def test_max_tarpit_duration_allowed(self):
        """Test that maximum TARPIT duration is allowed."""
        config = ActionConfig(tarpit_duration=300)
        assert config.tarpit_duration == 300
    
    def test_max_ban_duration_allowed(self):
        """Test that maximum ban duration is allowed."""
        config = ActionConfig(ban_duration=2592000, permanent_ban=False)
        assert config.ban_duration == 2592000
    
    def test_zero_ban_duration_with_permanent_false(self):
        """Test zero ban duration with permanent_ban=False."""
        config = ActionConfig(ban_duration=0, permanent_ban=False)
        assert config.ban_duration == 0
        assert config.permanent_ban is False
