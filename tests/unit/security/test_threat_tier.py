#!/usr/bin/env python3
"""
Unit tests for threat tier classification.

Tests threat tier enums, configuration validation, and tier behavior.
"""

import pytest

from src.security.threat_tier import (
    ThreatTier,
    ThreatTierConfig,
)


class TestThreatTier:
    """Test ThreatTier enum."""
    
    def test_tier_ordering(self):
        """Test that tiers are properly ordered."""
        assert ThreatTier.NORMAL < ThreatTier.SUSPICIOUS
        assert ThreatTier.SUSPICIOUS < ThreatTier.BLOCK
        assert ThreatTier.BLOCK < ThreatTier.BANNED
    
    def test_get_action_name(self):
        """Test action name retrieval."""
        assert ThreatTier.NORMAL.get_action_name() == "allow"
        assert ThreatTier.SUSPICIOUS.get_action_name() == "log"
        assert ThreatTier.BLOCK.get_action_name() == "block"
        assert ThreatTier.BANNED.get_action_name() == "ban"
    
    def test_get_severity_level(self):
        """Test severity level retrieval."""
        assert ThreatTier.NORMAL.get_severity_level() == "info"
        assert ThreatTier.SUSPICIOUS.get_severity_level() == "warning"
        assert ThreatTier.BLOCK.get_severity_level() == "error"
        assert ThreatTier.BANNED.get_severity_level() == "critical"
    
    def test_should_block_connection(self):
        """Test connection blocking decision."""
        assert not ThreatTier.NORMAL.should_block_connection()
        assert not ThreatTier.SUSPICIOUS.should_block_connection()
        assert ThreatTier.BLOCK.should_block_connection()
        assert ThreatTier.BANNED.should_block_connection()
    
    def test_string_representation(self):
        """Test string representation."""
        assert str(ThreatTier.NORMAL) == "NORMAL"
        assert str(ThreatTier.SUSPICIOUS) == "SUSPICIOUS"
        assert str(ThreatTier.BLOCK) == "BLOCK"
        assert str(ThreatTier.BANNED) == "BANNED"
    
    def test_integer_values(self):
        """Test integer values for comparison."""
        assert int(ThreatTier.NORMAL) == 0
        assert int(ThreatTier.SUSPICIOUS) == 1
        assert int(ThreatTier.BLOCK) == 2
        assert int(ThreatTier.BANNED) == 3


class TestThreatTierConfig:
    """Test ThreatTierConfig class."""
    
    def test_default_initialization(self):
        """Test default configuration values."""
        config = ThreatTierConfig()
        
        assert config.thresholds['suspicious'] == 1
        assert config.thresholds['block'] == 5
        assert config.thresholds['ban'] == 10
        
        assert config.durations['suspicious'] == 300
        assert config.durations['block'] == 3600
        assert config.durations['ban'] == 604800
    
    def test_custom_initialization(self):
        """Test custom configuration values."""
        config = ThreatTierConfig(
            suspicious_threshold=2,
            block_threshold=10,
            ban_threshold=20,
            suspicious_duration=600,
            block_duration=7200,
            ban_duration=1209600,
        )
        
        assert config.thresholds['suspicious'] == 2
        assert config.thresholds['block'] == 10
        assert config.thresholds['ban'] == 20
        
        assert config.durations['suspicious'] == 600
        assert config.durations['block'] == 7200
        assert config.durations['ban'] == 1209600
    
    def test_threshold_ordering_validation(self):
        """Test that thresholds must be properly ordered."""
        # Valid ordering
        config = ThreatTierConfig(
            suspicious_threshold=1,
            block_threshold=5,
            ban_threshold=10,
        )
        assert config.thresholds['suspicious'] == 1
        
        # Invalid: suspicious > block
        with pytest.raises(ValueError, match="must be ordered"):
            ThreatTierConfig(
                suspicious_threshold=10,
                block_threshold=5,
                ban_threshold=20,
            )
        
        # Invalid: block > ban
        with pytest.raises(ValueError, match="must be ordered"):
            ThreatTierConfig(
                suspicious_threshold=1,
                block_threshold=20,
                ban_threshold=10,
            )
    
    def test_threshold_unreasonably_high(self):
        """Test that unreasonably high thresholds are rejected."""
        with pytest.raises(ValueError, match="unreasonably high"):
            ThreatTierConfig(
                suspicious_threshold=1,
                block_threshold=5,
                ban_threshold=1001,
            )
    
    def test_negative_duration_validation(self):
        """Test that negative durations are rejected."""
        with pytest.raises(ValueError, match="cannot be negative"):
            ThreatTierConfig(suspicious_duration=-1)
        
        with pytest.raises(ValueError, match="cannot be negative"):
            ThreatTierConfig(block_duration=-1)
        
        with pytest.raises(ValueError, match="cannot be negative"):
            ThreatTierConfig(ban_duration=-1)
    
    def test_gdpr_duration_limits(self):
        """Test GDPR compliance duration limits."""
        # Suspicious duration too long
        with pytest.raises(ValueError, match="GDPR limit"):
            ThreatTierConfig(suspicious_duration=2000)
        
        # Block duration too long
        with pytest.raises(ValueError, match="GDPR limit"):
            ThreatTierConfig(block_duration=10000)
        
        # Ban duration too long
        with pytest.raises(ValueError, match="GDPR limit"):
            ThreatTierConfig(ban_duration=86400 * 31)  # 31 days
    
    def test_permanent_ban_allowed(self):
        """Test that permanent ban (duration=0) is allowed."""
        config = ThreatTierConfig(ban_duration=0)
        assert config.durations['ban'] == 0
        assert config.is_permanent_ban()
    
    def test_get_threshold(self):
        """Test threshold retrieval by tier."""
        config = ThreatTierConfig(
            suspicious_threshold=2,
            block_threshold=10,
            ban_threshold=20,
        )
        
        assert config.get_threshold(ThreatTier.NORMAL) == 0
        assert config.get_threshold(ThreatTier.SUSPICIOUS) == 2
        assert config.get_threshold(ThreatTier.BLOCK) == 10
        assert config.get_threshold(ThreatTier.BANNED) == 20
    
    def test_get_duration(self):
        """Test duration retrieval by tier."""
        config = ThreatTierConfig(
            suspicious_duration=300,
            block_duration=3600,
            ban_duration=86400,
        )
        
        assert config.get_duration(ThreatTier.NORMAL) == 0
        assert config.get_duration(ThreatTier.SUSPICIOUS) == 300
        assert config.get_duration(ThreatTier.BLOCK) == 3600
        assert config.get_duration(ThreatTier.BANNED) == 86400
    
    def test_is_permanent_ban(self):
        """Test permanent ban detection."""
        config_temporary = ThreatTierConfig(ban_duration=86400)
        assert not config_temporary.is_permanent_ban()
        
        config_permanent = ThreatTierConfig(ban_duration=0)
        assert config_permanent.is_permanent_ban()
    
    def test_from_config_dict(self):
        """Test creation from configuration dictionary."""
        config_dict = {
            'thresholds': {
                'suspicious': 2,
                'block': 10,
                'ban': 20,
            },
            'ban_durations': {
                'suspicious': 600,
                'block': 7200,
                'ban': 1209600,
            },
        }
        
        config = ThreatTierConfig.from_config_dict(config_dict)
        
        assert config.thresholds['suspicious'] == 2
        assert config.thresholds['block'] == 10
        assert config.thresholds['ban'] == 20
        
        assert config.durations['suspicious'] == 600
        assert config.durations['block'] == 7200
        assert config.durations['ban'] == 1209600
    
    def test_from_config_dict_with_defaults(self):
        """Test creation from config dict uses defaults for missing values."""
        config_dict = {}
        config = ThreatTierConfig.from_config_dict(config_dict)
        
        # Should use default values
        assert config.thresholds['suspicious'] == 1
        assert config.thresholds['block'] == 5
        assert config.thresholds['ban'] == 10
    
    def test_from_config_dict_invalid(self):
        """Test that invalid config dict raises error."""
        config_dict = {
            'thresholds': {
                'suspicious': 'invalid',  # Non-integer
            }
        }
        
        with pytest.raises(ValueError, match="Invalid threat tier configuration"):
            ThreatTierConfig.from_config_dict(config_dict)
    
    def test_to_dict(self):
        """Test serialization to dictionary."""
        config = ThreatTierConfig(
            suspicious_threshold=2,
            block_threshold=10,
            ban_threshold=20,
            suspicious_duration=600,
            block_duration=7200,
            ban_duration=1209600,
        )
        
        result = config.to_dict()
        
        assert result['thresholds'] == {
            'suspicious': 2,
            'block': 10,
            'ban': 20,
        }
        assert result['durations'] == {
            'suspicious': 600,
            'block': 7200,
            'ban': 1209600,
        }
        
        # Verify it's a copy (immutability)
        result['thresholds']['suspicious'] = 999
        assert config.thresholds['suspicious'] == 2  # Original unchanged


class TestThreatTierConfigEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_zero_thresholds_allowed(self):
        """Test that zero thresholds are allowed."""
        config = ThreatTierConfig(
            suspicious_threshold=0,
            block_threshold=0,
            ban_threshold=10,
        )
        assert config.thresholds['suspicious'] == 0
        assert config.thresholds['block'] == 0
    
    def test_equal_thresholds_allowed(self):
        """Test that equal thresholds are allowed."""
        config = ThreatTierConfig(
            suspicious_threshold=5,
            block_threshold=5,
            ban_threshold=5,
        )
        assert config.thresholds['suspicious'] == 5
        assert config.thresholds['block'] == 5
        assert config.thresholds['ban'] == 5
    
    def test_max_gdpr_durations_allowed(self):
        """Test that maximum GDPR durations are allowed."""
        config = ThreatTierConfig(
            suspicious_duration=1800,     # Max 30 minutes
            block_duration=7200,          # Max 2 hours
            ban_duration=2592000,         # Max 30 days
        )
        assert config.durations['suspicious'] == 1800
        assert config.durations['block'] == 7200
        assert config.durations['ban'] == 2592000
