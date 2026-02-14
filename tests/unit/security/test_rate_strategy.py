#!/usr/bin/env python3
"""
Unit tests for rate limiting strategy definitions.

Tests cover:
- Strategy enum validation
- Key generation and injection prevention
- Configuration validation
- Immutable data structures
"""

import pytest
import time

from src.security.rate_strategy import (
    RateLimitStrategy,
    RateMetrics,
    StrategyConfig,
)


class TestRateLimitStrategy:
    """Test RateLimitStrategy enum."""
    
    def test_valid_strategies(self):
        """Test all valid strategy types exist."""
        assert RateLimitStrategy.BY_IP.value == "by_ip"
        assert RateLimitStrategy.BY_JA4.value == "by_ja4"
        assert RateLimitStrategy.BY_IP_JA4_PAIR.value == "by_ip_ja4_pair"
    
    def test_from_string_valid(self):
        """Test converting valid string to strategy."""
        assert RateLimitStrategy.from_string("by_ip") == RateLimitStrategy.BY_IP
        assert RateLimitStrategy.from_string("by_ja4") == RateLimitStrategy.BY_JA4
        assert RateLimitStrategy.from_string("by_ip_ja4_pair") == RateLimitStrategy.BY_IP_JA4_PAIR
    
    def test_from_string_invalid(self):
        """Test invalid string returns None."""
        assert RateLimitStrategy.from_string("invalid") is None
        assert RateLimitStrategy.from_string("") is None
        assert RateLimitStrategy.from_string("by_ip; DROP TABLE") is None
    
    def test_get_redis_key_prefix(self):
        """Test Redis key prefix generation."""
        assert RateLimitStrategy.BY_IP.get_redis_key_prefix() == "rate:ip"
        assert RateLimitStrategy.BY_JA4.get_redis_key_prefix() == "rate:ja4"
        assert RateLimitStrategy.BY_IP_JA4_PAIR.get_redis_key_prefix() == "rate:ip_ja4_pair"
    
    def test_get_entity_id_by_ip(self):
        """Test entity ID generation for BY_IP strategy."""
        strategy = RateLimitStrategy.BY_IP
        ja4 = "t13d1516h2_abc123_def456"
        ip = "192.168.1.100"
        
        entity_id = strategy.get_entity_id(ja4, ip)
        assert entity_id == ip
    
    def test_get_entity_id_by_ja4(self):
        """Test entity ID generation for BY_JA4 strategy."""
        strategy = RateLimitStrategy.BY_JA4
        ja4 = "t13d1516h2_abc123_def456"
        ip = "192.168.1.100"
        
        entity_id = strategy.get_entity_id(ja4, ip)
        assert entity_id == ja4
    
    def test_get_entity_id_by_pair(self):
        """Test entity ID generation for BY_IP_JA4_PAIR strategy."""
        strategy = RateLimitStrategy.BY_IP_JA4_PAIR
        ja4 = "t13d1516h2_abc123_def456"
        ip = "192.168.1.100"
        
        entity_id = strategy.get_entity_id(ja4, ip)
        assert entity_id == f"{ip}|{ja4}"
        assert "|" in entity_id
    
    def test_get_entity_id_prevents_injection_colon(self):
        """Test entity ID generation prevents Redis key injection with colons."""
        strategy = RateLimitStrategy.BY_IP
        
        # Try injection with colon in IP
        with pytest.raises(ValueError, match="invalid characters"):
            strategy.get_entity_id("t13d1516h2_abc123_def456", "192.168.1.100:6379")
        
        # Try injection with colon in JA4
        with pytest.raises(ValueError, match="invalid characters"):
            strategy.get_entity_id("t13:INJECT", "192.168.1.100")
    
    def test_get_entity_id_prevents_injection_space(self):
        """Test entity ID generation prevents injection with spaces."""
        strategy = RateLimitStrategy.BY_IP
        
        with pytest.raises(ValueError, match="invalid characters"):
            strategy.get_entity_id("t13 INJECT", "192.168.1.100")
        
        with pytest.raises(ValueError, match="invalid characters"):
            strategy.get_entity_id("t13d1516h2_abc123_def456", "192.168.1.100 .")
    
    def test_get_entity_id_validates_empty(self):
        """Test entity ID generation validates empty inputs."""
        strategy = RateLimitStrategy.BY_IP
        
        with pytest.raises(ValueError, match="non-empty string"):
            strategy.get_entity_id("", "192.168.1.100")
        
        with pytest.raises(ValueError, match="non-empty string"):
            strategy.get_entity_id("t13d1516h2_abc123_def456", "")
    
    def test_get_entity_id_validates_type(self):
        """Test entity ID generation validates input types."""
        strategy = RateLimitStrategy.BY_IP
        
        with pytest.raises(ValueError):
            strategy.get_entity_id(None, "192.168.1.100")
        
        with pytest.raises(ValueError):
            strategy.get_entity_id("t13d1516h2_abc123_def456", None)


class TestRateMetrics:
    """Test RateMetrics data class."""
    
    def test_create_valid_metrics(self):
        """Test creating valid rate metrics."""
        metrics = RateMetrics(
            connections_per_second=5,
            strategy=RateLimitStrategy.BY_IP,
            entity_id="192.168.1.100",
            timestamp=time.time(),
            window_seconds=1.0,
        )
        
        assert metrics.connections_per_second == 5
        assert metrics.strategy == RateLimitStrategy.BY_IP
        assert metrics.entity_id == "192.168.1.100"
        assert metrics.window_seconds == 1.0
    
    def test_metrics_immutable(self):
        """Test that RateMetrics is immutable."""
        metrics = RateMetrics(
            connections_per_second=5,
            strategy=RateLimitStrategy.BY_IP,
            entity_id="192.168.1.100",
            timestamp=time.time(),
        )
        
        # Should not be able to modify
        with pytest.raises(Exception):  # FrozenInstanceError
            metrics.connections_per_second = 10
    
    def test_metrics_validates_negative_connections(self):
        """Test validation rejects negative connection count."""
        with pytest.raises(ValueError, match="cannot be negative"):
            RateMetrics(
                connections_per_second=-1,
                strategy=RateLimitStrategy.BY_IP,
                entity_id="192.168.1.100",
                timestamp=time.time(),
            )
    
    def test_metrics_validates_zero_window(self):
        """Test validation rejects zero/negative window."""
        with pytest.raises(ValueError, match="must be positive"):
            RateMetrics(
                connections_per_second=5,
                strategy=RateLimitStrategy.BY_IP,
                entity_id="192.168.1.100",
                timestamp=time.time(),
                window_seconds=0,
            )
        
        with pytest.raises(ValueError, match="must be positive"):
            RateMetrics(
                connections_per_second=5,
                strategy=RateLimitStrategy.BY_IP,
                entity_id="192.168.1.100",
                timestamp=time.time(),
                window_seconds=-1,
            )
    
    def test_metrics_validates_empty_entity_id(self):
        """Test validation rejects empty entity ID."""
        with pytest.raises(ValueError, match="cannot be empty"):
            RateMetrics(
                connections_per_second=5,
                strategy=RateLimitStrategy.BY_IP,
                entity_id="",
                timestamp=time.time(),
            )
    
    def test_metrics_validates_strategy_type(self):
        """Test validation requires RateLimitStrategy enum."""
        with pytest.raises(ValueError, match="must be RateLimitStrategy"):
            RateMetrics(
                connections_per_second=5,
                strategy="by_ip",  # String not enum
                entity_id="192.168.1.100",
                timestamp=time.time(),
            )
    
    def test_to_dict(self):
        """Test converting metrics to dictionary."""
        metrics = RateMetrics(
            connections_per_second=5,
            strategy=RateLimitStrategy.BY_IP,
            entity_id="192.168.1.100",
            timestamp=123456.789,
            window_seconds=1.0,
        )
        
        result = metrics.to_dict()
        
        assert result['connections_per_second'] == 5
        assert result['strategy'] == "by_ip"
        assert 'entity_id_hash' in result  # Hashed for privacy
        assert result['entity_id_hash'] != "192.168.1.100"  # Should be hashed
        assert len(result['entity_id_hash']) == 16  # SHA256 truncated
        assert result['timestamp'] == 123456.789
        assert result['window_seconds'] == 1.0
    
    def test_exceeds_threshold(self):
        """Test threshold comparison."""
        metrics = RateMetrics(
            connections_per_second=5,
            strategy=RateLimitStrategy.BY_IP,
            entity_id="192.168.1.100",
            timestamp=time.time(),
        )
        
        assert metrics.exceeds_threshold(4) is True
        assert metrics.exceeds_threshold(5) is False
        assert metrics.exceeds_threshold(6) is False
    
    def test_exceeds_threshold_validates(self):
        """Test threshold comparison validates input."""
        metrics = RateMetrics(
            connections_per_second=5,
            strategy=RateLimitStrategy.BY_IP,
            entity_id="192.168.1.100",
            timestamp=time.time(),
        )
        
        with pytest.raises(ValueError, match="cannot be negative"):
            metrics.exceeds_threshold(-1)


class TestStrategyConfig:
    """Test StrategyConfig data class."""
    
    def test_create_valid_config(self):
        """Test creating valid strategy configuration."""
        config = StrategyConfig(
            enabled=True,
            suspicious_threshold=1,
            block_threshold=5,
            ban_threshold=10,
            action='tarpit',
            ban_duration=3600,
        )
        
        assert config.enabled is True
        assert config.suspicious_threshold == 1
        assert config.block_threshold == 5
        assert config.ban_threshold == 10
        assert config.action == 'tarpit'
        assert config.ban_duration == 3600
    
    def test_validates_threshold_ordering(self):
        """Test validation enforces threshold ordering."""
        # Block threshold less than suspicious should fail
        with pytest.raises(ValueError, match="must be ordered"):
            StrategyConfig(
                enabled=True,
                suspicious_threshold=5,
                block_threshold=1,  # Wrong order
                ban_threshold=10,
                action='tarpit',
                ban_duration=3600,
            )
        
        # Ban threshold less than block should fail
        with pytest.raises(ValueError, match="must be ordered"):
            StrategyConfig(
                enabled=True,
                suspicious_threshold=1,
                block_threshold=10,
                ban_threshold=5,  # Wrong order
                action='tarpit',
                ban_duration=3600,
            )
    
    def test_validates_action(self):
        """Test validation enforces valid action types."""
        valid_actions = ['log', 'tarpit', 'block']
        
        for action in valid_actions:
            config = StrategyConfig(
                enabled=True,
                suspicious_threshold=1,
                block_threshold=5,
                ban_threshold=10,
                action=action,
                ban_duration=3600,
            )
            assert config.action == action
        
        # Invalid action should fail
        with pytest.raises(ValueError, match="must be one of"):
            StrategyConfig(
                enabled=True,
                suspicious_threshold=1,
                block_threshold=5,
                ban_threshold=10,
                action='invalid',
                ban_duration=3600,
            )
    
    def test_validates_negative_ban_duration(self):
        """Test validation rejects negative ban duration."""
        with pytest.raises(ValueError, match="cannot be negative"):
            StrategyConfig(
                enabled=True,
                suspicious_threshold=1,
                block_threshold=5,
                ban_threshold=10,
                action='tarpit',
                ban_duration=-1,
            )
    
    def test_validates_excessive_ban_duration(self):
        """Test validation rejects excessively long bans."""
        # 30 days should be OK
        config = StrategyConfig(
            enabled=True,
            suspicious_threshold=1,
            block_threshold=5,
            ban_threshold=10,
            action='tarpit',
            ban_duration=86400 * 30,
        )
        assert config.ban_duration == 86400 * 30
        
        # More than 30 days should fail (GDPR concern)
        with pytest.raises(ValueError, match="too long"):
            StrategyConfig(
                enabled=True,
                suspicious_threshold=1,
                block_threshold=5,
                ban_threshold=10,
                action='tarpit',
                ban_duration=86400 * 31,
            )
    
    def test_from_config_dict_valid(self):
        """Test creating config from dictionary."""
        config_dict = {
            'enabled': True,
            'thresholds': {
                'suspicious': 1,
                'block': 5,
                'ban': 10,
            },
            'action': 'tarpit',
            'ban_duration': 3600,
        }
        
        config = StrategyConfig.from_config_dict(config_dict)
        
        assert config.enabled is True
        assert config.suspicious_threshold == 1
        assert config.block_threshold == 5
        assert config.ban_threshold == 10
        assert config.action == 'tarpit'
        assert config.ban_duration == 3600
    
    def test_from_config_dict_defaults(self):
        """Test defaults are applied for missing values."""
        config_dict = {}
        
        config = StrategyConfig.from_config_dict(config_dict)
        
        assert config.enabled is False  # Default
        assert config.suspicious_threshold == 1
        assert config.block_threshold == 5
        assert config.ban_threshold == 10
        assert config.action == 'tarpit'
        assert config.ban_duration == 3600
    
    def test_from_config_dict_invalid_type(self):
        """Test invalid configuration dictionary raises error."""
        with pytest.raises(ValueError, match="Invalid strategy configuration"):
            StrategyConfig.from_config_dict({
                'enabled': 'not_a_bool',  # Wrong type
                'thresholds': 'not_a_dict',  # Wrong type
            })


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
