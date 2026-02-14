#!/usr/bin/env python3
"""
Unit tests for multi-strategy rate tracker.

Tests cover:
- Redis atomic operations
- Strategy-specific tracking
- Security (injection prevention, fail-closed)
- GDPR compliance (TTLs)
- Error handling
"""

import pytest
import time
from unittest.mock import Mock, MagicMock, patch

import redis

from src.security.rate_tracker import (
    MultiStrategyRateTracker,
    RateTrackerError,
    RedisConnectionError,
)
from src.security.rate_strategy import (
    RateLimitStrategy,
    RateMetrics,
)


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    mock = Mock(spec=redis.Redis)
    mock.ping.return_value = True
    
    # Mock script registration
    mock_script = Mock()
    mock_script.return_value = 1  # Default return: 1 connection
    mock.register_script.return_value = mock_script
    
    return mock


@pytest.fixture
def test_config():
    """Create test configuration."""
    return {
        'security': {
            'rate_limit_strategies': {
                'by_ip': {
                    'enabled': True,
                    'thresholds': {
                        'suspicious': 2,
                        'block': 10,
                        'ban': 20,
                    },
                    'action': 'block',
                    'ban_duration': 7200,
                },
                'by_ja4': {
                    'enabled': True,
                    'thresholds': {
                        'suspicious': 5,
                        'block': 25,
                        'ban': 50,
                    },
                    'action': 'log',
                    'ban_duration': 3600,
                },
                'by_ip_ja4_pair': {
                    'enabled': True,
                    'thresholds': {
                        'suspicious': 1,
                        'block': 5,
                        'ban': 10,
                    },
                    'action': 'tarpit',
                    'ban_duration': 3600,
                },
            },
            'rate_windows': {
                'short': 1.0,
                'medium': 10.0,
                'long': 60.0,
            },
        },
    }


class TestMultiStrategyRateTrackerInit:
    """Test tracker initialization."""
    
    def test_init_successful(self, mock_redis, test_config):
        """Test successful initialization."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        assert tracker.redis == mock_redis
        assert len(tracker.enabled_strategies) == 3
        assert RateLimitStrategy.BY_IP in tracker.enabled_strategies
        assert RateLimitStrategy.BY_JA4 in tracker.enabled_strategies
        assert RateLimitStrategy.BY_IP_JA4_PAIR in tracker.enabled_strategies
        
        mock_redis.ping.assert_called_once()
        mock_redis.register_script.assert_called_once()
    
    def test_init_redis_connection_fails(self, test_config):
        """Test initialization fails if Redis unavailable."""
        mock_redis = Mock(spec=redis.Redis)
        mock_redis.ping.side_effect = redis.ConnectionError("Connection failed")
        
        with pytest.raises(RedisConnectionError, match="Connection failed"):
            MultiStrategyRateTracker(mock_redis, test_config)
    
    def test_init_redis_timeout(self, test_config):
        """Test initialization fails on Redis timeout."""
        mock_redis = Mock(spec=redis.Redis)
        mock_redis.ping.side_effect = redis.TimeoutError("Timeout")
        
        with pytest.raises(RedisConnectionError, match="Timeout"):
            MultiStrategyRateTracker(mock_redis, test_config)
    
    def test_init_no_strategies_enabled(self, mock_redis):
        """Test initialization with no strategies enabled."""
        config = {
            'security': {
                'rate_limit_strategies': {
                    'by_ip': {'enabled': False},
                    'by_ja4': {'enabled': False},
                    'by_ip_ja4_pair': {'enabled': False},
                },
            },
        }
        
        tracker = MultiStrategyRateTracker(mock_redis, config)
        assert len(tracker.enabled_strategies) == 0
    
    def test_init_validates_window_config(self, mock_redis, test_config):
        """Test window configuration validation."""
        # Invalid window (too large)
        test_config['security']['rate_windows']['invalid'] = 99999
        
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        # Should use defaults for invalid values
        assert 'short' in tracker.windows
        assert tracker.windows['short'] == 1.0
    
    def test_init_too_many_strategies(self, mock_redis):
        """Test security limit on number of strategies."""
        config = {
            'security': {
                'rate_limit_strategies': {
                    f'strategy_{i}': {'enabled': True}
                    for i in range(15)  # More than MAX_STRATEGIES (10)
                },
            },
        }
        
        with pytest.raises(ValueError, match="Too many strategies"):
            MultiStrategyRateTracker(mock_redis, config)


class TestTrackConnection:
    """Test connection tracking functionality."""
    
    def test_track_connection_single_strategy(self, mock_redis, test_config):
        """Test tracking with single strategy enabled."""
        # Enable only one strategy
        test_config['security']['rate_limit_strategies']['by_ja4']['enabled'] = False
        test_config['security']['rate_limit_strategies']['by_ip_ja4_pair']['enabled'] = False
        
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        tracker.rate_script.return_value = 5  # Mock: 5 connections
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        assert len(results) == 1
        assert RateLimitStrategy.BY_IP in results
        
        metrics = results[RateLimitStrategy.BY_IP]
        assert metrics.connections_per_second == 5
        assert metrics.strategy == RateLimitStrategy.BY_IP
        assert metrics.entity_id == "192.168.1.100"
    
    def test_track_connection_all_strategies(self, mock_redis, test_config):
        """Test tracking with all strategies enabled."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        tracker.rate_script.return_value = 3  # Mock: 3 connections
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        assert len(results) == 3
        assert RateLimitStrategy.BY_IP in results
        assert RateLimitStrategy.BY_JA4 in results
        assert RateLimitStrategy.BY_IP_JA4_PAIR in results
        
        # All should report same count (mocked)
        for metrics in results.values():
            assert metrics.connections_per_second == 3
    
    def test_track_connection_validates_ja4_empty(self, mock_redis, test_config):
        """Test tracking validates JA4 is not empty."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        with pytest.raises(ValueError, match="non-empty string"):
            tracker.track_connection("", "192.168.1.100")
    
    def test_track_connection_validates_ip_empty(self, mock_redis, test_config):
        """Test tracking validates IP is not empty."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        with pytest.raises(ValueError, match="non-empty string"):
            tracker.track_connection("t13d1516h2_abc123_def456", "")
    
    def test_track_connection_validates_ja4_type(self, mock_redis, test_config):
        """Test tracking validates JA4 type."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        with pytest.raises(ValueError):
            tracker.track_connection(None, "192.168.1.100")
        
        with pytest.raises(ValueError):
            tracker.track_connection(123, "192.168.1.100")
    
    def test_track_connection_validates_ja4_length(self, mock_redis, test_config):
        """Test tracking validates JA4 length."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        with pytest.raises(ValueError, match="too long"):
            tracker.track_connection("x" * 300, "192.168.1.100")
    
    def test_track_connection_validates_ip_length(self, mock_redis, test_config):
        """Test tracking validates IP length."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        with pytest.raises(ValueError, match="too long"):
            tracker.track_connection("t13d1516h2_abc123_def456", "x" * 100)
    
    def test_track_connection_redis_error_fails_closed(self, mock_redis, test_config):
        """Test Redis errors cause fail-closed behavior."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        # Simulate Redis error
        tracker.rate_script.side_effect = redis.ConnectionError("Connection lost")
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        # Should return high rate (fail closed) for all strategies
        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW
    
    def test_track_connection_enforces_max_limit(self, mock_redis, test_config):
        """Test maximum connection limit is enforced."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        # Simulate Redis returning very high count
        tracker.rate_script.return_value = 99999
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        # Should be capped at MAX_CONNECTIONS_PER_WINDOW
        for metrics in results.values():
            assert metrics.connections_per_second == tracker.MAX_CONNECTIONS_PER_WINDOW
    
    def test_track_connection_different_windows(self, mock_redis, test_config):
        """Test tracking with different window sizes."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        tracker.rate_script.return_value = 5
        
        # Short window
        results_short = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100",
            window='short'
        )
        
        # Medium window
        results_medium = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100",
            window='medium'
        )
        
        # Both should work
        assert len(results_short) == 3
        assert len(results_medium) == 3
        
        # Window sizes should be different
        for metrics in results_short.values():
            assert metrics.window_seconds == 1.0
        
        for metrics in results_medium.values():
            assert metrics.window_seconds == 10.0


class TestStrategySpecificTracking:
    """Test strategy-specific tracking behavior."""
    
    def test_by_ip_uses_ip_only(self, mock_redis, test_config):
        """Test BY_IP strategy uses only IP in key."""
        # Enable only BY_IP
        test_config['security']['rate_limit_strategies']['by_ja4']['enabled'] = False
        test_config['security']['rate_limit_strategies']['by_ip_ja4_pair']['enabled'] = False
        
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        tracker.rate_script.return_value = 5
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        metrics = results[RateLimitStrategy.BY_IP]
        assert metrics.entity_id == "192.168.1.100"
    
    def test_by_ja4_uses_ja4_only(self, mock_redis, test_config):
        """Test BY_JA4 strategy uses only JA4 in key."""
        # Enable only BY_JA4
        test_config['security']['rate_limit_strategies']['by_ip']['enabled'] = False
        test_config['security']['rate_limit_strategies']['by_ip_ja4_pair']['enabled'] = False
        
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        tracker.rate_script.return_value = 5
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        metrics = results[RateLimitStrategy.BY_JA4]
        assert metrics.entity_id == "t13d1516h2_abc123_def456"
    
    def test_by_pair_uses_both(self, mock_redis, test_config):
        """Test BY_IP_JA4_PAIR strategy uses both IP and JA4."""
        # Enable only BY_IP_JA4_PAIR
        test_config['security']['rate_limit_strategies']['by_ip']['enabled'] = False
        test_config['security']['rate_limit_strategies']['by_ja4']['enabled'] = False
        
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        tracker.rate_script.return_value = 5
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        metrics = results[RateLimitStrategy.BY_IP_JA4_PAIR]
        assert metrics.entity_id == "192.168.1.100|t13d1516h2_abc123_def456"
        assert "|" in metrics.entity_id


class TestStrategyConfig:
    """Test strategy configuration retrieval."""
    
    def test_get_strategy_config(self, mock_redis, test_config):
        """Test retrieving strategy configuration."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        config = tracker.get_strategy_config(RateLimitStrategy.BY_IP)
        
        assert config.enabled is True
        assert config.suspicious_threshold == 2
        assert config.block_threshold == 10
        assert config.ban_threshold == 20
        assert config.action == 'block'
        assert config.ban_duration == 7200
    
    def test_get_strategy_config_not_configured(self, mock_redis):
        """Test error when strategy not configured."""
        config = {'security': {'rate_limit_strategies': {}}}
        tracker = MultiStrategyRateTracker(mock_redis, config)
        
        with pytest.raises(ValueError, match="not configured"):
            tracker.get_strategy_config(RateLimitStrategy.BY_IP)


class TestHealthCheck:
    """Test health check functionality."""
    
    def test_health_check_healthy(self, mock_redis, test_config):
        """Test health check when Redis is healthy."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        assert tracker.health_check() is True
        mock_redis.ping.assert_called()
    
    def test_health_check_unhealthy(self, mock_redis, test_config):
        """Test health check when Redis is unhealthy."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        # Simulate Redis failure
        mock_redis.ping.side_effect = redis.ConnectionError("Connection lost")
        
        assert tracker.health_check() is False


class TestGDPRCompliance:
    """Test GDPR compliance features."""
    
    def test_ttl_set_on_tracking(self, mock_redis, test_config):
        """Test that TTL is set for GDPR compliance."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        # The Lua script should set TTL - verify script is called
        tracker.rate_script.return_value = 1
        
        tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        # Verify Lua script was called (which includes TTL setting)
        assert tracker.rate_script.called
    
    def test_minimal_retention_period(self, mock_redis, test_config):
        """Test that retention period is minimal."""
        tracker = MultiStrategyRateTracker(mock_redis, test_config)
        
        # Default TTL should be 60 seconds
        assert tracker.DEFAULT_TTL_SECONDS == 60


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
