#!/usr/bin/env python3
"""
Unit tests for action enforcement.

Tests action application, Redis state management, and enforcement logic.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch

from src.security.action_types import ActionType, ActionConfig
from src.security.action_enforcer import ActionEnforcer
from src.security.rate_strategy import RateLimitStrategy
from src.security.threat_tier import ThreatTier


@pytest.fixture
def mock_redis():
    """Create mock Redis client."""
    redis = Mock()
    redis.ping.return_value = True
    redis.exists.return_value = False
    redis.get.return_value = None
    redis.set.return_value = True
    redis.setex.return_value = True
    redis.delete.return_value = 0
    redis.ttl.return_value = -1
    redis.keys.return_value = []
    return redis


@pytest.fixture
def action_config():
    """Create test action configuration."""
    return ActionConfig(
        tarpit_enabled=True,
        tarpit_duration=10,
        block_action="tarpit",
        ban_duration=3600,
        permanent_ban=False,
    )


@pytest.fixture
def enforcer(mock_redis, action_config):
    """Create test action enforcer."""
    return ActionEnforcer(
        redis_client=mock_redis,
        action_config=action_config,
    )


class TestActionEnforcerInit:
    """Test ActionEnforcer initialization."""
    
    def test_init_successful(self, mock_redis, action_config):
        """Test successful initialization."""
        enforcer = ActionEnforcer(
            redis_client=mock_redis,
            action_config=action_config,
        )
        
        assert enforcer.redis == mock_redis
        assert enforcer.action_config == action_config
        mock_redis.ping.assert_called_once()
    
    def test_init_redis_none(self, action_config):
        """Test initialization fails with None Redis client."""
        with pytest.raises(ValueError, match="Redis client is required"):
            ActionEnforcer(
                redis_client=None,
                action_config=action_config,
            )
    
    def test_init_redis_connection_fails(self, action_config):
        """Test initialization fails when Redis connection fails."""
        redis = Mock()
        redis.ping.side_effect = Exception("Connection failed")
        
        with pytest.raises(Exception, match="Connection failed"):
            ActionEnforcer(
                redis_client=redis,
                action_config=action_config,
            )
    
    def test_init_with_strategy_configs(self, mock_redis, action_config):
        """Test initialization with strategy configurations."""
        strategy_configs = {
            RateLimitStrategy.BY_IP: {'action': 'block'},
            RateLimitStrategy.BY_IP_JA4_PAIR: {'action': 'tarpit'},
        }
        
        enforcer = ActionEnforcer(
            redis_client=mock_redis,
            action_config=action_config,
            strategy_configs=strategy_configs,
        )
        
        assert enforcer.strategy_configs == strategy_configs


class TestEnforceNormal:
    """Test enforcement for NORMAL tier."""
    
    def test_enforce_normal_tier(self, enforcer):
        """Test NORMAL tier allows connection."""
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.NORMAL,
        )
        
        assert result.allowed is True
        assert result.action_type == ActionType.LOG
        assert result.reason == "Normal traffic"
        assert result.duration == 0


class TestEnforceSuspicious:
    """Test enforcement for SUSPICIOUS tier."""
    
    def test_enforce_suspicious_tier(self, enforcer, mock_redis):
        """Test SUSPICIOUS tier logs but allows connection."""
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.SUSPICIOUS,
        )
        
        assert result.allowed is True
        assert result.action_type == ActionType.LOG
        assert "Suspicious" in result.reason
        assert result.duration == 300  # 5 minutes
        
        # Verify Redis store
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        assert "suspicious:" in call_args[0][0]
        assert call_args[0][1] == 300  # TTL


class TestEnforceBlock:
    """Test enforcement for BLOCK tier."""
    
    def test_enforce_block_with_tarpit(self, enforcer, mock_redis):
        """Test BLOCK tier applies TARPIT."""
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
        )
        
        assert result.allowed is False
        assert result.action_type == ActionType.TARPIT
        assert "TARPIT" in result.reason
        assert result.duration == 3600
        
        # Verify Redis store
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        assert "blocked:tarpit:" in call_args[0][0]
        assert call_args[0][1] == 3600  # TTL
    
    def test_enforce_block_with_block_action(self, mock_redis):
        """Test BLOCK tier with hard block action."""
        config = ActionConfig(
            tarpit_enabled=False,
            block_action="block",
        )
        enforcer = ActionEnforcer(mock_redis, config)
        
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
        )
        
        assert result.allowed is False
        assert result.action_type == ActionType.BLOCK
        assert "blocked" in result.reason
    
    def test_enforce_block_with_action_override(self, enforcer):
        """Test BLOCK tier with action override."""
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
            action_override="block",
        )
        
        assert result.allowed is False
        assert result.action_type == ActionType.BLOCK
    
    def test_enforce_block_with_strategy_action(self, mock_redis, action_config):
        """Test BLOCK tier with strategy-specific action."""
        strategy_configs = {
            RateLimitStrategy.BY_IP: {'action': 'block'},
        }
        enforcer = ActionEnforcer(mock_redis, action_config, strategy_configs)
        
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
            strategy=RateLimitStrategy.BY_IP,
        )
        
        assert result.action_type == ActionType.BLOCK


class TestEnforceBanned:
    """Test enforcement for BANNED tier."""
    
    def test_enforce_ban_temporary(self, enforcer, mock_redis):
        """Test BANNED tier applies temporary ban."""
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BANNED,
        )
        
        assert result.allowed is False
        assert result.action_type == ActionType.BAN
        assert "Banned" in result.reason
        assert result.duration == 3600
        
        # Verify Redis store
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        assert "banned:temporary:" in call_args[0][0]
        assert call_args[0][1] == 3600  # TTL
    
    def test_enforce_ban_permanent(self, mock_redis):
        """Test BANNED tier applies permanent ban."""
        config = ActionConfig(ban_duration=0, permanent_ban=True)
        enforcer = ActionEnforcer(mock_redis, config)
        
        result = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BANNED,
        )
        
        assert result.allowed is False
        assert result.action_type == ActionType.BAN
        assert "Permanently" in result.reason
        assert result.duration == 0
        
        # Verify Redis store (no TTL)
        mock_redis.set.assert_called_once()
        call_args = mock_redis.set.call_args
        assert "banned:permanent:" in call_args[0][0]


class TestIsBlocked:
    """Test checking if entity is blocked."""
    
    def test_is_blocked_not_blocked(self, enforcer, mock_redis):
        """Test checking entity that is not blocked."""
        mock_redis.exists.return_value = False
        
        is_blocked, reason = enforcer.is_blocked(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
        )
        
        assert is_blocked is False
        assert reason is None
    
    def test_is_blocked_blocked(self, enforcer, mock_redis):
        """Test checking entity that is blocked."""
        mock_redis.exists.return_value = True
        mock_redis.ttl.return_value = 1800
        
        is_blocked, reason = enforcer.is_blocked(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
        )
        
        assert is_blocked is True
        assert "Blocked" in reason
        assert "1800s" in reason
    
    def test_is_blocked_banned_temporary(self, enforcer, mock_redis):
        """Test checking entity that is temporarily banned."""
        def exists_side_effect(key):
            return "banned:" in key
        
        mock_redis.exists.side_effect = exists_side_effect
        mock_redis.ttl.return_value = 3600
        
        is_blocked, reason = enforcer.is_blocked(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
        )
        
        assert is_blocked is True
        assert "Banned" in reason
        assert "3600s" in reason
    
    def test_is_blocked_banned_permanent(self, enforcer, mock_redis):
        """Test checking entity that is permanently banned."""
        def exists_side_effect(key):
            return "banned:" in key
        
        mock_redis.exists.side_effect = exists_side_effect
        mock_redis.ttl.return_value = -1  # No TTL
        
        is_blocked, reason = enforcer.is_blocked(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
        )
        
        assert is_blocked is True
        assert "Permanently banned" in reason
    
    def test_is_blocked_specific_strategies(self, enforcer, mock_redis):
        """Test checking with specific strategies."""
        mock_redis.exists.return_value = False
        
        is_blocked, reason = enforcer.is_blocked(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            strategies=[RateLimitStrategy.BY_IP],
        )
        
        assert is_blocked is False


class TestUnban:
    """Test manual unban functionality."""
    
    def test_unban_banned_entity(self, enforcer, mock_redis):
        """Test unbanning a banned entity."""
        mock_redis.delete.return_value = 1  # 1 key deleted
        
        result = enforcer.unban(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
        )
        
        assert result is True
        assert mock_redis.delete.call_count > 0
    
    def test_unban_not_banned_entity(self, enforcer, mock_redis):
        """Test unbanning an entity that is not banned."""
        mock_redis.delete.return_value = 0  # No keys deleted
        
        result = enforcer.unban(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
        )
        
        assert result is False
    
    def test_unban_specific_strategy(self, enforcer, mock_redis):
        """Test unbanning with specific strategy."""
        mock_redis.delete.return_value = 1
        
        result = enforcer.unban(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            strategy=RateLimitStrategy.BY_IP,
        )
        
        assert result is True


class TestEnforcementStats:
    """Test enforcement statistics."""
    
    def test_get_enforcement_stats(self, enforcer, mock_redis):
        """Test getting enforcement statistics."""
        # Mock Redis keys response
        mock_redis.keys.side_effect = [
            [b"blocked:tarpit:1", b"blocked:tarpit:2"],  # 2 tarpit blocks
            [b"blocked:block:1"],                         # 1 hard block
            [b"banned:temporary:1"],                      # 1 temp ban
            [],                                           # 0 permanent bans
            [b"suspicious:1", b"suspicious:2", b"suspicious:3"],  # 3 suspicious
        ]
        
        stats = enforcer.get_enforcement_stats()
        
        assert stats['blocked_tarpit'] == 2
        assert stats['blocked_block'] == 1
        assert stats['total_blocked'] == 3
        assert stats['banned_temporary'] == 1
        assert stats['banned_permanent'] == 0
        assert stats['total_banned'] == 1
        assert stats['suspicious'] == 3
    
    def test_get_enforcement_stats_error(self, enforcer, mock_redis):
        """Test getting stats when Redis error occurs."""
        mock_redis.keys.side_effect = Exception("Redis error")
        
        stats = enforcer.get_enforcement_stats()
        
        assert stats == {}


class TestFromConfig:
    """Test creating enforcer from configuration."""
    
    def test_from_config(self, mock_redis):
        """Test creation from configuration dictionary."""
        config = {
            'security': {
                'tarpit_enabled': True,
                'tarpit_duration': 30,
                'block_action': 'tarpit',
                'ban_duration': 7200,
                'rate_limit_strategies': {
                    'by_ip': {
                        'enabled': True,
                        'action': 'block',
                    },
                    'by_ip_ja4_pair': {
                        'enabled': True,
                        'action': 'tarpit',
                    },
                },
            }
        }
        
        enforcer = ActionEnforcer.from_config(mock_redis, config)
        
        assert enforcer.action_config.tarpit_duration == 30
        assert RateLimitStrategy.BY_IP in enforcer.strategy_configs
        assert RateLimitStrategy.BY_IP_JA4_PAIR in enforcer.strategy_configs
    
    def test_from_config_minimal(self, mock_redis):
        """Test creation with minimal configuration."""
        config = {}
        
        enforcer = ActionEnforcer.from_config(mock_redis, config)
        
        # Should use defaults
        assert enforcer.action_config.tarpit_duration == 10


class TestEnforceEdgeCases:
    """Test edge cases and error handling."""
    
    def test_enforce_invalid_inputs(self, enforcer):
        """Test enforcement with invalid inputs."""
        # Empty JA4
        result = enforcer.enforce(
            ja4="",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
        )
        
        assert result.allowed is False
        assert result.action_type == ActionType.BLOCK
        assert "Invalid" in result.reason
    
    def test_enforce_unknown_tier(self, enforcer):
        """Test enforcement with unknown tier (fail secure)."""
        # Mock an invalid tier (shouldn't happen in practice)
        with patch('src.security.action_enforcer.ThreatTier') as mock_tier:
            mock_tier.NORMAL = ThreatTier.NORMAL
            mock_tier.SUSPICIOUS = ThreatTier.SUSPICIOUS
            mock_tier.BLOCK = ThreatTier.BLOCK
            mock_tier.BANNED = ThreatTier.BANNED
            
            result = enforcer.enforce(
                ja4="t13d1516h2_abc_def",
                ip="192.168.1.100",
                tier=999,  # Invalid tier
            )
            
            # Should fail secure
            assert result.allowed is False
    
    def test_enforce_with_different_strategies(self, enforcer):
        """Test enforcement with different strategies."""
        # BY_IP
        result_ip = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
            strategy=RateLimitStrategy.BY_IP,
        )
        
        # BY_JA4
        result_ja4 = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
            strategy=RateLimitStrategy.BY_JA4,
        )
        
        # BY_IP_JA4_PAIR
        result_pair = enforcer.enforce(
            ja4="t13d1516h2_abc_def",
            ip="192.168.1.100",
            tier=ThreatTier.BLOCK,
            strategy=RateLimitStrategy.BY_IP_JA4_PAIR,
        )
        
        # All should block
        assert result_ip.allowed is False
        assert result_ja4.allowed is False
        assert result_pair.allowed is False
        
        # Entity IDs should be different
        assert result_ip.entity_id != result_pair.entity_id
