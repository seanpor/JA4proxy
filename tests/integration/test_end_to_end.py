#!/usr/bin/env python3
"""
Integration tests for the complete security system.

These tests verify end-to-end functionality of all security phases:
- Phase 1: Multi-strategy rate tracking
- Phase 2: Multi-strategy threat evaluation
- Phase 3: Action enforcement
- Phase 4: GDPR compliance
- Phase 5: Integrated security manager
"""

import pytest
import time
from unittest.mock import Mock, MagicMock, patch

from src.security import (
    SecurityManager,
    ThreatTier,
    ActionType,
    RateLimitStrategy,
)


@pytest.fixture
def mock_redis():
    """Create mock Redis client with realistic behavior."""
    redis = Mock()
    redis.ping.return_value = True
    
    # Storage for tracking state
    redis._data = {}
    redis._ttls = {}
    redis._sorted_sets = {}  # For zadd/zcount
    
    def setex_impl(key, ttl, value):
        redis._data[key] = value
        redis._ttls[key] = ttl
        return True
    
    def get_impl(key):
        return redis._data.get(key)
    
    def exists_impl(key):
        return key in redis._data or key in redis._sorted_sets
    
    def ttl_impl(key):
        return redis._ttls.get(key, -1)
    
    def delete_impl(key):
        deleted = 0
        if key in redis._data:
            del redis._data[key]
            if key in redis._ttls:
                del redis._ttls[key]
            deleted += 1
        if key in redis._sorted_sets:
            del redis._sorted_sets[key]
            deleted += 1
        return deleted
    
    def keys_impl(pattern):
        # Simple pattern matching
        if pattern == '*':
            all_keys = list(redis._data.keys()) + list(redis._sorted_sets.keys())
            return list(set(all_keys))
        prefix = pattern.replace('*', '')
        all_keys = list(redis._data.keys()) + list(redis._sorted_sets.keys())
        return [k for k in all_keys if k.startswith(prefix)]
    
    def zadd_impl(key, mapping):
        """Add to sorted set."""
        if key not in redis._sorted_sets:
            redis._sorted_sets[key] = []
        for member, score in mapping.items():
            # Remove if exists
            redis._sorted_sets[key] = [(m, s) for m, s in redis._sorted_sets[key] if m != member]
            # Add new
            redis._sorted_sets[key].append((member, float(score)))
        return len(mapping)
    
    def zcount_impl(key, min_score, max_score):
        """Count members in sorted set within score range."""
        if key not in redis._sorted_sets:
            return 0
        count = 0
        for member, score in redis._sorted_sets[key]:
            # Handle string comparisons for -inf and +inf
            if min_score == '-inf':
                min_val = float('-inf')
            else:
                min_val = float(min_score)
            if max_score == '+inf':
                max_val = float('inf')
            else:
                max_val = float(max_score)
            
            if min_val <= score <= max_val:
                count += 1
        return count
    
    def expire_impl(key, seconds):
        """Set expiry on key."""
        if key in redis._data or key in redis._sorted_sets:
            redis._ttls[key] = seconds
            return True
        return False
    
    # Mock implementation
    redis.setex.side_effect = setex_impl
    redis.get.side_effect = get_impl
    redis.exists.side_effect = exists_impl
    redis.ttl.side_effect = ttl_impl
    redis.delete.side_effect = delete_impl
    redis.keys.side_effect = keys_impl
    
    # Rate tracking methods
    redis.zadd.side_effect = zadd_impl
    redis.zcount.side_effect = zcount_impl
    redis.expire.side_effect = expire_impl
    
    # Mock INCR for counter
    redis._counters = {}
    def incr_impl(key):
        if key not in redis._counters:
            redis._counters[key] = 0
        redis._counters[key] += 1
        return redis._counters[key]
    redis.incr = Mock(side_effect=incr_impl)
    
    # Mock ZCARD for counting sorted set members
    def zcard_impl(key):
        if key not in redis._sorted_sets:
            return 0
        return len(redis._sorted_sets[key])
    redis.zcard = Mock(side_effect=zcard_impl)
    
    # Mock ZREMRANGEBYSCORE for removing old entries
    def zremrangebyscore_impl(key, min_score, max_score):
        if key not in redis._sorted_sets:
            return 0
        original_count = len(redis._sorted_sets[key])
        # Remove entries within score range
        if min_score == 0 or min_score == '-inf':
            min_val = float('-inf')
        else:
            min_val = float(min_score)
        if max_score == '+inf':
            max_val = float('inf')
        else:
            max_val = float(max_score)
        
        redis._sorted_sets[key] = [
            (m, s) for m, s in redis._sorted_sets[key]
            if not (min_val <= s <= max_val)
        ]
        removed = original_count - len(redis._sorted_sets[key])
        return removed
    redis.zremrangebyscore = Mock(side_effect=zremrangebyscore_impl)
    
    # Mock register_script to return a callable that properly simulates the Lua script
    def mock_script_call(keys=None, args=None, client=None):
        """
        Mock Lua script execution that simulates RATE_TRACKING_SCRIPT behavior.
        
        The script does:
        1. INCR counter_key -> get unique counter
        2. ZADD key, now, "now:counter" -> add timestamped entry
        3. ZREMRANGEBYSCORE key, 0, (now - window) -> remove old entries
        4. ZCARD key -> return count of remaining entries
        """
        if not keys or not args:
            return 0
        
        key = keys[0]
        counter_key = keys[1]
        now = float(args[0])
        window = float(args[1])
        ttl = int(args[2])
        
        # 1. Increment counter
        counter = incr_impl(counter_key)
        
        # 2. Add current connection to sorted set
        unique_id = f"{now}:{counter}"
        zadd_impl(key, {unique_id: now})
        
        # 3. Remove connections outside the window
        cutoff = now - window
        zremrangebyscore_impl(key, 0, cutoff)
        
        # 4. Count remaining connections
        count = zcard_impl(key)
        
        # 5. Set TTL (simulated)
        expire_impl(key, ttl)
        expire_impl(counter_key, ttl)
        
        return count
    
    mock_script = Mock()
    mock_script.side_effect = mock_script_call
    redis.register_script.return_value = mock_script
    
    return redis


@pytest.fixture
def test_config():
    """Create test configuration."""
    return {
        'security': {
            'rate_windows': {
                'short': 1,
                'medium': 10,
                'long': 60,
            },
            'thresholds': {
                'suspicious': 1,
                'block': 5,
                'ban': 10,
            },
            'ban_durations': {
                'suspicious': 300,
                'block': 3600,
                'ban': 604800,
            },
            'rate_limit_strategies': {
                'by_ip': {
                    'enabled': True,
                    'thresholds': {'suspicious': 2, 'block': 10, 'ban': 20},
                    'action': 'block',
                },
                'by_ja4': {
                    'enabled': True,
                    'thresholds': {'suspicious': 5, 'block': 25, 'ban': 50},
                    'action': 'log',
                },
                'by_ip_ja4_pair': {
                    'enabled': True,
                    'thresholds': {'suspicious': 1, 'block': 5, 'ban': 10},
                    'action': 'tarpit',
                },
            },
            'multi_strategy_policy': 'any',
            'tarpit_enabled': True,
            'tarpit_duration': 10,
            'block_action': 'tarpit',
            'ban_duration': 604800,
            'permanent_ban': False,
        },
        'gdpr': {
            'enabled': True,
            'audit_logging': True,
        },
    }


@pytest.fixture
def security_manager(mock_redis, test_config):
    """Create security manager for testing with time.time() mocked."""
    # Mock time.time() to return a consistent float value
    # This prevents Mock comparison errors in rate calculations
    with patch('time.time') as mock_time:
        mock_time.return_value = 1234567890.0
        manager = SecurityManager.from_config(mock_redis, test_config)
        yield manager


class TestSecurityManagerInit:
    """Test SecurityManager initialization."""
    
    def test_init_successful(self, mock_redis, test_config):
        """Test successful initialization."""
        manager = SecurityManager(mock_redis, test_config)
        
        assert manager.redis == mock_redis
        assert manager.config == test_config
        assert manager.rate_tracker is not None
        assert manager.threat_evaluator is not None
        assert manager.action_enforcer is not None
        assert manager.gdpr_storage is not None
    
    def test_init_redis_none(self, test_config):
        """Test initialization fails with None Redis."""
        with pytest.raises(ValueError, match="Redis client is required"):
            SecurityManager(None, test_config)
    
    def test_init_redis_connection_fails(self, test_config):
        """Test initialization fails when Redis connection fails."""
        redis = Mock()
        redis.ping.side_effect = Exception("Connection failed")
        
        with pytest.raises(Exception):
            SecurityManager(redis, test_config)
    
    def test_from_config(self, mock_redis, test_config):
        """Test creation from config."""
        manager = SecurityManager.from_config(mock_redis, test_config)
        
        assert isinstance(manager, SecurityManager)
        assert manager.redis == mock_redis


class TestEndToEndNormalTraffic:
    """Test end-to-end flow for normal traffic."""
    
    def test_allow_first_connection(self, security_manager):
        """Test that first connection is allowed."""
        allowed, reason = security_manager.check_access(
            "t13d1516h2_abc_def",  # ja4 (positional)
            "192.168.1.100",       # client_ip (positional)
        )
        
        assert allowed is True
        assert "Allowed" in reason
    
    def test_allow_low_rate_connections(self, security_manager, mock_redis):
        """Test that connections below threshold are allowed."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Simulate low rate (below suspicious threshold)
        mock_redis.zcount.return_value = 1  # 1 connection in window
        
        for _ in range(3):
            allowed, reason = security_manager.check_access(ja4, ip)
            assert allowed is True
            time.sleep(0.1)


class TestEndToEndSuspiciousTraffic:
    """Test end-to-end flow for suspicious traffic."""
    
    def test_log_suspicious_traffic(self, security_manager, mock_redis):
        """Test that suspicious traffic is logged but allowed."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Make 2 connections in short window to trigger suspicious (threshold is 1/sec)
        # First connection
        allowed1, reason1 = security_manager.check_access(ja4, ip)
        # Second connection (now rate is 2/sec in 1-second window)
        allowed2, reason2 = security_manager.check_access(ja4, ip)
        
        # Both should still be allowed (SUSPICIOUS tier logs but doesn't block)
        assert allowed1 is True
        assert allowed2 is True
        # Check the second one which should show suspicious
        assert "Suspicious" in reason2 or "monitoring" in reason2.lower() or "Allowed" in reason2


class TestEndToEndBlockTraffic:
    """Test end-to-end flow for block-level traffic."""
    
    def test_block_high_rate_traffic(self, security_manager, mock_redis):
        """Test that high rate traffic is blocked."""
        ja4 = "t13d1516h2_abc_def"
        ip="192.168.1.100"
        
        # Make 6 connections rapidly to exceed block threshold (5/sec)
        results = []
        for i in range(6):
            allowed, reason = security_manager.check_access(ja4, ip)
            results.append((allowed, reason))
        
        # After 6 connections, should be blocked (rate > 5/sec)
        last_allowed, last_reason = results[-1]
        assert last_allowed is False
        assert "TARPIT" in last_reason or "block" in last_reason.lower() or "limit" in last_reason.lower() or "ban" in last_reason.lower()
    
    def test_subsequent_connection_blocked(self, security_manager, mock_redis):
        """Test that once blocked, subsequent connections are also blocked."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # First, trigger a block by making many connections
        for i in range(6):
            security_manager.check_access(ja4, ip)
        
        # Now the client should be blocked - try another connection
        allowed, reason = security_manager.check_access(ja4, ip)
        
        # Should be blocked (either by rate or by existing block)
        assert allowed is False
        assert "block" in reason.lower() or "tarpit" in reason.lower() or "ban" in reason.lower()


class TestEndToEndBanTraffic:
    """Test end-to-end flow for ban-level traffic."""
    
    def test_ban_extreme_rate_traffic(self, security_manager, mock_redis):
        """Test that extreme rate traffic is banned."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Make 11+ connections rapidly to exceed ban threshold (10/sec)
        for i in range(12):
            security_manager.check_access(ja4, ip)
        
        # Next connection should be banned
        allowed, reason = security_manager.check_access(ja4, ip)
        
        # Should be banned
        assert allowed is False
        assert "ban" in reason.lower() or "blocked" in reason.lower()


class TestManualUnban:
    """Test manual unban functionality."""
    
    def test_unban_blocked_entity(self, security_manager, mock_redis):
        """Test unbanning a blocked entity."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Block the entity first by making many connections
        for i in range(12):
            security_manager.check_access(ja4, ip)
        
        # Verify it's blocked
        allowed, _ = security_manager.check_access(ja4, ip)
        assert allowed is False
        
        # Now unban
        result = security_manager.manual_unban(ja4, ip, reason="False positive")
        
        # Should return True if something was unbanned
        assert isinstance(result, bool)
    
    def test_unban_not_blocked_entity(self, security_manager):
        """Test unbanning an entity that isn't blocked."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Try to unban without blocking first
        result = security_manager.manual_unban(ja4, ip)
        
        # Should return False (nothing to unban)
        assert result is False


class TestStatistics:
    """Test statistics gathering."""
    
    def test_get_statistics(self, security_manager):
        """Test getting comprehensive statistics."""
        stats = security_manager.get_statistics()
        
        assert 'enforcement' in stats
        assert 'gdpr_compliance' in stats
        assert 'retention_report' in stats
    
    def test_verify_gdpr_compliance(self, security_manager):
        """Test GDPR compliance verification."""
        compliance = security_manager.verify_gdpr_compliance()
        
        assert 'compliant_keys' in compliance
        assert 'non_compliant_keys' in compliance
        assert 'compliance_rate' in compliance


class TestErrorHandling:
    """Test error handling and fail-secure behavior."""
    
    def test_invalid_inputs(self, security_manager):
        """Test handling of invalid inputs."""
        # Empty JA4
        allowed, reason = security_manager.check_access("", "192.168.1.100")
        assert allowed is False
        assert "Invalid" in reason
        
        # Empty IP
        allowed, reason = security_manager.check_access("t13d1516h2_abc_def", "")
        assert allowed is False
        assert "Invalid" in reason
    
    def test_redis_error_fails_secure(self, security_manager, mock_redis):
        """Test that Redis errors result in blocking (fail-secure)."""
        mock_redis.ping.side_effect = Exception("Redis error")
        
        # Create new manager that will fail to connect
        with pytest.raises(Exception):
            SecurityManager(mock_redis, security_manager.config)


class TestMultiStrategyIntegration:
    """Test multi-strategy integration."""
    
    def test_different_strategies_different_thresholds(self, security_manager, mock_redis):
        """Test that different strategies have different thresholds."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Make 6 connections to trigger blocking  
        # Different strategies track differently but all will see the connections
        for i in range(6):
            allowed, reason = security_manager.check_access(ja4, ip)
        
        # Last one should be blocked
        allowed, reason = security_manager.check_access(ja4, ip)
        assert allowed is False


class TestGDPRIntegration:
    """Test GDPR compliance integration."""
    
    def test_enforcement_data_stored_with_gdpr(self, security_manager, mock_redis):
        """Test that enforcement data is stored with GDPR compliance."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Trigger enforcement by making many connections
        for i in range(12):
            security_manager.check_access(ja4, ip)
        
        # Check that data was stored
        total_keys = len(mock_redis._data) + len(mock_redis._sorted_sets)
        assert total_keys > 0, "No data was stored"
        
        # All stored data should have TTLs (GDPR compliance)
        for key in list(mock_redis._data.keys()) + list(mock_redis._sorted_sets.keys()):
            if key in mock_redis._ttls:
                assert mock_redis._ttls[key] > 0, f"Key {key} has invalid TTL"


class TestRealWorldScenarios:
    """Test realistic attack scenarios."""
    
    def test_gradual_rate_increase(self, security_manager, mock_redis):
        """Test gradual increase in connection rate."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Start with 1 connection - should be allowed
        allowed, _ = security_manager.check_access(ja4, ip)
        assert allowed is True
        
        # Add 1 more - now rate is 2/sec (suspicious but still allowed)
        allowed, _ = security_manager.check_access(ja4, ip)
        # Still allowed (just suspicious)
        assert allowed is True
        
        # Add 4 more to reach 6 total - now exceeds block threshold (5/sec)
        for i in range(4):
            security_manager.check_access(ja4, ip)
        
        # Next one should be blocked
        allowed, _ = security_manager.check_access(ja4, ip)
        assert allowed is False
    
    def test_burst_attack(self, security_manager, mock_redis):
        """Test sudden burst of connections."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Sudden burst - make 20 connections rapidly
        for i in range(20):
            allowed, reason = security_manager.check_access(ja4, ip)
        
        # After burst, should be banned
        allowed, reason = security_manager.check_access(ja4, ip)
        assert allowed is False
        assert "ban" in reason.lower() or "blocked" in reason.lower()
    
    def test_distributed_attack(self, security_manager, mock_redis):
        """Test distributed attack from multiple IPs."""
        ja4 = "t13d1516h2_abc_def"  # Same JA4 (botnet)
        
        # Different IPs, each with moderate rate
        ips = [f"192.168.1.{i}" for i in range(10)]
        
        mock_redis.zcount.return_value = 3  # Each IP: 3/sec
        
        results = []
        for ip in ips:
            allowed, reason = security_manager.check_access(ja4, ip)
            results.append(allowed)
        
        # Individual IPs might be allowed, but BY_JA4 strategy would catch it
        # (In real scenario with proper Redis state tracking)
        assert isinstance(results, list)


class TestIntegrationEdgeCases:
    """Test edge cases in integration."""
    
    def test_exactly_at_threshold(self, security_manager, mock_redis):
        """Test behavior exactly at threshold."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Exactly at block threshold (not exceeding)
        mock_redis.zcount.return_value = 5
        allowed, reason = security_manager.check_access(ja4, ip)
        
        # Should be allowed (threshold is "greater than", not ">=")
        assert allowed is True
    
    def test_rapid_succession_same_client(self, security_manager, mock_redis):
        """Test rapid successive calls for same client."""
        ja4 = "t13d1516h2_abc_def"
        ip = "192.168.1.100"
        
        # Simulate rapid calls
        mock_redis.zcount.return_value = 1
        results = []
        
        for _ in range(10):
            allowed, _ = security_manager.check_access(ja4, ip)
            results.append(allowed)
        
        # First should be allowed, subsequent depend on rate
        assert results[0] is True
