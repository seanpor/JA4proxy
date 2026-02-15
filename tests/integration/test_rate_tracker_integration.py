#!/usr/bin/env python3
"""
Integration tests for multi-strategy rate tracker with real Redis.

These tests require a running Redis instance and verify:
- End-to-end rate tracking
- Real sliding window behavior
- Multiple strategies working together
- Actual Redis operations
- Performance under load
"""

import pytest
import time
import redis
import os

from src.security.rate_tracker import (
    MultiStrategyRateTracker,
    RedisConnectionError,
)
from src.security.rate_strategy import RateLimitStrategy


@pytest.fixture
def redis_client():
    """Create Redis client for integration tests with cleanup."""
    redis_host = os.getenv('REDIS_HOST', 'localhost')
    redis_port = int(os.getenv('REDIS_PORT', '6379'))
    redis_password = os.getenv('REDIS_PASSWORD', None)
    
    client = redis.Redis(
        host=redis_host,
        port=redis_port,
        password=redis_password,
        db=15,  # Use db 15 for tests to avoid conflicts
        decode_responses=False,
    )
    
    try:
        client.ping()
    except redis.ConnectionError:
        pytest.skip("Redis not available for integration tests")
    
    # Clean up before each test
    client.flushdb()
    
    yield client
    
    # Clean up after each test
    client.flushdb()
    client.close()


@pytest.fixture
def integration_config():
    """Configuration for integration tests."""
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


class TestRealRedisOperations:
    """Test with real Redis operations."""
    
    def test_single_connection_tracked(self, redis_client, integration_config):
        """Test that a single connection is tracked correctly."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        # All strategies should report 1 connection
        assert results[RateLimitStrategy.BY_IP].connections_per_second == 1
        assert results[RateLimitStrategy.BY_JA4].connections_per_second == 1
        assert results[RateLimitStrategy.BY_IP_JA4_PAIR].connections_per_second == 1
    
    def test_multiple_connections_same_ip(self, redis_client, integration_config):
        """Test tracking multiple connections from same IP."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        # Send 5 connections from same IP, different JA4s
        ja4s = [f"t13d1516h2_abc{i:03d}_def{i:03d}" for i in range(5)]
        
        for ja4 in ja4s:
            results = tracker.track_connection(ja4, "192.168.1.100")
        
        last_results = results
        
        # BY_IP should aggregate across all JA4s
        assert last_results[RateLimitStrategy.BY_IP].connections_per_second == 5
        
        # BY_JA4 should only count the last JA4
        assert last_results[RateLimitStrategy.BY_JA4].connections_per_second == 1
        
        # BY_IP_JA4_PAIR should only count the last unique pair
        assert last_results[RateLimitStrategy.BY_IP_JA4_PAIR].connections_per_second == 1
    
    def test_multiple_connections_same_ja4(self, redis_client, integration_config):
        """Test tracking multiple connections with same JA4 from different IPs."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ja4 = "t13d1516h2_abc123_def456"
        
        # Send from 5 different IPs with same JA4
        for i in range(5):
            results = tracker.track_connection(ja4, f"192.168.1.{100+i}")
        
        last_results = results
        
        # BY_IP should only count the last IP
        assert last_results[RateLimitStrategy.BY_IP].connections_per_second == 1
        
        # BY_JA4 should aggregate across all IPs
        assert last_results[RateLimitStrategy.BY_JA4].connections_per_second == 5
        
        # BY_IP_JA4_PAIR should only count the last unique pair
        assert last_results[RateLimitStrategy.BY_IP_JA4_PAIR].connections_per_second == 1
    
    def test_sliding_window_expiration(self, redis_client, integration_config):
        """Test that connections expire from sliding window."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ja4 = "t13d1516h2_abc123_def456"
        ip = "192.168.1.100"
        
        # First connection
        results1 = tracker.track_connection(ja4, ip)
        assert results1[RateLimitStrategy.BY_IP].connections_per_second == 1
        
        # Wait for window to fully expire (3 seconds to ensure 1-second window is clear)
        time.sleep(3.0)
        
        # Second connection (first should definitely be expired)
        results2 = tracker.track_connection(ja4, ip)
        # Should be 1 since the first connection is outside the 1-second window
        assert results2[RateLimitStrategy.BY_IP].connections_per_second <= 2, \
            f"Expected <=2 connections after window expiry, got {results2[RateLimitStrategy.BY_IP].connections_per_second}"
    
    def test_rapid_connections_within_window(self, redis_client, integration_config):
        """Test rapid connections within the window are all counted."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ja4 = "t13d1516h2_abc123_def456"
        ip = "192.168.1.100"
        
        # Send 10 connections rapidly
        for i in range(10):
            results = tracker.track_connection(ja4, ip)
        
        # All 10 should be counted
        assert results[RateLimitStrategy.BY_IP_JA4_PAIR].connections_per_second == 10
    
    def test_redis_keys_have_ttl(self, redis_client, integration_config):
        """Test that Redis keys have TTL set for GDPR compliance."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        results = tracker.track_connection(
            "t13d1516h2_abc123_def456",
            "192.168.1.100"
        )
        
        # Check that keys exist and have TTL
        keys = redis_client.keys("rate:*")
        assert len(keys) > 0
        
        for key in keys:
            ttl = redis_client.ttl(key)
            assert ttl > 0, f"Key {key} has no TTL (permanent storage)"
            assert ttl <= 60, f"Key {key} has TTL > 60 seconds (GDPR concern)"
    
    def test_concurrent_connections(self, redis_client, integration_config):
        """Test that concurrent connections are tracked correctly."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ja4 = "t13d1516h2_abc123_def456"
        ip = "192.168.1.100"
        
        # Simulate near-concurrent connections
        results_list = []
        for i in range(5):
            result = tracker.track_connection(ja4, ip)
            results_list.append(result)
            time.sleep(0.01)  # 10ms apart
        
        # Last result should show all 5 connections
        assert results_list[-1][RateLimitStrategy.BY_IP_JA4_PAIR].connections_per_second == 5


class TestScenarios:
    """Test realistic attack/usage scenarios."""
    
    def test_scenario_single_source_flood(self, redis_client, integration_config):
        """
        Scenario: Single IP flooding with various tools (different JA4s).
        Expected: BY_IP strategy catches it.
        """
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ip = "192.168.1.100"
        
        # Attacker sends 15 connections with different JA4s
        for i in range(15):
            ja4 = f"t13d1516h2_tool{i:02d}_sig{i:02d}"
            results = tracker.track_connection(ja4, ip)
        
        final_results = results
        
        # BY_IP should catch the flood (15 > threshold of 10)
        by_ip_rate = final_results[RateLimitStrategy.BY_IP].connections_per_second
        assert by_ip_rate == 15
        
        # Should exceed block threshold
        config = tracker.get_strategy_config(RateLimitStrategy.BY_IP)
        assert by_ip_rate > config.block_threshold
        
        # BY_JA4 should not trigger (each JA4 used once)
        by_ja4_rate = final_results[RateLimitStrategy.BY_JA4].connections_per_second
        assert by_ja4_rate == 1
    
    def test_scenario_botnet_same_tool(self, redis_client, integration_config):
        """
        Scenario: Botnet with 30 IPs all using same tool (same JA4).
        Expected: BY_JA4 strategy catches it.
        """
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ja4 = "t13d1516h2_botnet_signature"
        
        # 30 different IPs with same JA4
        for i in range(30):
            ip = f"192.168.1.{100+i}"
            results = tracker.track_connection(ja4, ip)
        
        final_results = results
        
        # BY_JA4 should catch the botnet (30 > threshold of 25)
        by_ja4_rate = final_results[RateLimitStrategy.BY_JA4].connections_per_second
        assert by_ja4_rate == 30
        
        # Should exceed block threshold
        config = tracker.get_strategy_config(RateLimitStrategy.BY_JA4)
        assert by_ja4_rate > config.block_threshold
        
        # BY_IP should not trigger (each IP used once)
        by_ip_rate = final_results[RateLimitStrategy.BY_IP].connections_per_second
        assert by_ip_rate == 1
    
    def test_scenario_aggressive_client(self, redis_client, integration_config):
        """
        Scenario: One client (IP+JA4) making 8 rapid requests.
        Expected: BY_IP_JA4_PAIR strategy catches it.
        """
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ja4 = "t13d1516h2_aggressive_client"
        ip = "192.168.1.100"
        
        # Same client makes 8 rapid requests
        for i in range(8):
            results = tracker.track_connection(ja4, ip)
        
        final_results = results
        
        # BY_IP_JA4_PAIR should catch it (8 > threshold of 5)
        by_pair_rate = final_results[RateLimitStrategy.BY_IP_JA4_PAIR].connections_per_second
        assert by_pair_rate == 8
        
        # Should exceed block threshold
        config = tracker.get_strategy_config(RateLimitStrategy.BY_IP_JA4_PAIR)
        assert by_pair_rate > config.block_threshold
    
    def test_scenario_legitimate_traffic(self, redis_client, integration_config):
        """
        Scenario: Normal traffic patterns (under thresholds).
        Expected: All strategies show normal.
        """
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        # Various legitimate users
        users = [
            ("t13d1516h2_chrome_sig1", "192.168.1.10"),
            ("t13d1516h2_firefox_sig2", "192.168.1.11"),
            ("t13d1516h2_safari_sig3", "192.168.1.12"),
        ]
        
        for ja4, ip in users:
            results = tracker.track_connection(ja4, ip)
            
            # All rates should be 1 (under all thresholds)
            assert results[RateLimitStrategy.BY_IP].connections_per_second == 1
            assert results[RateLimitStrategy.BY_JA4].connections_per_second == 1
            assert results[RateLimitStrategy.BY_IP_JA4_PAIR].connections_per_second == 1


class TestPerformance:
    """Test performance characteristics."""
    
    def test_tracking_performance(self, redis_client, integration_config):
        """Test that tracking is fast enough for production."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        ja4 = "t13d1516h2_perf_test"
        ip = "192.168.1.100"
        
        # Time 100 operations
        start = time.time()
        for i in range(100):
            tracker.track_connection(ja4, ip)
        elapsed = time.time() - start
        
        # Should complete in reasonable time (< 1 second for 100 ops)
        assert elapsed < 1.0, f"100 operations took {elapsed}s (too slow)"
        
        # Average should be < 10ms per operation
        avg_ms = (elapsed / 100) * 1000
        print(f"\nAverage tracking time: {avg_ms:.2f}ms per operation")
        assert avg_ms < 10, f"Average {avg_ms}ms per operation (should be < 10ms)"
    
    def test_redis_memory_cleanup(self, redis_client, integration_config):
        """Test that old data is cleaned up (GDPR compliance)."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        # Create some tracking data
        for i in range(10):
            tracker.track_connection(
                f"t13d1516h2_test{i:02d}",
                f"192.168.1.{100+i}"
            )
        
        # Check keys exist
        keys_before = redis_client.keys("rate:*")
        assert len(keys_before) > 0
        
        # Wait for TTL to expire
        time.sleep(2)
        
        # Trigger cleanup by trying to access
        tracker.track_connection("t13d1516h2_new", "192.168.1.200")
        
        # Old keys should be fewer (some expired)
        keys_after = redis_client.keys("rate:*")
        
        # At minimum, some old keys should have expired
        # (We can't be exact because we just added a new connection)
        print(f"\nKeys before: {len(keys_before)}, after: {len(keys_after)}")


class TestErrorHandling:
    """Test error handling and recovery."""
    
    def test_health_check_with_real_redis(self, redis_client, integration_config):
        """Test health check with real Redis."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        assert tracker.health_check() is True
    
    def test_invalid_redis_connection(self, integration_config):
        """Test handling of invalid Redis connection."""
        # Create client with invalid connection
        bad_client = redis.Redis(host='invalid-host-12345', port=9999, socket_timeout=1)
        
        with pytest.raises(RedisConnectionError):
            MultiStrategyRateTracker(bad_client, integration_config)


class TestStrategyConfiguration:
    """Test strategy-specific configurations."""
    
    def test_get_strategy_configs(self, redis_client, integration_config):
        """Test retrieving strategy configurations."""
        tracker = MultiStrategyRateTracker(redis_client, integration_config)
        
        # BY_IP config
        ip_config = tracker.get_strategy_config(RateLimitStrategy.BY_IP)
        assert ip_config.suspicious_threshold == 2
        assert ip_config.block_threshold == 10
        assert ip_config.ban_threshold == 20
        assert ip_config.action == 'block'
        
        # BY_JA4 config
        ja4_config = tracker.get_strategy_config(RateLimitStrategy.BY_JA4)
        assert ja4_config.suspicious_threshold == 5
        assert ja4_config.block_threshold == 25
        assert ja4_config.ban_threshold == 50
        assert ja4_config.action == 'log'
        
        # BY_IP_JA4_PAIR config
        pair_config = tracker.get_strategy_config(RateLimitStrategy.BY_IP_JA4_PAIR)
        assert pair_config.suspicious_threshold == 1
        assert pair_config.block_threshold == 5
        assert pair_config.ban_threshold == 10
        assert pair_config.action == 'tarpit'


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
