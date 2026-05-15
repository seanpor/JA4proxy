# Integration Tests for Stream Processing
# Phase 12a: Foundation  |  Phase 12 gap-close: Redis HLL + hot-reload

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
import redis as redis_module

from src.analytics.authentication import HMACAuthenticator
from src.analytics.stream_consumer import StreamConsumer


class TestStreamConsumerIntegration:
    """Integration tests for stream consumer."""

    @pytest.mark.asyncio
    async def test_end_to_end_processing(self):
        """Test end-to-end event processing."""
        # Create test events
        events = [
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.1",
                "ja4": "t13d1520h3_abc123",
                "action": "block",
                "score": 85,
                "proxy_id": "proxy-1",
            },
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.2",
                "ja4": "t13d1520h3_def456",
                "action": "allow",
                "score": 15,
                "proxy_id": "proxy-1",
            },
        ]

        # Create consumer with mock Redis
        consumer = StreamConsumer(
            redis_url="redis://localhost", hmac_secret="test_secret", hmac_required=True
        )

        # Mock the Redis connection
        mock_redis = AsyncMock()
        mock_redis.xreadgroup.return_value = []  # No events initially
        consumer.redis = mock_redis

        # Sign events
        authenticator = HMACAuthenticator("test_secret")
        signed_events = []
        for event in events:
            signed_event = authenticator.sign(event.copy())
            signed_events.append(signed_event)

        # Test event validation
        for signed_event in signed_events:
            # This should not raise an exception
            result = await consumer.validate_event(signed_event)
            assert result == True

        # Test event processing
        for signed_event in signed_events:
            success = await consumer.process_event("test-id", signed_event)
            assert success == True

        # Check aggregation results
        results = consumer.aggregation_manager.get_aggregation_results()
        assert len(results) == 1

        subnet = "192.168.1.0/24"
        assert subnet in results
        assert results[subnet]["total_events"] == 2
        assert results[subnet]["block_events"] == 1
        assert results[subnet]["allow_events"] == 1

        # Check HyperLogLog results
        hll_counts = consumer.hll_manager.get_all_counts()
        assert hll_counts[subnet] == 2

    @pytest.mark.asyncio
    async def test_hmac_validation_failure(self):
        """Test HMAC validation failure."""
        consumer = StreamConsumer(
            redis_url="redis://localhost",
            hmac_secret="correct_secret",
            hmac_required=True,
        )

        # Create event with wrong HMAC
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
            "hmac": "wrong_hmac_signature",
        }

        # This should raise an exception
        with pytest.raises(Exception, match="HMAC verification failed"):
            await consumer.validate_event(event)

    @pytest.mark.asyncio
    async def test_invalid_event_schema(self):
        """Test invalid event schema rejection."""
        consumer = StreamConsumer(
            redis_url="redis://localhost",
            hmac_secret="test_secret",
            hmac_required=False,  # Disable HMAC for this test
        )

        # Create event with missing required field
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            # Missing proxy_id
        }

        # This should raise an exception
        with pytest.raises(Exception, match="Schema validation failed"):
            await consumer.validate_event(event)

    @pytest.mark.asyncio
    async def test_consumer_initialization(self):
        """Test consumer initialization with various configurations."""
        # Test with HMAC enabled
        consumer1 = StreamConsumer(
            redis_url="redis://localhost", hmac_secret="secret1", hmac_required=True
        )
        assert consumer1.hmac_auth.secret == "secret1"
        assert consumer1.hmac_auth.required == True

        # Test with HMAC disabled
        consumer2 = StreamConsumer(
            redis_url="redis://localhost", hmac_secret="secret2", hmac_required=False
        )
        assert consumer2.hmac_auth.secret == "secret2"
        assert consumer2.hmac_auth.required == False

        # Test with custom aggregation window
        consumer3 = StreamConsumer(redis_url="redis://localhost", aggregation_window=60)
        assert consumer3.aggregation_manager.window_seconds == 60


class TestHealthEndpoints:
    """Test health endpoints."""

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check functionality."""
        from src.analytics.main import AnalyticsNode

        # Create analytics node
        node = AnalyticsNode("config/analytics.yaml")

        # Mock the consumer
        mock_consumer = AsyncMock()
        mock_consumer.redis = AsyncMock()
        mock_consumer.redis.ping = AsyncMock()
        node.consumer = mock_consumer

        # Test healthy case
        health = await node.health_check()
        assert health["status"] == "healthy"
        assert health["redis"] == "connected"

        # Test unhealthy case (no consumer)
        node.consumer = None
        health = await node.health_check()
        assert health["status"] == "unhealthy"

        # Test unhealthy case (Redis failure)
        mock_consumer.redis.ping.side_effect = Exception("Connection error")
        node.consumer = mock_consumer
        health = await node.health_check()
        assert health["status"] == "unhealthy"
        assert "Connection error" in health["error"]


class TestRedisHyperLogLog:
    """Phase 12 gap-close: process_event() must write to Redis HLL key (analytics:hll:{subnet})."""

    def _make_consumer_with_mock_redis(self) -> tuple:
        consumer = StreamConsumer(
            redis_url="redis://localhost",
            hmac_secret="test_secret",
            hmac_required=False,
        )
        mock_redis = AsyncMock()
        mock_redis.pfadd = AsyncMock(return_value=1)
        mock_redis.expire = AsyncMock(return_value=1)
        consumer.redis = mock_redis
        return consumer, mock_redis

    @pytest.mark.asyncio
    async def test_process_event_calls_redis_pfadd(self):
        """process_event() calls redis.pfadd(analytics:hll:{subnet}, ip) for each event."""
        consumer, mock_redis = self._make_consumer_with_mock_redis()
        event = {
            "timestamp": time.time(),
            "src_ip": "10.0.0.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 75,
            "proxy_id": "proxy-1",
        }
        await consumer.process_event("id-1", event)

        mock_redis.pfadd.assert_called_once_with(
            "analytics:hll:10.0.0.0/24", "10.0.0.1"
        )
        mock_redis.expire.assert_called_once_with("analytics:hll:10.0.0.0/24", 86400)

    @pytest.mark.asyncio
    async def test_process_event_ipv6_uses_48_subnet(self):
        """IPv6 IPs use /48 subnet key per CLAUDE.md and REDIS_SCHEMA.md."""
        consumer, mock_redis = self._make_consumer_with_mock_redis()
        event = {
            "timestamp": time.time(),
            "src_ip": "2001:db8:1234:5678::1",
            "ja4": "t13d1520h3_abc123",
            "action": "allow",
            "score": 5,
            "proxy_id": "proxy-1",
        }
        await consumer.process_event("id-2", event)

        pfadd_call = mock_redis.pfadd.call_args
        key = pfadd_call[0][0]
        assert key.startswith("analytics:hll:")
        assert "/48" in key, f"Expected /48 subnet key, got: {key}"

    @pytest.mark.asyncio
    async def test_redis_pfadd_failure_does_not_crash_processing(self):
        """Redis PFADD failure must not prevent event processing (fail open)."""
        consumer, mock_redis = self._make_consumer_with_mock_redis()
        mock_redis.pfadd = AsyncMock(side_effect=redis_module.RedisError("Redis down"))
        event = {
            "timestamp": time.time(),
            "src_ip": "1.2.3.4",
            "ja4": "t13d1520h3_abc123",
            "action": "allow",
            "score": 10,
            "proxy_id": "proxy-1",
        }
        result = await consumer.process_event("id-3", event)
        assert result is True  # Processing succeeded despite Redis failure

        # In-process HLL still updated
        assert consumer.hll_manager.count_unique_ips("1.2.3.0/24") == 1

    @pytest.mark.asyncio
    async def test_redis_hll_ttl_is_24_hours(self):
        """analytics:hll:{subnet} key must get a 24 h (86400 s) TTL."""
        consumer, mock_redis = self._make_consumer_with_mock_redis()
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.5.10",
            "ja4": "t13d1520h3_abc123",
            "action": "flag",
            "score": 25,
            "proxy_id": "proxy-1",
        }
        await consumer.process_event("id-4", event)
        mock_redis.expire.assert_called_once_with("analytics:hll:192.168.5.0/24", 86400)


class TestAnalyticsNodeHotReload:
    """Phase 12 gap-close: SIGHUP hot-reloads config without stopping the analytics node."""

    def test_handle_reload_updates_config(self, tmp_path):
        """_handle_reload() reloads config from disk and updates self.config."""
        import yaml

        from src.analytics.main import AnalyticsNode

        config_data = {
            "redis": {"host": "localhost", "port": 6379},
            "stream": {
                "key": "ja4proxy:events",
                "consumer_group": "analytics",
                "consumer_name": "analytics-1",
                "batch_size": 100,
                "timeout_ms": 5000,
            },
            "security": {"hmac_secret": "secret", "hmac_required": False},
            "aggregation": {"window_seconds": 300},
            "monitoring": {"enabled": False},
        }
        config_file = tmp_path / "analytics.yaml"
        config_file.write_text(yaml.dump(config_data))

        node = AnalyticsNode(config_file=str(config_file))
        assert node.config["stream"]["batch_size"] == 100

        # Write new config with different batch_size
        config_data["stream"]["batch_size"] = 200
        config_file.write_text(yaml.dump(config_data))

        node._handle_reload()

        assert node.config["stream"]["batch_size"] == 200

    def test_handle_reload_propagates_to_consumer(self, tmp_path):
        """_handle_reload() updates consumer.batch_size and consumer.timeout_ms."""
        import yaml

        from src.analytics.main import AnalyticsNode

        config_data = {
            "redis": {"host": "localhost", "port": 6379},
            "stream": {
                "key": "ja4proxy:events",
                "consumer_group": "analytics",
                "consumer_name": "analytics-1",
                "batch_size": 50,
                "timeout_ms": 3000,
            },
            "security": {"hmac_secret": "secret", "hmac_required": False},
            "aggregation": {"window_seconds": 300},
            "monitoring": {"enabled": False},
        }
        config_file = tmp_path / "analytics.yaml"
        config_file.write_text(yaml.dump(config_data))

        node = AnalyticsNode(config_file=str(config_file))
        mock_consumer = MagicMock()
        node.consumer = mock_consumer

        config_data["stream"]["batch_size"] = 150
        config_data["stream"]["timeout_ms"] = 8000
        config_file.write_text(yaml.dump(config_data))

        node._handle_reload()

        assert mock_consumer.batch_size == 150
        assert mock_consumer.timeout_ms == 8000

    def test_handle_reload_bad_file_does_not_crash(self, tmp_path):
        """_handle_reload() with a corrupt config file logs a warning and keeps old config."""
        import yaml

        from src.analytics.main import AnalyticsNode

        config_data = {
            "redis": {"host": "localhost", "port": 6379},
            "stream": {
                "key": "ja4proxy:events",
                "consumer_group": "analytics",
                "consumer_name": "analytics-1",
                "batch_size": 100,
                "timeout_ms": 5000,
            },
            "security": {"hmac_secret": "secret", "hmac_required": False},
            "aggregation": {"window_seconds": 300},
            "monitoring": {"enabled": False},
        }
        config_file = tmp_path / "analytics.yaml"
        config_file.write_text(yaml.dump(config_data))

        node = AnalyticsNode(config_file=str(config_file))
        original_batch = node.config["stream"]["batch_size"]

        # Corrupt the config file
        config_file.write_text(": bad: yaml: [[[")

        # Should not raise
        node._handle_reload()

        # Old config still intact
        assert node.config["stream"]["batch_size"] == original_batch
