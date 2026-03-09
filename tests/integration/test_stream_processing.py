# Integration Tests for Stream Processing
# Phase 12a: Foundation

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch

from src.analytics.stream_consumer import StreamConsumer
from src.analytics.authentication import HMACAuthenticator


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
                "proxy_id": "proxy-1"
            },
            {
                "timestamp": time.time(),
                "src_ip": "192.168.1.2",
                "ja4": "t13d1520h3_def456",
                "action": "allow",
                "score": 15,
                "proxy_id": "proxy-1"
            }
        ]
        
        # Create consumer with mock Redis
        consumer = StreamConsumer(
            redis_url="redis://localhost",
            hmac_secret="test_secret",
            hmac_required=True
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
            hmac_required=True
        )
        
        # Create event with wrong HMAC
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85,
            "proxy_id": "proxy-1",
            "hmac": "wrong_hmac_signature"
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
            hmac_required=False  # Disable HMAC for this test
        )
        
        # Create event with missing required field
        event = {
            "timestamp": time.time(),
            "src_ip": "192.168.1.1",
            "ja4": "t13d1520h3_abc123",
            "action": "block",
            "score": 85
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
            redis_url="redis://localhost",
            hmac_secret="secret1",
            hmac_required=True
        )
        assert consumer1.hmac_auth.secret == "secret1"
        assert consumer1.hmac_auth.required == True
        
        # Test with HMAC disabled
        consumer2 = StreamConsumer(
            redis_url="redis://localhost",
            hmac_secret="secret2",
            hmac_required=False
        )
        assert consumer2.hmac_auth.secret == "secret2"
        assert consumer2.hmac_auth.required == False
        
        # Test with custom aggregation window
        consumer3 = StreamConsumer(
            redis_url="redis://localhost",
            aggregation_window=60
        )
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