"""Integration tests for WriteBuffer (Phase 26e)."""

import asyncio
import tempfile
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as redis

from src.config.loader import ConfigLoader
from src.security.pipeline import ConnectionContext, Pipeline
from src.security.write_buffer import WriteBuffer
from src.cache.local_cache import LocalCache


class TestWriteBuffer:
    """Test WriteBuffer functionality and integration."""

    async def test_write_buffer_initialization(self):
        """Test WriteBuffer initialization with valid parameters."""
        mock_redis = MagicMock(spec=redis.Redis)
        buffer = WriteBuffer(mock_redis, flush_interval_ms=50, max_batch_size=500, max_queue_size=1000)
        
        assert buffer.redis_client == mock_redis
        assert buffer.flush_interval_ms == 0.05  # 50ms converted to seconds
        assert buffer.max_batch_size == 500
        assert buffer.max_queue_size == 1000

    async def test_write_buffer_enqueue_and_flush(self):
        """Test WriteBuffer enqueue and flush operations."""
        mock_redis = MagicMock(spec=redis.Redis)
        mock_redis.pipeline = MagicMock(return_value=MagicMock())
        
        buffer = WriteBuffer(mock_redis, flush_interval_ms=100, max_batch_size=10, max_queue_size=20)
        
        # Start the buffer
        await buffer.start()
        
        # Enqueue some operations
        for i in range(5):
            success = await buffer.enqueue("hset", f"key:{i}", "field", f"value{i}")
            assert success is True
        
        # Stop the buffer (triggers final flush)
        await buffer.stop()

    async def test_write_buffer_overflow(self):
        """Test WriteBuffer overflow handling."""
        mock_redis = MagicMock(spec=redis.Redis)
        buffer = WriteBuffer(mock_redis, flush_interval_ms=100, max_batch_size=5, max_queue_size=10)
        
        # Start the buffer
        await buffer.start()
        
        # Fill the queue to capacity
        for i in range(15):  # More than max_queue_size
            success = await buffer.enqueue("zadd", f"key:{i}", {f"member{i}": i})
            # Should always return True (drops oldest when full)
            assert success is True
        
        # Stop the buffer
        await buffer.stop()

    async def test_write_buffer_with_pipeline(self):
        """Test WriteBuffer integration with Pipeline."""
        config_text = """
security_policy:
  alpn_browser_bypass: {enabled: true}
  ja4_whitelist_bypass: {enabled: true}
  mtls_bypass: {enabled: true}
  static_ip_allowlist: {enabled: true}
  ja4_blacklist_bypass: {enabled: true}
  country_blacklist_bypass: {enabled: true}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            loader = ConfigLoader(config_path)
            config = await loader.load()
            
            # Create mock Redis client
            mock_redis = MagicMock(spec=redis.Redis)
            mock_redis.ping = AsyncMock()
            mock_redis.get = AsyncMock(return_value=None)
            mock_redis.hmget = AsyncMock(return_value={})
            mock_redis.zadd = AsyncMock()
            mock_redis.evalsha = AsyncMock(return_value={"connections_per_second": 0})
            mock_redis.pipeline = MagicMock(return_value=MagicMock())
            
            cache = LocalCache({})
            cache.dial = 0
            
            # Create pipeline
            pipeline = Pipeline(config=config, local_cache=cache, redis_client=mock_redis)
            
            # Start pipeline (starts WriteBuffer)
            await pipeline.start()
            
            # Create test context
            ctx = ConnectionContext(
                client_ip="1.2.3.4",
                ja4="t13d_test_fingerprint",
                alpn="h2",
                sni="example.com",
                tls_version="TLSv1.3",
                cipher_list=[0x1301, 0x1302],
                client_certificate=None,
                country="US"
            )
            
            # Process a connection (should use WriteBuffer for post-decision writes)
            result = await pipeline.process(ctx)
            
            # Stop pipeline (stops WriteBuffer)
            await pipeline.stop()
            
        finally:
            os.unlink(config_path)

    async def test_write_buffer_error_handling(self):
        """Test WriteBuffer error handling and fail-open behavior."""
        # Create a mock Redis client that will fail
        mock_redis = MagicMock(spec=redis.Redis)
        
        # Mock pipeline to raise an error
        mock_pipeline_context = MagicMock()
        mock_pipeline_context.__aenter__.return_value = mock_pipeline_context
        mock_pipeline_context.__aexit__.return_value = None
        mock_pipeline_context.execute.side_effect = Exception("Redis connection failed")
        mock_redis.pipeline.return_value = mock_pipeline_context
        
        buffer = WriteBuffer(mock_redis, flush_interval_ms=100, max_batch_size=5, max_queue_size=10)
        
        # Start the buffer
        await buffer.start()
        
        # Enqueue some operations
        for i in range(3):
            success = await buffer.enqueue("set", f"key:{i}", f"value{i}")
            assert success is True
        
        # Stop the buffer (should handle error gracefully)
        await buffer.stop()
        
        # Verify that the pipeline execute was called (error handling worked)
        assert mock_pipeline_context.execute.called


if __name__ == "__main__":
    asyncio.run(pytest.main([__file__, "-v"]))
