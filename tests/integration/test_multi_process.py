"""Integration tests for multi-process worker model (Phase 26d)."""

import asyncio
import tempfile
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as redis

from src.config.loader import ConfigLoader
from src.security.pipeline import ConnectionContext, Pipeline


class TestMultiProcessScaling:
    """Test multi-process scaling configuration and behavior."""

    async def test_worker_count_configuration(self):
        """Test that worker count can be configured."""
        config_text = """
tarpit:
  worker_count: 4
  max_per_ip: 1  # Adjusted for 4 workers: ceil(3/4) = 1
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            loader = ConfigLoader(config_path)
            config = await loader.load()
            
            assert config['tarpit']['worker_count'] == 4
            assert config['tarpit']['max_per_ip'] == 1
        finally:
            os.unlink(config_path)

    async def test_single_worker_configuration(self):
        """Test default single worker configuration."""
        config_text = """
tarpit:
  worker_count: 1
  max_per_ip: 3  # Default for single worker
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            loader = ConfigLoader(config_path)
            config = await loader.load()
            
            assert config['tarpit']['worker_count'] == 1
            assert config['tarpit']['max_per_ip'] == 3
        finally:
            os.unlink(config_path)

    async def test_two_worker_configuration(self):
        """Test 2 worker configuration with adjusted max_per_ip."""
        config_text = """
tarpit:
  worker_count: 2
  max_per_ip: 2  # ceil(3/2) = 2
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            loader = ConfigLoader(config_path)
            config = await loader.load()
            
            assert config['tarpit']['worker_count'] == 2
            assert config['tarpit']['max_per_ip'] == 2
        finally:
            os.unlink(config_path)

    async def test_pipeline_with_worker_config(self):
        """Test that pipeline works correctly with worker configuration."""
        config_text = """
security_policy:
  alpn_browser_bypass: {enabled: true}
  ja4_whitelist_bypass: {enabled: true}
  mtls_bypass: {enabled: true}
  static_ip_allowlist: {enabled: true}
  ja4_blacklist_bypass: {enabled: true}
  country_blacklist_bypass: {enabled: true}
tarpit:
  worker_count: 4
  max_per_ip: 1
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
            
            from src.cache.local_cache import LocalCache
            cache = LocalCache({})
            cache.dial = 0
            
            # Create pipeline
            pipeline = Pipeline(config=config, local_cache=cache, redis_client=mock_redis)
            
            # Verify worker count is loaded
            assert config['tarpit']['worker_count'] == 4
            assert config['tarpit']['max_per_ip'] == 1
            
            # Start and stop pipeline (tests WriteBuffer lifecycle)
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
            
            # Process a connection
            result = await pipeline.process(ctx)
            
            # Stop pipeline
            await pipeline.stop()
            
        finally:
            os.unlink(config_path)


if __name__ == "__main__":
    asyncio.run(pytest.main([__file__, "-v"]))
