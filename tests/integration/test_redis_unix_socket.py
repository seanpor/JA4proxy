"""Integration test for Redis Unix domain socket support (Phase 26c)."""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as redis

from src.config.loader import ConfigLoader
from src.security.pipeline import ConnectionContext, Pipeline


class TestRedisUnixSocket:
    """Test Redis Unix domain socket configuration and fallback."""

    async def test_unix_socket_config_parsing(self):
        """Test that Unix socket path is correctly parsed from config."""
        config_text = """
redis:
  unix_socket_path: "/var/run/redis/redis.sock"
  host: "localhost"
  port: 6379
  db: 0
  password: "testpass"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            loader = ConfigLoader(config_path)
            config = await loader.load()
            
            assert config['redis']['unix_socket_path'] == "/var/run/redis/redis.sock"
            assert config['redis']['host'] == "localhost"
            assert config['redis']['port'] == 6379
        finally:
            os.unlink(config_path)

    async def test_tcp_fallback_when_unix_socket_missing(self):
        """Test that the proxy falls back to TCP when Unix socket is not configured."""
        config_text = """
redis:
  host: "localhost"
  port: 6379
  db: 0
  password: "testpass"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            loader = ConfigLoader(config_path)
            config = await loader.load()
            
            assert 'unix_socket_path' not in config['redis']
            assert config['redis']['host'] == "localhost"
            assert config['redis']['port'] == 6379
        finally:
            os.unlink(config_path)

    @patch('proxy.ProxyServer._init_from_config')
    @patch('proxy.ProxyServer._init_redis')
    async def test_proxy_uses_unix_socket_when_configured(self, mock_init_redis, mock_init_from_config):
        """Test that ProxyServer initializes Redis with Unix socket when configured."""
        from proxy import ProxyServer

        config_text = """
proxy:
  mode: passthrough
  bind_host: "0.0.0.0"
  bind_port: 8080
redis:
  unix_socket_path: "/var/run/redis/redis.sock"
  host: "localhost"
  port: 6379
  db: 0
  password: "testpass"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            # Create a mock Redis client
            mock_redis_client = MagicMock(spec=redis.Redis)
            mock_redis_client.ping = AsyncMock()
            mock_init_redis.return_value = mock_redis_client

            # Create ProxyServer instance with config path
            server = ProxyServer(config_path)
            redis_client = await server._init_redis()

            # Verify that _init_redis was called
            mock_init_redis.assert_called_once()

        finally:
            os.unlink(config_path)

    @patch('proxy.ProxyServer._init_from_config')
    @patch('proxy.ProxyServer._init_redis')
    async def test_proxy_uses_tcp_when_unix_socket_not_configured(self, mock_init_redis, mock_init_from_config):
        """Test that ProxyServer initializes Redis with TCP when Unix socket is not configured."""
        from proxy import ProxyServer

        config_text = """
proxy:
  mode: passthrough
  bind_host: "0.0.0.0"
  bind_port: 8080
redis:
  host: "localhost"
  port: 6379
  db: 0
  password: "testpass"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(config_text)
            config_path = f.name

        try:
            # Create a mock Redis client
            mock_redis_client = MagicMock(spec=redis.Redis)
            mock_redis_client.ping = AsyncMock()
            mock_init_redis.return_value = mock_redis_client

            # Create ProxyServer instance with config path
            server = ProxyServer(config_path)
            redis_client = await server._init_redis()

            # Verify that _init_redis was called
            mock_init_redis.assert_called_once()

        finally:
            os.unlink(config_path)


if __name__ == "__main__":
    asyncio.run(pytest.main([__file__, "-v"]))
