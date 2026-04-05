"""Redis connection management for the management API.

Uses redis.asyncio throughout — no blocking I/O on the event loop.

The connection pool is created once at application startup (via the FastAPI
lifespan context manager in main.py) and torn down on shutdown.

Usage
-----
from management.api.redis_client import get_redis

async def my_route(redis: Redis = Depends(get_redis)):
    value = await redis.get("some:key")
"""

import logging
import os
from typing import AsyncGenerator, Optional

import redis.asyncio as aioredis
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

# Module-level pool — created by init_redis(), destroyed by close_redis()
_redis_pool: Optional[aioredis.ConnectionPool] = None
_redis_client: Optional[Redis] = None


def _build_redis_url() -> str:
    """Build a Redis URL from environment variables.

    Checks REDIS_URL first, then falls back to component env vars.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        return url

    host = os.environ.get("REDIS_HOST", "localhost")
    port = int(os.environ.get("REDIS_PORT", "6379"))
    db = int(os.environ.get("REDIS_DB", "0"))
    password = os.environ.get("REDIS_PASSWORD", "")

    if password:
        return f"redis://:{password}@{host}:{port}/{db}"
    return f"redis://{host}:{port}/{db}"


async def init_redis(override_client: Optional[Redis] = None) -> None:
    """Initialise the Redis connection pool.

    Args:
        override_client: Supply a ready-made client (e.g. fakeredis in tests).
            When provided, no real connection pool is created.
    """
    global _redis_pool, _redis_client

    if override_client is not None:
        _redis_client = override_client
        logger.debug("Redis: using injected client (test mode)")
        return

    url = _build_redis_url()
    _redis_pool = aioredis.ConnectionPool.from_url(
        url,
        decode_responses=True,
        max_connections=20,
    )
    _redis_client = aioredis.Redis(connection_pool=_redis_pool)
    logger.info("Redis connection pool initialised: %s", url.split("@")[-1])


async def close_redis() -> None:
    """Tear down the Redis connection pool on application shutdown."""
    global _redis_pool, _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None
    logger.info("Redis connection pool closed")


def get_redis_client() -> Optional[Redis]:
    """Return the current Redis client, or None if not initialised."""
    return _redis_client


async def get_redis() -> AsyncGenerator[Redis, None]:
    """FastAPI dependency — yields the Redis client for a single request.

    Raises:
        RuntimeError: If Redis has not been initialised (startup failure).
    """
    client = get_redis_client()
    if client is None:
        raise RuntimeError("Redis client is not initialised")
    yield client
