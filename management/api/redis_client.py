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
from urllib.parse import urlparse

import redis.asyncio as aioredis
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


def _redact_redis_url(url: str) -> str:
    """Return a log-safe form of ``url`` with any password replaced by ``***``.

    Pentest finding JA4PROXY-2026-0053 flagged that the prior implementation
    logged ``url.split("@")[-1]``, which leaks the password whenever the
    URL has no ``@`` separator (e.g. a bare ``redis://host:6379/0``) and
    also breaks for passwords that themselves contain ``@``. Using
    ``urllib.parse.urlparse`` splits at the last ``@`` exactly like
    redis-py does internally, so the redacted form matches the host/port
    that the client will actually connect to.
    """
    try:
        parts = urlparse(url)
    except ValueError:
        return "<unparseable-redis-url>"
    if parts.password is None:
        return url
    user = parts.username or ""
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or ""
    return f"{parts.scheme}://{user}:***@{host}{port}{path}"


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
    safe_url = _redact_redis_url(url)
    try:
        _redis_pool = aioredis.ConnectionPool.from_url(
            url,
            decode_responses=True,
            max_connections=20,
        )
        _redis_client = aioredis.Redis(connection_pool=_redis_pool)
    except Exception as exc:  # noqa: BLE001 — we always re-raise
        # JA4PROXY-2026-0053: the exception text from ConnectionPool.from_url
        # can echo the URL (including password) if the URL is malformed.
        # Swallowing and logging the redacted form prevents the raw URL from
        # landing in the traceback the caller prints; we still re-raise so
        # startup fails loudly.
        logger.error(
            "Redis connection pool init failed for %s: %s",
            safe_url,
            type(exc).__name__,
        )
        raise
    logger.info("Redis connection pool initialised: %s", safe_url)


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
