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

    Retained as the correct tool for anywhere a URL genuinely must be
    displayed. The connection logs in this module no longer use it — they call
    ``_redis_endpoint`` instead, which never carries the password at all rather
    than carrying it and cleaning it.
    """
    try:
        parts = urlparse(url)
    except ValueError:
        return "<unparsable-redis-url>"
    if parts.password is None:
        return url
    user = parts.username or ""
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or ""
    return f"{parts.scheme}://{user}:***@{host}{port}{path}"


def _redis_endpoint() -> str:
    """Return ``host:port`` for ``url`` — the only part of it a log ever needs.

    CodeQL alert #100 (``py/clear-text-logging-sensitive-data``, high) fired on
    the connection logs because ``REDIS_PASSWORD`` reaches them through
    ``_build_redis_url`` -> ``_redact_redis_url`` -> ``logger``. The redaction
    is correct, but taint analysis cannot verify a hand-rolled sanitiser, and
    "the scanner is wrong" is a poor place to keep a secret: the guarantee then
    rests on every future edit of that helper preserving a property no tool
    checks.

    A first attempt took ``_build_redis_url()``'s output and read ``hostname``
    and ``port`` off the parse result. That is safe by inspection — those two
    fields structurally cannot hold credentials — but it did NOT clear the
    alert, because the string being parsed is the one ``REDIS_PASSWORD`` was
    interpolated into, so the taint still reaches the logger.

    This version reads the same configuration inputs **independently**, and
    never touches the concatenated URL at all. The password is not merely
    stripped on the way to the log; it is never on that path. That is a real
    structural difference, not a way of quieting the scanner: the log value now
    derives from configuration, not from a secret-bearing string.

    The log lines lost nothing — they existed to say WHICH Redis was reached or
    missed, and that is exactly host and port.

    Falls back to a sentinel rather than raising: ``urlparse().port`` raises
    ValueError on a non-numeric port, and a diagnostic log line must never be
    the thing that takes down startup.
    """
    url = os.environ.get("REDIS_URL")
    if url:
        try:
            parts = urlparse(url)
            host = parts.hostname or ""
            port: object = parts.port
        except ValueError:
            return "<unparsable-redis-url>"
    else:
        # Component form: these never held the password to begin with.
        host = os.environ.get("REDIS_HOST", "localhost")
        port = os.environ.get("REDIS_PORT", "6379")
    if not host:
        return "<unparsable-redis-url>"
    return f"{host}:{port}" if port else host


# Socket read deadline for this pool. MUST stay above the longest `block=` used
# by any blocking read on it, with headroom — see the comment at the from_url()
# call. Exported so the guard test can compare it against the call sites.
BLOCKING_SOCKET_TIMEOUT_S = 30.0

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
    # Read from the environment independently — never derived from `url`, which
    # is the string REDIS_PASSWORD was interpolated into. See _redis_endpoint.
    endpoint = _redis_endpoint()
    try:
        _redis_pool = aioredis.ConnectionPool.from_url(
            url,
            decode_responses=True,
            max_connections=20,
            # Must exceed every blocking read made on this pool — today that is
            # routes/events.py's xread(block=_BLOCK_MS). redis-py 8.x defaults
            # this to 5s; a block window >= the socket deadline makes the client
            # lose the race and raise TimeoutError on EVERY poll, which is how
            # the analytics consumer silently ingested nothing. Guarded by
            # tests/unit/test_redis_blocking_timeouts.py.
            socket_timeout=BLOCKING_SOCKET_TIMEOUT_S,
            health_check_interval=30,
        )
        _redis_client = aioredis.Redis(connection_pool=_redis_pool)
    except Exception as exc:  # noqa: BLE001 — we always re-raise
        # JA4PROXY-2026-0053: the exception text from ConnectionPool.from_url
        # can echo the URL (including password) if the URL is malformed. So we
        # log the exception TYPE and the endpoint only — never str(exc), and
        # never the URL — then re-raise so startup still fails loudly.
        logger.error(
            "Redis connection pool init failed for %s: %s",
            endpoint,
            type(exc).__name__,
        )
        # ManagementUIRedisErrors alerts on this. It existed for months with
        # nothing emitting it, so when the console's Redis credentials were
        # wrong on 2026-08-17 -- every call failing with AuthenticationError,
        # the login rate limiter failing closed, nobody able to log in -- the
        # alert that describes exactly that could not fire.
        try:
            from .prometheus_metrics import REDIS_ERRORS

            REDIS_ERRORS.labels("connect").inc()
        except Exception:  # noqa: BLE001 — metrics must never mask the real error
            pass
        raise
    logger.info("Redis connection pool initialised: %s", endpoint)


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
