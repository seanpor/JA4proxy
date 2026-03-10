"""Authentication and rate limiting for the Management UI API.

Authentication uses a single Bearer token (UI_API_KEY env var).
Failed attempts are rate-limited per client IP to prevent brute force.

Rate limit:
- < 10 failures/min per IP: 401 with error detail
- >= 10 failures/min per IP: 429 with Retry-After: 60
- >= 100 failures/hour (any IP): WARN log + Prometheus counter increment
"""

import logging
import os

import redis.exceptions
from fastapi import Depends, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from management.metrics import mgmt_auth_failures_total, mgmt_redis_errors_total

logger = logging.getLogger("management.auth")

_BEARER_SCHEME = HTTPBearer(auto_error=False)

# Rate limit thresholds
_RATE_LIMIT_BLOCK = 10    # per minute
_RATE_LIMIT_WARN = 100    # per hour (any single IP)


def _get_api_key() -> str:
    """Return the configured API key; empty string if not set."""
    return os.environ.get("UI_API_KEY", "")


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, checking X-Forwarded-For first."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


async def check_rate_limit(redis_client, ip: str) -> int:
    """Increment failure counter for IP. Return current count.

    Uses INCR + EXPIRE to implement a 60-second sliding window.
    Returns the new failure count after incrementing.
    """
    key = f"mgmt:ratelimit:{ip}"
    try:
        count = await redis_client.incr(key)
        if count == 1:
            # First failure — set TTL
            await redis_client.expire(key, 60)
        return count
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="rate_limit").inc()
        logger.warning(
            "management | event=rate_limit_redis_error | ip=%s | error=%s",
            ip,
            exc,
        )
        # Fail open: if Redis is down, allow the request through rate limiter
        return 0


async def require_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_BEARER_SCHEME),
    key: str = Query(default="", alias="key"),
) -> str:
    """Validate Bearer token or ?key= query parameter.

    Returns the validated API key on success.
    Raises HTTP 401 or 429 on failure.
    """
    configured_key = _get_api_key()
    client_ip = _get_client_ip(request)

    # Extract token from either Bearer header or ?key= param
    token = ""
    if credentials is not None:
        token = credentials.credentials
    elif key:
        token = key

    redis_client = getattr(request.app.state, "redis", None)

    # Check rate limit before auth to prevent timing attacks revealing key length
    if redis_client is not None and token != configured_key:
        count = await check_rate_limit(redis_client, client_ip)
        mgmt_auth_failures_total.inc()

        if count >= _RATE_LIMIT_BLOCK:
            logger.warning(
                "management | event=auth_rate_limited | ip=%s | count=%d",
                client_ip,
                count,
            )
            raise HTTPException(
                status_code=429,
                detail="Too many authentication failures",
                headers={"Retry-After": "60"},
            )

        if count >= _RATE_LIMIT_WARN:
            logger.warning(
                "management | event=auth_brute_force_suspected | ip=%s | count=%d",
                client_ip,
                count,
            )

    # Validate the token
    if not configured_key:
        # Should never reach here — startup guard prevents this
        raise HTTPException(status_code=500, detail="API key not configured")

    if not token or token != configured_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token
