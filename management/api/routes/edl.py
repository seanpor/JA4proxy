"""EDL (External Dynamic List) feed — Phase 316e.

Serves a plaintext, one-entry-per-line list of active bans for firewalls to
**pull** via URL. F5 BIG-IP and Palo Alto NGFW both natively consume an EDL URL,
so this single endpoint replaces the per-vendor push clients the original 316e
outline proposed (see ADR-316e). Pull-only, token-authed, ETag-cached, and
fail-open.

Routes
------
GET /api/v1/edl/{list_name}
    list_name ∈ {banned_ips, banned_cidrs, combined}

Auth
----
A management-API token (the existing ``mgmt:token:*`` store) presented as an
``X-API-Key`` header, an ``Authorization: Bearer`` header, or a ``?token=``
query parameter (firewalls vary in what they can send). Mint one with
``POST /api/v1/tokens`` and hand it to the firewall — revocation and expiry come
for free from the existing token store.

Source data (read-only)
-----------------------
``ban:{ip}`` (operator/TAP bans) and ``ban_cidr:{cidr}`` (RDAP block-expansion).
This endpoint never writes ban state; it only reads it.

Fail-open
---------
A Redis error while building the list serves an **empty** feed (HTTP 200), never
a 5xx: an empty blocklist under-blocks (safe per the core asymmetry), and a 5xx
would break the firewall's poller. The error is logged.
"""

import hashlib
import logging
import time
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from ..auth import get_bearer_user
from ..proxy_config import get_proxy_config
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["edl"])

_BAN_KEY_PREFIX = "ban:"
_BAN_CIDR_KEY_PREFIX = "ban_cidr:"
_VALID_LISTS = ("banned_ips", "banned_cidrs", "combined")

_DEFAULT_MAX_ENTRIES = 100_000  # F5/PaloAlto EDLs have vendor caps; bound the body
_DEFAULT_CACHE_TTL = 60  # seconds; ETag makes most polls a cheap 304 regardless
_DEFAULT_RATE_LIMIT_PER_MIN = 120  # generous; a sane firewall polls every 1-5 min
_RATE_WINDOW_SECONDS = 60


def _edl_config() -> dict:
    """Return the ``edl`` section of proxy.yml (empty dict if absent)."""
    return get_proxy_config().get("edl") or {}


def _extract_token(request: Request) -> str | None:
    """Pull the feed token from X-API-Key, Authorization: Bearer, or ?token=."""
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()
    authz = request.headers.get("Authorization", "")
    if authz.startswith("Bearer "):
        return authz.split(" ", 1)[1].strip()
    token = request.query_params.get("token")
    if token:
        return token.strip()
    return None


async def _require_edl_client(request: Request, redis) -> str:
    """Authenticate the firewall via a management-API token. Returns the token
    identity (for logging/rate-limiting). Raises 401 if absent or invalid.

    Reuses ``get_bearer_user`` so revocation and expiry are honoured; does NOT
    use the interactive ``require_role`` dependency, which redirects browsers to
    /login — wrong for a machine poller.
    """
    raw = _extract_token(request)
    unauth = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="EDL feed requires a valid token (X-API-Key, Bearer, or ?token=)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not raw:
        raise unauth
    result = await get_bearer_user(raw, redis)
    if result is None:
        raise unauth
    identity, _role = result
    return identity


async def _check_rate_limit(identity: str, redis, limit: int) -> None:
    """Per-token sliding-window rate limit. Mirrors the threat-intel limiter and
    is fail-open: any Redis error skips the check rather than blocking a poll."""
    if limit <= 0:
        return
    key = f"edl:ratelimit:{identity}"
    now = time.time()
    try:
        await redis.zremrangebyscore(key, 0, now - _RATE_WINDOW_SECONDS)
        if await redis.zcard(key) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="EDL poll rate limit exceeded",
                headers={"Retry-After": str(_RATE_WINDOW_SECONDS)},
            )
        await redis.zadd(key, {f"{now}:{uuid4().hex[:8]}": now})
        await redis.expire(key, _RATE_WINDOW_SECONDS)
    except HTTPException:
        raise
    except Exception:
        return  # fail-open


async def _scan_suffixes(redis, prefix: str) -> list[str]:
    """SCAN keys matching ``{prefix}*`` and return the part after the prefix."""
    out: list[str] = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor=cursor, match=f"{prefix}*", count=500)
        out.extend(k[len(prefix) :] for k in keys)
        if cursor == 0:
            break
    return out


@router.get("/api/v1/edl/{list_name}")
async def get_edl(
    list_name: str,
    request: Request,
    redis=Depends(get_redis),
) -> Response:
    """Serve a plaintext EDL of active bans for the named list."""
    cfg = _edl_config()
    if not cfg.get("enabled", False):
        # Conservative default: the feed is off until an operator opts in. 404
        # (not 503) so a disabled feed reveals nothing about token validity.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="EDL feed not enabled")
    if list_name not in _VALID_LISTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown EDL list '{list_name}' (valid: {', '.join(_VALID_LISTS)})",
        )

    identity = await _require_edl_client(request, redis)
    await _check_rate_limit(identity, redis, int(cfg.get("rate_limit_per_min", _DEFAULT_RATE_LIMIT_PER_MIN)))

    max_entries = int(cfg.get("max_entries", _DEFAULT_MAX_ENTRIES))
    cache_ttl = int(cfg.get("cache_ttl", _DEFAULT_CACHE_TTL))

    # Build the list. Fail-open: any Redis error serves an empty feed, never 5xx.
    entries: list[str] = []
    try:
        if list_name in ("banned_ips", "combined"):
            entries.extend(await _scan_suffixes(redis, _BAN_KEY_PREFIX))
        if list_name in ("banned_cidrs", "combined"):
            entries.extend(await _scan_suffixes(redis, _BAN_CIDR_KEY_PREFIX))
    except Exception:
        logger.exception("edl | event=build_error | list=%s | serving_empty=true", list_name)
        entries = []

    entries = sorted(set(entries))  # dedupe + stable order ⇒ stable ETag
    truncated = False
    if len(entries) > max_entries:
        logger.warning(
            "edl | event=truncated | list=%s | total=%d | cap=%d",
            list_name,
            len(entries),
            max_entries,
        )
        entries = entries[:max_entries]
        truncated = True

    body = "\n".join(entries)
    if body:
        body += "\n"  # trailing newline: many parsers expect line-terminated lists
    etag = '"' + hashlib.sha256(body.encode()).hexdigest()[:16] + '"'

    headers = {
        "ETag": etag,
        "Cache-Control": f"max-age={cache_ttl}",
        "X-EDL-Count": str(len(entries)),
    }
    if truncated:
        headers["X-EDL-Truncated"] = "true"

    if request.headers.get("If-None-Match") == etag:
        logger.info(
            "edl | event=served | list=%s | client=%s | status=304 | count=%d",
            list_name,
            identity,
            len(entries),
        )
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers=headers)

    logger.info(
        "edl | event=served | list=%s | client=%s | status=200 | count=%d",
        list_name,
        identity,
        len(entries),
    )
    return Response(content=body, media_type="text/plain", headers=headers)
