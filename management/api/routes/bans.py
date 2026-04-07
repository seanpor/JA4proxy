"""Ban management endpoints.

Routes
------
GET    /api/v1/bans          — list all active bans
POST   /api/v1/bans/{ip}     — create a ban
DELETE /api/v1/bans/{ip}     — lift a ban

Redis key pattern: ban:{ip} → String (reason), with TTL

Design notes
------------
- SCAN is used to list bans (no KEYS in production — SCAN is O(1) per call).
- TTL is fetched per key for the listing response.
- IPv6 addresses are supported (stored as-is in the key).
- All write ops create audit log entries.
"""

import json
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..auth import require_role
from ..models import BanCreateRequest, BanCreateResponse, BanEntry, BanList, BanRemoveResponse, Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bans"])

_AUDIT_KEY = "management:audit_log"
_BAN_KEY_PREFIX = "ban:"
_DEFAULT_TTL = 3600


async def _write_audit(
    redis,
    action: str,
    user: str,
    detail: dict,
    client_ip: str,
) -> None:
    """Append an audit log entry and trim to 1000 entries."""
    entry = json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user": user,
            "detail": detail,
            "ip": client_ip,
        }
    )
    await redis.lpush(_AUDIT_KEY, entry)
    await redis.ltrim(_AUDIT_KEY, 0, 999)


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@router.get("/api/v1/bans", response_model=BanList)
async def list_bans(
    request: Request,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> BanList:
    """List all active bans by scanning ban:* keys."""
    bans: list[BanEntry] = []

    # Use SCAN to avoid blocking Redis with KEYS in production
    cursor = 0
    while True:
        cursor, keys = await redis.scan(
            cursor=cursor,
            match=f"{_BAN_KEY_PREFIX}*",
            count=100,
        )
        for key in keys:
            ip = key[len(_BAN_KEY_PREFIX):]
            reason = await redis.get(key)
            if reason is None:
                continue  # Key expired between SCAN and GET
            ttl_remaining: Optional[int] = await redis.ttl(key)
            # ttl() returns -1 for persistent keys, -2 for expired/missing
            if ttl_remaining == -2:
                continue
            if ttl_remaining == -1:
                ttl_remaining = None

            bans.append(
                BanEntry(
                    ip=ip,
                    reason=reason,
                    ttl_remaining=ttl_remaining,
                )
            )

        if cursor == 0:
            break

    return BanList(bans=bans, count=len(bans))


@router.post("/api/v1/bans/{ip:path}", response_model=BanCreateResponse)
async def create_ban(
    ip: str,
    request: Request,
    body: Optional[BanCreateRequest] = None,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> BanCreateResponse:
    """Create a ban for the given IP address.

    The IP is URL-decoded so IPv6 addresses passed percent-encoded work.
    """
    identity = current_user[0]
    ip = urllib.parse.unquote(ip)

    # Use default body if none provided
    if body is None:
        body = BanCreateRequest()

    key = f"{_BAN_KEY_PREFIX}{ip}"
    await redis.set(key, body.reason, ex=body.ttl)

    logger.info(
        "bans | event=ban_created | ip=%s | ttl=%d | reason=%s | user=%s",
        ip,
        body.ttl,
        body.reason,
        identity,
    )

    await _write_audit(
        redis,
        action="ban_created",
        user=identity,
        detail={"ip": ip, "ttl": body.ttl, "reason": body.reason},
        client_ip=_client_ip(request),
    )

    return BanCreateResponse(
        message=f"Ban created for {ip}",
        ip=ip,
        ttl=body.ttl,
        reason=body.reason,
    )


@router.delete("/api/v1/bans/{ip:path}", response_model=BanRemoveResponse)
async def lift_ban(
    ip: str,
    request: Request,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> BanRemoveResponse:
    """Lift (remove) a ban for the given IP address.

    Raises:
        HTTPException(404): If no ban exists for the IP.
    """
    identity = current_user[0]
    ip = urllib.parse.unquote(ip)
    key = f"{_BAN_KEY_PREFIX}{ip}"

    deleted = await redis.delete(key)
    if deleted == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active ban found for IP: {ip}",
        )

    logger.info(
        "bans | event=ban_lifted | ip=%s | user=%s",
        ip,
        identity,
    )

    await _write_audit(
        redis,
        action="ban_lifted",
        user=identity,
        detail={"ip": ip},
        client_ip=_client_ip(request),
    )

    return BanRemoveResponse(message=f"Ban lifted for {ip}", ip=ip)
