"""Ban management endpoints.

Routes
------
GET    /api/v1/bans          — list all active bans
POST   /api/v1/bans/{ip}     — create a ban
DELETE /api/v1/bans/{ip}     — lift a ban
PATCH  /api/v1/bans/{ip}     — extend an active ban's TTL

Redis key pattern: ban:{ip} → String (reason), with TTL

Design notes
------------
- SCAN is used to list bans (no KEYS in production — SCAN is O(1) per call).
- TTL is fetched per key for the listing response.
- IPv6 addresses are supported (stored as-is in the key).
- All write ops create audit log entries using the enhanced schema (MFA/SSO Hardening Cluster 5).
"""

import logging
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..audit_utils import write_audit
from ..auth import require_role
from ..models import (
    BanCreateRequest,
    BanCreateResponse,
    BanEntry,
    BanExtendRequest,
    BanExtendResponse,
    BanList,
    BanRemoveResponse,
    Role,
)
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bans"])

_BAN_KEY_PREFIX = "ban:"


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
            ip = key[len(_BAN_KEY_PREFIX) :]
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
    identity, role = current_user
    ip = urllib.parse.unquote(ip)

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

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ban.created",
        resource_type="ban",
        resource_id=ip,
        before_value=None,
        after_value={"ip": ip, "ttl": body.ttl, "reason": body.reason},
        role=role.value,
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
    identity, role = current_user
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

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ban.deleted",
        resource_type="ban",
        resource_id=ip,
        before_value={"ip": ip},
        after_value=None,
        role=role.value,
    )

    return BanRemoveResponse(message=f"Ban lifted for {ip}", ip=ip)


@router.patch("/api/v1/bans/{ip:path}", response_model=BanExtendResponse)
async def extend_ban(
    ip: str,
    request: Request,
    body: BanExtendRequest,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> BanExtendResponse:
    """Extend an active ban's TTL by the given number of seconds.

    Raises:
        HTTPException(404): If no ban exists for the IP.
    """
    identity, role = current_user
    ip = urllib.parse.unquote(ip)
    key = f"{_BAN_KEY_PREFIX}{ip}"

    existing_ttl = await redis.ttl(key)
    # ttl() returns -1 for persistent keys (no TTL), -2 for expired/missing
    if existing_ttl == -2:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active ban found for IP: {ip}",
        )

    # For persistent bans (ttl == -1), treat existing TTL as 0 and extend from now
    if existing_ttl == -1:
        existing_ttl = 0

    reason = await redis.get(key) or ""
    if isinstance(reason, bytes):
        reason = reason.decode("utf-8", errors="replace")

    new_ttl = existing_ttl + body.extend_ttl_seconds
    await redis.set(key, reason, ex=new_ttl)

    new_expires_at = (
        datetime.now(tz=timezone.utc) + timedelta(seconds=new_ttl)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    logger.info(
        "bans | event=ban_extended | ip=%s | previous_ttl=%d | new_ttl=%d | user=%s",
        ip,
        existing_ttl,
        new_ttl,
        identity,
    )

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ban.extended",
        resource_type="ban",
        resource_id=ip,
        before_value={"ttl": existing_ttl},
        after_value={"ttl": new_ttl, "extended_by": body.extend_ttl_seconds},
        role=role.value,
    )

    return BanExtendResponse(
        ip=ip,
        new_expires_at=new_expires_at,
        previous_ttl=existing_ttl,
        new_ttl=new_ttl,
    )
