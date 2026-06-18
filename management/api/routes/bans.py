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

import ipaddress
import json
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..audit_utils import write_audit
from ..auth import _client_ip, require_role
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

# Phase 237: CIDR expansion support
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

_MAX_CIDR_PREFIX = 16


class BanRequest(BaseModel):
    ip: str = Field(..., description="IPv4, IPv6, or CIDR range (e.g. 203.0.113.0/24).")
    reason: str = Field(..., min_length=10, description="Reason for the ban (min 10 chars).")
    duration_hours: int = Field(24, ge=1, le=720, description="Ban duration in hours (max 30 days).")
    allow_private: bool = Field(
        False,
        description="Set true to allow banning private/RFC1918 ranges.",
    )


def _expand_cidr(cidr_str: str, allow_private: bool) -> list[str]:
    """Expand a CIDR block into individual IP strings."""
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IP or CIDR: {cidr_str!r} — {exc}") from exc

    if network.prefixlen < _MAX_CIDR_PREFIX:
        host_count = network.num_addresses
        raise ValueError(
            f"CIDR /{network.prefixlen} covers {host_count:,} addresses. "
            f"Maximum allowed is /{_MAX_CIDR_PREFIX} ({2 ** (32 - _MAX_CIDR_PREFIX):,} addresses). "
            f"Larger blocks risk collateral damage to legitimate users. "
            f"Ban individual /24 blocks instead."
        )

    if not allow_private:
        for private_net in _PRIVATE_NETWORKS:
            if network.overlaps(private_net):
                raise ValueError(
                    f"CIDR {cidr_str} overlaps private/reserved range {private_net}. "
                    f"Banning this range would block internal/loopback traffic. "
                    f"If you intend this, pass allow_private=true."
                )

    if isinstance(network, ipaddress.IPv4Network) and network.prefixlen >= 24:
        hosts = [str(ip) for ip in network.hosts()]
    else:
        hosts = [str(ip) for ip in network]

    return hosts


@router.post("/api/v1/bans")
async def create_ban_cidr(
    body: BanRequest,
    request: Request,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
):
    """Ban an IP address or CIDR range.

    For individual IPs: creates one ban:IP key.
    For CIDRs: expands and creates one key per host IP using a Redis pipeline.
    Rejects CIDR ranges larger than /16 and private/RFC1918 ranges (unless
    allow_private=true is passed).

    Phase 237 Step C: CIDR expansion.
    """
    identity, role = current_user
    ttl_seconds = body.duration_hours * 3600

    try:
        ips_to_ban = _expand_cidr(body.ip, body.allow_private)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if not ips_to_ban:
        raise HTTPException(status_code=422, detail="CIDR expansion produced zero IPs.")

    try:
        _BAN_BATCH_SIZE = 500
        for i in range(0, len(ips_to_ban), _BAN_BATCH_SIZE):
            batch = ips_to_ban[i : i + _BAN_BATCH_SIZE]
            pipe = redis.pipeline()
            for ip in batch:
                key = f"{_BAN_KEY_PREFIX}{ip}"
                pipe.set(key, body.reason, ex=ttl_seconds)
            await pipe.execute()
    except Exception as exc:
        logger.warning(
            "bans | event=ban_write_error | cidr=%s | ips=%s | error=%s",
            body.ip, len(ips_to_ban), exc,
        )
        raise HTTPException(status_code=500, detail="Redis write failed.")

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="ban.created",
        resource_type="ban",
        resource_id=body.ip,
        before_value=None,
        after_value={"ip": body.ip, "ip_count": len(ips_to_ban), "reason": body.reason,
                      "duration_hours": body.duration_hours},
        role=role.value,
    )

    logger.info(
        "bans | event=ban_created | user=%s | cidr=%s | ips=%s | ttl_hours=%s",
        identity, body.ip, len(ips_to_ban), body.duration_hours,
    )

    return {
        "ok": True,
        "banned_ip": body.ip,
        "host_count": len(ips_to_ban),
        "duration_hours": body.duration_hours,
    }


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
