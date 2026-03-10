"""IP and CIDR ban management router.

Endpoints:
  GET    /api/v1/bans               list active IP bans (paginated)
  POST   /api/v1/bans               add an IP ban
  DELETE /api/v1/bans/{ip}          release an IP ban
  GET    /api/v1/cidrs              list CIDR blocks (paginated)
  POST   /api/v1/cidrs              add a CIDR block
  DELETE /api/v1/cidrs/{cidr}       remove a CIDR block

All mutations publish to the ja4proxy:invalidate stream and write to
the management:audit_log.
"""

import ipaddress
import logging
import urllib.parse
from typing import Optional

import redis.exceptions
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from management.auth import require_api_key
from management.metrics import mgmt_actions_total, mgmt_redis_errors_total
from management.models import BanAddRequest, BanEntry, CIDRAddRequest, CIDREntry, PaginatedResponse
from management.redis_helpers import (
    get_all_bans,
    get_all_cidrs,
    publish_invalidation,
    write_audit_log,
)

logger = logging.getLogger("management.routers.bans")
router = APIRouter()


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _handle_redis_error(op: str, exc: Exception) -> None:
    mgmt_redis_errors_total.labels(operation=op).inc()
    logger.error("management | event=redis_error | op=%s | error=%s", op, exc)


# ── IP Ban endpoints ──────────────────────────────────────────────────────────

@router.get("/bans", response_model=PaginatedResponse)
async def list_bans(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    _key: str = Depends(require_api_key),
) -> PaginatedResponse:
    """List all active IP bans with pagination."""
    redis = request.app.state.redis
    try:
        items, total = await get_all_bans(redis, page=page, per_page=per_page)
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("list_bans", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("list_bans", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page)


@router.post("/bans", status_code=201)
async def add_ban(
    request: Request,
    payload: BanAddRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Add an IP ban. Publishes to invalidate stream and writes audit log."""
    redis = request.app.state.redis
    actor_ip = _get_client_ip(request)

    ban_key = f"ban:{payload.ip}"
    reason_value = f"manual:{payload.reason}"

    try:
        if payload.ttl_s > 0:
            await redis.set(ban_key, reason_value, ex=payload.ttl_s)
        else:
            await redis.set(ban_key, reason_value)

        await publish_invalidation(redis, {
            "event": "ban_added",
            "ip": payload.ip,
            "ttl_s": payload.ttl_s,
        })
        await write_audit_log(
            redis,
            event_type="ban_added",
            actor_ip=actor_ip,
            detail={"ip": payload.ip, "reason": payload.reason, "ttl_s": payload.ttl_s},
        )
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("add_ban", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("add_ban", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="ban_add").inc()
    logger.info(
        "management | event=ban_added | actor_ip=%s | ip=%s | ttl_s=%d",
        actor_ip,
        payload.ip,
        payload.ttl_s,
    )
    return {"ip": payload.ip, "reason": payload.reason, "ttl_s": payload.ttl_s}


@router.delete("/bans/{ip}")
async def release_ban(
    ip: str,
    request: Request,
    _key: str = Depends(require_api_key),
) -> dict:
    """Release (delete) an active IP ban."""
    # Decode URL-encoded IP (IPv6 with colons may be encoded)
    ip = urllib.parse.unquote(ip)

    redis = request.app.state.redis
    actor_ip = _get_client_ip(request)
    ban_key = f"ban:{ip}"

    try:
        existing = await redis.get(ban_key)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"No ban found for IP {ip!r}")

        await redis.delete(ban_key)
        await publish_invalidation(redis, {"event": "ban_release", "ip": ip})
        await write_audit_log(
            redis,
            event_type="ban_released",
            actor_ip=actor_ip,
            detail={"ip": ip},
        )
    except HTTPException:
        raise
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("release_ban", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("release_ban", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="ban_release").inc()
    logger.info(
        "management | event=ban_released | actor_ip=%s | ip=%s", actor_ip, ip
    )
    return {"ip": ip, "released": True}


# ── CIDR block endpoints ──────────────────────────────────────────────────────

@router.get("/cidrs", response_model=PaginatedResponse)
async def list_cidrs(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    _key: str = Depends(require_api_key),
) -> PaginatedResponse:
    """List all active CIDR blocks with pagination."""
    redis = request.app.state.redis
    try:
        items, total = await get_all_cidrs(redis, page=page, per_page=per_page)
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("list_cidrs", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("list_cidrs", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page)


@router.post("/cidrs", status_code=201)
async def add_cidr(
    request: Request,
    payload: CIDRAddRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Add a CIDR block. Publishes to invalidate stream and writes audit log."""
    redis = request.app.state.redis
    actor_ip = _get_client_ip(request)
    cidr_key = f"ban_cidr:{payload.cidr}"

    try:
        if payload.ttl_s > 0:
            await redis.set(cidr_key, f"manual:{payload.reason}", ex=payload.ttl_s)
        else:
            await redis.set(cidr_key, f"manual:{payload.reason}")

        await publish_invalidation(redis, {"event": "cidr_blocked", "cidr": payload.cidr})
        await write_audit_log(
            redis,
            event_type="cidr_blocked",
            actor_ip=actor_ip,
            detail={"cidr": payload.cidr, "reason": payload.reason},
        )
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("add_cidr", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("add_cidr", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="cidr_block").inc()
    return {"cidr": payload.cidr, "reason": payload.reason}


@router.delete("/cidrs/{cidr:path}")
async def remove_cidr(
    cidr: str,
    request: Request,
    _key: str = Depends(require_api_key),
) -> dict:
    """Remove a CIDR block."""
    cidr = urllib.parse.unquote(cidr)

    redis = request.app.state.redis
    actor_ip = _get_client_ip(request)
    cidr_key = f"ban_cidr:{cidr}"

    try:
        existing = await redis.get(cidr_key)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"No CIDR block found for {cidr!r}")

        await redis.delete(cidr_key)
        await publish_invalidation(redis, {"event": "cidr_released", "cidr": cidr})
        await write_audit_log(
            redis,
            event_type="cidr_released",
            actor_ip=actor_ip,
            detail={"cidr": cidr},
        )
    except HTTPException:
        raise
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("remove_cidr", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("remove_cidr", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="cidr_release").inc()
    return {"cidr": cidr, "released": True}
