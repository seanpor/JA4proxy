"""JA4 fingerprint management router.

Endpoints:
  GET    /api/v1/fingerprints/blacklist
  POST   /api/v1/fingerprints/blacklist
  DELETE /api/v1/fingerprints/blacklist/{fingerprint}
  GET    /api/v1/fingerprints/whitelist
  POST   /api/v1/fingerprints/whitelist
  DELETE /api/v1/fingerprints/whitelist/{fingerprint}
  GET    /api/v1/fingerprints/candidates
  POST   /api/v1/fingerprints/candidates/{fingerprint}/approve
  POST   /api/v1/fingerprints/candidates/{fingerprint}/dismiss

Redis keys:
  ja4:blacklist  — SET of JA4 strings
  ja4:whitelist  — SET of JA4 strings
  ja4:candidates — Sorted set (score = observation count)
"""

import logging
import urllib.parse
from typing import Optional

import redis.exceptions
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from management.auth import require_api_key
from management.metrics import mgmt_actions_total, mgmt_redis_errors_total
from management.models import FingerprintAddRequest, FingerprintEntry, PaginatedResponse
from management.redis_helpers import (
    get_fingerprint_candidates,
    publish_invalidation,
    write_audit_log,
)

logger = logging.getLogger("management.routers.fingerprints")
router = APIRouter()


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _handle_redis_error(op: str, exc: Exception) -> None:
    mgmt_redis_errors_total.labels(operation=op).inc()
    logger.error("management | event=redis_error | op=%s | error=%s", op, exc)


async def _list_set(r, key: str, page: int, per_page: int) -> PaginatedResponse:
    """Read a Redis SET and return paginated list."""
    members = await r.smembers(key)
    items = [
        {"fingerprint": m if isinstance(m, str) else m.decode()}
        for m in sorted(members)
    ]
    total = len(items)
    start = (page - 1) * per_page
    end = start + per_page
    return PaginatedResponse(items=items[start:end], total=total, page=page, per_page=per_page)


# ── Blacklist endpoints ───────────────────────────────────────────────────────

@router.get("/fingerprints/blacklist", response_model=PaginatedResponse)
async def list_blacklist(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    _key: str = Depends(require_api_key),
) -> PaginatedResponse:
    """List all JA4 fingerprints in the blacklist."""
    r = request.app.state.redis
    try:
        return await _list_set(r,"ja4:blacklist", page, per_page)
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("list_blacklist", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("list_blacklist", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")


@router.post("/fingerprints/blacklist", status_code=201)
async def add_to_blacklist(
    request: Request,
    payload: FingerprintAddRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Add a JA4 fingerprint to the blacklist."""
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        await r.sadd("ja4:blacklist", payload.fingerprint)
        await publish_invalidation(r,{
            "event": "ja4_blacklist_add",
            "value": payload.fingerprint,
        })
        await write_audit_log(
            r,
            event_type="fingerprint_blacklisted",
            actor_ip=actor_ip,
            detail={"fingerprint": payload.fingerprint, "reason": payload.reason},
        )
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("add_blacklist", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("add_blacklist", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="fingerprint_blacklist_add").inc()
    return {"fingerprint": payload.fingerprint, "list": "blacklist"}


@router.delete("/fingerprints/blacklist/{fingerprint:path}")
async def remove_from_blacklist(
    fingerprint: str,
    request: Request,
    _key: str = Depends(require_api_key),
) -> dict:
    """Remove a JA4 fingerprint from the blacklist."""
    fingerprint = urllib.parse.unquote(fingerprint)
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        removed = await r.srem("ja4:blacklist", fingerprint)
        if not removed:
            raise HTTPException(
                status_code=404,
                detail=f"Fingerprint {fingerprint!r} not in blacklist",
            )
        await publish_invalidation(r,{
            "event": "ja4_blacklist_remove",
            "value": fingerprint,
        })
        await write_audit_log(
            r,
            event_type="fingerprint_blacklist_removed",
            actor_ip=actor_ip,
            detail={"fingerprint": fingerprint},
        )
    except HTTPException:
        raise
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("remove_blacklist", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("remove_blacklist", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="fingerprint_blacklist_remove").inc()
    return {"fingerprint": fingerprint, "removed": True}


# ── Whitelist endpoints ───────────────────────────────────────────────────────

@router.get("/fingerprints/whitelist", response_model=PaginatedResponse)
async def list_whitelist(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    _key: str = Depends(require_api_key),
) -> PaginatedResponse:
    """List all JA4 fingerprints in the whitelist."""
    r = request.app.state.redis
    try:
        return await _list_set(r,"ja4:whitelist", page, per_page)
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("list_whitelist", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("list_whitelist", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")


@router.post("/fingerprints/whitelist", status_code=201)
async def add_to_whitelist(
    request: Request,
    payload: FingerprintAddRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Add a JA4 fingerprint to the whitelist."""
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        await r.sadd("ja4:whitelist", payload.fingerprint)
        await write_audit_log(
            r,
            event_type="fingerprint_whitelisted",
            actor_ip=actor_ip,
            detail={"fingerprint": payload.fingerprint, "reason": payload.reason},
        )
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("add_whitelist", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("add_whitelist", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="fingerprint_whitelist_add").inc()
    return {"fingerprint": payload.fingerprint, "list": "whitelist"}


@router.delete("/fingerprints/whitelist/{fingerprint:path}")
async def remove_from_whitelist(
    fingerprint: str,
    request: Request,
    _key: str = Depends(require_api_key),
) -> dict:
    """Remove a JA4 fingerprint from the whitelist."""
    fingerprint = urllib.parse.unquote(fingerprint)
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        is_member = await r.sismember("ja4:whitelist", fingerprint)
        if not is_member:
            raise HTTPException(
                status_code=404,
                detail=f"Fingerprint {fingerprint!r} not in whitelist",
            )
        await r.srem("ja4:whitelist", fingerprint)
        await publish_invalidation(r,{
            "event": "whitelist_remove",
            "value": fingerprint,
        })
        await write_audit_log(
            r,
            event_type="fingerprint_whitelist_removed",
            actor_ip=actor_ip,
            detail={"fingerprint": fingerprint},
        )
    except HTTPException:
        raise
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("remove_whitelist", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("remove_whitelist", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="fingerprint_whitelist_remove").inc()
    return {"fingerprint": fingerprint, "removed": True}


# ── Candidates endpoints ──────────────────────────────────────────────────────

@router.get("/fingerprints/candidates", response_model=PaginatedResponse)
async def list_candidates(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    sort: str = Query(default="count"),
    _key: str = Depends(require_api_key),
) -> PaginatedResponse:
    """List JA4 candidate fingerprints sorted by observation count."""
    r = request.app.state.redis
    try:
        items, total = await get_fingerprint_candidates(
            r, sort=sort, page=page, per_page=per_page
        )
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("list_candidates", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("list_candidates", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    return PaginatedResponse(items=items, total=total, page=page, per_page=per_page)


@router.post("/fingerprints/candidates/{fingerprint:path}/approve")
async def approve_candidate(
    fingerprint: str,
    request: Request,
    _key: str = Depends(require_api_key),
) -> dict:
    """Approve a candidate fingerprint — moves it to the blacklist."""
    fingerprint = urllib.parse.unquote(fingerprint)
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        score = await r.zscore("ja4:candidates", fingerprint)
        if score is None:
            raise HTTPException(
                status_code=404,
                detail=f"Candidate {fingerprint!r} not found",
            )

        await r.sadd("ja4:blacklist", fingerprint)
        await r.zrem("ja4:candidates", fingerprint)
        await publish_invalidation(r,{
            "event": "ja4_blacklist_add",
            "value": fingerprint,
        })
        await write_audit_log(
            r,
            event_type="candidate_approved",
            actor_ip=actor_ip,
            detail={"fingerprint": fingerprint, "count": score},
        )
    except HTTPException:
        raise
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("approve_candidate", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("approve_candidate", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="candidate_approve").inc()
    return {"fingerprint": fingerprint, "approved": True, "added_to": "blacklist"}


@router.post("/fingerprints/candidates/{fingerprint:path}/dismiss")
async def dismiss_candidate(
    fingerprint: str,
    request: Request,
    _key: str = Depends(require_api_key),
) -> dict:
    """Dismiss a candidate fingerprint — removes it from the queue."""
    fingerprint = urllib.parse.unquote(fingerprint)
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        score = await r.zscore("ja4:candidates", fingerprint)
        if score is None:
            raise HTTPException(
                status_code=404,
                detail=f"Candidate {fingerprint!r} not found",
            )

        await r.zrem("ja4:candidates", fingerprint)
        await write_audit_log(
            r,
            event_type="candidate_dismissed",
            actor_ip=actor_ip,
            detail={"fingerprint": fingerprint},
        )
    except HTTPException:
        raise
    except redis.exceptions.RedisError as exc:
        _handle_redis_error("dismiss_candidate", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        _handle_redis_error("dismiss_candidate", exc)
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="candidate_dismiss").inc()
    return {"fingerprint": fingerprint, "dismissed": True}
