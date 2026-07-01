"""Shift handover snapshot endpoint.

GET /api/v1/snapshot — returns a structured JSON document capturing the current
system state. Designed for SOC shift handover: the outgoing analyst downloads
the snapshot; the incoming analyst reads it to understand current threat posture.

Requires operator or admin role.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..auth import get_current_user
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["snapshots"])

_BAN_KEY_PREFIX = "ban:"
_AUDIT_KEY = "management:audit_log"
_DIAL_KEY = "config:dial"
_INTELLIGENCE_INDEX = "analytics:findings:index"
_INTELLIGENCE_KEY_PREFIX = "analytics:finding:"
_EVENTS_STREAM = "events:connection"


async def _read_dial(redis) -> dict:
    """Read current dial value and updated_at timestamp."""
    raw = await redis.get(_DIAL_KEY)
    value = int(raw) if raw else 0
    audit_raw = await redis.lrange(_AUDIT_KEY, 0, 99)
    updated_at = None
    for entry in audit_raw:
        try:
            e = json.loads(entry)
            if e.get("action") == "dial_change":
                updated_at = e.get("timestamp")
                break
        except (json.JSONDecodeError, AttributeError):
            continue
    return {"value": value, "updated_at": updated_at or "unknown"}


async def _read_active_bans(redis) -> list[dict]:
    """Read all currently active ban entries."""
    bans = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor=cursor, match=f"{_BAN_KEY_PREFIX}*", count=100)
        for key in keys:
            ip = key[len(_BAN_KEY_PREFIX):] if isinstance(key, str) else key.decode()[len(_BAN_KEY_PREFIX):]
            reason = await redis.get(key)
            ttl = await redis.ttl(key)
            if ttl == -2:
                continue
            bans.append({
                "ip": ip,
                "reason": reason.decode() if isinstance(reason, bytes) else (reason or ""),
                "ttl_seconds": ttl if ttl >= 0 else None,
            })
        if cursor == 0:
            break
    bans.sort(key=lambda b: b.get("ttl_seconds") or 999999)
    return bans


async def _read_top_threats(redis, window_seconds: int = 3600) -> list[dict]:
    """Read top scoring IPs from the event stream in the last window_seconds."""
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    since_ms = now_ms - (window_seconds * 1000)
    try:
        entries = await redis.xrange(_EVENTS_STREAM, f"{since_ms}-0", "+", count=5000)
    except Exception as exc:
        logger.warning("snapshots | event=stream_read_error | error=%s", exc)
        return []
    ip_scores: dict[str, float] = {}
    for _entry_id, fields in entries:
        ip = fields.get(b"client_ip", fields.get("client_ip", b"")).decode() if isinstance(
            fields.get(b"client_ip", fields.get("client_ip", "")), bytes
        ) else fields.get("client_ip", "")
        score_raw = fields.get(b"risk_score", fields.get("risk_score", b"0"))
        try:
            score = float(score_raw.decode() if isinstance(score_raw, bytes) else score_raw)
        except (ValueError, AttributeError):
            score = 0.0
        if ip:
            ip_scores[ip] = max(ip_scores.get(ip, 0.0), score)
    sorted_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"ip": ip, "max_score": round(score, 1)} for ip, score in sorted_ips]


async def _read_analytics_findings(redis) -> list[dict]:
    """Read active (non-dismissed) HIGH-confidence analytics findings."""
    findings = []
    try:
        raw_ids = await redis.zrevrange(_INTELLIGENCE_INDEX, 0, 19)
        for fid in raw_ids:
            if isinstance(fid, bytes):
                fid = fid.decode()
            key = f"{_INTELLIGENCE_KEY_PREFIX}{fid}"
            raw = await redis.hgetall(key)
            if not raw:
                continue
            decoded = {
                (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in raw.items()
            }
            if decoded.get("dismissed") == "1":
                continue
            findings.append({
                "id": fid,
                "tier": decoded.get("tier"),
                "type": decoded.get("type"),
                "confidence": decoded.get("confidence"),
                "description": decoded.get("description", "")[:200],
                "suggested_action": decoded.get("suggested_action"),
                "created_at": decoded.get("created_at"),
            })
    except Exception as exc:
        logger.warning("snapshots | event=analytics_read_error | error=%s", exc)
    return findings


async def _read_system_health(redis) -> dict:
    """Read key system health indicators."""
    health: dict[str, Any] = {}
    try:
        await redis.ping()
        health["redis"] = "ok"
    except Exception:
        health["redis"] = "error"
    try:
        info = await redis.info("memory")
        health["redis_used_memory"] = info.get("used_memory_human", "unknown")
        health["redis_maxmemory"] = info.get("maxmemory_human", "unlimited")
    except Exception:
        health["redis_used_memory"] = "unknown"
    try:
        stats = await redis.info("stats")
        health["redis_evicted_keys"] = stats.get("evicted_keys", 0)
    except Exception:
        health["redis_evicted_keys"] = "unknown"
    try:
        hb = await redis.get("analytics:heartbeat")
        health["analytics_heartbeat"] = hb.decode() if isinstance(hb, bytes) else (hb or "never")
    except Exception:
        health["analytics_heartbeat"] = "unknown"
    return health


@router.get("/api/v1/snapshot")
async def get_snapshot(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Return a structured JSON snapshot of current system state.

    This is the shift handover document. It captures all information an
    incoming analyst needs to understand the current situation without
    having to navigate through multiple dashboard pages.

    Requires operator or admin role.
    """
    user_name, user_role = current_user[0], (current_user[1] if len(current_user) > 1 else "auditor")

    if user_role not in (Role.operator, Role.admin):
        raise HTTPException(status_code=403, detail="Operator or admin role required.")

    generated_at = datetime.now(timezone.utc).isoformat()

    try:
        dial = await _read_dial(redis)
        active_bans = await _read_active_bans(redis)
        top_threats = await _read_top_threats(redis, window_seconds=3600)
        analytics_findings = await _read_analytics_findings(redis)
        system_health = await _read_system_health(redis)

        watchlist_count = await redis.scard("ja4:watchlist") or 0

        snapshot: dict[str, Any] = {
            "generated_at": generated_at,
            "generated_by": user_name,
            "dial": dial,
            "active_bans": active_bans,
            "active_ban_count": len(active_bans),
            "watchlist_count": int(watchlist_count),
            "top_threats_1h": top_threats,
            "active_analytics_findings": analytics_findings,
            "system_health": system_health,
        }

        logger.info(
            "snapshots | event=snapshot_generated | user=%s | bans=%s | findings=%s",
            user_name, len(active_bans), len(analytics_findings),
        )

        return JSONResponse(
            content=snapshot,
            headers={
                "Content-Disposition": f'attachment; filename="ja4proxy-snapshot-{generated_at[:10]}.json"',
                "Content-Type": "application/json",
            },
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("snapshots | event=snapshot_error | user=%s | error=%s", user_name, exc)
        raise HTTPException(status_code=500, detail="Failed to generate snapshot.")
