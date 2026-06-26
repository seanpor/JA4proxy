"""Under-attack aggregation endpoints.

GET /api/v1/attack/top  — top attacking IPs in the last 5 minutes

This is the data source for the Under Attack live dashboard, polled every 5s.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis
from .connections import _parse_entry

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attack"])

_STREAM_KEY = "events:connection"


async def _read_attack_window(redis, window_seconds: int = 300) -> List[Dict[str, Any]]:
    """Read recent stream events within window_seconds.

    Returns a list of parsed entry dicts, newest-first, filtered to the window.
    Each dict has: ip, ja4, risk_score, action_taken, timestamp (ISO8601 str).

    _parse_entry is imported from connections.py and takes the fields dict
    (second element of each XREVRANGE tuple). Returns None for malformed entries.
    """
    cutoff_dt = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    try:
        raw = await redis.xrevrange(_STREAM_KEY, "+", "-", count=500)
    except Exception:
        logger.warning("attack | event=stream_read_error")
        return []

    entries = []
    for _entry_id, fields in raw:
        parsed = _parse_entry(fields)
        if not parsed or not parsed.get("timestamp"):
            continue
        try:
            ts_str = parsed["timestamp"]
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        # Entries are newest-first; once we pass the cutoff, all remaining are older.
        if ts < cutoff_dt:
            break
        entries.append(parsed)
    return entries


@router.get("/api/v1/attack/top")
async def get_top_attackers(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Return the top attacking IPs from the last 5 minutes, sorted by connection count."""
    try:
        entries = await _read_attack_window(redis, window_seconds=300)
    except Exception:
        logger.warning("attack | event=read_error")
        return JSONResponse({"generated_at": datetime.now(timezone.utc).isoformat(),
                             "window_seconds": 300, "attackers": []})

    # Aggregate per IP.
    ip_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "connection_count": 0,
        "block_count": 0,
        "max_score": 0,
        "last_seen": None,
        "ja4": "",
    })

    for entry in entries:
        ip = entry.get("ip", "")
        if not ip:
            continue
        d = ip_data[ip]
        d["connection_count"] += 1
        action = entry.get("action_taken", "")
        if action in ("block", "ban", "tarpit"):
            d["block_count"] += 1
        score = entry.get("risk_score") or 0
        try:
            score = int(score)
        except (ValueError, TypeError):
            score = 0
        if score > d["max_score"]:
            d["max_score"] = score
        ts = entry.get("timestamp", "")
        if ts and (d["last_seen"] is None or ts > d["last_seen"]):
            d["last_seen"] = ts
        if not d["ja4"] and entry.get("ja4"):
            d["ja4"] = entry["ja4"]

    if not ip_data:
        return JSONResponse({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "window_seconds": 300,
            "attackers": [],
        })

    # Enrich with ban status (batch TTL checks).
    attackers = []
    for ip, d in sorted(ip_data.items(), key=lambda x: x[1]["connection_count"], reverse=True):
        try:
            ttl_secs = await redis.ttl(f"ban:{ip}")
        except Exception:
            ttl_secs = -2

        if ttl_secs > 0:
            current_status = "banned"
            ban_expires = (
                datetime.now(timezone.utc) + timedelta(seconds=ttl_secs)
            ).isoformat()
        else:
            current_status = "active"
            ban_expires = None

        attackers.append({
            "ip": ip,
            "connection_count": d["connection_count"],
            "block_count": d["block_count"],
            "max_score": d["max_score"],
            "last_seen": d["last_seen"],
            "ja4": d["ja4"],
            "current_status": current_status,
            "ban_expires": ban_expires,
        })

    return JSONResponse({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_seconds": 300,
        "attackers": attackers,
    })
