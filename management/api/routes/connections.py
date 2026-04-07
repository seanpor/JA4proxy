"""Connection history endpoints.

GET /api/v1/connections  — recent connection events from the Redis Stream
GET /api/v1/fingerprints/{ja4}  — aggregate stats for a JA4 fingerprint
GET /api/v1/fingerprints/{ja4}/history  — chronological event list for a JA4

All three endpoints require at minimum the Analyst role.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["connections"])

_STREAM_KEY = "ja4proxy:events"
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500


def _parse_entry(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the standard connection fields from a stream entry field dict."""
    return {
        "ip": fields.get("ip", ""),
        "ja4": fields.get("ja4", ""),
        "risk_score": fields.get("risk_score"),
        "action_taken": fields.get("action_taken", ""),
        "timestamp": fields.get("timestamp", ""),
    }


@router.get("/api/v1/connections")
async def get_connections(
    ip: Optional[str] = Query(None, description="Filter by exact IP"),
    ja4: Optional[str] = Query(None, description="Filter by exact JA4 fingerprint"),
    action: Optional[str] = Query(None, description="Filter by action_taken"),
    since: Optional[str] = Query(None, description="ISO 8601 timestamp — only events after this"),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT, description="Max results"),
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Return recent connection events from the stream, optionally filtered.

    Reads up to limit*2 raw entries from the stream tail, applies filters,
    then returns at most *limit* results. ``truncated`` is True when the
    raw stream has more entries than were returned.
    """
    any_filter = any(v is not None for v in (ip, ja4, action, since))

    # Read extra entries so filters still yield a full page
    raw_count = limit * 2 if any_filter else limit

    try:
        raw = await redis.xrevrange(_STREAM_KEY, count=raw_count)
    except Exception as exc:  # noqa: BLE001
        logger.warning("connections | event=stream_read_error | error=%s", exc)
        raw = []

    # Determine the total stream length for truncation detection
    try:
        stream_len = await redis.xlen(_STREAM_KEY)
    except Exception:
        stream_len = 0

    # Build result list by applying filters
    results: List[Dict[str, Any]] = []
    for _entry_id, fields in raw:
        entry = _parse_entry(fields)

        if ip is not None and entry["ip"] != ip:
            continue
        if ja4 is not None and entry["ja4"] != ja4:
            continue
        if action is not None and entry["action_taken"] != action:
            continue
        if since is not None:
            ts = entry.get("timestamp", "")
            if ts and ts <= since:
                continue

        results.append(entry)
        if len(results) >= limit:
            break

    # Truncated when: we hit the limit and either there are more stream entries,
    # or we applied filters and consumed all raw entries without knowing the true total.
    truncated = len(results) == limit and stream_len > limit

    return {"connections": results, "count": len(results), "truncated": truncated}


@router.get("/api/v1/fingerprints/{ja4}")
async def get_fingerprint_detail(
    ja4: str,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Return aggregate statistics for a given JA4 fingerprint.

    Scans the full event stream for matching entries and returns total
    connection count, unique IPs, last-seen timestamp, and action breakdown.

    Returns 404 if the fingerprint has never appeared in the stream.
    """
    try:
        raw = await redis.xrange(_STREAM_KEY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("connections | event=stream_read_error | error=%s", exc)
        raw = []

    unique_ips: set[str] = set()
    actions: Dict[str, int] = {}
    last_seen: Optional[str] = None
    total = 0

    for _entry_id, fields in raw:
        if fields.get("ja4") != ja4:
            continue

        total += 1
        ip_val = fields.get("ip", "")
        if ip_val:
            unique_ips.add(ip_val)

        action_val = fields.get("action_taken", "")
        if action_val:
            actions[action_val] = actions.get(action_val, 0) + 1

        ts = fields.get("timestamp", "")
        if ts and (last_seen is None or ts > last_seen):
            last_seen = ts

    if total == 0:
        raise HTTPException(status_code=404, detail=f"Fingerprint '{ja4}' not found in stream")

    return {
        "fingerprint": ja4,
        "total_connections": total,
        "unique_ips": sorted(unique_ips),
        "last_seen": last_seen,
        "actions": actions,
    }


@router.get("/api/v1/fingerprints/{ja4}/history")
async def get_fingerprint_history(
    ja4: str,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Return the chronological event history for a JA4 fingerprint.

    Reads the full stream and returns all matching events sorted oldest-first.
    """
    try:
        raw = await redis.xrange(_STREAM_KEY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("connections | event=stream_read_error | error=%s", exc)
        raw = []

    events: List[Dict[str, Any]] = []
    for _entry_id, fields in raw:
        if fields.get("ja4") != ja4:
            continue
        events.append(_parse_entry(fields))

    # Sort by timestamp field (ISO 8601 strings compare correctly lexicographically)
    events.sort(key=lambda e: e.get("timestamp", ""))

    return {
        "fingerprint": ja4,
        "events": events,
        "count": len(events),
    }
