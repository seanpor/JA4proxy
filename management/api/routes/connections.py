"""Connection history endpoints.

GET /api/v1/connections  — recent connection events from the Redis Stream
GET /api/v1/fingerprints/{ja4}  — aggregate stats for a JA4 fingerprint
GET /api/v1/fingerprints/{ja4}/history  — chronological event list for a JA4

All three endpoints require at minimum the Analyst role.

Compliance Reporting additions to GET /api/v1/connections
----------------------------------------------
?until=<iso8601>    — upper bound for the query window (exclusive upper bound)
?page_token=<str>   — opaque cursor for the next page (returned in response when
                       has_more=true).  Based on stream entry offset.
?limit=             — max results per page (default 100, max 10,000 for compliance use).

Pagination contract (Compliance Reporting)
------------------------------
{
  "connections": [...],
  "count": N,
  "truncated": bool,          # legacy field — kept for backwards compatibility
  "has_more": bool,           # true when more pages exist
  "next_page_token": str|null # pass as ?page_token= on next call; null when done
}

page_token is a base64-encoded JSON cursor: {"offset": int, "since": str, "until": str}.
The cursor encodes the stream read offset so adding new events after a page is fetched
does not affect the next page (position-stable).
"""

import base64
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["connections"])

_STREAM_KEY = "ja4proxy:events"
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 10_000  # raised from 500 for compliance bulk exports


def _parse_entry(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the standard connection fields from a stream entry field dict."""
    return {
        "ip": fields.get("ip", ""),
        "ja4": fields.get("ja4", ""),
        "risk_score": fields.get("risk_score"),
        "action_taken": fields.get("action_taken", ""),
        "timestamp": fields.get("timestamp", ""),
    }


def _encode_page_token(offset: int, since: str, until: str) -> str:
    """Encode a pagination cursor as a URL-safe base64 string."""
    payload = json.dumps({"offset": offset, "since": since or "", "until": until or ""})
    return base64.urlsafe_b64encode(payload.encode()).decode()


def _decode_page_token(token: str) -> dict[str, Any]:
    """Decode a pagination cursor.  Returns {} on any error."""
    try:
        payload = base64.urlsafe_b64decode(token.encode()).decode()
        return json.loads(payload)
    except Exception:
        return {}


@router.get("/api/v1/connections")
async def get_connections(
    ip: Optional[str] = Query(None, description="Filter by exact IP"),
    ja4: Optional[str] = Query(None, description="Filter by exact JA4 fingerprint"),
    action: Optional[str] = Query(None, description="Filter by action_taken"),
    since: Optional[str] = Query(None, description="ISO 8601 timestamp — only events after this"),
    until: Optional[str] = Query(None, description="ISO 8601 timestamp — only events before this (Compliance Reporting)"),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT, description="Max results per page"),
    page_token: Optional[str] = Query(None, description="Cursor for next page (from previous response)"),
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Return connection events from the stream with optional filtering and pagination.

    Compliance Reporting adds: ?until=, ?page_token= for cursor-based pagination.
    """
    # Validate since < until
    if since is not None and until is not None and since >= until:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="'since' must be before 'until'",
        )

    # Resolve offset from page_token
    offset = 0
    if page_token:
        cursor = _decode_page_token(page_token)
        offset = int(cursor.get("offset", 0))
        # page_token encodes the original since/until for stability — honour them
        if not since:
            since = cursor.get("since") or None
        if not until:
            until = cursor.get("until") or None

    # Read the full stream (oldest-first for stable pagination)
    try:
        raw = await redis.xrange(_STREAM_KEY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("connections | event=stream_read_error | error=%s", exc)
        raw = []

    try:
        stream_len = await redis.xlen(_STREAM_KEY)
    except Exception:
        stream_len = 0

    # Apply filters to all entries, then slice with offset for pagination
    all_filtered: List[Dict[str, Any]] = []
    for _entry_id, fields in raw:
        entry = _parse_entry(fields)

        if ip is not None and entry["ip"] != ip:
            continue
        if ja4 is not None and entry["ja4"] != ja4:
            continue
        if action is not None and entry["action_taken"] != action:
            continue
        ts = entry.get("timestamp", "")
        if since is not None and ts and ts <= since:
            continue
        if until is not None and ts and ts >= until:
            continue

        all_filtered.append(entry)

    total_filtered = len(all_filtered)
    page = all_filtered[offset : offset + limit]
    next_offset = offset + len(page)
    has_more = next_offset < total_filtered

    next_page_token: Optional[str] = None
    if has_more:
        next_page_token = _encode_page_token(
            next_offset,
            since or "",
            until or "",
        )

    # Legacy truncated flag for backwards compatibility
    truncated = len(page) == limit and stream_len > limit

    return {
        "connections": page,
        "count": len(page),
        "truncated": truncated,
        "has_more": has_more,
        "next_page_token": next_page_token,
        "total_in_window": total_filtered,
    }


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
