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
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["connections"])

# Go proxy stream — events:connection with JSON-in-event payload
_STREAM_KEY = "events:connection"

# phase-827: drill-downs page backwards through the stream rather than taking a
# fixed slice of the newest entries.
#
# Both the fingerprint and IP profiles used xrevrange(count=5000), while the
# tables linking to them aggregate the WHOLE stream via xrange. With 13,410
# events buffered, a fingerprint could show "2,000+ connections" in the table
# and open a drill-down reporting zero IPs, because all of its traffic sat
# outside the newest 5,000. A detail view that contradicts the row you clicked
# is worse than a slow one.
#
# The scan is bounded so a very large stream cannot make this unbounded, and
# the response reports when the bound was hit instead of quietly under-counting.
_PROFILE_SCAN_LIMIT = 100_000
_PROFILE_SCAN_BATCH = 2_000


async def _scan_stream(redis) -> tuple[list, int, bool]:
    """Page backwards over the event stream. Returns (entries, scanned, truncated).

    Callers apply their own time cutoff while iterating; this only bounds total
    work. Kept in one place so the fingerprint and IP profiles cannot drift
    apart again.
    """
    entries: list = []
    cursor = "+"
    scanned = 0
    while scanned < _PROFILE_SCAN_LIMIT:
        batch = await redis.xrevrange(
            _STREAM_KEY, max=cursor, min="-", count=_PROFILE_SCAN_BATCH
        )
        if not batch:
            return entries, scanned, False
        entries.extend(batch)
        scanned += len(batch)
        if len(batch) < _PROFILE_SCAN_BATCH:
            return entries, scanned, False
        # xrevrange's max is inclusive, so step one id past the last we saw.
        ms, _, seq = batch[-1][0].partition("-")
        cursor = f"{ms}-{int(seq) - 1}" if seq and int(seq) > 0 else str(int(ms) - 1)
    return entries, scanned, True
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 10_000  # raised from 500 for compliance bulk exports


def _parse_entry(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the standard connection fields from a stream entry field dict.

    The Go proxy writes ECS-dotted JSON in the ``event`` field:
    ``{"@timestamp":"...","event.action":"...","source.ip":"...","ja4proxy.fingerprint.ja4":"...","event.risk_score":...}``.
    """
    raw = fields.get("event", "")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            parsed = {}
    elif isinstance(raw, dict):
        parsed = raw
    else:
        parsed = {}
    signals = parsed.get("ja4proxy.signals", [])
    if not isinstance(signals, list):
        signals = []
    return {
        "ip": parsed.get("source.ip", ""),
        "ja4": parsed.get("ja4proxy.fingerprint.ja4", ""),
        "risk_score": parsed.get("event.risk_score"),
        "action_taken": parsed.get("event.action", ""),
        "signals": signals,
        "timestamp": parsed.get("@timestamp", ""),
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
    since: Optional[str] = Query(
        None, description="ISO 8601 timestamp — only events after this"
    ),
    until: Optional[str] = Query(
        None,
        description="ISO 8601 timestamp — only events before this (Compliance Reporting)",
    ),
    limit: int = Query(
        _DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT, description="Max results per page"
    ),
    page_token: Optional[str] = Query(
        None, description="Cursor for next page (from previous response)"
    ),
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
        entry = _parse_entry(fields)
        if entry["ja4"] != ja4:
            continue

        total += 1
        ip_val = entry["ip"]
        if ip_val:
            unique_ips.add(ip_val)

        action_val = entry["action_taken"]
        if action_val:
            actions[action_val] = actions.get(action_val, 0) + 1

        ts = entry["timestamp"]
        if ts and (last_seen is None or ts > last_seen):
            last_seen = ts

    if total == 0:
        raise HTTPException(
            status_code=404, detail=f"Fingerprint '{ja4}' not found in stream"
        )

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
        entry = _parse_entry(fields)
        if entry["ja4"] != ja4:
            continue
        events.append(entry)

    # Sort by timestamp field (ISO 8601 strings compare correctly lexicographically)
    events.sort(key=lambda e: e.get("timestamp", ""))

    return {
        "fingerprint": ja4,
        "events": events,
        "count": len(events),
    }


@router.get("/api/v1/fingerprints/{ja4}/profile")
async def get_fingerprint_profile(
    ja4: str,
    request: Request,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Aggregate profile for a JA4 fingerprint from the live event stream.

    Reads from ``events:connection`` (the stream the Go proxy writes to)
    and parses the JSON ``event`` field containing flat ECS-dotted keys.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_ms = int(cutoff.timestamp() * 1000)

    ips: set[str] = set()
    action_counts: dict[str, int] = {}
    hourly_buckets: dict[int, float] = {}
    total_events = 0

    events, scanned_events, scan_truncated = await _scan_stream(redis)
    for _msg_id, fields in events:
        raw = fields.get("event", "{}")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        event_ts = parsed.get("@timestamp", "")
        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                if ts.timestamp() * 1000 < cutoff_ms:
                    break
            except (ValueError, TypeError):
                pass

        evt_ja4 = parsed.get("ja4proxy.fingerprint.ja4", "")
        if evt_ja4 != ja4:
            continue

        total_events += 1
        src_ip = parsed.get("source.ip", "")
        if src_ip:
            ips.add(src_ip)

        action = parsed.get("event.action", "allow")
        action_counts[action] = action_counts.get(action, 0) + 1

        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                hour_key = int(ts.replace(minute=0, second=0, microsecond=0).timestamp())
                score = parsed.get("event.risk_score", 0)
                if isinstance(score, (int, float)):
                    hourly_buckets[hour_key] = max(hourly_buckets.get(hour_key, 0), float(score))
            except (ValueError, TypeError):
                pass

    is_banned = any([await redis.exists(f"ban:{ip}") for ip in ips]) if ips else False
    is_allowlisted = await redis.sismember("ja4:whitelist", ja4)

    return {
        "ja4": ja4,
        # Surfaced so the UI can say what the numbers are based on rather than
        # presenting a truncated count as a complete one.
        "scanned_events": scanned_events,
        "truncated": scan_truncated,
        "total_events": total_events,
        "unique_ips": len(ips),
        "ips_sample": sorted(ips)[:20],
        "action_counts": action_counts,
        "is_banned": bool(is_banned),
        "is_allowlisted": bool(is_allowlisted),
        "hourly_scores": [
            {"timestamp": k, "max_score": v}
            for k, v in sorted(hourly_buckets.items())
        ],
    }


@router.get("/api/v1/ip/{ip:path}/profile")
async def get_ip_profile(
    ip: str,
    request: Request,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Aggregate profile for a source IP from the live event stream.

    Uses ``:path`` converter to preserve dots and colons in IPv4/IPv6.
    Reads from ``events:connection`` and parses the JSON ``event`` field.
    """
    ip = urllib.parse.unquote(ip)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    cutoff_ms = int(cutoff.timestamp() * 1000)

    ja4_set: set[str] = set()
    history: list[dict] = []
    hourly_buckets: dict[int, list[float]] = {}
    total_events = 0

    events, scanned_events, scan_truncated = await _scan_stream(redis)
    for _msg_id, fields in events:
        raw = fields.get("event", "{}")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        event_ts = parsed.get("@timestamp", "")
        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                if ts.timestamp() * 1000 < cutoff_ms:
                    break
            except (ValueError, TypeError):
                pass

        src_ip = parsed.get("source.ip", "")
        if src_ip != ip:
            continue

        total_events += 1
        ja4 = parsed.get("ja4proxy.fingerprint.ja4", "")
        if ja4:
            ja4_set.add(ja4)

        action = parsed.get("event.action", "allow")
        score = parsed.get("event.risk_score", 0)
        try:
            score = float(score)
        except (ValueError, TypeError):
            score = 0.0

        history.append({
            "timestamp": event_ts,
            "action": action,
            "score": score,
            "ja4": ja4,
        })

        if event_ts:
            try:
                ts = datetime.fromisoformat(event_ts)
                hour_key = int(ts.replace(minute=0, second=0, microsecond=0).timestamp())
                if hour_key not in hourly_buckets:
                    hourly_buckets[hour_key] = []
                hourly_buckets[hour_key].append(score)
            except (ValueError, TypeError):
                pass

    hourly_scores = [
        {"timestamp": k, "avg_score": round(sum(v) / len(v), 1), "max_score": max(v)}
        for k, v in sorted(hourly_buckets.items())
    ]

    is_banned = await redis.exists(f"ban:{ip}")

    return {
        "ip": ip,
        "total_events": total_events,
        "unique_ja4": len(ja4_set),
        "fingerprints": sorted(ja4_set),
        "is_banned": bool(is_banned),
        "geo": {"country": "Unknown", "asn": "Unknown"},
        "history": history[-50:],
        "hourly_scores": hourly_scores,
    }
