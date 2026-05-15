"""Audit log endpoint — GET /api/v1/audit.

Returns management audit log entries in newest-first order.

Formats
-------
?format=json   (default) — JSON response: {"entries": [...], "count": N}
?format=jsonl  — NDJSON, one JSON object per line
?format=csv    — CSV with header row

Filters (applied before format serialisation)
------
?action=<value>   — filter by action_type field (e.g. "allowlist.created")
?actor=<value>    — filter by actor_id substring (e.g. "alice")
?since=<iso8601>  — filter by timestamp >= value

Redis key: management:audit_log (LIST of JSON strings)
Entries are written by LPUSH so index 0 is always the newest.
"""

import csv
import io
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response

from ..audit_utils import _AUDIT_KEY, _MAX_ENTRIES
from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["audit"])

_CSV_FIELDS = [
    "timestamp",
    "actor_id",
    "actor_ip",
    "action_type",
    "resource_type",
    "resource_id",
    "role",
    "before_value",
    "after_value",
    "session_id",
]


def _apply_filters(
    entries: list[dict[str, Any]],
    action: Optional[str],
    actor: Optional[str],
    since: Optional[str],
) -> list[dict[str, Any]]:
    """Apply query-param filters to a list of parsed audit entries.

    Filter semantics
    ----------------
    ?action=<v>  — entry['action_type'] == <v>  (exact match)
    ?actor=<v>   — <v> in entry['actor_id']     (substring match)
    ?since=<v>   — entry['timestamp'] >= <v>    (lexicographic; ISO 8601 sorts correctly)
    """
    result = entries
    if action is not None:
        result = [e for e in result if e.get("action_type") == action]
    if actor is not None:
        result = [e for e in result if actor in e.get("actor_id", "")]
    if since is not None:
        result = [e for e in result if e.get("timestamp", "") >= since]
    return result


@router.get("/api/v1/audit")
async def get_audit_log(
    request: Request,
    output_format: Optional[str] = Query(
        default=None,
        alias="format",
        description="Response format: json (default), jsonl, csv",
    ),
    action: Optional[str] = Query(
        default=None, description="Filter by action_type field"
    ),
    actor: Optional[str] = Query(
        default=None, description="Filter by actor_id substring"
    ),
    since: Optional[str] = Query(
        default=None, description="Filter by timestamp >= value (ISO 8601)"
    ),
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> Response:
    """Return management audit log entries with optional filters and format control."""
    raw_entries = await redis.lrange(_AUDIT_KEY, 0, _MAX_ENTRIES - 1)

    parsed: list[dict[str, Any]] = []
    for raw in raw_entries:
        try:
            parsed.append(json.loads(raw))
        except json.JSONDecodeError:
            logger.warning("audit | event=malformed_entry | raw=%r", raw)
            continue

    filtered = _apply_filters(parsed, action, actor, since)

    fmt = (output_format or "json").lower()

    if fmt == "jsonl":
        lines = "\n".join(json.dumps(entry) for entry in filtered)
        if lines:
            lines += "\n"
        return Response(
            content=lines,
            media_type="application/x-ndjson",
        )

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=_CSV_FIELDS,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for entry in filtered:
            # Serialise nested values as JSON strings for CSV cells
            row = {
                field: (
                    json.dumps(entry.get(field))
                    if isinstance(entry.get(field), (dict, list))
                    else (entry.get(field) or "")
                )
                for field in _CSV_FIELDS
            }
            writer.writerow(row)
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="audit.csv"'},
        )

    # Default: JSON
    return Response(
        content=json.dumps(
            {"entries": filtered, "count": len(filtered)},
            default=str,
        ),
        media_type="application/json",
    )
