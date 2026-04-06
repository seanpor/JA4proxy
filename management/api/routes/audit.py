"""Audit log endpoint — GET /api/v1/audit.

Returns the last 1000 management audit log entries in newest-first order.

Redis key: management:audit_log (LIST of JSON strings)
Entries are written by LPUSH so index 0 is always the newest.
"""

import json
import logging

from fastapi import APIRouter, Depends, Request

from ..auth import get_current_user
from ..models import AuditLog
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["audit"])

_AUDIT_KEY = "management:audit_log"
_MAX_ENTRIES = 1000


@router.get("/api/v1/audit", response_model=AuditLog)
async def get_audit_log(
    request: Request,
    current_user: str = Depends(get_current_user),
    redis=Depends(get_redis),
) -> AuditLog:
    """Return the management audit log (newest-first, max 1000 entries)."""
    raw_entries = await redis.lrange(_AUDIT_KEY, 0, _MAX_ENTRIES - 1)

    parsed: list[dict] = []
    for raw in raw_entries:
        try:
            parsed.append(json.loads(raw))
        except json.JSONDecodeError:
            logger.warning("audit | event=malformed_entry | raw=%r", raw)
            continue

    return AuditLog(entries=parsed, count=len(parsed))
