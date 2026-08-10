"""Operational metrics summary endpoint.

GET /api/v1/metrics/summary  — snapshot of key operational metrics

Returns:
    dial (int): current dial setting
    active_bans (int): count of active ban:* keys
    events_stream_length (int): total entries in events:connection stream
    timestamp (str): ISO 8601 UTC timestamp of the snapshot
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])

_STREAM_KEY = "events:connection"
_BAN_PATTERN = "ban:*"


@router.get("/api/v1/metrics/summary")
async def metrics_summary(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
):
    """Return an operational metrics snapshot.

    All values are read from Redis at request time — no caching.
    """
    # ── Dial ─────────────────────────────────────────────────────────────────
    try:
        dial_raw = await redis.get("config:dial")
        dial = int(dial_raw) if dial_raw is not None else 0
    except Exception as exc:  # noqa: BLE001
        logger.warning("metrics | event=dial_read_error | error=%s", exc)
        dial = 0

    # ── Active bans ───────────────────────────────────────────────────────────
    ban_count = 0
    try:
        async for _key in redis.scan_iter(_BAN_PATTERN):
            ban_count += 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("metrics | event=ban_scan_error | error=%s", exc)

    # ── Stream length ─────────────────────────────────────────────────────────
    try:
        stream_len = await redis.xlen(_STREAM_KEY)
    except Exception as exc:  # noqa: BLE001
        logger.warning("metrics | event=xlen_error | error=%s", exc)
        stream_len = 0

    return {
        "dial": dial,
        "active_bans": ban_count,
        "events_stream_length": stream_len,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
