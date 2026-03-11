"""Async Redis helper functions for the Management UI.

All functions use SCAN (never KEYS) for iterating keys.
All writes to audit logs use LPUSH + LTRIM to cap at 1000 entries.
"""

import json
import logging
import time
from typing import Any, Optional

import redis.exceptions

from management.metrics import mgmt_redis_errors_total

logger = logging.getLogger("management.redis_helpers")


async def get_all_bans(
    r,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Scan ban:{ip} keys and return paginated results.

    Uses SCAN to iterate keys — never KEYS. Returns (items, total).
    """
    items = []
    try:
        async for key in r.scan_iter("ban:*"):
            ip = key[4:] if isinstance(key, str) else key.decode()[4:]
            reason = await r.get(key)
            ttl = await r.ttl(key)
            items.append({
                "ip": ip,
                "reason": reason or "unknown",
                "ttl_s": ttl if ttl > 0 else None,
            })
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="scan_bans").inc()
        logger.error("management | event=redis_error | op=get_all_bans | error=%s", exc)
        raise

    total = len(items)
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], total


async def get_all_cidrs(
    r,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Scan ban_cidr:{cidr} keys and return paginated results.

    Uses SCAN to iterate keys — never KEYS. Returns (items, total).
    """
    items = []
    try:
        async for key in r.scan_iter("ban_cidr:*"):
            cidr = key[9:] if isinstance(key, str) else key.decode()[9:]
            reason = await r.get(key)
            ttl = await r.ttl(key)
            items.append({
                "cidr": cidr,
                "reason": reason or "unknown",
                "ttl_s": ttl if ttl > 0 else None,
            })
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="scan_cidrs").inc()
        logger.error("management | event=redis_error | op=get_all_cidrs | error=%s", exc)
        raise

    total = len(items)
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], total


async def write_audit_log(
    r,
    event_type: str,
    actor_ip: str,
    detail: Optional[dict] = None,
    key: str = "management:audit_log",
) -> None:
    """Write one entry to the audit log. Caps at 1000 entries via LTRIM.

    Format: JSON with event, actor_ip, timestamp, detail fields.
    """
    entry = {
        "event": event_type,
        "actor_ip": actor_ip,
        "timestamp": str(time.time()),
        "detail": detail or {},
    }
    try:
        await r.lpush(key, json.dumps(entry))
        await r.ltrim(key, 0, 999)  # Keep last 1000 entries
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="write_audit_log").inc()
        logger.error(
            "management | event=audit_log_write_failed | key=%s | error=%s",
            key,
            exc,
        )
        # Don't raise — audit log failure must not break the operation


async def get_audit_log(
    r,
    page: int = 1,
    per_page: int = 50,
    event_type: Optional[str] = None,
    key: str = "management:audit_log",
) -> tuple[list[dict], int]:
    """Read paginated audit log entries from Redis LIST.

    Filters by event_type if provided. Returns (items, total).
    """
    try:
        raw_entries = await r.lrange(key, 0, -1)
        total_in_redis = await r.llen(key)
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="get_audit_log").inc()
        logger.error("management | event=redis_error | op=get_audit_log | error=%s", exc)
        raise

    entries = []
    for raw in raw_entries:
        try:
            entry = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue
        if event_type is not None and entry.get("event") != event_type:
            continue
        entries.append(entry)

    total = len(entries)
    start = (page - 1) * per_page
    end = start + per_page
    return entries[start:end], total


async def get_fingerprint_candidates(
    r,
    sort: str = "count",
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Read JA4 candidate fingerprints from the sorted set.

    Sorted by score (count of observations) descending.
    Returns (items, total).
    """
    try:
        total = await r.zcard("ja4:candidates")
        # ZRANGE with REV and scores — fetch all and slice
        raw = await r.zrange("ja4:candidates", 0, -1, withscores=True)
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="get_candidates").inc()
        logger.error(
            "management | event=redis_error | op=get_fingerprint_candidates | error=%s",
            exc,
        )
        raise

    # Sort descending by score
    if isinstance(raw, list) and raw:
        # Handle both list-of-tuples and interleaved formats
        if isinstance(raw[0], (list, tuple)):
            pairs = [(item[0], item[1]) for item in raw]
        else:
            # Interleaved: [member, score, member, score, ...]
            pairs = list(zip(raw[0::2], raw[1::2]))
        pairs.sort(key=lambda x: x[1], reverse=True)
    else:
        pairs = []

    start = (page - 1) * per_page
    end = start + per_page
    page_items = pairs[start:end]

    items = [
        {
            "fingerprint": fp if isinstance(fp, str) else fp.decode(),
            "count": score,
        }
        for fp, score in page_items
    ]
    return items, total


async def publish_invalidation(r, message_dict: dict[str, Any]) -> None:
    """Publish a message to the ja4proxy:invalidate stream via XADD.

    The message_dict is serialised to JSON and stored under the "event" field.
    """
    try:
        await r.xadd(
            "ja4proxy:invalidate",
            {"event": json.dumps(message_dict)},
            maxlen=10000,
        )
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="publish_invalidation").inc()
        logger.error(
            "management | event=redis_error | op=publish_invalidation | error=%s",
            exc,
        )
        raise
