"""List management endpoints — JA4 whitelist/blacklist and IP allowlist.

Routes
------
GET    /api/v1/lists/ja4/whitelist
POST   /api/v1/lists/ja4/whitelist/{entry}
DELETE /api/v1/lists/ja4/whitelist/{entry}

GET    /api/v1/lists/ja4/blacklist
POST   /api/v1/lists/ja4/blacklist/{entry}
DELETE /api/v1/lists/ja4/blacklist/{entry}

GET    /api/v1/lists/ip/allowlist
POST   /api/v1/lists/ip/allowlist/{entry}
DELETE /api/v1/lists/ip/allowlist/{entry}

Redis keys (matching proxy.py's existing schema)
-------------------------------------------------
ja4:whitelist    → SET of JA4 fingerprint strings
ja4:blacklist    → SET of JA4 fingerprint strings
static:allowlist → SET of IP/CIDR strings

Design notes
------------
- Duplicate adds are idempotent (SADD is set semantics).
- DELETE of a nonexistent entry returns 404.
- All writes create an audit log entry.
- Unknown list_type or list_name → 404.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..auth import require_role
from ..models import ListAddResponse, ListEntries, ListRemoveResponse, Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["lists"])

_AUDIT_KEY = "management:audit_log"

# Mapping of (list_type, list_name) → Redis key
_LIST_KEYS: dict[tuple[str, str], str] = {
    ("ja4", "whitelist"): "ja4:whitelist",
    ("ja4", "blacklist"): "ja4:blacklist",
    ("ip", "allowlist"): "static:allowlist",
}


def _resolve_key(list_type: str, list_name: str) -> str:
    """Resolve the Redis key for a given list_type/list_name pair.

    Raises:
        HTTPException(404): If the combination is unknown.
    """
    key = _LIST_KEYS.get((list_type, list_name))
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown list: {list_type}/{list_name}",
        )
    return key


async def _write_audit(
    redis,
    action: str,
    user: str,
    detail: dict,
    client_ip: str,
) -> None:
    """Append an audit log entry and trim to 1000 entries."""
    entry = json.dumps(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "user": user,
            "detail": detail,
            "ip": client_ip,
        }
    )
    await redis.lpush(_AUDIT_KEY, entry)
    await redis.ltrim(_AUDIT_KEY, 0, 999)


def _client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@router.get("/api/v1/lists/{list_type}/{list_name}", response_model=ListEntries)
async def get_list(
    list_type: str,
    list_name: str,
    request: Request,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> ListEntries:
    """Return all entries in the specified list."""
    redis_key = _resolve_key(list_type, list_name)
    entries = await redis.smembers(redis_key)
    entry_list = sorted(entries)
    return ListEntries(entries=entry_list, count=len(entry_list))


@router.post(
    "/api/v1/lists/{list_type}/{list_name}/{entry:path}",
    response_model=ListAddResponse,
)
async def add_to_list(
    list_type: str,
    list_name: str,
    entry: str,
    request: Request,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> ListAddResponse:
    """Add an entry to the specified list (idempotent — safe to call multiple times)."""
    identity = current_user[0]
    redis_key = _resolve_key(list_type, list_name)
    await redis.sadd(redis_key, entry)
    logger.info(
        "lists | event=entry_added | list=%s/%s | entry=%s | user=%s",
        list_type,
        list_name,
        entry,
        identity,
    )

    await _write_audit(
        redis,
        action="list_entry_added",
        user=identity,
        detail={"list": f"{list_type}/{list_name}", "entry": entry},
        client_ip=_client_ip(request),
    )

    return ListAddResponse(
        message=f"Entry added to {list_type}/{list_name}",
        entry=entry,
    )


@router.delete(
    "/api/v1/lists/{list_type}/{list_name}/{entry:path}",
    response_model=ListRemoveResponse,
)
async def remove_from_list(
    list_type: str,
    list_name: str,
    entry: str,
    request: Request,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
) -> ListRemoveResponse:
    """Remove an entry from the specified list.

    Raises:
        HTTPException(404): If the entry does not exist in the list.
    """
    identity = current_user[0]
    redis_key = _resolve_key(list_type, list_name)
    removed = await redis.srem(redis_key, entry)

    if removed == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Entry '{entry}' not found in {list_type}/{list_name}",
        )

    logger.info(
        "lists | event=entry_removed | list=%s/%s | entry=%s | user=%s",
        list_type,
        list_name,
        entry,
        identity,
    )

    await _write_audit(
        redis,
        action="list_entry_removed",
        user=identity,
        detail={"list": f"{list_type}/{list_name}", "entry": entry},
        client_ip=_client_ip(request),
    )

    return ListRemoveResponse(
        message=f"Entry removed from {list_type}/{list_name}",
        entry=entry,
    )
