"""Canonical list endpoints with full resource model (UUID + managed_by).

Routes
------
POST   /api/v1/allowlist
GET    /api/v1/allowlist
GET    /api/v1/allowlist/{resource_id}
DELETE /api/v1/allowlist/{resource_id}

POST   /api/v1/blocklist
GET    /api/v1/blocklist
GET    /api/v1/blocklist/{resource_id}
DELETE /api/v1/blocklist/{resource_id}

POST   /api/v1/watchlist
GET    /api/v1/watchlist
GET    /api/v1/watchlist/{resource_id}
DELETE /api/v1/watchlist/{resource_id}

Redis key mapping
-----------------
Each list has three Redis structures:
  {list_name}:entry:{uuid}  → Hash with full resource metadata
  {list_name}:idx           → SET of UUIDs (index for enumeration)
  {proxy_set}               → SET of raw entry strings (fast O(1) proxy lookup)

Design
------
- Dual-write: HSET + SADD into proxy SET are pipelined (atomic).
- Duplicate entries are idempotent: returns the existing resource (200).
- Expired entries are filtered at read time (not deleted from Redis).
- Migration: legacy plain SET entries promoted to Hash records on startup.
- Old /api/v1/lists/... routes are untouched and continue to work.
"""

import ipaddress
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from ..audit_utils import write_audit
from ..auth import _client_ip, require_role
from ..models import (
    ManagedBy,
    ResourceCreate,
    ResourceListResponse,
    ResourceResponse,
    Role,
)
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["canonical-lists"])

# ── Redis key configuration ───────────────────────────────────────────────────

LIST_CONFIG: dict[str, dict[str, str]] = {
    "allowlist": {
        "hash_prefix": "allowlist:entry",
        "idx_key": "allowlist:idx",
        "proxy_set": "ja4:whitelist",
        "migrated_flag": "allowlist:migrated",
    },
    "blocklist": {
        "hash_prefix": "blocklist:entry",
        "idx_key": "blocklist:idx",
        "proxy_set": "ja4:blacklist",
        "migrated_flag": "blocklist:migrated",
    },
    "watchlist": {
        "hash_prefix": "watchlist:entry",
        "idx_key": "watchlist:idx",
        "proxy_set": "ja4:watchlist",
        "migrated_flag": "watchlist:migrated",
    },
    "ip": {
        "hash_prefix": "ip_allowlist:entry",
        "idx_key": "ip_allowlist:idx",
        "proxy_set": "static:allowlist",
        "migrated_flag": "ip_allowlist:migrated",
    },
}

_VALID_LIST_NAMES = frozenset(("allowlist", "blocklist", "watchlist"))


def _is_ip_entry(entry: str) -> bool:
    """Return True if *entry* looks like an IP address or CIDR."""
    if "/" in entry:
        entry = entry.split("/", 1)[0]
    try:
        ipaddress.ip_address(entry)
        return True
    except ValueError:
        return False


def _resolve_list_config(
    list_name: str, body: Optional[ResourceCreate] = None
) -> dict[str, str]:
    """Return the LIST_CONFIG dict for *list_name*, handling IP sub-type for allowlist."""
    if list_name == "allowlist" and body is not None:
        # IP allowlist: explicit list_type='ip' or entry looks like IP/CIDR
        if body.list_type == "ip" or (body.entry and _is_ip_entry(body.entry)):
            return LIST_CONFIG["ip"]
    return LIST_CONFIG[list_name]


def _is_expired(expires_at: Optional[str]) -> bool:
    """Return True if *expires_at* is a timestamp in the past."""
    if not expires_at:
        return False
    try:
        dt = datetime.fromisoformat(expires_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt <= datetime.now(timezone.utc)
    except ValueError:
        return False


def _hash_to_response(record: dict) -> ResourceResponse:
    """Convert a Redis Hash record dict to a ResourceResponse."""
    expires_at = record.get("expires_at") or None
    return ResourceResponse(
        id=record["id"],
        entry=record["entry"],
        list_type=record["list_type"],
        managed_by=record["managed_by"],
        note=record.get("note", ""),
        created_at=record["created_at"],
        created_by=record["created_by"],
        expires_at=expires_at if expires_at else None,
    )


# ── Migration helper ──────────────────────────────────────────────────────────


async def migrate_legacy_entries(redis, list_name: str) -> None:
    """Promote plain SET entries to full Hash records if not already migrated.

    Only entries in the proxy SET that have no corresponding Hash record (checked
    by both uuid5 key existence AND by scanning the idx for matching entry strings)
    are promoted. This prevents duplicates when migration runs after management API
    writes have already created Hash records for the same entry.

    Args:
        redis: The Redis client.
        list_name: One of 'allowlist', 'blocklist', 'watchlist', 'ip'.
    """
    cfg = LIST_CONFIG[list_name]
    if await redis.exists(cfg["migrated_flag"]):
        return  # already migrated

    # Set the flag first to prevent concurrent migration re-runs
    await redis.set(cfg["migrated_flag"], "1")

    existing = await redis.smembers(cfg["proxy_set"])
    if not existing:
        return

    # Build a set of already-indexed entry strings to skip
    indexed_entries: set[str] = set()
    uuids = await redis.smembers(cfg["idx_key"])
    for resource_id in uuids:
        record = await redis.hgetall(f"{cfg['hash_prefix']}:{resource_id}")
        if record and record.get("entry"):
            indexed_entries.add(record["entry"])

    now = datetime.now(timezone.utc).isoformat()

    for entry in existing:
        if entry in indexed_entries:
            continue  # already indexed — skip (avoids duplicates with uuid4 entries)

        stable_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, entry))
        key = f"{cfg['hash_prefix']}:{stable_uuid}"
        if not await redis.exists(key):
            pipe = redis.pipeline()
            pipe.hset(
                key,
                mapping={
                    "id": stable_uuid,
                    "entry": entry,
                    "list_type": list_name,
                    "managed_by": "legacy",
                    "note": "",
                    "created_at": now,
                    "created_by": "migration",
                    "expires_at": "",
                },
            )
            pipe.sadd(cfg["idx_key"], stable_uuid)
            await pipe.execute()


# ── Shared CRUD helpers ───────────────────────────────────────────────────────


async def _ensure_migrated(redis, list_name: str) -> None:
    """Run migration for *list_name* if it has not been run yet.

    This guards the GET route so that legacy entries are visible even when the
    lifespan is not triggered (e.g. in tests using ASGITransport directly).
    """
    cfg = LIST_CONFIG[list_name]
    if not await redis.exists(cfg["migrated_flag"]):
        await migrate_legacy_entries(redis, list_name)


async def _get_all_entries(
    redis, list_name: str, managed_by_filter: Optional[str] = None
) -> list[ResourceResponse]:
    """Return all non-expired entries from *list_name*, optionally filtered by managed_by."""
    await _ensure_migrated(redis, list_name)
    cfg = LIST_CONFIG[list_name]
    uuids = await redis.smembers(cfg["idx_key"])

    results: list[ResourceResponse] = []
    for resource_id in uuids:
        record = await redis.hgetall(f"{cfg['hash_prefix']}:{resource_id}")
        if not record:
            continue
        if _is_expired(record.get("expires_at")):
            continue
        if (
            managed_by_filter is not None
            and record.get("managed_by") != managed_by_filter
        ):
            continue
        results.append(_hash_to_response(record))

    return results


async def _create_entry(
    redis,
    list_name: str,
    body: ResourceCreate,
    identity: str,
) -> tuple[ResourceResponse, int]:
    """Create or return an existing entry. Returns (ResourceResponse, http_status_code)."""
    cfg = _resolve_list_config(list_name, body)
    # Use the list_name that matches the config (may be "ip" for IP entries under allowlist)
    effective_list_name = next(k for k, v in LIST_CONFIG.items() if v is cfg)

    # Duplicate check: scan idx for existing entry with the same entry string
    uuids = await redis.smembers(cfg["idx_key"])
    for existing_uuid in uuids:
        record = await redis.hgetall(f"{cfg['hash_prefix']}:{existing_uuid}")
        if record and record.get("entry") == body.entry:
            # Return existing resource (idempotent)
            return _hash_to_response(record), 200

    # New entry
    resource_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    expires_at = body.expires_at or ""

    pipe = redis.pipeline()
    pipe.hset(
        f"{cfg['hash_prefix']}:{resource_id}",
        mapping={
            "id": resource_id,
            "entry": body.entry,
            "list_type": effective_list_name,
            "managed_by": body.managed_by.value,
            "note": body.note,
            "created_at": now,
            "created_by": identity,
            "expires_at": expires_at,
        },
    )
    pipe.sadd(cfg["idx_key"], resource_id)
    pipe.sadd(cfg["proxy_set"], body.entry)
    await pipe.execute()

    response = ResourceResponse(
        id=resource_id,
        entry=body.entry,
        list_type=effective_list_name,
        managed_by=body.managed_by.value,
        note=body.note,
        created_at=now,
        created_by=identity,
        expires_at=body.expires_at if body.expires_at else None,
    )
    return response, 201


async def _delete_entry(redis, list_name: str, resource_id: str) -> dict:
    """Remove a resource by ID. Returns the record dict (empty if not found).

    Callers can use the returned record as ``before_value`` in audit writes
    without making a second ``hgetall`` round-trip.
    """
    cfg = LIST_CONFIG[list_name]
    record = await redis.hgetall(f"{cfg['hash_prefix']}:{resource_id}")

    pipe = redis.pipeline()
    pipe.delete(f"{cfg['hash_prefix']}:{resource_id}")
    pipe.srem(cfg["idx_key"], resource_id)
    if record:
        pipe.srem(cfg["proxy_set"], record.get("entry", ""))
    await pipe.execute()
    return record


# ── Route handlers ────────────────────────────────────────────────────────────


def _make_list_routes(list_name: str) -> None:
    """Register CRUD routes for *list_name* on the shared router."""

    @router.post(
        f"/api/v1/{list_name}",
        response_model=ResourceResponse,
        status_code=status.HTTP_201_CREATED,
        summary=f"Add entry to {list_name}",
    )
    async def post_entry(
        body: ResourceCreate,
        request: Request,
        current_user=Depends(require_role(Role.operator)),
        redis=Depends(get_redis),
    ) -> ResourceResponse:
        identity, role = current_user
        response, http_status = await _create_entry(redis, list_name, body, identity)
        if http_status == 201:
            await write_audit(
                redis,
                actor_id=identity,
                actor_ip=_client_ip(request),
                action_type=f"{list_name}.created",
                resource_type=list_name,
                resource_id=response.id,
                before_value=None,
                after_value={
                    "entry": response.entry,
                    "managed_by": response.managed_by,
                },
                role=role.value,
            )
        return response

    @router.get(
        f"/api/v1/{list_name}",
        response_model=ResourceListResponse,
        summary=f"List all entries in {list_name}",
    )
    async def get_entries(
        managed_by: Optional[str] = Query(default=None),
        current_user=Depends(require_role(Role.auditor)),
        redis=Depends(get_redis),
    ) -> ResourceListResponse:
        entries = await _get_all_entries(redis, list_name, managed_by)
        return ResourceListResponse(entries=entries, count=len(entries))

    @router.get(
        f"/api/v1/{list_name}/{{resource_id}}",
        response_model=ResourceResponse,
        summary=f"Get a single {list_name} entry by UUID",
    )
    async def get_entry_by_id(
        resource_id: str,
        current_user=Depends(require_role(Role.auditor)),
        redis=Depends(get_redis),
    ) -> ResourceResponse:
        cfg = LIST_CONFIG[list_name]
        record = await redis.hgetall(f"{cfg['hash_prefix']}:{resource_id}")
        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found"
            )
        if _is_expired(record.get("expires_at")):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resource not found (expired)",
            )
        return _hash_to_response(record)

    @router.delete(
        f"/api/v1/{list_name}/{{resource_id}}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary=f"Delete a {list_name} entry by UUID",
    )
    async def delete_entry(
        resource_id: str,
        request: Request,
        current_user=Depends(require_role(Role.operator)),
        redis=Depends(get_redis),
    ) -> None:
        identity, role = current_user
        record = await _delete_entry(redis, list_name, resource_id)
        before_val = dict(record) if record else None
        await write_audit(
            redis,
            actor_id=identity,
            actor_ip=_client_ip(request),
            action_type=f"{list_name}.deleted",
            resource_type=list_name,
            resource_id=resource_id,
            before_value=before_val,
            after_value=None,
            role=role.value,
        )


# Register routes for all three canonical list names
for _list_name in ("allowlist", "blocklist", "watchlist"):
    _make_list_routes(_list_name)
