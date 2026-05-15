"""HTMX partial (fragment) routes.

These routes return rendered HTML fragments used by HTMX to update parts
of the UI without a full-page reload.

All routes require authentication (JWT cookie). They return HTML responses
rendered from templates in management/templates/partials/.

Routes
------
GET /api/v1/partials/health-cards   — health status card grid
GET /api/v1/partials/dial           — dial widget with current value
GET /api/v1/partials/bans           — active bans table
GET /api/v1/partials/audit          — audit log table rows
GET /api/v1/partials/list-table     — a single list table (whitelist/blacklist/allowlist)
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..auth import get_current_user
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["partials"])

# Injected by main.py (same instance as pages.py)
_templates: Optional[Jinja2Templates] = None

# Module start time for health uptime
_START_TIME = time.monotonic()


def set_templates(templates: Jinja2Templates) -> None:
    """Called by main.py to inject the Jinja2Templates instance."""
    global _templates
    _templates = templates


def _get_templates() -> Jinja2Templates:
    if _templates is None:
        raise RuntimeError("Templates not initialised. Call set_templates() first.")
    return _templates


# ── Mapping helpers ────────────────────────────────────────────────────────────

_LIST_REDIS_KEYS: dict[str, tuple[str, str, str]] = {
    # query_param  → (list_type, list_name, redis_key)
    "ja4_whitelist": ("ja4", "whitelist", "ja4:whitelist"),
    "ja4_blacklist": ("ja4", "blacklist", "ja4:blacklist"),
    "ip_allowlist": ("ip", "allowlist", "static:allowlist"),
}

_BAN_KEY_PREFIX = "ban:"
_AUDIT_KEY = "management:audit_log"
_DIAL_KEY = "config:dial"


async def _get_dial(redis) -> int:
    """Read current dial from Redis (default 0)."""
    raw: Optional[str] = await redis.get(_DIAL_KEY)
    if raw is None:
        return 0
    try:
        return int(raw)
    except ValueError:
        return 0


# ── Routes ─────────────────────────────────────────────────────────────────────


@router.get("/api/v1/partials/health-cards", response_class=HTMLResponse)
async def health_cards_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the health cards grid as an HTML fragment."""
    templates = _get_templates()

    # Gather health data
    redis_status = "error"
    active_bans = 0
    events_per_min = 0

    try:
        await redis.ping()
        redis_status = "ok"

        # Count active bans via SCAN
        cursor = 0
        while True:
            cursor, keys = await redis.scan(
                cursor=cursor, match=f"{_BAN_KEY_PREFIX}*", count=100
            )
            active_bans += len(keys)
            if cursor == 0:
                break

        # Events per minute: read from a counter key the proxy writes
        raw_epm = await redis.get("stats:events_per_min")
        if raw_epm:
            try:
                events_per_min = int(raw_epm)
            except ValueError:
                pass

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=redis_error | error=%s", exc)

    dial_value = await _get_dial(redis) if redis_status == "ok" else 0

    health_cards = [
        {
            "label": "Redis",
            "value": "OK" if redis_status == "ok" else "DOWN",
            "unit": "",
            "status": "ok" if redis_status == "ok" else "error",
            "icon_path": "M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4",
        },
        {
            "label": "Active Bans",
            "value": str(active_bans),
            "unit": "",
            "status": "warn" if active_bans > 50 else "ok",
            "icon_path": "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636",
        },
        {
            "label": "Dial Setting",
            "value": str(dial_value),
            "unit": "/100",
            "status": (
                "ok" if dial_value == 0 else ("warn" if dial_value <= 49 else "error")
            ),
            "icon_path": "M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0",
        },
        {
            "label": "Events/min",
            "value": str(events_per_min),
            "unit": "",
            "status": "ok",
            "icon_path": "M13 10V3L4 14h7v7l9-11h-7z",
        },
    ]

    return templates.TemplateResponse(
        request,
        "partials/health_cards.html",
        {
            "user": current_user[0],
            "health_cards": health_cards,
            "dial_value": dial_value,
        },
    )


@router.get("/api/v1/partials/dial", response_class=HTMLResponse)
async def dial_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the dial widget HTML fragment with the current dial value."""
    templates = _get_templates()
    dial_value = await _get_dial(redis)

    return templates.TemplateResponse(
        request,
        "partials/dial_widget.html",
        {"user": current_user[0], "dial_value": dial_value},
    )


@router.get("/api/v1/partials/bans", response_class=HTMLResponse)
async def bans_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the bans table HTML fragment."""
    templates = _get_templates()

    bans: list[dict] = []
    try:
        cursor = 0
        while True:
            cursor, keys = await redis.scan(
                cursor=cursor, match=f"{_BAN_KEY_PREFIX}*", count=100
            )
            for key in keys:
                ip = key[len(_BAN_KEY_PREFIX) :]
                reason = await redis.get(key)
                if reason is None:
                    continue
                ttl_remaining = await redis.ttl(key)
                if ttl_remaining == -2:
                    continue
                if ttl_remaining == -1:
                    ttl_remaining = None
                bans.append(
                    {
                        "ip": ip,
                        "reason": reason,
                        "ttl": ttl_remaining,
                        "banned_at": "—",
                        "banned_by": "system",
                    }
                )
            if cursor == 0:
                break

        # Sort by TTL ascending (soonest-expiring first)
        bans.sort(key=lambda b: b["ttl"] if b["ttl"] is not None else 999999)

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=bans_redis_error | error=%s", exc)

    dial_value = await _get_dial(redis)

    return templates.TemplateResponse(
        request,
        "partials/bans_table.html",
        {"user": current_user[0], "bans": bans, "dial_value": dial_value},
    )


@router.get("/api/v1/partials/audit", response_class=HTMLResponse)
async def audit_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    filter: str = Query("all", description="Filter: all | dial | ban | list | reload"),
) -> HTMLResponse:
    """Return audit log table rows as an HTML fragment."""
    templates = _get_templates()

    events: list[dict] = []
    try:
        # Read 200 raw entries starting at offset (we may need to filter)
        raw_entries = await redis.lrange(_AUDIT_KEY, offset, offset + 199)
        parsed: list[dict] = []
        for raw in raw_entries:
            try:
                parsed.append(json.loads(raw))
            except json.JSONDecodeError:
                continue

        # Apply filter
        if filter != "all":
            parsed = [
                e for e in parsed if filter.lower() in (e.get("action", "").lower())
            ]

        # Limit to 100
        events = parsed[:100]

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=audit_redis_error | error=%s", exc)

    # Normalise events for template: flatten detail dict into top-level fields
    normalised: list[dict] = []
    for e in events:
        detail = e.get("detail", {})
        # Map audit schema to template fields
        normalised.append(
            {
                "timestamp": e.get("timestamp", "—")[:19].replace("T", " "),
                "changed_by": e.get("user", "system"),
                "action": e.get("action", "unknown"),
                "item": detail.get("ip")
                or detail.get("entry")
                or detail.get("list")
                or "",
                "old_value": detail.get("from"),
                "new_value": detail.get("to"),
                "details": detail if detail else None,
            }
        )

    dial_value = await _get_dial(redis)

    return templates.TemplateResponse(
        request,
        "partials/audit_table.html",
        {"user": current_user[0], "events": normalised, "dial_value": dial_value},
    )


@router.get("/api/v1/partials/list-table", response_class=HTMLResponse)
async def list_table_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
    list: str = Query(
        ..., description="List name: ja4_whitelist | ja4_blacklist | ip_allowlist"
    ),
) -> HTMLResponse:
    """Return a list entries table as an HTML fragment."""
    templates = _get_templates()

    mapping = _LIST_REDIS_KEYS.get(list)
    if mapping is None:
        return HTMLResponse(
            content=f'<div class="px-4 py-3 text-sm text-[#f87171]">Unknown list: {list}</div>',
            status_code=400,
        )

    list_type, list_name, redis_key = mapping
    is_ja4 = list_type == "ja4"
    delete_url_prefix = f"/api/v1/lists/{list_type}/{list_name}"

    entries: list[dict] = []
    try:
        raw_entries = await redis.smembers(redis_key)
        entries = [
            {"value": e, "added_at": "—", "added_by": "system"}
            for e in sorted(raw_entries)
        ]
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "partials | event=list_redis_error | list=%s | error=%s", list, exc
        )

    dial_value = await _get_dial(redis)

    return templates.TemplateResponse(
        request,
        "partials/list_table.html",
        {
            "user": current_user[0],
            "list_name": list,
            "entries": entries,
            "is_ja4": is_ja4,
            "delete_url_prefix": delete_url_prefix,
            "dial_value": dial_value,
        },
    )
