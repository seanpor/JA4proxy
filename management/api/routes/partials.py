"""HTMX partial (fragment) routes.

These routes return rendered HTML fragments used by HTMX to update parts
of the UI without a full-page reload.

All routes require authentication (JWT cookie). They return HTML responses
rendered from templates in management/templates/partials/.

Routes
------
GET /api/v1/partials/health-cards       — health status card grid
GET /api/v1/partials/dial               — dial widget with current value
GET /api/v1/partials/bans               — active bans table
GET /api/v1/partials/audit              — audit log table rows
GET /api/v1/partials/list-table         — a single list table (whitelist/blacklist/allowlist)
GET /api/v1/partials/situation          — threat posture situation bar
GET /api/v1/partials/intelligence       — analytics intelligence row (Phase 236)
GET /api/v1/partials/intelligence-review — intelligence review page content (Phase 236)
POST /api/v1/intelligence/dismiss/{id}  — dismiss an analytics finding (Phase 236)
POST /api/v1/intelligence/mark-fp/{id}  — mark finding as false positive (Phase 236)
"""

import html
import ipaddress
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..auth import get_current_user
from ..ja4_corpus import browser_label as _corpus_label  # phase-250
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


async def _find_manual_attribution(redis, client_ip: str, event_ts: float) -> Optional[str]:
    """Check the audit log for a manual ban on client_ip near event_ts.

    Returns the operator username if a manual action is found within ±5 seconds,
    None otherwise. Used to add [manual] attribution to live feed events.
    """
    try:
        raw_entries = await redis.lrange("management:audit_log", 0, 199)
        for raw in raw_entries:
            try:
                e = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if e.get("action") not in ("manual_ban", "list_add"):
                continue
            detail = e.get("detail", {})
            if detail.get("ip") != client_ip:
                continue
            try:
                audit_ts = datetime.fromisoformat(e["timestamp"]).timestamp()
                if abs(audit_ts - event_ts) <= 5.0:
                    return e.get("user", "operator")
            except (ValueError, KeyError):
                continue
    except Exception as exc:
        logger.warning(
            "partials | event=attribution_lookup_error | ip=%s | error=%s",
            client_ip, exc,
        )
    return None


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
    evictions = 0

    try:
        await redis.ping()
        redis_status = "ok"

        # Eviction count: query via INFO stats
        try:
            info = await redis.info("stats")
            if info:
                evictions = int(info.get("evicted_keys", 0))
        except Exception as exc:
            logger.warning("partials | event=redis_info_error | error=%s", exc)

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
            "value": f"OK ({evictions} evictions)" if redis_status == "ok" else "DOWN",
            "unit": "",
            "status": "ok" if (redis_status == "ok" and evictions == 0) else ("warn" if evictions < 100 else "error"),
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

    revert_seconds_remaining = 0
    try:
        raw = await redis.get("config:dial_override")
        if raw:
            rec = json.loads(raw)
            revert_seconds_remaining = max(0, int(rec["expires_at_epoch"]) - int(time.time()))
    except Exception:  # noqa: BLE001
        pass

    return templates.TemplateResponse(
        request,
        "partials/dial_widget.html",
        {
            "user": current_user[0],
            "dial_value": dial_value,
            "revert_seconds_remaining": revert_seconds_remaining,
            # The widget must step according to the SERVER's cap, not a
            # hardcoded 10 — that mismatch is what disabled every preset.
            "max_dial_change": _dial_max_change(),
        },
    )


def _dial_max_change() -> int:
    """Expose management.max_dial_change so the UI and API agree."""
    try:
        from ..routes.dial import _max_dial_change

        return _max_dial_change()
    except Exception:  # noqa: BLE001
        return 100


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
        # Escape the user-supplied value before reflecting it into HTML —
        # `list` is an unvalidated query parameter, so interpolating it raw
        # is a reflected-XSS sink (CodeQL py/reflective-xss).
        return HTMLResponse(
            content=(
                '<div class="px-4 py-3 text-sm text-[#f87171]">'
                f"Unknown list: {html.escape(list)}</div>"
            ),
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


@router.get("/api/v1/partials/situation", response_class=HTMLResponse)
async def situation_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the threat posture situation bar as an HTML fragment (polled every 10s).

    Classifies proxy state as one of:
      - PROXY_DOWN — no heartbeat keys in Redis
      - NOMINAL — proxy is up, 0 blocking actions in last 5 min
      - ELEVATED — 1–9 blocking actions in last 5 min
      - ACTIVE — 10+ blocking actions in last 5 min
    """
    templates = _get_templates()

    state = "PROXY_DOWN"
    block_count = 0
    events_per_min_val = 0.0
    top_ip = "—"
    max_risk = 0

    try:
        # ── 1. Detect proxy liveness via heartbeat keys ──────────────
        heartbeat_keys = []
        cursor = 0
        while True:
            cursor, keys = await redis.scan(
                cursor=cursor, match="proxy:heartbeat:*", count=100
            )
            heartbeat_keys.extend(keys)
            if cursor == 0:
                break

        if not heartbeat_keys:
            state = "PROXY_DOWN"
        else:
            # ── 2. Read last 5 min of connection events from stream ──
            five_min_ago = f"{int(time.time() * 1000) - 300_000}-0"
            stream_entries = await redis.xrevrange(
                "events:connection",
                max="+",
                min=five_min_ago,
                count=1000,
            )

            total_events = len(stream_entries)
            block_actions = {"block", "ban", "tarpit"}
            ip_counts: dict[str, int] = {}

            for entry_id, fields in stream_entries:
                raw_event = fields.get("event", "{}")
                try:
                    event_data = json.loads(raw_event)

                    action = event_data.get("event.action", "")
                    if action in block_actions:
                        block_count += 1

                    risk = event_data.get("event.risk_score", 0)
                    if isinstance(risk, (int, float)) and risk > max_risk:
                        max_risk = int(risk)

                    src_ip = event_data.get("source.ip", "")
                    if src_ip:
                        ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    continue

            # Top attacking IP (most events in window)
            if ip_counts:
                top_ip = max(ip_counts, key=ip_counts.get)

            # Events per minute
            events_per_min_val = round(total_events / 5.0, 1)

            # ── 3. Classify ──────────────────────────────────────────
            if block_count == 0:
                state = "NOMINAL"
            elif block_count <= 9:
                state = "ELEVATED"
            else:
                state = "ACTIVE"

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=situation_redis_error | error=%s", exc)
        state = "PROXY_DOWN"

    dial_value = await _get_dial(redis)

    return templates.TemplateResponse(
        request,
        "partials/situation_bar.html",
        {
            "user": current_user[0],
            "state": state,
            "block_count": block_count,
            "events_per_min": events_per_min_val,
            "top_ip": top_ip,
            "max_risk": max_risk,
            "dial_value": dial_value,
        },
    )


# ── Threat Posture ──────────────────────────────────────────────────────────────
# Proxy action vocabulary (verified in internal/security/action_decider.go
# and internal/metrics/metrics.go): allow, flag, rate_limit, tarpit, block, ban

_STREAM_KEY = "events:connection"
_JA4_LABELS_KEY = "config:ja4_labels"

_WINDOW_SECONDS: dict[str, int] = {
    "5m":  5 * 60,
    "15m": 15 * 60,
    "1h":  60 * 60,
    "24h": 24 * 60 * 60,
}
_DEFAULT_WINDOW = "15m"
_VALID_ACTIONS = {"allow", "flag", "rate_limit", "tarpit", "block", "ban"}


def _window_min_id(seconds: int) -> str:
    """Return the Redis stream ID for 'seconds ago'."""
    min_ms = int((time.time() - seconds) * 1000)
    return f"{min_ms}-0"


@router.get("/api/v1/partials/threat-posture", response_class=HTMLResponse)
async def threat_posture_partial(
    request: Request,
    window: str = Query(_DEFAULT_WINDOW, description="Time window: 5m|15m|1h|24h"),
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the Threat Posture row as an HTML fragment.

    Reads the event stream for the selected time window and computes:
    - Top 10 source IPs by maximum risk score
    - Top 10 JA4 fingerprints by connection count
    - Action distribution (counts and percentages)
    - Stream depth (XLEN)

    Polled every 30 seconds by the dashboard (hx-trigger="every 30s").
    """
    templates = _get_templates()

    if window not in _WINDOW_SECONDS:
        window = _DEFAULT_WINDOW
    window_secs = _WINDOW_SECONDS[window]
    min_id = _window_min_id(window_secs)

    ip_scores: dict[str, float] = {}
    ip_actions: dict[str, str] = {}
    ip_counts: dict[str, int] = defaultdict(int)
    ja4_counts: dict[str, int] = defaultdict(int)
    action_dist: dict[str, int] = defaultdict(int)
    stream_depth = 0
    total_events = 0

    try:
        raw = await redis.xrevrange(_STREAM_KEY, max="+", min=min_id, count=5000)

        for _entry_id, fields in raw:
            total_events += 1
            raw_event = fields.get("event")
            if not raw_event:
                continue
            try:
                ev = json.loads(raw_event)
            except (ValueError, TypeError):
                continue
            ip = ev.get("source.ip", "")
            ja4 = ev.get("ja4proxy.fingerprint.ja4", "")
            action = ev.get("event.action", "")
            risk_raw = ev.get("event.risk_score", 0)

            try:
                score = float(risk_raw)
            except (ValueError, TypeError):
                score = 0.0

            if ip:
                ip_counts[ip] += 1
                if score > ip_scores.get(ip, -1):
                    ip_scores[ip] = score
                    ip_actions[ip] = action

            if ja4:
                ja4_counts[ja4] += 1

            if action in _VALID_ACTIONS:
                action_dist[action] += 1

        stream_depth = await redis.xlen(_STREAM_KEY)

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=threat_posture_redis_error | error=%s", exc)

    top_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:10]
    top_ip_rows = [
        {
            "ip": ip,
            "score": round(score, 1),
            "action": ip_actions.get(ip, ""),
            "count": ip_counts.get(ip, 0),
        }
        for ip, score in top_ips
    ]

    top_ja4_raw = sorted(ja4_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    ja4_labels: dict[str, str] = {}
    if top_ja4_raw:
        try:
            for fp, _ in top_ja4_raw:
                label = await redis.hget(_JA4_LABELS_KEY, fp)
                if label:
                    ja4_labels[fp] = label
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "partials | event=ja4_label_lookup_error | error=%s", exc
            )

    top_ja4_rows = [
        {
            "fingerprint": fp,
            # Redis label takes precedence; fall back to corpus label (phase-250).
            "label": ja4_labels.get(fp, "") or _corpus_label(fp),
            "count": count,
        }
        for fp, count in top_ja4_raw
    ]

    DISPLAY_ACTIONS = ["allow", "flag", "rate_limit", "tarpit", "block", "ban"]
    total_actions = sum(action_dist.values()) or 1
    action_pct = {
        act: {
            "count": action_dist.get(act, 0),
            "pct": round(action_dist.get(act, 0) / total_actions * 100, 1),
        }
        for act in DISPLAY_ACTIONS
    }

    stream_warn = stream_depth > 80_000

    user = current_user[0]
    role = current_user[1].value

    return templates.TemplateResponse(
        request,
        "partials/threat_posture.html",
        {
            "user": user,
            "role": role,
            "window": window,
            "windows": list(_WINDOW_SECONDS.keys()),
            "top_ips": top_ip_rows,
            "top_ja4": top_ja4_rows,
            "action_pct": action_pct,
            "stream_depth": stream_depth,
            "stream_warn": stream_warn,
            "total_events": total_events,
        },
    )


# ── Infrastructure ─────────────────────────────────────────────────────────────

_PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")


@router.get("/api/v1/partials/infrastructure", response_class=HTMLResponse)
async def infrastructure_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the Infrastructure row as an HTML fragment.

    Data sources:
    - redis.info("memory") → memory usage
    - redis.info("stats")  → evicted_keys
    - proxy:heartbeat:*    → proxy up/down (deferred to Phase 239)
    - analytics:heartbeat  → analytics up/down
    - tarpit:active_count  → active tarpit connections

    Polled every 30 seconds.
    """
    templates = _get_templates()

    redis_mem_used = "?"
    redis_mem_max = "?"
    redis_mem_pct = 0.0
    redis_evictions = 0
    redis_ok = False

    try:
        mem_info = await redis.info("memory")
        stats_info = await redis.info("stats")
        redis_ok = True

        used_bytes = int(mem_info.get("used_memory", 0))
        max_bytes  = int(mem_info.get("maxmemory", 0))
        redis_mem_used = mem_info.get("used_memory_human", "?")
        redis_mem_max  = mem_info.get("maxmemory_human", "unlimited") if max_bytes else "unlimited"

        if max_bytes > 0:
            redis_mem_pct = round(used_bytes / max_bytes * 100, 1)
        else:
            redis_mem_pct = 0.0

        redis_evictions = int(stats_info.get("evicted_keys", 0))

    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_redis_error | error=%s", exc)

    proxy_up = False
    proxy_unknown = True
    proxy_last_seen = None
    try:
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor=cursor, match="proxy:heartbeat:*", count=50)
            if keys:
                proxy_up = True
                proxy_unknown = False
                ttl = await redis.ttl(keys[0])
                if ttl and ttl > 0:
                    secs_ago = 90 - ttl
                    proxy_last_seen = f"{secs_ago}s ago"
                break
            if cursor == 0:
                proxy_unknown = True
                break
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_proxy_hb_error | error=%s", exc)

    analytics_up = False
    analytics_last_seen = None
    try:
        hb = await redis.get("analytics:heartbeat")
        if hb:
            analytics_up = True
            analytics_last_seen = hb
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_analytics_hb_error | error=%s", exc)

    tarpit_active = None
    try:
        raw_tarpit = await redis.get("tarpit:active_count")
        if raw_tarpit is not None:
            tarpit_active = int(raw_tarpit)
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=infra_tarpit_count_error | error=%s", exc)

    if redis_mem_pct == 0:
        mem_colour = "ok"
    elif redis_mem_pct < 60:
        mem_colour = "ok"
    elif redis_mem_pct < 85:
        mem_colour = "warn"
    else:
        mem_colour = "error"

    user = current_user[0]
    role = current_user[1].value

    return templates.TemplateResponse(
        request,
        "partials/infrastructure.html",
        {
            "user": user,
            "role": role,
            "redis_ok": redis_ok,
            "redis_mem_used": redis_mem_used,
            "redis_mem_max": redis_mem_max,
            "redis_mem_pct": redis_mem_pct,
            "mem_colour": mem_colour,
            "redis_evictions": redis_evictions,
            "proxy_up": proxy_up,
            "proxy_unknown": proxy_unknown,
            "proxy_last_seen": proxy_last_seen,
            "analytics_up": analytics_up,
            "analytics_last_seen": analytics_last_seen,
            "tarpit_active": tarpit_active,
        },
    )


# ── Triage Queue ────────────────────────────────────────────────────────────────


@router.get("/api/v1/partials/triage-queue", response_class=HTMLResponse)
async def triage_queue_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the Triage Queue as an HTML fragment.

    The triage queue surfaces IPs in the 'grey zone': score 35-65, at least
    50 connections in the last 24h, not on any list, score trending upward,
    and not recently dismissed.

    Polled every 60 seconds.
    """
    templates = _get_templates()

    try:
        triage_range_raw = await redis.get("config:triage_range") or "35,65"
        triage_min_count_raw = await redis.get("config:triage_min_count") or "50"
        score_min, score_max = (float(x) for x in triage_range_raw.split(",", 1))
        min_count = int(triage_min_count_raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_config_error | error=%s", exc)
        score_min, score_max, min_count = 35.0, 65.0, 50

    min_id_24h = _window_min_id(24 * 60 * 60)
    ip_scores: dict[str, list[float]] = {}
    ip_counts: dict[str, int] = {}

    try:
        raw = await redis.xrevrange(_STREAM_KEY, max="+", min=min_id_24h, count=10000)
        for _entry_id, fields in raw:
            raw_event = fields.get("event")
            if not raw_event:
                continue
            try:
                ev = json.loads(raw_event)
            except (ValueError, TypeError):
                continue
            ip = ev.get("source.ip", "")
            if not ip:
                continue
            try:
                score = float(ev.get("event.risk_score", 0))
            except (ValueError, TypeError):
                score = 0.0
            ip_scores.setdefault(ip, []).append(score)
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_stream_error | error=%s", exc)

    listed_ips: set[str] = set()
    try:
        for key in ("static:allowlist", "static:blocklist", "static:watchlist"):
            members = await redis.smembers(key)
            listed_ips.update(members)
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor=cursor, match="ban:*", count=100)
            for k in keys:
                listed_ips.add(k[len("ban:"):])
            if cursor == 0:
                break
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_list_error | error=%s", exc)

    candidates = []
    for ip, scores in ip_scores.items():
        count = ip_counts.get(ip, 0)
        max_score = max(scores)
        if max_score < score_min or max_score > score_max:
            continue
        if count < min_count:
            continue
        if ip in listed_ips:
            continue

        if len(scores) >= 4:
            mid = len(scores) // 2
            first_half_avg = sum(scores[:mid]) / mid
            second_half_avg = sum(scores[mid:]) / (len(scores) - mid)
            trend = second_half_avg - first_half_avg
        else:
            trend = 0.0

        if trend < 0:
            continue

        try:
            dismissed = await redis.get(f"dismissed:triage:{ip}")
        except Exception:
            dismissed = None
        if dismissed:
            continue

        if trend > 2:
            trend_label = "↑"
        elif trend > -2:
            trend_label = "→"
        else:
            trend_label = "↓"

        candidates.append({
            "ip": ip,
            "score": round(max_score, 1),
            "count": count,
            "trend": trend_label,
            "trend_value": round(trend, 1),
        })

    candidates.sort(key=lambda x: x["score"], reverse=True)
    candidates = candidates[:25]

    user = current_user[0]
    role = current_user[1].value

    return templates.TemplateResponse(
        request,
        "partials/triage_queue.html",
        {
            "user": user,
            "role": role,
            "candidates": candidates,
            "total_count": len(candidates),
        },
    )


@router.post("/api/v1/triage/dismiss/{ip}", response_class=HTMLResponse)
async def triage_dismiss(
    ip: str,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Dismiss an IP from the triage queue for 4 hours."""
    import re
    if not re.match(r'^[\d\.]{7,15}$|^[\da-fA-F:]{3,39}$', ip):
        from fastapi.responses import HTMLResponse as _H
        return _H(
            content='<div class="text-red-400 text-xs p-2">Invalid IP format</div>',
            status_code=400,
        )

    try:
        four_hours = 4 * 3600
        await redis.set(f"dismissed:triage:{ip}", "1", ex=four_hours)
        logger.info(
            "partials | event=triage_dismiss | ip=%s | user=%s",
            ip, current_user[0]
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("partials | event=triage_dismiss_error | ip=%s | error=%s", ip, exc)

    return HTMLResponse(
        content=f'<!-- dismissed: {html.escape(ip)} -->',
        status_code=200,
    )


# ── Phase 236: Analytics Intelligence ──────────────────────────────────────────

# Phase 236 — schema constant (mirrors output_writer.FINDING_SCHEMA)
# Intentionally duplicated: the two services run in separate containers and
# the management Dockerfile only copies management/. A parity test at
# tests/unit/test_schema_parity.py verifies both copies stay in sync.
_FINDING_SCHEMA = {
    "confidence":       {"type": float,  "required": True,  "min": 0.0,  "max": 1.0},
    "tier":             {"type": str,    "required": True,  "enum": {"HIGH", "MEDIUM", "LOW"}},
    "type":             {"type": str,    "required": True,  "enum": {"beaconing", "campaign", "drift", "slowscan"}},
    "subject_ip":       {"type": str,    "required": False, "max_len": 45},
    "subject_ja4":      {"type": str,    "required": False, "max_len": 64},
    "description":      {"type": str,    "required": True,  "max_len": 500},
    "evidence_count":   {"type": int,    "required": True,  "min": 0},
    "model_version":    {"type": str,    "required": True,  "max_len": 32},
    "model_trained_at": {"type": str,    "required": True,  "max_len": 32},
    "fp_rate_estimate": {"type": float,  "required": True,  "min": 0.0,  "max": 1.0},
    "suggested_action": {"type": str,    "required": True,  "enum": {"monitor", "watchlist", "investigate", "block"}},
    "created_at":       {"type": str,    "required": True,  "max_len": 32},
    "dismissed":        {"type": str,    "required": True,  "enum": {"0", "1"}},
}

_INTELLIGENCE_KEY_PREFIX = "analytics:finding:"
_INTELLIGENCE_INDEX = "analytics:findings:index"


def _validate_finding(raw: dict, finding_id: str) -> Optional[dict]:
    """Validate an analytics finding against the schema.

    Returns a cleaned dict if valid, None if invalid.
    Any validation failure results in silent discard with a WARNING log.
    This is the schema-validation security control described in PHASE_231.md
    (Analytics Trust Boundary section).
    """
    cleaned: dict = {}
    for field, rules in _FINDING_SCHEMA.items():
        value = raw.get(field)
        if value is None:
            if rules.get("required"):
                logger.warning(
                    "partials | event=finding_schema_fail | id=%s | reason=missing_required | field=%s",
                    finding_id, field,
                )
                return None
            cleaned[field] = ""
            continue
        expected_type = rules["type"]
        try:
            coerced = expected_type(value)
        except (ValueError, TypeError):
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=type_error | field=%s | value=%s",
                finding_id, field, value,
            )
            return None
        if "min" in rules and coerced < rules["min"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=below_min | field=%s",
                finding_id, field,
            )
            return None
        if "max" in rules and coerced > rules["max"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=above_max | field=%s",
                finding_id, field,
            )
            return None
        if "enum" in rules and coerced not in rules["enum"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=invalid_enum | field=%s | value=%s",
                finding_id, field, coerced,
            )
            return None
        if "max_len" in rules and len(str(coerced)) > rules["max_len"]:
            logger.warning(
                "partials | event=finding_schema_fail | id=%s | reason=too_long | field=%s",
                finding_id, field,
            )
            return None
        cleaned[field] = coerced
    cleaned["id"] = finding_id
    return cleaned


@router.get("/api/v1/partials/intelligence", response_class=HTMLResponse)
async def intelligence_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the analytics intelligence row as an HTML fragment.

    Filters to HIGH-confidence, non-dismissed findings only.
    All findings are schema-validated before rendering (Decision 5, PHASE_231.md).
    """
    templates = _get_templates()

    high_findings: list[dict] = []
    total_unreviewed = 0

    try:
        raw_ids = await redis.zrevrange(_INTELLIGENCE_INDEX, 0, 49)

        for finding_id in raw_ids:
            if isinstance(finding_id, bytes):
                finding_id = finding_id.decode()

            key = f"{_INTELLIGENCE_KEY_PREFIX}{finding_id}"
            raw = await redis.hgetall(key)
            if not raw:
                continue

            decoded = {
                (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in raw.items()
            }

            finding = _validate_finding(decoded, finding_id)
            if finding is None:
                continue

            if finding.get("dismissed") == "1":
                continue

            total_unreviewed += 1

            if finding.get("tier") == "HIGH":
                high_findings.append(finding)

        total_high = len(high_findings)
        high_findings = high_findings[:5]

    except Exception as exc:
        logger.warning("partials | event=intelligence_redis_error | error=%s", exc)

    dial_value = await _get_dial(redis)

    return templates.TemplateResponse(
        request,
        "partials/intelligence.html",
        {
            "user": current_user[0],
            "findings": high_findings,
            "total_unreviewed": total_unreviewed,
            "total_high": total_high,
            "dial_value": dial_value,
        },
    )


@router.get("/api/v1/partials/intelligence-review", response_class=HTMLResponse)
async def intelligence_review_partial(
    request: Request,
    tier: str = Query("all", description="Filter by tier: all | MEDIUM | LOW"),
    type: str = Query("all", description="Filter by type: all | beaconing | campaign | drift | slowscan"),
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the intelligence review content as an HTML fragment.

    Shows MEDIUM and LOW confidence findings for analyst review.
    Supports tier and type filtering via query parameters.
    """
    templates = _get_templates()
    findings: list[dict] = []

    try:
        raw_ids = await redis.zrevrange(_INTELLIGENCE_INDEX, 0, 199)

        for finding_id in raw_ids:
            if isinstance(finding_id, bytes):
                finding_id = finding_id.decode()

            key = f"{_INTELLIGENCE_KEY_PREFIX}{finding_id}"
            raw = await redis.hgetall(key)
            if not raw:
                continue

            decoded = {
                (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in raw.items()
            }

            finding = _validate_finding(decoded, finding_id)
            if finding is None:
                continue

            if finding.get("dismissed") == "1":
                continue

            if tier != "all" and finding.get("tier") != tier:
                continue
            if type != "all" and finding.get("type") != type:
                continue

            findings.append(finding)

    except Exception as exc:
        logger.warning("partials | event=intelligence_review_redis_error | error=%s", exc)

    return templates.TemplateResponse(
        request,
        "partials/intelligence_review_content.html",
        {
            "user": current_user[0],
            "findings": findings,
            "tier": tier,
            "type": type,
        },
    )


_DISMISS_TEMPLATE = """
<div class="bg-[#1e293b] border border-[#334155] rounded-lg p-3 opacity-50"
     id="finding-{finding_id}">
  <p class="text-xs text-[#64748b]">Finding dismissed.</p>
</div>
"""

_FP_TEMPLATE = """
<div class="bg-[#1e293b] border border-[#334155] rounded-lg p-3 opacity-50"
     id="finding-{finding_id}">
  <p class="text-xs text-[#64748b]">Marked as false positive. Feedback sent to analytics engine.</p>
</div>
"""


@router.post("/api/v1/intelligence/dismiss/{finding_id}", response_class=HTMLResponse)
async def dismiss_finding(
    finding_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Dismiss an analytics finding.

    Sets dismissed=1 on the finding hash. The finding disappears from the
    dashboard on the next 60s poll. The key retains its original TTL so it
    reappears naturally if the pattern continues (after the TTL expires, the
    finding is gone; the analytics engine will write a new one if the pattern
    persists).
    """
    key = f"analytics:finding:{finding_id}"
    try:
        exists = await redis.exists(key)
        if not exists:
            raise HTTPException(status_code=404, detail="Finding not found")
        await redis.hset(key, "dismissed", "1")
        logger.info(
            "partials | event=finding_dismissed | id=%s | user=%s",
            finding_id, current_user[0],
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "partials | event=dismiss_redis_error | id=%s | error=%s",
            finding_id, exc,
        )
        raise HTTPException(status_code=500, detail="Redis error")

    return HTMLResponse(content=_DISMISS_TEMPLATE.format(finding_id=html.escape(finding_id)))


@router.post("/api/v1/intelligence/mark-fp/{finding_id}", response_class=HTMLResponse)
async def mark_finding_fp(
    finding_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Mark an analytics finding as a false positive.

    Sets dismissed=1 and writes a feedback event to the analytics:feedback
    stream. The analytics engine consumes this stream to adjust future
    scoring. This implements the feedback loop described in Decision 5
    of PHASE_231.md.
    """
    key = f"analytics:finding:{finding_id}"
    feedback_stream = "analytics:feedback"

    try:
        exists = await redis.exists(key)
        if not exists:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding_type = await redis.hget(key, "type")
        model_version = await redis.hget(key, "model_version")

        pipe = redis.pipeline()
        pipe.hset(key, "dismissed", "1")
        pipe.xadd(
            feedback_stream,
            {
                "finding_id": finding_id,
                "feedback_type": "false_positive",
                "finding_type": finding_type or "unknown",
                "model_version": model_version or "unknown",
                "reported_by": current_user[0],
                "reported_at": datetime.now(timezone.utc).isoformat(),
            },
            maxlen=10000,
        )
        await pipe.execute()
        logger.info(
            "partials | event=finding_marked_fp | id=%s | user=%s",
            finding_id, current_user[0],
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(
            "partials | event=mark_fp_redis_error | id=%s | error=%s",
            finding_id, exc,
        )
        raise HTTPException(status_code=500, detail="Redis error")

    return HTMLResponse(content=_FP_TEMPLATE.format(finding_id=html.escape(finding_id)))


# ── Phase 247 / Phase 250: Attack IP Table partial ───────────────────────────

@router.get("/api/v1/partials/attack-top", response_class=HTMLResponse)
@router.get("/api/v1/partials/attack-table", response_class=HTMLResponse)
async def attack_table_partial(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the top-attackers table as an HTML fragment (polled every 5s).

    Registered under both /attack-top (Phase 250 template) and /attack-table
    (Phase 247 compatibility). Uses Phase 250's ECS event field format.
    """
    import json as _json

    from .attack import top_attackers  # local import to avoid circular dep

    templates = _get_templates()
    result = await top_attackers(redis=redis, _user=current_user)
    data = _json.loads(result.body)
    return templates.TemplateResponse(
        request,
        "partials/attack_table.html",
        {"attackers": data.get("attackers", []), "role": current_user[1].value},
    )


# ── Phase 250: Attack Fingerprint Table partial ───────────────────────────────

@router.get("/api/v1/partials/attack-fingerprint-table", response_class=HTMLResponse)
async def attack_fingerprint_table_partial(
    request: Request,
    attack_mode: bool = Query(False),
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Return the attack fingerprint table as an HTML fragment for HTMX polling.

    Delegates to the JSON endpoint in attack.py and renders the result as HTML.
    """
    import json as _json

    from .attack import top_fingerprints  # local import to avoid circular dep

    templates = _get_templates()
    result = await top_fingerprints(attack_mode=attack_mode, _user=current_user, redis=redis)
    data = _json.loads(result.body)
    return templates.TemplateResponse(
        request,
        "partials/attack_fingerprint_table.html",
        {"data": data, "attack_mode": attack_mode},
    )
