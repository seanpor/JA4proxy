"""SSE events endpoint — GET /api/v1/events.

Streams connection events from ``events:connection`` (the stream the Go
proxy writes to) and yields enriched HTML table rows with clickable IP
and JA4 links to the drill-down pages.

Each Redis stream entry has one field ``event`` containing a JSON string
of flat ECS-dotted keys (written by the Go proxy at ``cmd/ja4pd/main.go``).

Implementation notes
--------------------
- Uses XREAD with BLOCK=1000ms to avoid busy-waiting.
- Tracks the last stream ID seen so reconnecting clients don't get
  duplicate events (they start from the current tip).
- Handles client disconnect gracefully via asyncio.CancelledError.
- Multiple concurrent clients are supported (each has its own cursor).
"""

import asyncio
import html
import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])

_STREAM_KEY = "events:connection"
# How much history to paint before tailing. Enough to fill the visible table
# (the client trims to 50 rows) without making the first byte slow.
_BACKFILL_COUNT = 25
_BLOCK_MS = 1000
_HEARTBEAT_INTERVAL = 15


def _build_row(parsed: dict, entry_id: str) -> str:
    """Build an HTML table row with clickable IP and JA4 links."""
    ts_raw = parsed.get("@timestamp", "")
    ts_display = entry_id[:8] if entry_id else ""
    if ts_raw:
        try:
            dt = datetime.fromisoformat(ts_raw)
            ts_display = dt.strftime("%H:%M:%S")
        except (ValueError, TypeError):
            ts_display = ts_raw

    ip = parsed.get("source.ip", "")
    ja4 = parsed.get("ja4proxy.fingerprint.ja4", "")
    action = parsed.get("event.action", "allow")
    score = parsed.get("event.risk_score", 0)

    # phase-828b: the event carries ~20 fields and this row rendered five. The
    # most costly omission was bypass_reason: a connection blocked by an
    # explicit list entry and one blocked by its score looked IDENTICAL here
    # ("block / 100"), despite calling for opposite responses -- "who added that
    # list entry" versus "which signals fired". Country and ASN organisation
    # were likewise already resolved on every event and thrown away, so the feed
    # could not distinguish Vodafone Ireland from a host in another hemisphere.
    bypass_reason = parsed.get("ja4proxy.bypass_reason") or ""
    country = parsed.get("client.geo.country_iso") or ""
    asn_org = parsed.get("client.as.organization.name") or ""
    origin = " ".join(x for x in (country, asn_org) if x)

    if action in ("block", "ban"):
        action_class = "bg-red-900/50 text-red-300"
    elif action in ("flag", "rate_limit"):
        action_class = "bg-yellow-900/50 text-yellow-300"
    elif action == "allow":
        action_class = "bg-green-900/50 text-green-300"
    elif action == "tarpit":
        action_class = "bg-purple-900/50 text-purple-300"
    else:
        action_class = "bg-slate-700/50 text-slate-300"

    block_btn = ""
    if ja4:
        block_btn += (
            f"<button "
            f"hx-post=\"/api/v1/lists/ja4/blacklist/{ja4}\" "
            f"hx-swap=\"outerHTML\" "
            f"hx-confirm=\"Block fingerprint {ja4[:20]}…?\" "
            f"class=\"px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-900/40 text-red-300 "
            f"hover:bg-red-800/60 transition-colors\" "
            f"title=\"Blacklist this JA4 fingerprint\">Block</button> "
        )
    if ip:
        block_btn += (
            f"<button "
            f"hx-post=\"/api/v1/bans\" "
            f"hx-vals='{{\"ip\": \"{ip}\", \"reason\": \"Banned from live feed\", \"ttl_seconds\": 3600}}' "
            f"hx-swap=\"outerHTML\" "
            f"hx-confirm=\"Ban IP {ip} for 1 hour?\" "
            f"class=\"px-1.5 py-0.5 rounded text-[10px] font-medium bg-orange-900/40 text-orange-300 "
            f"hover:bg-orange-800/60 transition-colors\" "
            f"title=\"Ban this IP for 1 hour\">Ban</button>"
        )

    return (
        f"<tr class=\"border-b border-slate-700/50 hover:bg-slate-700/30 transition-colors\">"
        f"<td class=\"py-2 px-3 text-xs text-slate-400\">{ts_display}</td>"
        f"<td class=\"py-2 px-3\"><a href=\"/ip/{ip}\" "
        f"class=\"text-blue-400 hover:underline font-mono text-xs\">{ip}</a></td>"
        f"<td class=\"py-2 px-3 hidden sm:table-cell\"><a href=\"/fingerprint/{ja4}\" "
        f"class=\"text-blue-400 hover:underline font-mono text-xs truncate max-w-[200px] inline-block\">{ja4}</a></td>"
        f"<td class=\"py-2 px-3 hidden lg:table-cell text-xs text-slate-400 truncate max-w-[180px]\" "
        f"title=\"{html.escape(origin, quote=True)}\">{html.escape(origin) or '&mdash;'}</td>"
        f"<td class=\"py-2 px-3\">"
        f"<span class=\"px-1.5 py-0.5 rounded text-xs font-medium {action_class}\">{action}</span>"
        + (
            f"<span class=\"block text-[10px] text-slate-500 font-mono\" "
            f"title=\"Decided by an explicit rule, not by score\">"
            f"{html.escape(bypass_reason)}</span>"
            if bypass_reason
            else ""
        )
        + "</td>"
        f"<td class=\"py-2 px-3 text-xs text-slate-300 text-right\">{score}</td>"
        f"<td class=\"py-2 px-3 text-right whitespace-nowrap\">{block_btn}</td>"
        f"</tr>"
    )


async def _event_generator(request: Request, redis):
    """Async generator that yields SSE events from the Redis Stream.

    Each event is a JSON string of flat ECS-dotted keys. We parse it,
    extract the fields needed for the live feed table, and yield an
    enriched HTML row with clickable IP/JA4 links.

    Starts by replaying the most recent ``_BACKFILL_COUNT`` events.

    phase-828: it previously started at ``"$"`` -- "only what arrives after you
    connect". On a stack with 54,000 events in the stream but no traffic in
    flight, the operator opened the dashboard and saw five pulsing grey
    placeholder bars and nothing else, indefinitely. The feed looked broken and
    the history it was sitting on was unreachable. Live-only is the right
    default for a tail; it is the wrong default for the first paint.
    """
    last_id = "$"

    # Replay oldest-to-newest. The client swaps with hx-swap="afterbegin", so
    # each row is prepended -- feeding them chronologically leaves the newest
    # at the top, matching the order live events then arrive in.
    try:
        recent = await redis.xrevrange(_STREAM_KEY, "+", "-", count=_BACKFILL_COUNT)
    except Exception as exc:  # noqa: BLE001 — backfill must never break the tail
        logger.warning("events | event=backfill_failed | error=%s", exc)
        recent = []

    for msg_id, fields in reversed(recent or []):
        raw = fields.get("event", "{}")
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        yield {"data": _build_row(parsed, msg_id), "id": msg_id}
        last_id = msg_id

    # Tell the client the first paint is done, so it can clear the placeholder
    # rows and -- if the backfill was empty -- say so in words rather than
    # leaving skeletons up forever.
    yield {"event": "backfill-complete", "data": str(len(recent or []))}

    while True:
        if await request.is_disconnected():
            logger.debug("events | event=client_disconnected")
            break

        try:
            results = await redis.xread(
                {_STREAM_KEY: last_id},
                block=_BLOCK_MS,
                count=10,
            )
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("events | event=stream_error | error=%s", exc)
            await asyncio.sleep(1)
            continue

        if not results:
            yield {"comment": "keepalive"}
            continue

        for _stream_entry, messages in results:
            for msg_id, fields in messages:
                last_id = msg_id
                raw = fields.get("event", "{}")
                try:
                    parsed = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    parsed = {}

                row_html = _build_row(parsed, msg_id)
                yield {"data": row_html, "id": msg_id}


@router.get("/api/v1/events")
async def stream_events(
    request: Request,
    current_user=Depends(require_role(Role.analyst)),
    redis=Depends(get_redis),
):
    """Stream live connection events as Server-Sent Events.

    Clients should connect with ``Accept: text/event-stream``.
    The stream never ends — clients must disconnect when done.

    When the client requests ``Accept: application/json`` (e.g. in tests or
    when probing the endpoint), a non-streaming JSON acknowledgement is returned
    instead of an infinite SSE stream.
    """
    logger.info("events | event=client_connected | user=%s", current_user[0])

    accept = request.headers.get("Accept", "")
    if "text/event-stream" not in accept:
        return JSONResponse(
            content={"stream": "events:connection", "status": "available"},
            status_code=200,
        )

    return EventSourceResponse(
        _event_generator(request, redis),
        media_type="text/event-stream",
    )
