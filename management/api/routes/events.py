"""SSE events endpoint — GET /api/v1/events.

Streams events from the ``ja4proxy:events`` Redis Stream to connected
clients using Server-Sent Events (SSE).

Each event read from the stream is forwarded as a SSE ``data:`` line
containing the JSON payload.

Implementation notes
--------------------
- Uses XREAD with BLOCK=1000ms to avoid busy-waiting.
- Tracks the last stream ID seen so reconnecting clients don't get
  duplicate events (they start from the current tip).
- Handles client disconnect gracefully via asyncio.CancelledError.
- Multiple concurrent clients are supported (each has its own cursor).
"""

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])

_STREAM_KEY = "ja4proxy:events"
_BLOCK_MS = 1000  # How long to wait for new events before looping
_HEARTBEAT_INTERVAL = 15  # seconds between keep-alive comments


async def _event_generator(request: Request, redis):
    """Async generator that yields SSE events from the Redis Stream.

    Starts from the latest entry (``$``) so new connections only receive
    new events, not the full historical backlog.
    """
    last_id = "$"

    while True:
        # Check if the client has disconnected
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
            logger.debug("events | event=stream_cancelled")
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("events | event=stream_error | error=%s", exc)
            await asyncio.sleep(1)
            continue

        if not results:
            # No new events — yield a keep-alive comment to prevent timeout
            yield {"comment": "keepalive"}
            continue

        for _stream_key, messages in results:
            for msg_id, fields in messages:
                last_id = msg_id
                data_str = fields.get("data", "{}")
                try:
                    # Validate it's JSON before forwarding
                    json.loads(data_str)
                except json.JSONDecodeError:
                    data_str = json.dumps({"raw": data_str})

                yield {"data": data_str, "id": msg_id}


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
        # Non-SSE client (e.g. test probe, health check) — return a plain JSON
        # acknowledgement rather than an infinite stream.
        return JSONResponse(
            content={"stream": "ja4proxy:events", "status": "available"},
            status_code=200,
        )

    return EventSourceResponse(
        _event_generator(request, redis),
        media_type="text/event-stream",
    )
