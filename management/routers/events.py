"""SSE Events router for JA4Proxy Management UI."""

import asyncio
import json
import time
from typing import AsyncGenerator, Optional

import redis.asyncio as aioredis
import redis.exceptions as redis_exc
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from prometheus_client import Counter, Gauge
from sse_starlette.sse import EventSourceResponse

from ..server import authenticate, _get_client_ip

router = APIRouter()

# Metrics
mgmt_sse_subscribers_active = Gauge(
    "ja4proxy_mgmt_sse_subscribers_active",
    "Number of active SSE subscribers"
)
mgmt_redis_errors_total = Counter(
    "ja4proxy_mgmt_redis_errors_total",
    "Total Redis errors in management UI",
    ["operation"]
)

_MAX_SSE_SUBSCRIBERS = 50
_HEARTBEAT_INTERVAL = 15.0
_STREAM_KEY = "ja4proxy:events"


async def _event_generator(
    request: Request,
    filter_action: Optional[str],
    filter_country: Optional[str],
    filter_asn_type: Optional[str],
    min_score: int,
) -> AsyncGenerator[dict, None]:
    """Read from Redis Stream, filter, and yield SSE events."""
    r = request.app.state.redis
    last_id = "$"  # Only new events
    last_heartbeat = time.monotonic()

    try:
        while True:
            if await request.is_disconnected():
                break

            # Heartbeat
            now = time.monotonic()
            if now - last_heartbeat >= _HEARTBEAT_INTERVAL:
                yield {"event": "heartbeat", "data": json.dumps({
                    "type": "heartbeat",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })}
                last_heartbeat = now

            try:
                results = await r.xread(
                    {_STREAM_KEY: last_id}, count=100, block=1000
                )
            except redis_exc.RedisError:
                mgmt_redis_errors_total.labels(operation="sse_xread").inc()
                await asyncio.sleep(1.0)
                continue

            if not results:
                continue

            for _stream, messages in results:
                for msg_id, fields in messages:
                    last_id = msg_id
                    try:
                        raw = fields.get("data") or fields.get(b"data", b"")
                        event = json.loads(raw)
                    except (json.JSONDecodeError, TypeError):
                        continue

                    # Apply filters
                    if filter_action and event.get("action") != filter_action:
                        continue
                    if filter_country and event.get("country") != filter_country:
                        continue
                    if filter_asn_type and event.get("asn_type") != filter_asn_type:
                        continue
                    if event.get("score", 0) < min_score:
                        continue

                    yield {"event": "message", "data": json.dumps(event)}
    finally:
        mgmt_sse_subscribers_active.dec()


@router.get("/events")
async def live_feed(
    request: Request,
    filter_action: Optional[str] = None,
    filter_country: Optional[str] = None,
    filter_asn_type: Optional[str] = None,
    min_score: int = 0,
    authorization: Optional[str] = Header(None)
) -> EventSourceResponse:
    """Stream live connection events via SSE."""
    await authenticate(request, authorization)
    
    # Subscriber cap
    current = mgmt_sse_subscribers_active._value.get()
    if current >= _MAX_SSE_SUBSCRIBERS:
        raise HTTPException(status_code=429, detail="Too many SSE subscribers")

    mgmt_sse_subscribers_active.inc()
    
    return EventSourceResponse(
        _event_generator(request, filter_action, filter_country, filter_asn_type, min_score),
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/events/recent")
async def get_recent_events(
    request: Request,
    limit: int = 100,
    authorization: Optional[str] = Header(None)
) -> dict:
    """Get recent events from the stream."""
    await authenticate(request, authorization)
    
    r = request.app.state.redis
    try:
        events = await r.xrevrange(_STREAM_KEY, count=limit)
        result = []
        for event_id, fields in events:
            try:
                raw = fields.get("data") or fields.get(b"data", b"")
                event_data = json.loads(raw)
                result.append(event_data)
            except (json.JSONDecodeError, TypeError):
                continue
        
        return {"events": result}
    except redis_exc.RedisError:
        mgmt_redis_errors_total.labels(operation="sse_xrevrange").inc()
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve recent events"
        )
