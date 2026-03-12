"""Blocking dial control router.

Endpoints:
  GET  /api/v1/dial
  PUT  /api/v1/dial         — validates max 10 changes/hour, requires acknowledged
  POST /api/v1/dial/acknowledge

Redis keys:
  dial:current                       — string integer 0–100
  dial:blocking_acknowledged         — "true" once secops has acknowledged blocking risk
  mgmt:dial_changes:{YYYYMMDDHH}     — INCR counter, TTL 3600s

Safety rules:
  1. dial > 0 requires blocking_acknowledged == "true"
  2. Max 10 changes per hour (rate-limited per UTC hour)
  3. Setting dial = 0 always allowed (emergency downgrade)
"""

import json
import logging
import time
from datetime import datetime, timezone

import redis.exceptions
from fastapi import APIRouter, Depends, HTTPException, Request

from management.auth import require_api_key
from management.metrics import mgmt_actions_total, mgmt_redis_errors_total
from management.models import DialAcknowledgeRequest, DialResponse, DialUpdateRequest
from management.redis_helpers import publish_invalidation, write_audit_log

logger = logging.getLogger("management.routers.dial")
router = APIRouter()

_MAX_CHANGES_PER_HOUR = 10


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _hour_key() -> str:
    """Return the current UTC hour key for rate limiting."""
    now = datetime.now(timezone.utc)
    return f"mgmt:dial_changes:{now.strftime('%Y%m%d%H')}"


@router.get("/dial", response_model=DialResponse)
async def get_dial(
    request: Request,
    _key: str = Depends(require_api_key),
) -> DialResponse:
    """Return the current dial value and acknowledge state."""
    r = request.app.state.redis
    try:
        raw = await r.get("dial:current")
        ack_raw = await r.get("dial:blocking_acknowledged")
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="get_dial").inc()
        logger.error("management | event=redis_error | op=get_dial | error=%s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        mgmt_redis_errors_total.labels(operation="get_dial").inc()
        raise HTTPException(status_code=503, detail="Service unavailable")

    dial_value = int(raw) if raw is not None else 0
    acknowledged = ack_raw == "true" if ack_raw else False

    return DialResponse(dial=dial_value, blocking_acknowledged=acknowledged)


@router.put("/dial", response_model=DialResponse)
async def update_dial(
    request: Request,
    payload: DialUpdateRequest,
    _key: str = Depends(require_api_key),
) -> DialResponse:
    """Update the dial value.

    Safety rules:
    - dial > 0 requires blocking_acknowledged
    - Max 10 changes per UTC hour
    - dial = 0 is always allowed (emergency monitor mode)
    """
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        ack_raw = await r.get("dial:blocking_acknowledged")
        acknowledged = ack_raw == "true" if ack_raw else False

        # Rule 1: dial > 0 requires acknowledgment
        if payload.dial > 0 and not acknowledged:
            raise HTTPException(
                status_code=422,
                detail=(
                    "blocking_acknowledged must be set before raising the dial above 0. "
                    "Use POST /api/v1/dial/acknowledge first."
                ),
            )

        # Rule 2: rate limit (skip for dial=0 emergency downgrade)
        if payload.dial > 0:
            hour_key = _hour_key()
            count = await r.incr(hour_key)
            if count == 1:
                await r.expire(hour_key, 3600)
            if count > _MAX_CHANGES_PER_HOUR:
                # Undo the increment
                await r.incr(hour_key)  # actually decr
                raise HTTPException(
                    status_code=429,
                    detail=(
                        f"Dial change rate limit exceeded: max {_MAX_CHANGES_PER_HOUR} "
                        "changes per hour."
                    ),
                    headers={"Retry-After": "3600"},
                )

        old_raw = await r.get("dial:current")
        old_value = int(old_raw) if old_raw is not None else 0

        await r.set("dial:current", str(payload.dial))
        await publish_invalidation(r,{
            "event": "dial_change",
            "value": payload.dial,
            "old": old_value,
        })
        await write_audit_log(
            r,
            event_type="dial_changed",
            actor_ip=actor_ip,
            detail={
                "old": old_value,
                "new": payload.dial,
                "reason": payload.reason,
            },
        )
    except HTTPException:
        raise
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="update_dial").inc()
        logger.error("management | event=redis_error | op=update_dial | error=%s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        mgmt_redis_errors_total.labels(operation="update_dial").inc()
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="dial_change").inc()
    logger.info(
        "management | event=dial_changed | actor_ip=%s | new=%d | reason=%s",
        actor_ip,
        payload.dial,
        payload.reason,
    )
    return DialResponse(dial=payload.dial, blocking_acknowledged=acknowledged)


@router.post("/dial/acknowledge")
async def acknowledge_dial(
    request: Request,
    payload: DialAcknowledgeRequest,
    _key: str = Depends(require_api_key),
) -> dict:
    """Acknowledge that raising the dial will cause blocking.

    Must be called before setting dial > 0.
    """
    r = request.app.state.redis
    actor_ip = _get_client_ip(request)

    try:
        value = "true" if payload.acknowledged else "false"
        await r.set("dial:blocking_acknowledged", value)
        await write_audit_log(
            r,
            event_type="dial_acknowledged",
            actor_ip=actor_ip,
            detail={"acknowledged": payload.acknowledged},
        )
    except redis.exceptions.RedisError as exc:
        mgmt_redis_errors_total.labels(operation="acknowledge_dial").inc()
        logger.error("management | event=redis_error | op=acknowledge | error=%s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")
    except Exception as exc:
        mgmt_redis_errors_total.labels(operation="acknowledge_dial").inc()
        raise HTTPException(status_code=503, detail="Service unavailable")

    mgmt_actions_total.labels(action="dial_acknowledge").inc()
    return {"acknowledged": payload.acknowledged}


@router.get("/dial/counterfactual")
async def get_counterfactual_impact(
    request: Request,
    dial: int,
    _key: str = Depends(require_api_key),
) -> dict:
    """Estimate what percentage of recent traffic would be blocked at a given dial value."""
    r = request.app.state.redis

    # Validate dial range
    if not 0 <= dial <= 100:
        raise HTTPException(status_code=422, detail="Dial must be between 0 and 100")

    # Get recent events from the stream
    try:
        events = await r.xrevrange("ja4proxy:events", count=1000)
    except redis.exceptions.RedisError:
        mgmt_redis_errors_total.labels(operation="dial_counterfactual").inc()
        raise HTTPException(status_code=503, detail="Redis unavailable")

    if not events:
        return {
            "dial": dial,
            "estimated_block_pct": None,
            "reason": "insufficient_data",
            "sample_size": 0,
            "window": "last_1000_events",
        }

    # Get current thresholds
    thresholds = await r.hgetall("config:thresholds")
    block_threshold = int(thresholds.get("block", "70"))
    effective_threshold = block_threshold * (dial / 100.0)

    # Count how many connection events would be blocked at this dial
    blocked_count = 0
    total_events = 0

    for _event_id, fields in events:
        try:
            raw = fields.get("data") or fields.get(b"data", b"")
            event_data = json.loads(raw)

            if event_data.get("type") == "connection":
                score = event_data.get("score", 0)
                total_events += 1
                if score >= effective_threshold:
                    blocked_count += 1
        except (json.JSONDecodeError, TypeError, AttributeError):
            continue

    if total_events < 50:
        return {
            "dial": dial,
            "estimated_block_pct": None,
            "reason": "insufficient_data",
            "sample_size": total_events,
            "window": "last_1000_events",
        }

    block_pct = (blocked_count / total_events) * 100

    return {
        "dial": dial,
        "estimated_block_pct": round(block_pct, 2),
        "sample_size": total_events,
        "window": "last_1000_events",
        "blocked_count": blocked_count,
        "effective_threshold": effective_threshold,
    }
