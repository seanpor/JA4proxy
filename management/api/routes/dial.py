"""Dial management endpoints.

GET /api/v1/dial   — returns the current dial value (0-100).
PUT /api/v1/dial   — updates the dial value.

Constraints on PUT
------------------
- Value must be 0-100 (validated by Pydantic).
- Change per request must not exceed ±10 (prevents accidental big jumps).
- Every change is written to management:audit_log.

Redis key: config:dial (String, value is str(int))
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..auth import require_role
from ..models import DialUpdateRequest, DialValue, Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dial"])

_DIAL_KEY = "config:dial"
_AUDIT_KEY = "management:audit_log"
_MAX_DIAL_CHANGE = 10


async def _get_current_dial(redis) -> int:
    """Read the current dial value from Redis (default 0)."""
    raw: Optional[str] = await redis.get(_DIAL_KEY)
    if raw is None:
        return 0
    try:
        return int(raw)
    except ValueError:
        logger.warning("dial | event=invalid_value | raw=%r | defaulting_to=0", raw)
        return 0


async def _write_audit(
    redis,
    action: str,
    user: str,
    detail: dict,
    client_ip: str,
) -> None:
    """Write an audit log entry (LPUSH + LTRIM to 1000 entries)."""
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
    """Extract the real client IP, honouring X-Forwarded-For if present."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@router.get("/api/v1/dial", response_model=DialValue)
async def get_dial(
    request: Request,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> DialValue:
    """Return the current dial value."""
    value = await _get_current_dial(redis)
    return DialValue(value=value, updated_at=None)


@router.patch("/api/v1/dial", response_model=DialValue)
@router.put("/api/v1/dial", response_model=DialValue)
async def update_dial(
    body: DialUpdateRequest,
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    redis=Depends(get_redis),
) -> DialValue:
    """Update the dial value.

    Enforces a maximum change of ±10 per request to prevent accidental
    jumps in blocking aggression.

    Args:
        body: New dial value (0-100).

    Raises:
        HTTPException(400): If the requested change exceeds ±10.
    """
    identity = current_user[0]
    current = await _get_current_dial(redis)
    delta = abs(body.value - current)

    if delta > _MAX_DIAL_CHANGE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Dial change of {delta} exceeds the maximum of {_MAX_DIAL_CHANGE} "
                f"per request. Current value: {current}, requested: {body.value}. "
                f"Make multiple smaller changes."
            ),
        )

    await redis.set(_DIAL_KEY, str(body.value))
    logger.info(
        "dial | event=dial_changed | user=%s | from=%d | to=%d",
        identity,
        current,
        body.value,
    )

    await _write_audit(
        redis,
        action="dial_changed",
        user=identity,
        detail={"from": current, "to": body.value},
        client_ip=_client_ip(request),
    )

    return DialValue(
        value=body.value,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
