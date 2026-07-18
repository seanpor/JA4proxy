import os

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

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..audit_utils import write_audit
from ..auth import _client_ip, require_mfa_verified, require_role
from ..models import EMERGENCY_PRESETS, DialUpdateRequest, DialValue, EmergencyDialRequest, Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dial"])

_DIAL_KEY = "config:dial"
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
    _mfa=Depends(require_mfa_verified),
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
    identity, role = current_user
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

    # JA4PROXY-2026-0040: Signed Dial (Control Plane Integrity)
    # If an integrity key is configured, sign the new dial value.
    from ..proxy_config import get_proxy_config
    cfg = get_proxy_config()
    key_path = (cfg.get("sync") or {}).get("integrity_key_file")
    
    if key_path and os.path.exists(key_path):
        try:
            with open(key_path, "rb") as f:
                key = f.read().strip()
            if key:
                sig = hmac.new(key, str(body.value).encode(), hashlib.sha256).hexdigest()
                await redis.set(_DIAL_KEY + ":sig", sig)
                logger.info("dial | event=signed | key_path=%s", key_path)
        except Exception as e:
            logger.error("dial | event=sign_failed | error=%s", e)

    await redis.set(_DIAL_KEY, str(body.value))

    # Phase 237: schedule auto-revert if requested.
    override_key = "config:dial_override"
    if body.revert_after_hours is not None:
        expires_at = int(datetime.now(timezone.utc).timestamp()) + body.revert_after_hours * 3600
        await redis.set(override_key, json.dumps({
            "original_value": current,
            "override_value": body.value,
            "expires_at_epoch": expires_at,
        }))
        logger.info(
            "dial | event=revert_scheduled | user=%s | from=%s | to=%s | revert_in_hours=%s",
            identity, current, body.value, body.revert_after_hours,
        )
    else:
        await redis.delete(override_key)

    logger.info(
        "dial | event=dial_changed | user=%s | from=%d | to=%d",
        identity,
        current,
        body.value,
    )

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="dial.changed",
        resource_type="dial",
        resource_id=None,
        before_value={"value": current},
        after_value={"value": body.value},
        role=role.value,
    )

    return DialValue(
        value=body.value,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/api/v1/dial/emergency", response_model=DialValue)
async def emergency_dial(
    body: EmergencyDialRequest,
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    _mfa=Depends(require_mfa_verified),
    redis=Depends(get_redis),
) -> DialValue:
    """Set the dial to any value, bypassing the ±10 step limit.

    Requires admin role + MFA. Always schedules an auto-revert (1-4 hours).
    Reuses the Phase 237 config:dial_override key and revert poller.
    """
    identity, role = current_user

    if body.value is not None and body.preset is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either 'value' or 'preset', not both.",
        )
    if body.value is None and body.preset is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide either 'value' or 'preset'.",
        )

    target = body.value if body.value is not None else EMERGENCY_PRESETS[body.preset]
    current = await _get_current_dial(redis)

    from ..proxy_config import get_proxy_config
    cfg = get_proxy_config()
    key_path = (cfg.get("sync") or {}).get("integrity_key_file")

    if key_path and os.path.exists(key_path):
        try:
            with open(key_path, "rb") as f:
                key = f.read().strip()
            if key:
                sig = hmac.new(key, str(target).encode(), hashlib.sha256).hexdigest()
                await redis.set(_DIAL_KEY + ":sig", sig)
        except Exception as e:
            logger.error("dial | event=sign_failed | error=%s", e)

    await redis.set(_DIAL_KEY, str(target))

    expires_at = int(datetime.now(timezone.utc).timestamp()) + body.revert_after_hours * 3600
    override_key = "config:dial_override"
    await redis.set(override_key, json.dumps({
        "original_value": current,
        "override_value": target,
        "expires_at_epoch": expires_at,
    }))

    logger.warning(
        "dial | event=emergency_override | user=%s | from=%d | to=%d | preset=%s | revert_hours=%d",
        identity, current, target, body.preset, body.revert_after_hours,
    )

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="dial.emergency",
        resource_type="dial",
        resource_id=None,
        before_value={"value": current},
        after_value={"value": target, "preset": body.preset, "revert_hours": body.revert_after_hours},
        role=role.value,
    )

    return DialValue(
        value=target,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.delete("/api/v1/dial/revert")
async def cancel_revert(
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    _mfa=Depends(require_mfa_verified),
    redis=Depends(get_redis),
):
    """Cancel a scheduled dial revert by deleting the override record.

    After this, the poller will no longer auto-revert the dial on the next tick.
    """
    override_key = "config:dial_override"
    existed = await redis.delete(override_key)
    if existed:
        logger.info(
            "dial | event=revert_cancelled | user=%s",
            current_user[0],
        )
        await write_audit(
            redis,
            actor_id=current_user[0],
            actor_ip=_client_ip(request),
            action_type="dial.revert_cancelled",
            resource_type="dial",
            resource_id=None,
            before_value=None,
            after_value=None,
            role=current_user[1].value,
        )
    return {"ok": True}
