"""Attack Mode API endpoints.

POST   /api/v1/attack-mode  — activate attack mode (raises dial to 75, 4h auto-revert)
DELETE /api/v1/attack-mode  — cancel attack mode (restores original dial)
GET    /api/v1/attack-mode  — check current attack mode status

Attack Mode is a coordinated defensive posture for use during active attacks.
It raises the dial to 75 with a 4-hour auto-revert so the operator cannot
accidentally leave high-aggression blocking in place permanently.

Redis keys
----------
attack_mode:active  — String (JSON), TTL 14400s (4 hours)
    {"original_dial": int, "activated_at": str (ISO8601)}
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request

from ..audit_utils import write_audit
from ..auth import _client_ip, require_mfa_verified, require_role
from ..models import AttackModeStatus, Role
from ..redis_client import get_redis
from .dial import _DIAL_KEY, _get_current_dial

logger = logging.getLogger(__name__)

router = APIRouter(tags=["attack-mode"])

_ATTACK_MODE_KEY = "attack_mode:active"
_ATTACK_DIAL_TARGET = 75
_ATTACK_TTL_SECONDS = 14400  # 4 hours
_DIAL_OVERRIDE_KEY = "config:dial_override"


@router.post("/api/v1/attack-mode", response_model=AttackModeStatus)
async def activate_attack_mode(
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    _mfa=Depends(require_mfa_verified),
    redis=Depends(get_redis),
) -> AttackModeStatus:
    """Activate Attack Mode: raise dial to 75 with 4-hour auto-revert.

    Idempotent: if already active, returns current state without resetting TTL.
    """
    identity, role = current_user

    # Idempotent: return current state if already active.
    existing = await redis.get(_ATTACK_MODE_KEY)
    if existing:
        try:
            data = json.loads(existing)
        except (json.JSONDecodeError, TypeError):
            data = {}
        ttl = await redis.ttl(_ATTACK_MODE_KEY)
        reverts_at = (
            (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
            if ttl > 0
            else None
        )
        return AttackModeStatus(
            active=True,
            dial=_ATTACK_DIAL_TARGET,
            original_dial=data.get("original_dial"),
            reverts_at=reverts_at,
            message="Attack Mode already active.",
        )

    original_dial = await _get_current_dial(redis)
    activated_at = datetime.now(timezone.utc).isoformat()

    # Write attack_mode:active key.
    await redis.set(
        _ATTACK_MODE_KEY,
        json.dumps({"original_dial": original_dial, "activated_at": activated_at}),
        ex=_ATTACK_TTL_SECONDS,
    )

    # Raise the dial directly (same pattern as dial.py — no HTTP self-call).
    await redis.set(_DIAL_KEY, str(_ATTACK_DIAL_TARGET))
    expires_epoch = int(datetime.now(timezone.utc).timestamp()) + _ATTACK_TTL_SECONDS
    await redis.set(
        _DIAL_OVERRIDE_KEY,
        json.dumps({
            "original_value": original_dial,
            "override_value": _ATTACK_DIAL_TARGET,
            "expires_at_epoch": expires_epoch,
        }),
    )

    reverts_at = (
        datetime.now(timezone.utc) + timedelta(seconds=_ATTACK_TTL_SECONDS)
    ).isoformat()

    logger.warning(
        "attack_mode | event=activated | user=%s | original_dial=%d | target_dial=%d",
        identity,
        original_dial,
        _ATTACK_DIAL_TARGET,
    )

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="attack_mode.activated",
        resource_type="attack_mode",
        before_value={"dial": original_dial},
        after_value={"dial": _ATTACK_DIAL_TARGET, "revert_hours": 4},
        role=role.value,
    )

    return AttackModeStatus(
        active=True,
        dial=_ATTACK_DIAL_TARGET,
        original_dial=original_dial,
        reverts_at=reverts_at,
        message=f"Attack Mode active. Dial raised to {_ATTACK_DIAL_TARGET}. Auto-reverts in 4 hours.",
    )


@router.delete("/api/v1/attack-mode", response_model=AttackModeStatus)
async def deactivate_attack_mode(
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    _mfa=Depends(require_mfa_verified),
    redis=Depends(get_redis),
) -> AttackModeStatus:
    """Cancel Attack Mode: restore dial to the value it had before activation."""
    identity, role = current_user

    existing = await redis.get(_ATTACK_MODE_KEY)
    if not existing:
        return AttackModeStatus(
            active=False,
            message="Attack Mode was not active.",
        )

    try:
        data = json.loads(existing)
    except (json.JSONDecodeError, TypeError):
        data = {}

    original_dial = data.get("original_dial", 0)

    # Delete the attack mode key first so the state is consistent.
    await redis.delete(_ATTACK_MODE_KEY)

    # Restore the dial.
    await redis.set(_DIAL_KEY, str(original_dial))
    await redis.delete(_DIAL_OVERRIDE_KEY)

    logger.info(
        "attack_mode | event=deactivated | user=%s | restored_dial=%d",
        identity,
        original_dial,
    )

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="attack_mode.deactivated",
        resource_type="attack_mode",
        before_value={"dial": _ATTACK_DIAL_TARGET},
        after_value={"dial": original_dial},
        role=role.value,
    )

    return AttackModeStatus(
        active=False,
        dial=original_dial,
        message=f"Attack Mode cancelled. Dial restored to {original_dial}.",
    )


@router.get("/api/v1/attack-mode", response_model=AttackModeStatus)
async def get_attack_mode_status(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> AttackModeStatus:
    """Return current attack mode state."""
    raw = await redis.get(_ATTACK_MODE_KEY)
    if not raw:
        return AttackModeStatus(active=False)

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        data = {}

    ttl = await redis.ttl(_ATTACK_MODE_KEY)
    reverts_at: Optional[str] = None
    if ttl > 0:
        reverts_at = (
            datetime.now(timezone.utc) + timedelta(seconds=ttl)
        ).isoformat()

    return AttackModeStatus(
        active=True,
        dial=_ATTACK_DIAL_TARGET,
        original_dial=data.get("original_dial"),
        reverts_at=reverts_at,
    )


@router.get("/api/v1/partials/attack-mode-indicator")
async def attack_mode_indicator(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> str:
    """Return a red dot HTML span when attack mode is active, empty string otherwise.

    Polled by the sidebar nav every 10s via HTMX to show/hide the indicator.
    """
    from fastapi.responses import HTMLResponse

    raw = await redis.get(_ATTACK_MODE_KEY)
    if raw:
        return HTMLResponse(
            '<span class="w-2 h-2 rounded-full bg-red-500 ml-1 inline-block" '
            'title="Attack Mode active"></span>'
        )
    return HTMLResponse("")
