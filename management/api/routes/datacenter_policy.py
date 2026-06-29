"""Datacenter ASN policy endpoints (Phase 249).

Routes
------
GET  /api/v1/datacenter-policy  — current policy (auditor+)
PUT  /api/v1/datacenter-policy  — update policy and hot-reload (admin + MFA)

Redis keys
----------
config:datacenter_policy  — String (JSON), no TTL, overrides file config
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator

from ..audit_utils import write_audit
from ..auth import _client_ip, require_mfa_verified, require_role
from ..models import Role
from ..pubsub_signing import build_envelope
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["datacenter-policy"])

_RELOAD_CHANNEL = "config:reload"
_REDIS_KEY = "config:datacenter_policy"
_DATACENTER_LIST_PATH = Path("config/asn_datacenter_list.yml")
_VALID_ACTIONS = {"score", "tarpit", "block"}
_DEFAULT_POLICY = {"action": "score", "exceptions": [13335, 54113, 20940], "log_actions": True}


def _load_asn_names() -> dict[int, str]:
    """Load ASN→name mapping from config/asn_datacenter_list.yml."""
    try:
        raw = _DATACENTER_LIST_PATH.read_text()
        data = yaml.safe_load(raw)
        return {int(asn): name for asn, name in (data.get("asns") or {}).items()}
    except Exception:
        return {}


def _asn_list_count() -> int:
    try:
        raw = _DATACENTER_LIST_PATH.read_text()
        data = yaml.safe_load(raw)
        return len(data.get("asns") or {})
    except Exception:
        return 0


def _asn_list_updated() -> str:
    try:
        raw = _DATACENTER_LIST_PATH.read_text()
        for line in raw.splitlines():
            if "Updated:" in line:
                return line.split("Updated:")[-1].strip()
    except Exception:
        pass
    return "unknown"


class PolicyRequest(BaseModel):
    action: str
    exceptions: Optional[list[int]] = None
    log_actions: Optional[bool] = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in _VALID_ACTIONS:
            raise ValueError(f"action must be one of: {', '.join(sorted(_VALID_ACTIONS))}")
        return v


@router.get("/api/v1/datacenter-policy")
async def get_datacenter_policy(
    _user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> dict:
    """Return the current datacenter policy. Reads from Redis first; falls back to defaults."""
    raw = await redis.get(_REDIS_KEY)
    if raw:
        try:
            policy = json.loads(raw)
        except Exception:
            policy = dict(_DEFAULT_POLICY)
    else:
        policy = dict(_DEFAULT_POLICY)

    asn_names = _load_asn_names()
    exceptions_resolved = [
        {"asn": asn, "name": asn_names.get(asn, f"ASN {asn}")}
        for asn in (policy.get("exceptions") or [])
    ]

    return {
        "action": policy.get("action", "score"),
        "exceptions": exceptions_resolved,
        "log_actions": policy.get("log_actions", True),
        "asn_list_count": _asn_list_count(),
        "asn_list_updated": _asn_list_updated(),
    }


@router.put("/api/v1/datacenter-policy")
async def update_datacenter_policy(
    body: PolicyRequest,
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    _mfa=Depends(require_mfa_verified),
    redis=Depends(get_redis),
) -> dict:
    """Update the datacenter policy and publish a config reload."""
    identity, _role = current_user

    # Read current policy for before/after audit log.
    old_raw = await redis.get(_REDIS_KEY)
    old_policy = json.loads(old_raw) if old_raw else dict(_DEFAULT_POLICY)

    exceptions = body.exceptions if body.exceptions is not None else old_policy.get("exceptions", [])
    log_actions = body.log_actions if body.log_actions is not None else old_policy.get("log_actions", True)

    new_policy = {
        "action": body.action,
        "exceptions": exceptions,
        "log_actions": log_actions,
    }

    try:
        await redis.set(_REDIS_KEY, json.dumps(new_policy))
        payload = build_envelope(_RELOAD_CHANNEL, datetime.now(timezone.utc).isoformat())
        await redis.publish(_RELOAD_CHANNEL, payload)
    except Exception as exc:
        logger.error("datacenter_policy | event=update_failed | error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redis unavailable — policy not updated",
        ) from exc

    updated_at = datetime.now(timezone.utc).isoformat()

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="datacenter_policy.updated",
        resource_type="config",
        resource_id="datacenter_policy",
        before_value=old_policy,
        after_value=new_policy,
        role=_role,
    )

    logger.info(
        "datacenter_policy | event=updated | user=%s | action=%s",
        identity,
        body.action,
    )

    asn_names = _load_asn_names()
    exceptions_resolved = [
        {"asn": asn, "name": asn_names.get(asn, f"ASN {asn}")}
        for asn in exceptions
    ]

    return {
        "action": new_policy["action"],
        "exceptions": exceptions_resolved,
        "log_actions": new_policy["log_actions"],
        "updated_at": updated_at,
    }
