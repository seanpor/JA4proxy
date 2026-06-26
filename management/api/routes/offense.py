"""Offense counter API endpoints (Phase 248).

GET    /api/v1/ip/{ip}/offense  — current offense count and ban status
DELETE /api/v1/ip/{ip}/offense  — reset offense counter

The offense counter is maintained by the Go proxy in Redis (key: offense:{ip}).
This API provides read and reset access from the management UI.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from ipaddress import AddressValueError, ip_address

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..audit_utils import write_audit
from ..auth import _client_ip, require_mfa_verified, require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["offense"])


class OffenseStatus(BaseModel):
    ip: str
    offense_count: int
    current_action: str
    ban_expires: str | None = None


def _validate_ip(ip: str) -> str:
    try:
        return str(ip_address(ip))
    except (AddressValueError, ValueError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail=f"Invalid IP address: {ip!r}")


@router.get("/api/v1/ip/{ip}/offense", response_model=OffenseStatus)
async def get_offense_count(
    ip: str,
    _user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> OffenseStatus:
    """Return current offense count and ban status for an IP."""
    ip = _validate_ip(ip)
    offense_raw = await redis.get(f"offense:{ip}")
    offense_count = int(offense_raw) if offense_raw and offense_raw.isdigit() else 0

    ban_raw = await redis.get(f"ban:{ip}")
    ban_expires: str | None = None
    current_action = "active"

    if ban_raw is not None:
        current_action = "banned"
        ttl = await redis.ttl(f"ban:{ip}")
        if ttl > 0:
            ban_expires = (
                datetime.now(timezone.utc) + timedelta(seconds=ttl)
            ).isoformat()

    return OffenseStatus(
        ip=ip,
        offense_count=offense_count,
        current_action=current_action,
        ban_expires=ban_expires,
    )


@router.delete("/api/v1/ip/{ip}/offense", response_model=OffenseStatus)
async def reset_offense_count(
    ip: str,
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    _mfa=Depends(require_mfa_verified),
    redis=Depends(get_redis),
) -> OffenseStatus:
    """Reset the offense counter for an IP. Admin + MFA required."""
    ip = _validate_ip(ip)
    identity, role = current_user
    actor_ip = _client_ip(request)

    await redis.delete(f"offense:{ip}")

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=actor_ip,
        action_type="offense.reset",
        resource_type="ip",
        resource_id=ip,
        detail=json.dumps({"ip": ip}),
    )

    return OffenseStatus(ip=ip, offense_count=0, current_action="active")
