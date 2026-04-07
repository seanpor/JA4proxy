"""Config reload endpoint — POST /api/v1/config/reload.

Publishes a reload signal to the ``config.reload`` Redis Pub/Sub channel.
The proxy instances listen on this channel and hot-reload their config
when they receive the message.

Redis channel: config.reload
Payload: {"type": "config_reload", "timestamp": "<ISO8601>"}
"""

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from ..auth import get_current_user
from ..models import ConfigReloadResponse
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["config"])

_RELOAD_CHANNEL = "config.reload"
_AUDIT_KEY = "management:audit_log"


async def _write_audit(
    redis,
    action: str,
    user: str,
    detail: dict,
    client_ip: str,
) -> None:
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
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


@router.post("/api/v1/config/reload", response_model=ConfigReloadResponse)
async def reload_config(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> ConfigReloadResponse:
    """Publish a config reload signal to all proxy instances.

    All instances subscribed to ``config.reload`` will hot-reload their
    configuration on receipt.
    """
    identity = current_user[0]
    payload = json.dumps(
        {
            "type": "config_reload",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requested_by": identity,
        }
    )
    subscribers = await redis.publish(_RELOAD_CHANNEL, payload)
    logger.info(
        "config_ops | event=reload_published | user=%s | subscribers=%d",
        identity,
        subscribers,
    )

    await _write_audit(
        redis,
        action="config_reload",
        user=identity,
        detail={"channel": _RELOAD_CHANNEL, "subscribers": subscribers},
        client_ip=_client_ip(request),
    )

    return ConfigReloadResponse(
        message="Config reload signal published",
        published_to=_RELOAD_CHANNEL,
    )
