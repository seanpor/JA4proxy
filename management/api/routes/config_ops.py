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

from ..audit_utils import write_audit
from ..auth import _client_ip, require_role
from ..models import ConfigReloadResponse, Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["config"])

_RELOAD_CHANNEL = "config.reload"


@router.post("/api/v1/config/reload", response_model=ConfigReloadResponse)
async def reload_config(
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    redis=Depends(get_redis),
) -> ConfigReloadResponse:
    """Publish a config reload signal to all proxy instances.

    All instances subscribed to ``config.reload`` will hot-reload their
    configuration on receipt.
    """
    identity, role = current_user
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

    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="config.reload",
        resource_type="config",
        after_value={"channel": _RELOAD_CHANNEL, "subscribers": subscribers},
        role=role.value,
    )

    return ConfigReloadResponse(
        message="Config reload signal published",
        published_to=_RELOAD_CHANNEL,
    )
