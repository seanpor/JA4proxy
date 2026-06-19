"""Config reload endpoint — POST /api/v1/config/reload.

Publishes a reload signal to the ``config:reload`` Redis Pub/Sub channel — the
**colon-namespaced** channel the Go proxy actually subscribes to
(``internal/redis/pubsub.go``). All instances on that channel hot-reload their
config on receipt.

Phase 309 fix: this endpoint previously published to ``config.reload`` (with a
dot), which **no proxy listens on**, so UI-triggered reloads silently never
reached the proxy. ``config:reload`` is also a *critical* channel, so the
payload is HMAC-signed when ``redis.pubsub_hmac_secret`` is configured (see
``pubsub_signing``); otherwise the proxy performs no verification.

Redis channel: config:reload
Payload: {"type": "config:reload", "value": "<ISO8601>", "signature": "<hex>"?}
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from ..audit_utils import write_audit
from ..auth import _client_ip, require_role
from ..models import ConfigReloadResponse, Role
from ..pubsub_signing import build_envelope
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["config"])

_RELOAD_CHANNEL = "config:reload"


@router.post("/api/v1/config/reload", response_model=ConfigReloadResponse)
async def reload_config(
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    redis=Depends(get_redis),
) -> ConfigReloadResponse:
    """Publish a config reload signal to all proxy instances.

    All instances subscribed to ``config:reload`` will hot-reload their
    configuration on receipt.
    """
    identity, role = current_user
    payload = build_envelope(_RELOAD_CHANNEL, datetime.now(timezone.utc).isoformat())
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
