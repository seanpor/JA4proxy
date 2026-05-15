"""Proxy node endpoints.

GET /api/v1/nodes                   — list live proxy node heartbeats
POST /api/v1/nodes/{host}/reload    — publish a reload signal to the proxy

Node heartbeats are stored as Redis Hashes under keys matching ``mgmt:node:*``.
Each proxy instance writes its own heartbeat key with a short TTL so that
dead nodes automatically expire from the list.
"""

import json
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["nodes"])

_NODE_KEY_PATTERN = "mgmt:node:*"
_RELOAD_CHANNEL = "proxy:reload"


@router.get("/api/v1/nodes")
async def get_nodes(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
):
    """Return all live proxy nodes detected via heartbeat keys.

    Each node heartbeat is stored as a Redis Hash with fields:
    host, port, version, started_at, last_seen, connections_total.

    Nodes with expired TTLs are not returned (Redis deletes them automatically).
    """
    nodes: List[Dict[str, Any]] = []

    try:
        async for key in redis.scan_iter(_NODE_KEY_PATTERN):
            try:
                fields = await redis.hgetall(key)
                if fields:
                    nodes.append(fields)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "nodes | event=hgetall_error | key=%s | error=%s", key, exc
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("nodes | event=scan_error | error=%s", exc)

    return {"nodes": nodes, "count": len(nodes)}


@router.post("/api/v1/nodes/{host}/reload")
async def reload_node(
    host: str,
    current_user=Depends(require_role(Role.admin)),
    redis=Depends(get_redis),
):
    """Publish a reload signal to the named proxy host.

    The signal is published to the ``proxy:reload`` channel so that any
    proxy instance subscribed to it will receive the message.

    Always returns 200 with ``published: True`` — the endpoint does not
    verify that the host actually exists or received the message.
    """
    payload = json.dumps({"action": "reload", "host": host})
    try:
        await redis.publish(_RELOAD_CHANNEL, payload)
        logger.info(
            "nodes | event=reload_published | host=%s | channel=%s",
            host,
            _RELOAD_CHANNEL,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("nodes | event=publish_error | host=%s | error=%s", host, exc)
        raise HTTPException(
            status_code=503, detail="Failed to publish reload signal"
        ) from exc

    return {"published": True, "host": host}
