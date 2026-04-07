"""Webhook subscription CRUD endpoints.

POST   /api/v1/webhooks          — create a webhook (returns secret once)
GET    /api/v1/webhooks          — list all webhooks (no secrets)
GET    /api/v1/webhooks/{id}     — get a single webhook (no secrets)
PUT    /api/v1/webhooks/{id}     — update url / events / active in-place
DELETE /api/v1/webhooks/{id}     — delete a webhook (idempotent — always 204)

Redis schema
------------
webhook:{id}   → Hash: id, url, events (JSON list), secret_hash (bcrypt),
                        active ("true"/"false"), created_at, managed_by
webhook:idx    → SET of webhook IDs
"""

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["webhooks"])

_WEBHOOK_IDX = "webhook:idx"


# ── Request / response models ──────────────────────────────────────────────────


class WebhookCreate(BaseModel):
    """Body for POST /api/v1/webhooks."""

    url: str = Field(..., min_length=1, max_length=2048)
    events: List[str] = Field(default_factory=list)
    active: bool = True


class WebhookUpdate(BaseModel):
    """Body for PUT /api/v1/webhooks/{id}."""

    url: Optional[str] = None
    events: Optional[List[str]] = None
    active: Optional[bool] = None


# ── Helpers ────────────────────────────────────────────────────────────────────


def _hash_secret(raw: str) -> str:
    """Return a bcrypt hash of *raw* as a UTF-8 string."""
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()


def _decode_webhook(fields: Dict[str, str]) -> Dict[str, Any]:
    """Convert raw Hash fields to the API response shape (no secret fields)."""
    events_raw = fields.get("events", "[]")
    try:
        events_list = json.loads(events_raw)
    except json.JSONDecodeError:
        events_list = []

    return {
        "id": fields.get("id", ""),
        "url": fields.get("url", ""),
        "events": events_list,
        "active": fields.get("active", "true") == "true",
        "created_at": fields.get("created_at", ""),
        "managed_by": fields.get("managed_by", ""),
    }


# ── Routes ─────────────────────────────────────────────────────────────────────


@router.post("/api/v1/webhooks", status_code=201)
async def create_webhook(
    body: WebhookCreate,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
):
    """Create a new webhook subscription.

    Returns the full record plus a one-time plaintext secret.
    The secret is NOT stored; only its bcrypt hash is persisted.
    """
    import uuid
    webhook_id = str(uuid.uuid4())
    raw_secret = secrets.token_urlsafe(32)
    secret_hash = _hash_secret(raw_secret)
    created_at = datetime.now(timezone.utc).isoformat()

    identity = current_user[0] if isinstance(current_user, tuple) else str(current_user)

    mapping: Dict[str, str] = {
        "id": webhook_id,
        "url": body.url,
        "events": json.dumps(body.events),
        "secret_hash": secret_hash,
        "active": "true" if body.active else "false",
        "created_at": created_at,
        "managed_by": identity,
    }

    pipe = redis.pipeline()
    pipe.hset(f"webhook:{webhook_id}", mapping=mapping)
    pipe.sadd(_WEBHOOK_IDX, webhook_id)
    await pipe.execute()

    logger.info("webhooks | event=created | id=%s | url=%s", webhook_id, body.url)

    return {
        "id": webhook_id,
        "url": body.url,
        "events": body.events,
        "active": body.active,
        "created_at": created_at,
        "managed_by": identity,
        "secret": raw_secret,
    }


@router.get("/api/v1/webhooks")
async def list_webhooks(
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
):
    """Return all webhook subscriptions (no secrets)."""
    try:
        ids = await redis.smembers(_WEBHOOK_IDX)
    except Exception as exc:  # noqa: BLE001
        logger.warning("webhooks | event=smembers_error | error=%s", exc)
        ids = set()

    webhooks: List[Dict[str, Any]] = []
    for webhook_id in ids:
        try:
            fields = await redis.hgetall(f"webhook:{webhook_id}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("webhooks | event=hgetall_error | id=%s | error=%s", webhook_id, exc)
            continue
        if fields:
            webhooks.append(_decode_webhook(fields))

    return {"webhooks": webhooks, "count": len(webhooks)}


@router.get("/api/v1/webhooks/{webhook_id}")
async def get_webhook(
    webhook_id: str,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
):
    """Return a single webhook by ID (no secrets)."""
    try:
        fields = await redis.hgetall(f"webhook:{webhook_id}")
    except Exception as exc:  # noqa: BLE001
        logger.warning("webhooks | event=hgetall_error | id=%s | error=%s", webhook_id, exc)
        raise HTTPException(status_code=500, detail="Redis error") from exc

    if not fields:
        raise HTTPException(status_code=404, detail=f"Webhook '{webhook_id}' not found")

    return _decode_webhook(fields)


@router.put("/api/v1/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    body: WebhookUpdate,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
):
    """Update an existing webhook in-place.

    Only ``url``, ``events``, and ``active`` may be changed.
    Returns the updated resource.
    """
    try:
        fields = await redis.hgetall(f"webhook:{webhook_id}")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail="Redis error") from exc

    if not fields:
        raise HTTPException(status_code=404, detail=f"Webhook '{webhook_id}' not found")

    updates: Dict[str, str] = {}
    if body.url is not None:
        updates["url"] = body.url
    if body.events is not None:
        updates["events"] = json.dumps(body.events)
    if body.active is not None:
        updates["active"] = "true" if body.active else "false"

    if updates:
        await redis.hset(f"webhook:{webhook_id}", mapping=updates)

    # Re-read updated record
    updated_fields = await redis.hgetall(f"webhook:{webhook_id}")
    return _decode_webhook(updated_fields)


@router.delete("/api/v1/webhooks/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    current_user=Depends(require_role(Role.operator)),
    redis=Depends(get_redis),
):
    """Delete a webhook subscription.

    Idempotent — returns 204 whether or not the webhook existed.
    """
    try:
        pipe = redis.pipeline()
        pipe.delete(f"webhook:{webhook_id}")
        pipe.srem(_WEBHOOK_IDX, webhook_id)
        await pipe.execute()
    except Exception as exc:  # noqa: BLE001
        logger.warning("webhooks | event=delete_error | id=%s | error=%s", webhook_id, exc)

    return Response(status_code=204)
