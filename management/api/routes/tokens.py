"""Bearer token CRUD endpoints — MFA/SSO Hardening Cluster 1.

Routes
------
POST   /api/v1/tokens              — create a token (Admin only)
GET    /api/v1/tokens              — list all tokens (Admin only; no hash/plaintext)
GET    /api/v1/tokens/{token_id}   — inspect a single token (Admin only; no hash)
DELETE /api/v1/tokens/{token_id}   — revoke a token (idempotent)
POST   /api/v1/tokens/{token_id}/rotate — issue a replacement token

Redis schema
------------
mgmt:token:{id}  → Hash  {id, name, role, hash, created_at, expires_at, last_used_at}
mgmt:token:idx   → SET of active token IDs
"""

import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import List

import bcrypt as _bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response

from ..auth import require_admin
from ..models import (
    TokenCreate,
    TokenCreateResponse,
    TokenListResponse,
    TokenResponse,
    TokenRotateResponse,
)
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tokens"])

_IDX_KEY = "mgmt:token:idx"
_GRACE_TTL_SECONDS = 60


def _token_key(token_id: str) -> str:
    return f"mgmt:token:{token_id}"


def _fields_to_response(fields: dict) -> TokenResponse:
    """Convert Redis hash fields to a TokenResponse, omitting hash."""
    return TokenResponse(
        id=fields.get("id", ""),
        name=fields.get("name", ""),
        role=fields.get("role", ""),
        created_at=fields.get("created_at", ""),
        expires_at=fields.get("expires_at") or None,
        last_used_at=fields.get("last_used_at") or None,
    )


@router.post("/api/v1/tokens", response_model=TokenCreateResponse, status_code=201)
async def create_token(
    body: TokenCreate,
    request: Request,
    current_user=Depends(require_admin),
    redis=Depends(get_redis),
) -> TokenCreateResponse:
    """Create a new bearer token.  The plaintext is returned exactly once."""
    token_id = str(uuid.uuid4())
    raw_token = secrets.token_urlsafe(32)
    hashed = _bcrypt.hashpw(raw_token.encode(), _bcrypt.gensalt()).decode()
    now_iso = datetime.now(timezone.utc).isoformat()
    expires_at_str = body.expires_at or ""

    await redis.hset(
        _token_key(token_id),
        mapping={
            "id": token_id,
            "name": body.name,
            "role": body.role.value,
            "hash": hashed,
            "created_at": now_iso,
            "expires_at": expires_at_str,
            "last_used_at": "",
        },
    )
    await redis.sadd(_IDX_KEY, token_id)

    logger.info(  # nosemgrep
        "tokens | event=token_created | id=%s | name=%s | role=%s | user=%s",
        token_id,
        body.name,
        body.role.value,
        current_user[0],
    )

    return TokenCreateResponse(
        id=token_id,
        name=body.name,
        role=body.role.value,
        created_at=now_iso,
        expires_at=expires_at_str or None,
        last_used_at=None,
        token=raw_token,
    )


@router.get("/api/v1/tokens", response_model=TokenListResponse)
async def list_tokens(
    request: Request,
    current_user=Depends(require_admin),
    redis=Depends(get_redis),
) -> TokenListResponse:
    """List all tokens (metadata only — no hash, no plaintext)."""
    token_ids = await redis.smembers(_IDX_KEY)

    responses: List[TokenResponse] = []
    for tid in token_ids:
        fields = await redis.hgetall(_token_key(tid))
        if not fields:
            # Stale index entry; skip
            continue
        responses.append(_fields_to_response(fields))

    return TokenListResponse(tokens=responses, count=len(responses))


@router.get("/api/v1/tokens/{token_id}", response_model=TokenResponse)
async def get_token(
    token_id: str,
    request: Request,
    current_user=Depends(require_admin),
    redis=Depends(get_redis),
) -> TokenResponse:
    """Inspect a single token by ID (no hash, no plaintext)."""
    fields = await redis.hgetall(_token_key(token_id))
    if not fields:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Token not found: {token_id}",
        )
    return _fields_to_response(fields)


@router.delete("/api/v1/tokens/{token_id}", status_code=204)
async def delete_token(
    token_id: str,
    request: Request,
    current_user=Depends(require_admin),
    redis=Depends(get_redis),
) -> Response:
    """Revoke a token.  Idempotent — returns 204 even if token did not exist."""
    await redis.delete(_token_key(token_id))
    await redis.srem(_IDX_KEY, token_id)
    logger.info(  # nosemgrep
        "tokens | event=token_deleted | id=%s | user=%s",
        token_id,
        current_user[0],
    )
    return Response(status_code=204)


@router.post("/api/v1/tokens/{token_id}/rotate", response_model=TokenRotateResponse)
async def rotate_token(
    token_id: str,
    request: Request,
    current_user=Depends(require_admin),
    redis=Depends(get_redis),
) -> TokenRotateResponse:
    """Replace an existing token with a new one.

    The old token remains valid for a 60-second grace period (TTL on the Redis
    key) so in-flight requests using the old credential do not suddenly fail.
    """
    old_fields = await redis.hgetall(_token_key(token_id))
    if not old_fields:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Token not found: {token_id}",
        )

    # Issue the new token inheriting name and role from the old one
    new_id = str(uuid.uuid4())
    new_raw = secrets.token_urlsafe(32)
    new_hash = _bcrypt.hashpw(new_raw.encode(), _bcrypt.gensalt()).decode()
    now_iso = datetime.now(timezone.utc).isoformat()
    expires_at_str = old_fields.get("expires_at", "")

    await redis.hset(
        _token_key(new_id),
        mapping={
            "id": new_id,
            "name": old_fields.get("name", ""),
            # JA4PROXY-2026-0095 — a role-less/corrupt old token record must
            # rotate into the least-privileged role (auditor), not operator.
            "role": old_fields.get("role", "auditor"),
            "hash": new_hash,
            "created_at": now_iso,
            "expires_at": expires_at_str,
            "last_used_at": "",
        },
    )
    await redis.sadd(_IDX_KEY, new_id)

    # Set grace-period TTL on old key.
    # Keep the old token ID in the index during the grace period so bearer auth
    # continues to work for in-flight requests.  When the hash key expires,
    # the bearer lookup skips IDs whose hgetall returns empty — stale index
    # entries are harmless (they produce no false positives).
    await redis.expire(_token_key(token_id), _GRACE_TTL_SECONDS)
    # Remove old ID from the active listing index so it doesn't appear in GET /api/v1/tokens,
    # but leave it scannable by the bearer middleware for the grace period.
    # We deliberately do NOT srem here so the bearer lookup can still find the old hash.
    # (The listing endpoint shows stale index entries only if the hash still exists.)

    logger.info(  # nosemgrep
        "tokens | event=token_rotated | old_id=%s | new_id=%s | user=%s",
        token_id,
        new_id,
        current_user[0],
    )

    return TokenRotateResponse(id=new_id, token=new_raw)
