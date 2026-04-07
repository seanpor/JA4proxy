"""TOTP MFA endpoints — Phase 79 Cluster 6.

Routes
------
GET  /auth/mfa/totp/setup   — enroll TOTP; returns QR code PNG + 8 backup codes
POST /auth/mfa/totp/verify  — verify a 6-digit TOTP code or a backup code

Redis keys
----------
mgmt:totp:{user_id}          String  Fernet-encrypted base32 TOTP secret (no TTL)
mgmt:totp:backup:{user_id}   LIST    bcrypt-hashed backup codes (8 entries; consumed on use)
mgmt:mfa:session:{token_hash} String "verified", TTL = 8h
                              Keyed on SHA-256 of the cookie JWT so that MFA state
                              is bound to the specific session token, not just the user.

Security notes
--------------
* TOTP secret is encrypted at rest with Fernet (MANAGEMENT_MFA_ENCRYPTION_KEY env var).
* Backup codes are bcrypt-hashed; plaintext shown exactly once.
* Each backup code is single-use: the matching hash is LREM'd after successful use.
* The 401 response on failed backup code does NOT reveal how many codes remain.
* Bearer-token callers are not subject to the MFA session gate (API tokens are issued
  after enrollment and convey pre-verified identity).
"""

import base64
import io
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

import bcrypt as _bcrypt
import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..auth import get_current_user, mfa_session_key
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mfa"])

_BACKUP_CODE_COUNT = 8
_MFA_SESSION_TTL = 8 * 3600  # 8 hours, matches JWT expiry
_COOKIE_NAME = "token"

# ── Encryption ────────────────────────────────────────────────────────────────


def _get_fernet() -> Fernet:
    """Load Fernet from MANAGEMENT_MFA_ENCRYPTION_KEY env var.

    Raises:
        HTTPException(500): If the key is missing or invalid.
    """
    raw = os.environ.get("MANAGEMENT_MFA_ENCRYPTION_KEY", "")
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA encryption key not configured (MANAGEMENT_MFA_ENCRYPTION_KEY)",
        )
    try:
        return Fernet(raw.encode() if isinstance(raw, str) else raw)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA encryption key is invalid (must be a valid Fernet key)",
        )


async def _set_mfa_verified(redis, jwt_token: str) -> None:
    """Mark this session as MFA-verified (sets mgmt:mfa:session:{sha256(jwt)})."""
    await redis.set(mfa_session_key(jwt_token), "verified", ex=_MFA_SESSION_TTL)


# ── Setup endpoint ────────────────────────────────────────────────────────────


@router.get("/auth/mfa/totp/setup")
async def totp_setup(
    request: Request,
    token: Optional[str] = Cookie(default=None, alias="token"),
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Enroll TOTP for the current user.

    Generates a new TOTP secret, encrypts it with Fernet, stores it in Redis,
    generates 8 backup codes (bcrypt-hashed in Redis), and returns a QR code PNG
    (base64-encoded) plus the plaintext backup codes (shown exactly once).

    Calling this endpoint again rotates the secret and backup codes.

    Returns:
        JSON with ``qr_code`` (base64 PNG) and ``backup_codes`` (list of 8 strings).
    """
    identity, role = current_user
    # Use just the username part for the Redis key (strip "token:" prefix for API tokens)
    user_id = identity.removeprefix("token:")

    fernet = _get_fernet()

    # Generate a new TOTP secret
    raw_secret = pyotp.random_base32()
    encrypted_secret = fernet.encrypt(raw_secret.encode()).decode()

    # Generate 8 backup codes
    plaintext_codes = [
        secrets.token_hex(4).upper()  # 8 hex chars → readable, unambiguous
        for _ in range(_BACKUP_CODE_COUNT)
    ]
    hashed_codes = [
        _bcrypt.hashpw(code.encode(), _bcrypt.gensalt()).decode()
        for code in plaintext_codes
    ]

    # Store in Redis (pipeline for atomicity)
    pipe = redis.pipeline()
    pipe.set(f"mgmt:totp:{user_id}", encrypted_secret)
    pipe.delete(f"mgmt:totp:backup:{user_id}")  # rotation: clear old codes
    for h in hashed_codes:
        pipe.rpush(f"mgmt:totp:backup:{user_id}", h)
    await pipe.execute()

    # Build QR code
    issuer = "JA4proxy"
    totp_uri = pyotp.TOTP(raw_secret).provisioning_uri(
        name=user_id,
        issuer_name=issuer,
    )
    qr_img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    logger.info(
        "mfa | event=totp_enrolled | user=%s | role=%s",
        user_id,
        role.value,
    )

    return JSONResponse(
        content={
            "qr_code": qr_b64,
            "backup_codes": plaintext_codes,
            "enrolled_at": datetime.now(timezone.utc).isoformat(),
        }
    )


# ── Verify endpoint ───────────────────────────────────────────────────────────


@router.post("/auth/mfa/totp/verify")
async def totp_verify(
    request: Request,
    token: Optional[str] = Cookie(default=None, alias="token"),
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Verify a 6-digit TOTP code or a backup code.

    On success, marks the current session as MFA-verified (sets
    ``mgmt:mfa:session:{sha256(jwt)}``).

    Request body (JSON):
        ``code``: the 6-digit TOTP code or a backup code string.

    Returns:
        200 ``{"verified": true}`` for TOTP codes.
        200 ``{"verified": true, "backup_code_used": true}`` for backup codes.
        401 for wrong codes or expired TOTP window.
        404 if TOTP is not enrolled for this user.
    """
    identity, role = current_user
    user_id = identity.removeprefix("token:")

    # Parse request body
    try:
        body = await request.json()
        code = str(body.get("code", ""))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request body must be JSON with a 'code' field",
        )

    # Check enrollment
    encrypted_secret = await redis.get(f"mgmt:totp:{user_id}")
    if encrypted_secret is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="TOTP not enrolled for this user",
        )

    fernet = _get_fernet()
    try:
        raw_secret = fernet.decrypt(encrypted_secret.encode()).decode()
    except InvalidToken:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="TOTP secret could not be decrypted (key rotation?)",
        )

    # 1. Try TOTP verification (allow 1-step window: ±30s)
    totp = pyotp.TOTP(raw_secret)
    if totp.verify(code, valid_window=1):
        if token:
            await _set_mfa_verified(redis, token)
        logger.info("mfa | event=totp_verified | user=%s", user_id)
        return JSONResponse(content={"verified": True})

    # 2. Try backup codes — bcrypt check each stored hash
    backup_key = f"mgmt:totp:backup:{user_id}"
    stored_hashes = await redis.lrange(backup_key, 0, -1)

    for h in stored_hashes:
        try:
            matched = _bcrypt.checkpw(code.encode(), h.encode())
        except Exception:
            continue
        if matched:
            # Consume the code (remove the matching hash, single-use)
            await redis.lrem(backup_key, 1, h)
            if token:
                await _set_mfa_verified(redis, token)
            logger.info("mfa | event=backup_code_used | user=%s", user_id)
            return JSONResponse(content={"verified": True, "backup_code_used": True})

    # Both checks failed
    logger.warning("mfa | event=verify_failed | user=%s", user_id)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid code",
    )
