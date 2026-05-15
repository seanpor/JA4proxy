"""WebAuthn / FIDO2 MFA endpoints — MFA/SSO Hardening Cluster 7.

Routes
------
POST /auth/mfa/webauthn/register/begin    — generate registration challenge
POST /auth/mfa/webauthn/register/complete — verify attestation, store credential
POST /auth/mfa/webauthn/auth/begin        — generate authentication challenge
POST /auth/mfa/webauthn/auth/complete     — verify assertion, mark session MFA-verified

Redis keys
----------
mgmt:webauthn:challenge:{user_id}         String (JSON)  TTL=5min
    Stores the active challenge (registration or authentication).
    JSON shape: {"challenge": "<base64url>", "type": "registration"|"authentication"}

mgmt:webauthn:credential:{credential_id}  Hash           no TTL
    Per-credential record. Fields: user_id, public_key, sign_count, created_at.
    Both credential_id and public_key are base64url-encoded.

mgmt:webauthn:user:{user_id}:credentials  SET            no TTL
    Set of base64url credential IDs owned by this user.

Configuration (environment variables)
--------------------------------------
MANAGEMENT_WEBAUTHN_RP_ID     — Relying Party ID (default: "localhost")
MANAGEMENT_WEBAUTHN_ORIGIN    — Allowed origin (default: "http://localhost:8090")

Security notes
--------------
* Challenges are single-use: deleted after register/complete or auth/complete.
* sign_count is updated after each successful assertion to detect cloned keys.
* Bearer-token callers are exempt from the MFA session gate (same as TOTP).
* Credential ownership is validated in auth/complete before verification.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import webauthn
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from ..auth import get_current_user, mfa_session_key
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["mfa"])

_CHALLENGE_TTL = 300  # 5 minutes
_MFA_SESSION_TTL = 8 * 3600  # 8 hours, matches JWT expiry


def _rp_id() -> str:
    return os.environ.get("MANAGEMENT_WEBAUTHN_RP_ID", "localhost")


def _origin() -> str:
    return os.environ.get("MANAGEMENT_WEBAUTHN_ORIGIN", "http://localhost:8090")


def _challenge_key(user_id: str) -> str:
    return f"mgmt:webauthn:challenge:{user_id}"


def _credential_key(credential_id_b64: str) -> str:
    return f"mgmt:webauthn:credential:{credential_id_b64}"


def _user_credentials_key(user_id: str) -> str:
    return f"mgmt:webauthn:user:{user_id}:credentials"


async def _load_challenge(redis, user_id: str, expected_type: str) -> bytes:
    """Load, validate, and immediately consume the stored challenge for this user.

    The challenge is deleted before returning — it is single-use regardless of
    whether the subsequent verification succeeds.  This prevents an attacker from
    retrying with different attestation/assertion data within the 5-minute TTL.

    Raises:
        HTTPException(400): If no challenge found or type mismatch.
    """
    raw = await redis.get(_challenge_key(user_id))
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No pending {expected_type} challenge — call the begin endpoint first",
        )
    stored = json.loads(raw)
    if stored.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Challenge type mismatch: expected '{expected_type}', found '{stored.get('type')}'",
        )
    # Consume immediately — single-use on any code path
    await redis.delete(_challenge_key(user_id))
    return base64url_to_bytes(stored["challenge"])


# ── Registration ──────────────────────────────────────────────────────────────


@router.post("/auth/mfa/webauthn/register/begin")
async def webauthn_register_begin(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Generate a WebAuthn registration challenge.

    Returns the PublicKeyCredentialCreationOptions JSON that the browser needs
    to call ``navigator.credentials.create()``. Excludes any already-registered
    credentials to prevent duplicate registration.

    The challenge is stored in Redis with a 5-minute TTL.
    """
    identity, role = current_user
    user_id = identity.removeprefix("token:")

    # Load existing credential IDs to exclude them
    credential_ids = await redis.smembers(_user_credentials_key(user_id))
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in credential_ids
    ]

    options = webauthn.generate_registration_options(
        rp_id=_rp_id(),
        rp_name="JA4proxy Management",
        user_name=user_id,
        exclude_credentials=exclude_credentials,
    )

    await redis.set(
        _challenge_key(user_id),
        json.dumps(
            {
                "challenge": bytes_to_base64url(options.challenge),
                "type": "registration",
            }
        ),
        ex=_CHALLENGE_TTL,
    )

    logger.info("mfa | event=webauthn_register_begin | user=%s", user_id)
    return JSONResponse(content=json.loads(webauthn.options_to_json(options)))


@router.post("/auth/mfa/webauthn/register/complete", status_code=201)
async def webauthn_register_complete(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Verify WebAuthn attestation and store the new credential.

    Request body: the ``PublicKeyCredential`` JSON from ``navigator.credentials.create()``.

    On success stores:
    - ``mgmt:webauthn:credential:{credential_id}`` Hash record
    - Adds credential ID to ``mgmt:webauthn:user:{user_id}:credentials`` SET

    Returns:
        201 ``{"registered": true, "credential_id": "<base64url>"}``
        400 if no challenge found or attestation verification fails.
    """
    identity, role = current_user
    user_id = identity.removeprefix("token:")

    expected_challenge = await _load_challenge(redis, user_id, "registration")

    try:
        body: Dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request body must be valid JSON",
        )

    try:
        verification = webauthn.verify_registration_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
        )
    except Exception as exc:
        logger.warning(
            "mfa | event=webauthn_register_failed | user=%s | error=%s", user_id, exc
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration verification failed",
        )

    credential_id_b64 = bytes_to_base64url(verification.credential_id)
    public_key_b64 = bytes_to_base64url(verification.credential_public_key)

    pipe = redis.pipeline()
    pipe.hset(
        _credential_key(credential_id_b64),
        mapping={
            "user_id": user_id,
            "public_key": public_key_b64,
            "sign_count": str(verification.sign_count),
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    pipe.sadd(_user_credentials_key(user_id), credential_id_b64)
    # Note: challenge already consumed in _load_challenge above (single-use on any code path)
    await pipe.execute()

    logger.info(  # nosemgrep
        "mfa | event=webauthn_registered | user=%s | credential_id=%s",
        user_id,
        credential_id_b64,
    )
    return JSONResponse(
        status_code=201,
        content={"registered": True, "credential_id": credential_id_b64},
    )


# ── Authentication ────────────────────────────────────────────────────────────


@router.post("/auth/mfa/webauthn/auth/begin")
async def webauthn_auth_begin(
    request: Request,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Generate a WebAuthn authentication challenge.

    Returns the ``PublicKeyCredentialRequestOptions`` JSON the browser needs to
    call ``navigator.credentials.get()``. The ``allowCredentials`` list is
    populated with all credentials registered for this user.

    Returns:
        200 with challenge options JSON.
        404 if no credentials are enrolled.
    """
    identity, role = current_user
    user_id = identity.removeprefix("token:")

    credential_ids = await redis.smembers(_user_credentials_key(user_id))
    if not credential_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No WebAuthn credentials enrolled for this user",
        )

    allow_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid))
        for cid in credential_ids
    ]

    options = webauthn.generate_authentication_options(
        rp_id=_rp_id(),
        allow_credentials=allow_credentials,
    )

    await redis.set(
        _challenge_key(user_id),
        json.dumps(
            {
                "challenge": bytes_to_base64url(options.challenge),
                "type": "authentication",
            }
        ),
        ex=_CHALLENGE_TTL,
    )

    logger.info("mfa | event=webauthn_auth_begin | user=%s", user_id)
    return JSONResponse(content=json.loads(webauthn.options_to_json(options)))


@router.post("/auth/mfa/webauthn/auth/complete")
async def webauthn_auth_complete(
    request: Request,
    token: Optional[str] = Cookie(default=None, alias="token"),
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """Verify a WebAuthn assertion and mark the session as MFA-verified.

    Request body: the ``PublicKeyCredential`` JSON from ``navigator.credentials.get()``.
    Must contain an ``id`` field (base64url credential ID).

    On success sets ``mgmt:mfa:session:{sha256(jwt)}`` → "verified" (8h TTL).

    Returns:
        200 ``{"verified": true}``
        400 if no authentication challenge found.
        404 if the credential ID is not registered.
        401 if assertion verification fails.
    """
    identity, role = current_user
    user_id = identity.removeprefix("token:")

    expected_challenge = await _load_challenge(redis, user_id, "authentication")

    try:
        body: Dict[str, Any] = await request.json()
        credential_id_b64: str = str(body.get("id", ""))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request body must be JSON with an 'id' field",
        )

    if not credential_id_b64:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Missing 'id' field in request body",
        )

    # Load credential record
    cred = await redis.hgetall(_credential_key(credential_id_b64))
    if not cred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found — register this key first",
        )

    # Ownership check: credential must belong to the authenticated user
    if cred.get("user_id") != user_id:
        logger.warning(
            "mfa | event=webauthn_auth_ownership_mismatch | user=%s | cred_owner=%s",
            user_id,
            cred.get("user_id"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Credential does not belong to this user",
        )

    public_key_bytes = base64url_to_bytes(cred["public_key"])
    current_sign_count = int(cred.get("sign_count", "0"))

    try:
        verification = webauthn.verify_authentication_response(
            credential=body,
            expected_challenge=expected_challenge,
            expected_rp_id=_rp_id(),
            expected_origin=_origin(),
            credential_public_key=public_key_bytes,
            credential_current_sign_count=current_sign_count,
        )
    except Exception as exc:
        logger.warning(
            "mfa | event=webauthn_auth_failed | user=%s | error=%s", user_id, exc
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication verification failed",
        )

    # Update sign count atomically
    # Note: challenge already consumed in _load_challenge above (single-use on any code path)
    pipe = redis.pipeline()
    pipe.hset(
        _credential_key(credential_id_b64),
        "sign_count",
        str(verification.new_sign_count),
    )
    await pipe.execute()

    # Mark session as MFA-verified
    if token:
        await redis.set(mfa_session_key(token), "verified", ex=_MFA_SESSION_TTL)

    logger.info(  # nosemgrep
        "mfa | event=webauthn_auth_verified | user=%s | credential_id=%s",
        user_id,
        credential_id_b64,
    )
    return JSONResponse(content={"verified": True})


# ── Credential management (Gap 3 — Production Readiness) ────────────────────────────────


@router.get("/auth/mfa/webauthn/credentials")
async def webauthn_list_credentials(
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> JSONResponse:
    """List all WebAuthn credential IDs enrolled for the authenticated user.

    Returns a JSON object with a ``credentials`` list; each entry has
    ``credential_id`` (base64url) and ``created_at`` (ISO 8601).

    Returns:
        200 ``{"credentials": [...]}``
    """
    identity, role = current_user
    user_id = identity.removeprefix("token:")
    credential_ids = await redis.smembers(_user_credentials_key(user_id))
    result = []
    for cid in credential_ids:
        fields = await redis.hgetall(_credential_key(cid))
        result.append(
            {
                "credential_id": cid,
                "created_at": fields.get("created_at"),
            }
        )
    return JSONResponse(content={"credentials": result})


@router.delete("/auth/mfa/webauthn/credentials/{credential_id_b64}", status_code=204)
async def webauthn_delete_credential(
    credential_id_b64: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> Response:
    """Remove a single WebAuthn credential.

    Only the credential's owner may delete it.  Returns 204 on success.

    Returns:
        204 No Content on success.
        404 if the credential does not exist.
        403 if the credential belongs to a different user.
    """
    identity, role = current_user
    user_id = identity.removeprefix("token:")

    cred = await redis.hgetall(_credential_key(credential_id_b64))
    if not cred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Credential not found"
        )
    if cred.get("user_id") != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Credential does not belong to this user",
        )

    pipe = redis.pipeline()
    pipe.delete(_credential_key(credential_id_b64))
    pipe.srem(_user_credentials_key(user_id), credential_id_b64)
    await pipe.execute()

    logger.info(  # nosemgrep
        "mfa | event=webauthn_credential_deleted | user=%s | credential_id=%s",
        user_id,
        credential_id_b64,
    )
    return Response(status_code=204)
