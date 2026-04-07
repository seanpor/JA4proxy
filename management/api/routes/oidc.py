"""OIDC SSO endpoints — Phase 79 Cluster 9.

Routes (all public — no JWT required; they are part of the login flow)
------
GET /auth/sso/oidc/login     — start OIDC authorization code + PKCE flow
GET /auth/sso/oidc/callback  — exchange code for tokens, issue JWT cookie

Redis keys
----------
mgmt:oidc:state:{state}   String (JSON)  TTL=5min
    PKCE and CSRF state.  JSON shape: {"code_verifier": "...", "redirect": "/"}.
    Generated at /login, consumed and deleted at /callback — single-use.

Configuration (environment variables)
--------------------------------------
MANAGEMENT_OIDC_DISCOVERY_URL   OIDC discovery URL (required)
                                 e.g. https://keycloak/realms/ja4proxy/.well-known/openid-configuration
MANAGEMENT_OIDC_CLIENT_ID       OAuth 2.0 client ID (required)
MANAGEMENT_OIDC_CLIENT_SECRET   Client secret (required; read from env, not config file)
MANAGEMENT_OIDC_REDIRECT_URI    Callback URL (default: http://localhost:8090/auth/sso/oidc/callback)
MANAGEMENT_OIDC_SCOPES          Space-separated scopes (default: "openid email profile groups")
MANAGEMENT_OIDC_ROLE_MAPPING    JSON {"Group": "role"} (default: "{}")
MANAGEMENT_OIDC_DEFAULT_ROLE    Fallback role for unmapped users (default: "" = deny)
MANAGEMENT_OIDC_GROUPS_CLAIM    ID token claim containing group list (default: "groups")

Security notes
--------------
* PKCE (S256) is always used — no implicit flow, no code-only without verifier.
* State is stored in Redis with a 5-minute TTL and consumed on first use.
* ID token claims are extracted without signature verification in this implementation.
  TODO: Fetch JWKS from discovery doc and verify signature for production.
* Users not in any mapped group are denied (403) unless MANAGEMENT_OIDC_DEFAULT_ROLE is set.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Optional
from urllib.parse import urlencode

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JsonWebKey
from authlib.jose import jwt as authlib_jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response

from ..audit_utils import write_audit
from ..auth import _client_ip, _create_access_token, mfa_session_key
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sso"])

_STATE_TTL = 300  # 5 minutes

# ── JWKS cache (Gap 1 — Phase 100) ───────────────────────────────────────────

_jwks_cache: dict[str, tuple[object, float]] = {}  # uri → (key_set, expires_at)
_jwks_lock = asyncio.Lock()  # prevents duplicate concurrent JWKS fetches
_JWKS_DEFAULT_TTL = 3600  # 1 hour


def _clear_jwks_cache() -> None:
    """Clear the JWKS cache.  Used in tests to force a fresh fetch."""
    _jwks_cache.clear()


# ── Configuration helpers ─────────────────────────────────────────────────────


def _oidc_configured() -> bool:
    return bool(
        os.environ.get("MANAGEMENT_OIDC_DISCOVERY_URL")
        and os.environ.get("MANAGEMENT_OIDC_CLIENT_ID")
    )


def _redirect_uri() -> str:
    return os.environ.get(
        "MANAGEMENT_OIDC_REDIRECT_URI",
        "http://localhost:8090/auth/sso/oidc/callback",
    )


def _scopes() -> str:
    return os.environ.get("MANAGEMENT_OIDC_SCOPES", "openid email profile groups")


def _map_role(groups: list[str]) -> Optional[Role]:
    """Map a list of OIDC group names to a management Role.

    Merges group→role mappings from two sources, in priority order:
    1. ``MANAGEMENT_OIDC_ROLE_MAPPING`` env var (JSON dict) — highest priority
    2. ``sso.role_mapping`` in config/proxy.yml — base mapping

    First matching group wins.  Returns ``None`` (deny) when no group matches
    and no default role is set.
    """
    from ..proxy_config import get_sso_role_mapping  # local import avoids circular

    role_mapping_raw = os.environ.get("MANAGEMENT_OIDC_ROLE_MAPPING", "{}")
    default_role_str = os.environ.get("MANAGEMENT_OIDC_DEFAULT_ROLE", "")

    try:
        env_mapping: dict = json.loads(role_mapping_raw)
    except json.JSONDecodeError:
        env_mapping = {}

    # Config-file base; env var entries override config-file entries for the same group
    role_mapping: dict = {**get_sso_role_mapping(), **env_mapping}

    for group in (groups or []):
        role_str = role_mapping.get(group)
        if role_str:
            try:
                return Role(role_str)
            except ValueError:
                logger.warning(
                    "oidc | event=invalid_role_in_mapping | group=%s | role_str=%s",
                    group,
                    role_str,
                )

    if default_role_str:
        try:
            return Role(default_role_str)
        except ValueError:
            logger.warning("oidc | event=invalid_default_role | value=%s", default_role_str)

    return None


# ── PKCE helpers ──────────────────────────────────────────────────────────────


def _pkce_pair() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge_S256)``."""
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


async def _http_get_json(url: str) -> dict:
    """Fetch a JSON document from the given URL (mockable in tests)."""
    async with httpx.AsyncClient() as client:
        r = await client.get(url, timeout=10.0)
        r.raise_for_status()
        return r.json()


async def _fetch_jwks(jwks_uri: str) -> object:
    """Fetch and cache JWKS from the IdP.  Returns an authlib JsonWebKey key set.

    Uses an asyncio.Lock to prevent duplicate concurrent HTTP fetches for the
    same JWKS URI (avoids thundering-herd on cache miss).
    Cache is module-level — cleared by ``_clear_jwks_cache()`` in tests.
    Uses ``_http_get_json`` internally so tests can mock the HTTP call.
    """
    now = time.monotonic()
    # Fast path: check without lock first
    if jwks_uri in _jwks_cache:
        key_set, expires_at = _jwks_cache[jwks_uri]
        if now < expires_at:
            return key_set

    # Slow path: acquire lock, re-check, fetch
    async with _jwks_lock:
        now = time.monotonic()
        if jwks_uri in _jwks_cache:
            key_set, expires_at = _jwks_cache[jwks_uri]
            if now < expires_at:
                return key_set  # another coroutine already fetched while we waited

        jwks_data = await _http_get_json(jwks_uri)
        key_set = JsonWebKey.import_key_set(jwks_data)
        _jwks_cache[jwks_uri] = (key_set, now + _JWKS_DEFAULT_TTL)
        return key_set


async def _extract_claims(id_token: str, jwks_uri: str) -> dict:
    """Verify the ID token signature using JWKS and return its claims.

    In ``MANAGEMENT_TEST_MODE=1`` (unit tests only), signature verification is
    skipped and the payload is returned decoded without verification — this
    preserves the existing unit-test behaviour for tests that are not testing
    JWKS.  In all other environments, RS256/ES256 signature is fully verified.

    Args:
        id_token: The raw ID token JWT string.
        jwks_uri: The JWKS URI from the OIDC discovery document.

    Returns:
        Dict of verified JWT claims.

    Raises:
        HTTPException(401): On signature failure or claim validation failure.
    """
    if os.environ.get("MANAGEMENT_TEST_MODE") == "1":
        # Test mode — decode without signature verification
        try:
            parts = id_token.split(".")
            if len(parts) != 3:
                raise ValueError("Invalid ID token format")
            padding = "=" * (-len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(parts[1] + padding))
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to extract claims from ID token",
            ) from exc

    try:
        key_set = await _fetch_jwks(jwks_uri)
        claims = authlib_jwt.decode(id_token, key_set)
        claims.validate()
        return dict(claims)
    except Exception as exc:
        logger.warning("oidc | event=id_token_invalid | error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ID token signature verification failed",
        )


# ── Injectable I/O helpers (mockable in tests) ────────────────────────────────


async def _fetch_oidc_discovery(discovery_url: str) -> dict:
    """Fetch the OIDC discovery document from the given URL."""
    async with httpx.AsyncClient() as client:
        r = await client.get(discovery_url, timeout=10.0)
        r.raise_for_status()
        return r.json()


async def _exchange_code_for_tokens(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    """Exchange an authorization code for tokens using PKCE."""
    oauth = AsyncOAuth2Client(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
    )
    token = await oauth.fetch_token(
        token_endpoint,
        grant_type="authorization_code",
        code=code,
        code_verifier=code_verifier,
    )
    await oauth.aclose()
    return dict(token)


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/auth/sso/oidc/login")
async def oidc_login(
    request: Request,
    redis=Depends(get_redis),
) -> RedirectResponse:
    """Start the OIDC authorization code + PKCE flow.

    Fetches the discovery document, generates a PKCE pair and random state,
    stores them in Redis (5-min TTL), then redirects the browser to the
    IdP authorization endpoint.

    No authentication required (this is the start of the login flow).

    Returns:
        302 redirect to IdP authorization URL.
        503 if OIDC is not configured.
    """
    if not _oidc_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC SSO is not configured (missing MANAGEMENT_OIDC_DISCOVERY_URL)",
        )

    discovery_url = os.environ["MANAGEMENT_OIDC_DISCOVERY_URL"]
    try:
        discovery = await _fetch_oidc_discovery(discovery_url)
    except Exception as exc:
        logger.error("oidc | event=discovery_failed | url=%s | error=%s", discovery_url, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch OIDC discovery document",
        )

    authorization_endpoint = discovery["authorization_endpoint"]
    client_id = os.environ["MANAGEMENT_OIDC_CLIENT_ID"]
    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = _pkce_pair()

    await redis.set(
        f"mgmt:oidc:state:{state}",
        json.dumps({"code_verifier": code_verifier, "redirect": "/"}),
        ex=_STATE_TTL,
    )

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": _redirect_uri(),
        "scope": _scopes(),
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    redirect_url = f"{authorization_endpoint}?{urlencode(params)}"

    logger.info("oidc | event=login_initiated | state=%s", state)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.get("/auth/sso/oidc/callback")
async def oidc_callback(
    request: Request,
    redis=Depends(get_redis),
) -> Response:
    """Handle the OIDC authorization code callback.

    Validates the state (CSRF check), exchanges the code for tokens using
    PKCE, extracts claims from the ID token, maps groups to a role, and
    issues a JWT cookie.

    No authentication required (this IS the authentication step).

    Returns:
        302 redirect to post-login URL with ``token`` cookie set.
        400 if state is missing or expired.
        401 if token exchange or claim extraction fails.
        403 if the user's groups have no mapped role.
        503 if OIDC is not configured.
    """
    if not _oidc_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC SSO is not configured",
        )

    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")

    # CSRF / state check
    state_raw = await redis.get(f"mgmt:oidc:state:{state}")
    if not state_raw:
        logger.warning("oidc | event=invalid_state | state=%r", state)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OIDC state — start the login flow again",
        )
    # Consume state (single-use) — before any further checks so the state
    # cannot be replayed even on error paths (e.g. IdP error, token failure)
    await redis.delete(f"mgmt:oidc:state:{state}")

    # Check for IdP error response (e.g. access_denied, consent_required)
    idp_error = request.query_params.get("error", "")
    if idp_error:
        error_desc = request.query_params.get("error_description", idp_error)
        logger.warning(
            "oidc | event=idp_error | error=%s | state=%s", idp_error, state
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"IdP rejected the authentication request: {error_desc}",
        )

    state_data = json.loads(state_raw)
    code_verifier = state_data["code_verifier"]
    redirect_target = state_data.get("redirect", "/")

    # Fetch discovery to get token endpoint and JWKS URI
    discovery_url = os.environ["MANAGEMENT_OIDC_DISCOVERY_URL"]
    try:
        discovery = await _fetch_oidc_discovery(discovery_url)
        token_endpoint = discovery["token_endpoint"]
        jwks_uri = discovery.get("jwks_uri", "")
    except Exception as exc:
        logger.error("oidc | event=discovery_failed | error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to fetch OIDC discovery document",
        )

    # Exchange authorization code for tokens
    try:
        token_response = await _exchange_code_for_tokens(
            token_endpoint=token_endpoint,
            client_id=os.environ["MANAGEMENT_OIDC_CLIENT_ID"],
            client_secret=os.environ.get("MANAGEMENT_OIDC_CLIENT_SECRET", ""),
            code=code,
            redirect_uri=_redirect_uri(),
            code_verifier=code_verifier,
        )
    except Exception as exc:
        logger.warning("oidc | event=token_exchange_failed | error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token exchange failed",
        )

    # Verify ID token signature and extract claims (Gap 1 — Phase 100)
    id_token = token_response.get("id_token", "")
    try:
        claims = await _extract_claims(id_token, jwks_uri)
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("oidc | event=claims_extraction_failed | error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to extract claims from ID token",
        )

    sub = str(claims.get("sub") or claims.get("email") or "unknown")
    groups_claim = os.environ.get("MANAGEMENT_OIDC_GROUPS_CLAIM", "groups")
    groups: list[str] = claims.get(groups_claim) or []

    role = _map_role(groups)
    if role is None:
        logger.warning("oidc | event=role_mapping_denied | user=%s | groups=%s", sub, groups)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User's groups have no mapped role — access denied",
        )

    token = _create_access_token(sub, role=role.value)

    # Gap 4 (Phase 100): SSO-delegated MFA trust
    _MFA_SESSION_TTL = 8 * 3600
    trust_idp_mfa = os.environ.get("MANAGEMENT_SSO_TRUST_IDP_MFA", "false").lower() == "true"
    if trust_idp_mfa:
        amr = claims.get("amr") or []
        if isinstance(amr, str):
            amr = [amr]
        if set(amr) & {"mfa", "otp", "hwk", "swk"}:
            await redis.set(mfa_session_key(token), "verified", ex=_MFA_SESSION_TTL)
            logger.info("sso | event=idp_mfa_trusted | user=%s | provider=oidc", sub)

    response = RedirectResponse(url=redirect_target, status_code=302)
    response.set_cookie(
        "token",
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )

    # Gap 2 (Phase 100): audit SSO login event
    await write_audit(
        redis,
        actor_id=sub,
        actor_ip=_client_ip(request),
        action_type="sso.login",
        resource_type="session",
        role=role.value,
        after_value={"provider": "oidc"},
    )

    logger.info("oidc | event=login_success | user=%s | role=%s", sub, role.value)
    return response
