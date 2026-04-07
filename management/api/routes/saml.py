"""SAML 2.0 SSO endpoints — Phase 79 Cluster 8.

Routes (all public — no JWT required; they are part of the login flow)
------
GET  /auth/sso/saml/login   — redirect browser to IdP SSO URL
POST /auth/sso/saml/acs     — Assertion Consumer Service (IdP posts here)
GET  /auth/sso/metadata     — serve SAML SP metadata XML to the IdP

Redis keys
----------
mgmt:saml:nonce:{nonce}   String (redirect URL)  TTL=5min
    CSRF protection.  Generated at /login, verified and deleted at /acs.
    Value is the post-login redirect URL (default "/").

Configuration (environment variables)
--------------------------------------
MANAGEMENT_SAML_SP_ENTITY_ID      SP entityId (default: http://localhost:8090/auth/sso/metadata)
MANAGEMENT_SAML_SP_ACS_URL         ACS URL   (default: http://localhost:8090/auth/sso/saml/acs)
MANAGEMENT_SAML_IDP_ENTITY_ID      IdP entityId (required for login/ACS/metadata)
MANAGEMENT_SAML_IDP_SSO_URL        IdP SSO redirect binding URL (required)
MANAGEMENT_SAML_IDP_CERT           IdP X.509 cert (PEM without header; can be empty with STRICT=false)
MANAGEMENT_SAML_STRICT             "true"|"false" — validate signatures/certs (default: "true")
MANAGEMENT_SAML_ROLE_MAPPING       JSON object: {"Group Name": "role"} (default: "{}")
MANAGEMENT_SAML_DEFAULT_ROLE       Fallback role when no group matches (default: "" = deny)
MANAGEMENT_SAML_GROUPS_ATTRIBUTE   SAML attribute name for group list (default: "groups")

Group-to-role mapping example
------------------------------
MANAGEMENT_SAML_ROLE_MAPPING='{"Security-Admins":"admin","SecOps-Operators":"operator",
    "SOC-Analysts":"analyst","Audit-Team":"auditor"}'

Security notes
--------------
* Nonces are stored in Redis with a 5-minute TTL and consumed on first use (single-use).
* The ACS endpoint validates the nonce (RelayState) before processing the SAML response
  to prevent cross-site request forgery.
* With MANAGEMENT_SAML_STRICT=true (production default), python3-saml verifies the
  IdP signature on every response.  Set to false ONLY in development/test.
* Users not in any mapped group are denied (403) unless MANAGEMENT_SAML_DEFAULT_ROLE is set.
"""

import json
import logging
import os
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from ..auth import _create_access_token
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sso"])

_NONCE_TTL = 300  # 5 minutes


# ── Configuration helpers ─────────────────────────────────────────────────────


def _saml_configured() -> bool:
    """Return True if both required IdP env vars are set."""
    return bool(
        os.environ.get("MANAGEMENT_SAML_IDP_ENTITY_ID")
        and os.environ.get("MANAGEMENT_SAML_IDP_SSO_URL")
    )


def _get_saml_settings() -> dict:
    """Build the python3-saml settings dict from environment variables."""
    strict = os.environ.get("MANAGEMENT_SAML_STRICT", "true").lower() == "true"
    return {
        "strict": strict,
        "debug": False,
        "sp": {
            "entityId": os.environ.get(
                "MANAGEMENT_SAML_SP_ENTITY_ID",
                "http://localhost:8090/auth/sso/metadata",
            ),
            "assertionConsumerService": {
                "url": os.environ.get(
                    "MANAGEMENT_SAML_SP_ACS_URL",
                    "http://localhost:8090/auth/sso/saml/acs",
                ),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        },
        "idp": {
            "entityId": os.environ.get("MANAGEMENT_SAML_IDP_ENTITY_ID", ""),
            "singleSignOnService": {
                "url": os.environ.get("MANAGEMENT_SAML_IDP_SSO_URL", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": os.environ.get("MANAGEMENT_SAML_IDP_CERT", ""),
        },
    }


async def _build_request_data(request: Request) -> dict:
    """Build the request_data dict expected by python3-saml."""
    post_data: dict = {}
    if request.method == "POST":
        form = await request.form()
        post_data = dict(form)

    host = request.headers.get("host", "localhost")
    port_str = str(request.url.port or (443 if request.url.scheme == "https" else 80))
    return {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": host,
        "server_port": port_str,
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": post_data,
    }


def _map_role(groups: list[str]) -> Optional[Role]:
    """Map a list of SAML group names to a management Role.

    Checks ``MANAGEMENT_SAML_ROLE_MAPPING`` (JSON dict) in order; the first
    matching group wins.  Falls back to ``MANAGEMENT_SAML_DEFAULT_ROLE`` if no
    group matches.  Returns ``None`` (deny) if neither produces a valid role.
    """
    role_mapping_raw = os.environ.get("MANAGEMENT_SAML_ROLE_MAPPING", "{}")
    default_role_str = os.environ.get("MANAGEMENT_SAML_DEFAULT_ROLE", "")

    try:
        role_mapping: dict = json.loads(role_mapping_raw)
    except json.JSONDecodeError:
        role_mapping = {}

    for group in (groups or []):
        role_str = role_mapping.get(group)
        if role_str:
            try:
                return Role(role_str)
            except ValueError:
                logger.warning(
                    "saml | event=invalid_role_in_mapping | group=%s | role_str=%s",
                    group,
                    role_str,
                )

    if default_role_str:
        try:
            return Role(default_role_str)
        except ValueError:
            logger.warning(
                "saml | event=invalid_default_role | value=%s", default_role_str
            )

    return None


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get("/auth/sso/metadata")
async def saml_metadata(request: Request) -> Response:
    """Serve SAML SP metadata XML.

    The IdP administrator fetches this URL to configure the SP side of the
    trust relationship.  No authentication required.

    Returns:
        200 ``application/xml`` SP metadata.
        503 if SAML IdP is not configured (missing env vars).
    """
    if not _saml_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SAML SSO is not configured (missing MANAGEMENT_SAML_IDP_ENTITY_ID)",
        )

    settings = _get_saml_settings()
    saml_settings = OneLogin_Saml2_Settings(settings=settings, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()

    return Response(content=metadata, media_type="application/xml")


@router.get("/auth/sso/saml/login")
async def saml_login(
    request: Request,
    redis=Depends(get_redis),
) -> RedirectResponse:
    """Initiate SAML 2.0 login — redirect browser to the IdP SSO URL.

    Generates a random nonce, stores it in Redis (5-min TTL) for CSRF
    protection, and passes it as the RelayState.  The IdP will echo the
    RelayState back in the ACS POST so we can verify it there.

    No authentication required (this is the start of the login flow).

    Returns:
        302 redirect to IdP SSO URL.
        503 if SAML is not configured.
    """
    if not _saml_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SAML SSO is not configured (missing MANAGEMENT_SAML_IDP_ENTITY_ID)",
        )

    nonce = secrets.token_hex(16)
    await redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=_NONCE_TTL)

    request_data = await _build_request_data(request)
    auth = OneLogin_Saml2_Auth(request_data, _get_saml_settings())
    redirect_url: str = auth.login(return_to=nonce)

    logger.info("saml | event=login_initiated | nonce=%s", nonce)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/auth/sso/saml/acs")
async def saml_acs(
    request: Request,
    redis=Depends(get_redis),
) -> Response:
    """SAML Assertion Consumer Service — receive and process IdP response.

    The IdP POST-binds the base64-encoded SAMLResponse and the RelayState
    (nonce) here.  On success, issues a JWT cookie and redirects to the
    stored redirect URL.

    No authentication required (this IS the authentication step).

    Returns:
        302 redirect to post-login URL with ``token`` cookie set.
        400 if relay state (nonce) is missing or expired.
        401 if the SAML assertion is invalid.
        403 if the user's groups do not map to any role.
        503 if SAML is not configured.
    """
    if not _saml_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SAML SSO is not configured",
        )

    form = await request.form()
    nonce = str(form.get("RelayState", ""))

    # CSRF check — nonce must exist in Redis
    redirect_target = await redis.get(f"mgmt:saml:nonce:{nonce}")
    if redirect_target is None:
        logger.warning("saml | event=invalid_relay_state | nonce=%r", nonce)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired SAML relay state — start the login flow again",
        )
    # Consume nonce (single-use)
    await redis.delete(f"mgmt:saml:nonce:{nonce}")

    request_data = await _build_request_data(request)
    auth = OneLogin_Saml2_Auth(request_data, _get_saml_settings())
    auth.process_response()

    if not auth.is_authenticated():
        errors = auth.get_errors()
        logger.warning("saml | event=auth_failed | errors=%s", errors)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SAML authentication failed",
        )

    nameid = auth.get_nameid()
    groups_attr = os.environ.get("MANAGEMENT_SAML_GROUPS_ATTRIBUTE", "groups")
    groups: list[str] = auth.get_attribute(groups_attr) or []

    role = _map_role(groups)
    if role is None:
        logger.warning(
            "saml | event=role_mapping_denied | user=%s | groups=%s", nameid, groups
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User's groups have no mapped role — access denied",
        )

    token = _create_access_token(nameid, role=role.value)
    response = RedirectResponse(url=redirect_target or "/", status_code=302)
    response.set_cookie(
        "token",
        token,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    logger.info(
        "saml | event=login_success | user=%s | role=%s", nameid, role.value
    )
    return response
