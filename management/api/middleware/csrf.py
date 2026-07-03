"""PHASE_101 H8 — CSRF double-submit middleware with HMAC token.

Protects every mutating route under ``/api/v1/*`` against cross-site
request forgery using the **double-submit cookie** pattern:

* On every ``GET /api/v1/*`` response: set a ``csrf_token`` cookie
  (HttpOnly=False so JS can read it, SameSite=Strict, Secure in prod)
  and mirror the same value in an ``X-CSRF-Token`` response header so
  HTMX / fetch callers can copy it straight onto subsequent writes.
* On every ``POST/PUT/PATCH/DELETE /api/v1/*`` request: the
  ``X-CSRF-Token`` request header must equal the ``csrf_token`` cookie
  **and** the token must verify under the HMAC signature bound to the
  session identity (JWT ``sub`` claim or bearer-token ``name``).
* Mismatch / expired / missing → HTTP 403 with body
  ``{"error": "csrf_token_mismatch"}``.

Why double-submit with HMAC rather than pure random?
    A pure-random double-submit cookie leaks protection if an attacker
    can inject a cookie via a sibling sub-domain. Binding the token to
    the session identity with HMAC means a forged cookie from another
    origin can never produce a matching header — the attacker does not
    know the signing key.

The signing key is ``MANAGEMENT_JWT_SECRET`` — the same secret the JWT
layer already uses, so there is nothing new to provision.

Token format
------------
``{payload_b64}.{sig_b64}`` where ``payload_b64`` is the URL-safe base64
of ``"{session_id}:{issued_at_unix}"`` and ``sig_b64`` is the URL-safe
base64 of HMAC-SHA256 over the raw payload. 1-hour validity.

Bearer tokens (``Authorization: Bearer <...>``) bypass CSRF because
cross-site HTML cannot forge an ``Authorization`` header — the browser
simply will not attach one cross-origin.
"""

from __future__ import annotations

import base64
import hmac
import logging
import os
import time
from hashlib import sha256
from typing import Awaitable, Callable, Optional

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from ..environment import is_explicit_nonproduction, is_production

logger = logging.getLogger(__name__)

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
TOKEN_VALIDITY_SECONDS = 3600  # 1 hour
_API_PREFIX = "/api/v1/"
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _get_signing_key() -> bytes:
    """Return the shared signing key — same secret as JWT.

    Falls back to the dev secret when ``MANAGEMENT_TEST_MODE=1`` and
    ENVIRONMENT is an explicit, known dev/test value (JA4PROXY-2026-0093 —
    unset/unrecognised ENVIRONMENT is treated as production, so the test
    suite must set ENVIRONMENT to opt into this fallback, not merely avoid
    setting it to "production").
    """
    secret = os.environ.get("MANAGEMENT_JWT_SECRET")
    if secret:
        return secret.encode()
    if is_explicit_nonproduction() and os.environ.get("MANAGEMENT_TEST_MODE") == "1":
        return b"test-secret-do-not-use-in-production"
    raise RuntimeError(
        "MANAGEMENT_JWT_SECRET must be set for CSRF middleware to sign tokens."
    )


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign(session_id: str, issued_at: int) -> str:
    payload = f"{session_id}:{issued_at}".encode()
    sig = hmac.new(_get_signing_key(), payload, sha256).digest()
    return f"{_b64url_encode(payload)}.{_b64url_encode(sig)}"


def issue_token(session_id: str) -> str:
    """Mint a CSRF token bound to *session_id* valid for 1 h."""
    return _sign(session_id, int(time.time()))


def verify_token(token: str, session_id: str) -> bool:
    """Return True iff *token* is a valid un-expired signature for *session_id*."""
    if not token or "." not in token:
        return False
    try:
        payload_b64, sig_b64 = token.rsplit(".", 1)
        payload_bytes = _b64url_decode(payload_b64)
        sig = _b64url_decode(sig_b64)
    except (ValueError, TypeError):
        return False

    try:
        decoded = payload_bytes.decode()
        tok_session, issued_str = decoded.rsplit(":", 1)
        issued_at = int(issued_str)
    except (UnicodeDecodeError, ValueError):
        return False

    if tok_session != session_id:
        return False

    if int(time.time()) - issued_at > TOKEN_VALIDITY_SECONDS:
        return False

    expected = hmac.new(_get_signing_key(), payload_bytes, sha256).digest()
    return hmac.compare_digest(sig, expected)


def _extract_session_id(request: Request) -> Optional[str]:
    """Return the session identity from the JWT cookie, if present.

    We do NOT validate the JWT here — the auth dependency already does
    that for the routes. For CSRF binding we only need a stable
    identifier. If decoding fails we fall back to ``"anonymous"`` so
    pre-login GETs still receive a token (useful for the login form
    itself, though the login endpoint is not under ``/api/v1/``).
    """
    token = request.cookies.get("token")
    if not token:
        return None

    try:
        payload = jwt.get_unverified_claims(token)
    except JWTError:
        return None

    sub = payload.get("sub")
    return str(sub) if sub else None


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit CSRF enforcement for ``/api/v1/*`` mutating routes."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        path = request.url.path
        method = request.method

        # Test-only bypass: the management test suite has ~97 inline
        # AsyncClient instantiations that predate the middleware. When
        # ``MANAGEMENT_DISABLE_CSRF=1`` AND ENVIRONMENT is an explicit,
        # known dev/test value, skip enforcement so those tests keep
        # passing. Production deployments never set this flag; the
        # is_explicit_nonproduction() check is the backstop — unset or
        # unrecognised ENVIRONMENT (e.g. a DMZ deployment) is production
        # (JA4PROXY-2026-0093), so this bypass cannot activate there even
        # if the flag is set. Tests that verify CSRF enforcement explicitly
        # unset the flag or set ENVIRONMENT to a non-allowlisted value.
        if os.environ.get("MANAGEMENT_DISABLE_CSRF") == "1" and is_explicit_nonproduction():
            return await call_next(request)

        # Not an API route → middleware is a no-op.
        if not path.startswith(_API_PREFIX):
            return await call_next(request)

        # Bearer-token callers are out of scope — the browser cannot
        # attach ``Authorization`` cross-origin, so CSRF does not apply.
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return await call_next(request)

        session_id = _extract_session_id(request) or "anonymous"

        if method in _MUTATING_METHODS:
            cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
            header_token = request.headers.get(CSRF_HEADER_NAME)

            if not cookie_token or not header_token:
                logger.warning(
                    "csrf | event=missing_token | path=%s | method=%s | "
                    "cookie=%s | header=%s",
                    path,
                    method,
                    bool(cookie_token),
                    bool(header_token),
                )
                return JSONResponse(
                    status_code=403,
                    content={"error": "csrf_token_mismatch"},
                )

            if not hmac.compare_digest(cookie_token, header_token):
                logger.warning(
                    "csrf | event=cookie_header_mismatch | path=%s | method=%s",
                    path,
                    method,
                )
                return JSONResponse(
                    status_code=403,
                    content={"error": "csrf_token_mismatch"},
                )

            if not verify_token(header_token, session_id):
                logger.warning(
                    "csrf | event=signature_invalid_or_expired | path=%s | "
                    "method=%s | session=%s",
                    path,
                    method,
                    session_id,
                )
                return JSONResponse(
                    status_code=403,
                    content={"error": "csrf_token_mismatch"},
                )

            return await call_next(request)

        # Safe method (GET/HEAD/OPTIONS) → pass through, then mint a
        # token for the next write.
        response = await call_next(request)

        if method == "GET":
            existing = request.cookies.get(CSRF_COOKIE_NAME)
            if existing and verify_token(existing, session_id):
                token = existing
            else:
                token = issue_token(session_id)
                response.set_cookie(
                    key=CSRF_COOKIE_NAME,
                    value=token,
                    max_age=TOKEN_VALIDITY_SECONDS,
                    httponly=False,
                    samesite="strict",
                    secure=is_production() or request.url.scheme == "https",
                )
            response.headers[CSRF_HEADER_NAME] = token

        return response
