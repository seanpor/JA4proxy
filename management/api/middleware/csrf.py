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

logger = logging.getLogger(__name__)

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
TOKEN_VALIDITY_SECONDS = 3600  # 1 hour
_API_PREFIX = "/api/v1/"
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _get_signing_key() -> bytes:
    """Return the shared signing key — same secret as JWT.

    Falls back to the dev secret when ``MANAGEMENT_TEST_MODE=1`` and we
    are not in production so the test suite does not need to seed env.
    """
    secret = os.environ.get("MANAGEMENT_JWT_SECRET")
    if secret:
        return secret.encode()
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    in_prod = env in {"production", "prod"}
    if not in_prod and os.environ.get("MANAGEMENT_TEST_MODE") == "1":
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


def _is_production() -> bool:
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    return env in {"production", "prod"}


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
        # ``MANAGEMENT_DISABLE_CSRF=1`` AND we are not in production,
        # skip enforcement so those tests keep passing. Production
        # deployments never set this flag; the _is_production check is
        # the backstop. Tests that verify CSRF enforcement (test_csrf.py)
        # explicitly unset the flag in their module-level env.
        if os.environ.get("MANAGEMENT_DISABLE_CSRF") == "1" and not _is_production():
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
                    secure=_is_production() or request.url.scheme == "https",
                )
            response.headers[CSRF_HEADER_NAME] = token

        return response
