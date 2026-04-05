"""JWT authentication for the management API.

Auth flow
---------
1. POST /auth/login  {username, password}
   → validates credentials (bcrypt or plain-text in dev mode)
   → creates JWT (8h expiry)
   → sets httpOnly cookie ``token``
   → redirects to /

2. Every protected endpoint uses ``get_current_user(request)`` dependency.
   → reads ``token`` cookie
   → validates JWT signature and expiry
   → returns username string

Security notes
--------------
* JWT secret loaded from ``MANAGEMENT_JWT_SECRET`` env var (required in prod).
* Admin user from ``MANAGEMENT_ADMIN_USER`` (default "admin").
* Password hash from ``MANAGEMENT_ADMIN_PASSWORD_HASH`` (bcrypt).
* For dev: plain ``MANAGEMENT_ADMIN_PASSWORD`` accepted when hash not set.
* Rate limiting: 5 consecutive failures per IP → 5-min lockout (in-memory).
"""

import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Cookie, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from jose import JWTError, jwt
from passlib.context import CryptContext

from .models import LoginRequest

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

COOKIE_NAME = "token"
ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 8
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 300  # 5 minutes

# ── Password context ──────────────────────────────────────────────────────────

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── In-memory rate-limit state ────────────────────────────────────────────────
# { client_ip: {"count": int, "locked_until": float} }
_login_failures: dict[str, dict] = defaultdict(lambda: {"count": 0, "locked_until": 0.0})


# ── Helper functions ──────────────────────────────────────────────────────────


def _get_secret_key() -> str:
    """Return the JWT signing secret from environment.

    Raises:
        RuntimeError: If the secret is not configured and we are not in test mode.
    """
    secret = os.environ.get("MANAGEMENT_JWT_SECRET")
    if not secret:
        # Allow a default only in explicit test mode to avoid accidents in prod
        if os.environ.get("MANAGEMENT_TEST_MODE") == "1":
            return "test-secret-do-not-use-in-production"
        raise RuntimeError(
            "MANAGEMENT_JWT_SECRET environment variable is required but not set. "
            "Set it to a cryptographically random string (e.g. openssl rand -hex 32)."
        )
    return secret


def _get_admin_credentials() -> tuple[str, Optional[str], Optional[str]]:
    """Return (username, bcrypt_hash_or_None, plain_password_or_None).

    Priority: hash > plain text. Plain text only allowed when hash is absent
    (dev/test mode).
    """
    username = os.environ.get("MANAGEMENT_ADMIN_USER", "admin")
    pw_hash = os.environ.get("MANAGEMENT_ADMIN_PASSWORD_HASH")
    pw_plain = os.environ.get("MANAGEMENT_ADMIN_PASSWORD")
    return username, pw_hash, pw_plain


def _verify_password(plain: str) -> bool:
    """Verify a plain-text password against the configured credential store."""
    _, pw_hash, pw_plain = _get_admin_credentials()

    if pw_hash:
        return _pwd_context.verify(plain, pw_hash)

    if pw_plain:
        # Dev/test mode: constant-time compare to avoid timing attacks
        import hmac

        return hmac.compare_digest(plain, pw_plain)

    logger.warning(
        "auth | no admin password configured — all logins will fail"
    )
    return False


def _create_access_token(username: str) -> str:
    """Create a signed JWT for *username* with an 8-hour expiry."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(hours=TOKEN_EXPIRY_HOURS),
    }
    return jwt.encode(payload, _get_secret_key(), algorithm=ALGORITHM)


def _decode_token(token: str) -> dict:
    """Decode and validate a JWT.

    Returns:
        Decoded payload dict.

    Raises:
        HTTPException(401): on any JWT error.
    """
    try:
        payload = jwt.decode(token, _get_secret_key(), algorithms=[ALGORITHM])
        return payload
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc


def _client_ip(request: Request) -> str:
    """Extract the real client IP, honouring X-Forwarded-For if present."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _check_rate_limit(ip: str) -> None:
    """Raise HTTP 429 if the IP is locked out; clean up expired locks."""
    state = _login_failures[ip]
    now = time.monotonic()
    if state["locked_until"] > now:
        remaining = int(state["locked_until"] - now)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Locked out for {remaining}s.",
        )


def _record_failure(ip: str) -> None:
    """Increment failure counter; lock out after MAX_LOGIN_FAILURES."""
    state = _login_failures[ip]
    state["count"] += 1
    if state["count"] >= MAX_LOGIN_FAILURES:
        state["locked_until"] = time.monotonic() + LOCKOUT_SECONDS
        logger.warning(
            "auth | event=lockout | ip=%s | reason=too_many_failures", ip
        )


def _record_success(ip: str) -> None:
    """Clear failure state on successful login."""
    _login_failures[ip] = {"count": 0, "locked_until": 0.0}


# ── Dependency ────────────────────────────────────────────────────────────────


async def get_current_user(
    request: Request,
    token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
) -> str:
    """FastAPI dependency — returns the authenticated username.

    Checks the httpOnly ``token`` cookie. For API calls (Accept: application/json)
    raises HTTP 401. For browser navigations redirects to /login.

    Args:
        request: The incoming HTTP request.
        token: The JWT extracted from the cookie.

    Returns:
        Authenticated username string.

    Raises:
        HTTPException(401): For API clients when auth fails.
        RedirectResponse(/login): For browser clients when auth fails.
    """
    if token is None:
        return _unauthenticated_response(request)

    try:
        payload = _decode_token(token)
    except HTTPException:
        return _unauthenticated_response(request)

    username: Optional[str] = payload.get("sub")
    if username is None:
        return _unauthenticated_response(request)

    return username


def _unauthenticated_response(request: Request):
    """Raise 401 for API requests, redirect to /login for browser requests."""
    accept = request.headers.get("Accept", "")
    if "text/html" in accept and not request.url.path.startswith("/api/"):
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            headers={"Location": "/login"},
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter(tags=["auth"])


@router.post("/auth/login")
async def login(request: Request, response: Response) -> Response:
    """Validate credentials and set an httpOnly JWT cookie.

    On success: sets cookie and redirects to /.
    On failure: returns 401 JSON.
    """
    ip = _client_ip(request)
    _check_rate_limit(ip)

    # Parse body — supports both JSON and form data
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
        creds = LoginRequest(**body)
    else:
        form = await request.form()
        creds = LoginRequest(
            username=str(form.get("username", "")),
            password=str(form.get("password", "")),
        )

    admin_user, _, _ = _get_admin_credentials()

    if creds.username != admin_user or not _verify_password(creds.password):
        _record_failure(ip)
        logger.warning(
            "auth | event=login_failed | ip=%s | username=%s", ip, creds.username
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    _record_success(ip)
    token_str = _create_access_token(creds.username)
    logger.info("auth | event=login_success | ip=%s | username=%s", ip, creds.username)

    resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=token_str,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in production behind HTTPS
        max_age=TOKEN_EXPIRY_HOURS * 3600,
    )
    return resp


@router.post("/auth/logout")
async def logout(request: Request) -> Response:
    """Clear the auth cookie and redirect to /login."""
    ip = _client_ip(request)
    logger.info("auth | event=logout | ip=%s", ip)
    resp = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(key=COOKIE_NAME)
    return resp
