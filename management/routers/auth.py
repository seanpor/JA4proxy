"""Human-facing authentication router.

POST /api/v1/auth/login   — username + password → session token
POST /api/v1/auth/logout  — invalidate session token
GET  /api/v1/auth/me      — return current username

Sessions are stored in Redis as  mgmt:session:{token} → username
with an 8-hour TTL.  The UI_API_KEY env var still works for direct
API / scripting access (curl, Grafana, etc.).

Configuration (env vars):
  UI_USERNAME  — login username  (default: admin)
  UI_PASSWORD  — login password  (required; same as UI_API_KEY if not set separately)
"""

import logging
import os
import secrets

import redis.exceptions
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from management.auth import require_api_key

logger = logging.getLogger("management.routers.auth")
router = APIRouter()

_SESSION_TTL = 8 * 3600  # 8 hours
_SESSION_PREFIX = "mgmt:session:"


def _get_credentials() -> tuple[str, str]:
    username = os.environ.get("UI_USERNAME", "admin")
    # UI_PASSWORD takes precedence; fall back to UI_API_KEY so existing
    # deployments work without adding a second env var.
    password = os.environ.get("UI_PASSWORD") or os.environ.get("UI_API_KEY", "")
    return username, password


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str


@router.post("/auth/login", response_model=LoginResponse, status_code=200)
async def login(request: Request, payload: LoginRequest) -> LoginResponse:
    """Validate username + password and return a session token."""
    expected_username, expected_password = _get_credentials()

    # Constant-time comparison to prevent timing attacks
    username_ok = secrets.compare_digest(payload.username, expected_username)
    password_ok = secrets.compare_digest(payload.password, expected_password)

    if not (username_ok and password_ok):
        logger.warning(
            "management | event=login_failed | username=%s | ip=%s",
            payload.username,
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = secrets.token_urlsafe(32)
    r = request.app.state.redis

    try:
        await r.set(f"{_SESSION_PREFIX}{token}", payload.username, ex=_SESSION_TTL)
    except redis.exceptions.RedisError as exc:
        logger.error("management | event=session_create_failed | error=%s", exc)
        raise HTTPException(status_code=503, detail="Redis unavailable")

    logger.info(
        "management | event=login_success | username=%s | ip=%s",
        payload.username,
        request.client.host if request.client else "unknown",
    )
    return LoginResponse(token=token, username=payload.username)


@router.post("/auth/logout", status_code=200)
async def logout(request: Request, _key: str = Depends(require_api_key)) -> dict:
    """Invalidate the current session token."""
    # The token was already extracted by require_api_key; delete it from Redis
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        r = request.app.state.redis
        try:
            await r.delete(f"{_SESSION_PREFIX}{token}")
        except redis.exceptions.RedisError:
            pass  # Best-effort logout
    return {"logged_out": True}


@router.get("/auth/me", status_code=200)
async def me(request: Request, _key: str = Depends(require_api_key)) -> dict:
    """Return the username for the current session."""
    auth = request.headers.get("authorization", "")
    username = "api"  # default for direct API key access
    if auth.startswith("Bearer "):
        token = auth[7:]
        r = request.app.state.redis
        try:
            stored = await r.get(f"{_SESSION_PREFIX}{token}")
            if stored:
                username = stored
        except redis.exceptions.RedisError:
            pass
    return {"username": username}
