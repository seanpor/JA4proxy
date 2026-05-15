"""JWT authentication for the management API.

Auth flow
---------
1. POST /auth/login  {username, password}
   → validates credentials (bcrypt or plain-text in dev mode)
   → creates JWT (8h expiry)
   → sets httpOnly cookie ``token``
   → redirects to /

2. Every protected endpoint uses ``get_current_user(request)`` dependency.
   → checks Authorization: Bearer <token> header first
   → falls through to ``token`` cookie if bearer not present or invalid
   → returns (username, Role) tuple

Security notes
--------------
* JWT secret loaded from ``MANAGEMENT_JWT_SECRET`` env var (required in prod).
* Admin user from ``MANAGEMENT_ADMIN_USER`` (default "admin").
* Password hash from ``MANAGEMENT_ADMIN_PASSWORD_HASH`` (bcrypt).
* For dev: plain ``MANAGEMENT_ADMIN_PASSWORD`` accepted when hash not set.
* Rate limiting: 5 consecutive failures per IP → 5-min lockout (Redis-backed
  so the limiter applies uniformly across all workers and survives restarts —
  JA4PROXY-2026-0021).
"""

import asyncio
import hashlib
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import bcrypt as _bcrypt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from jose import JWTError, jwt
from passlib.context import CryptContext

from .models import LoginRequest, Role
from .redis_client import get_redis

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

COOKIE_NAME = "token"
ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = 8
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 300  # 5 minutes

# JA4PROXY-2026-0021 — Redis-backed rate limiter keys. The previous
# implementation stored counters in a per-process dict, which was bypassed by
# distributed brute-force (each worker had its own fresh 5-attempt quota) and
# cleared on restart. The Redis keys make the counter cluster-wide and
# durable. `login_failures` is incremented per failed attempt; when it reaches
# MAX_LOGIN_FAILURES the `login_lockout` key is set with LOCKOUT_SECONDS TTL.
LOGIN_FAILURE_KEY_PREFIX = "mgmt:auth:login_failures:"
LOGIN_LOCKOUT_KEY_PREFIX = "mgmt:auth:login_lockout:"

# ── Password context ──────────────────────────────────────────────────────────

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Helper functions ──────────────────────────────────────────────────────────


def _is_production() -> bool:
    """True if ENVIRONMENT is set to a production-equivalent value."""
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    return env in {"production", "prod"}


def _should_set_secure_cookie(request: Request) -> bool:
    """Return True if the JWT cookie must carry the Secure attribute.

    JA4PROXY-2026-0024 — the login endpoint used to hardcode secure=False,
    so a production deploy behind TLS still sent the session cookie in
    plaintext when a downgraded request (or MITM-induced HTTP redirect)
    reached the app. Always mark the cookie Secure when either:
      - the current request arrived over HTTPS (same rule used by the
        OIDC / SAML callback handlers), OR
      - ENVIRONMENT is set to production / prod (defence in depth for
        deployments that terminate TLS upstream and forward over HTTP).
    """
    if request.url.scheme == "https":
        return True
    if _is_production():
        return True
    return False


def is_test_mode() -> bool:
    """Return True iff MANAGEMENT_TEST_MODE is on AND we are not in production.

    JA4PROXY-2026-0023 — the MANAGEMENT_TEST_MODE flag enables authentication
    bypasses (JWT secret default, OIDC signature skip). To prevent an attacker
    who can set env vars from silently disabling authentication, test mode
    MUST be ignored whenever ENVIRONMENT=production. The complementary
    startup guard in management.api.main.create_app raises RuntimeError if
    both flags are set simultaneously so operators cannot deploy a
    misconfigured container.
    """
    if _is_production():
        return False
    return os.environ.get("MANAGEMENT_TEST_MODE") == "1"


def _get_secret_key() -> str:
    """Return the JWT signing secret from environment.

    Raises:
        RuntimeError: If the secret is not configured and we are not in test mode.
    """
    secret = os.environ.get("MANAGEMENT_JWT_SECRET")
    if not secret:
        # JA4PROXY-2026-0023: only allow the test-only default when test mode
        # is active AND we are definitely not in production.
        if is_test_mode():
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

    logger.warning("auth | no admin password configured — all logins will fail")
    return False


def _create_access_token(username: str, role: str = "admin") -> str:
    """Create a signed JWT for *username* with an 8-hour expiry.

    Args:
        username: The subject claim (username or SSO NameID).
        role: The role to embed in the token (default ``"admin"`` for the
              hard-coded admin login; SSO flows pass the mapped role explicitly).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
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


async def _check_rate_limit(ip: str, redis) -> None:
    """Raise HTTP 429 if the IP is locked out.

    Checks the Redis lockout key's TTL. If Redis is unreachable the limiter
    fails open — the rest of the login flow already depends on Redis for
    bearer-token lookups, so a missing Redis is a wider outage than the
    login rate limiter alone.
    """
    try:
        ttl = await redis.ttl(f"{LOGIN_LOCKOUT_KEY_PREFIX}{ip}")
    except Exception as exc:  # pragma: no cover — fail-open branch
        logger.warning("auth | event=rate_limit_check_failed | ip=%s | err=%s", ip, exc)
        return

    # redis-py returns -2 for missing keys, -1 for keys with no TTL.
    if ttl is not None and ttl > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Locked out for {ttl}s.",
        )


async def _record_failure(ip: str, redis) -> None:
    """Increment Redis failure counter; lock out after MAX_LOGIN_FAILURES."""
    failure_key = f"{LOGIN_FAILURE_KEY_PREFIX}{ip}"
    lockout_key = f"{LOGIN_LOCKOUT_KEY_PREFIX}{ip}"
    try:
        count = await redis.incr(failure_key)
        if count == 1:
            # First failure — set TTL so abandoned counters drain.
            await redis.expire(failure_key, LOCKOUT_SECONDS)
        if count >= MAX_LOGIN_FAILURES:
            await redis.set(lockout_key, "1", ex=LOCKOUT_SECONDS)
            logger.warning(
                "auth | event=lockout | ip=%s | reason=too_many_failures", ip
            )
    except Exception as exc:  # pragma: no cover — fail-open branch
        logger.warning(
            "auth | event=rate_limit_record_failure_failed | ip=%s | err=%s",
            ip,
            exc,
        )


async def _record_success(ip: str, redis) -> None:
    """Clear failure state on successful login."""
    try:
        await redis.delete(
            f"{LOGIN_FAILURE_KEY_PREFIX}{ip}",
            f"{LOGIN_LOCKOUT_KEY_PREFIX}{ip}",
        )
    except Exception as exc:  # pragma: no cover — fail-open branch
        logger.warning(
            "auth | event=rate_limit_record_success_failed | ip=%s | err=%s",
            ip,
            exc,
        )


# ── Bearer token helper ───────────────────────────────────────────────────────


async def get_bearer_user(
    raw_token: str,
    redis,
) -> Optional[Tuple[str, Role]]:
    """Validate a raw bearer token against stored Redis hashes.

    Scans all token IDs in mgmt:token:idx and bcrypt-checks each.
    Acceptable for MFA/SSO Hardening where token counts are small (< 100).

    Args:
        raw_token: The raw bearer token string from the Authorization header.
        redis: The Redis client.

    Returns:
        ``(identity, role)`` tuple on match, ``None`` if no token matches.
    """
    try:
        token_ids = await redis.smembers("mgmt:token:idx")
    except Exception:
        return None

    for token_id in token_ids:
        try:
            fields = await redis.hgetall(f"mgmt:token:{token_id}")
        except Exception:
            continue

        if not fields:
            continue

        stored_hash = fields.get("hash", "")
        if not stored_hash:
            continue

        # bcrypt is CPU-bound — run off the event loop
        try:
            match = await asyncio.to_thread(
                _bcrypt.checkpw, raw_token.encode(), stored_hash.encode()
            )
        except Exception:
            continue

        if not match:
            continue

        # Check expiry
        expires_at_str = fields.get("expires_at", "")
        if expires_at_str:
            try:
                expires_dt = datetime.fromisoformat(expires_at_str)
                if expires_dt.tzinfo is None:
                    expires_dt = expires_dt.replace(tzinfo=timezone.utc)
                if expires_dt <= datetime.now(timezone.utc):
                    continue  # expired — treat as invalid
            except ValueError:
                pass  # malformed date; ignore

        # Update last_used_at (fire-and-forget)
        try:
            await redis.hset(
                f"mgmt:token:{token_id}",
                "last_used_at",
                datetime.now(timezone.utc).isoformat(),
            )
        except Exception:
            pass

        name = fields.get("name", token_id)
        role_str = fields.get("role", "operator")
        try:
            role = Role(role_str)
        except ValueError:
            role = Role.operator

        return (f"token:{name}", role)

    return None


# ── Dependency ────────────────────────────────────────────────────────────────


async def get_current_user(
    request: Request,
    token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    redis=Depends(get_redis),
) -> Tuple[str, Role]:
    """FastAPI dependency — returns (username, role) tuple.

    Checks Authorization: Bearer header first, then falls through to cookie JWT.
    For API calls (Accept: application/json) raises HTTP 401 on auth failure.
    For browser navigations redirects to /login.

    Args:
        request: The incoming HTTP request.
        token: The JWT extracted from the cookie.
        redis: The Redis client (injected for bearer token lookup).

    Returns:
        (username, Role) tuple.

    Raises:
        HTTPException(401): For API clients when auth fails.
        RedirectResponse(/login): For browser clients when auth fails.
    """
    # 1. Try bearer token first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header.split(" ", 1)[1]
        result = await get_bearer_user(raw_token, redis)
        if result is not None:
            return result
        # Bearer header present but token invalid — reject immediately.
        # Do NOT fall through to cookie auth: a presented but invalid bearer
        # credential must not silently authenticate via a fallback mechanism.
        return _unauthenticated_response(request)

    # 2. Fall through to cookie JWT (only when no Bearer header was sent)
    if token is not None:
        try:
            payload = _decode_token(token)
            username: Optional[str] = payload.get("sub")
            if username is not None:
                # JA4PROXY-2026-0034 — default to the least-privileged role
                # when the JWT carries no role claim or a role value we do
                # not recognise. The original code defaulted to Role.admin,
                # which turned every tampered / malformed token into a
                # privilege escalation. Role.auditor is read-only and
                # matches the fail-closed posture expected for a management
                # plane.
                raw_role = payload.get("role")
                if raw_role is None:
                    logger.warning(
                        "auth | event=jwt_role_missing | sub=%s | defaulting to auditor",
                        username,
                    )
                    cookie_role = Role.auditor
                else:
                    try:
                        cookie_role = Role(raw_role)
                    except ValueError:
                        logger.warning(
                            "auth | event=jwt_role_invalid | sub=%s | raw_role=%r | "
                            "defaulting to auditor",
                            username,
                            raw_role,
                        )
                        cookie_role = Role.auditor
                return (username, cookie_role)
        except HTTPException:
            pass

    return _unauthenticated_response(request)


_ROLE_ORDER = {
    Role.auditor: 0,
    Role.analyst: 1,
    Role.operator: 2,
    Role.admin: 3,
}


def require_role(minimum_role: Role):
    """Return a FastAPI dependency that enforces minimum_role.

    Args:
        minimum_role: The minimum role required to access the endpoint.

    Returns:
        A FastAPI dependency function that returns the current user tuple
        or raises HTTP 403 if the role is insufficient.
    """

    async def _check(
        current_user: Tuple[str, Role] = Depends(get_current_user),
    ) -> Tuple[str, Role]:
        identity, role = current_user
        if _ROLE_ORDER[role] < _ROLE_ORDER[minimum_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{role.value}' insufficient; "
                    f"'{minimum_role.value}' or higher required."
                ),
            )
        return current_user

    return _check


async def require_admin(
    current_user: Tuple[str, Role] = Depends(get_current_user),
) -> Tuple[str, Role]:
    """Dependency — requires admin role; raises 403 otherwise."""
    identity, role = current_user
    if _ROLE_ORDER[role] < _ROLE_ORDER[Role.admin]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return current_user


def mfa_session_key(jwt_token: str) -> str:
    """Return the Redis key for the MFA session state of *jwt_token*.

    Keyed on SHA-256 of the JWT string so MFA state is bound to the
    specific session token, not just the username.
    """
    digest = hashlib.sha256(jwt_token.encode()).hexdigest()
    return f"mgmt:mfa:session:{digest}"


async def require_mfa_verified(
    request: Request,
    token: Optional[str] = Cookie(default=None, alias=COOKIE_NAME),
    current_user: Tuple[str, Role] = Depends(get_current_user),
    redis=Depends(get_redis),
) -> Tuple[str, Role]:
    """FastAPI dependency — enforce MFA verification for cookie-JWT sessions.

    Bearer-token callers are exempt: API tokens are issued post-enrollment and
    convey pre-verified identity.  Only cookie-JWT sessions with TOTP enrolled
    are subject to this gate.

    Raises:
        HTTPException(403): If TOTP is enrolled but not yet verified this session.
    """
    # Bearer-token callers bypass the MFA gate
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return current_user

    # No session cookie → already rejected by get_current_user; nothing more to do
    if token is None:
        return current_user

    identity, _role = current_user
    # Strip "token:" prefix if present (shouldn't be for cookie sessions, but be safe)
    user_id = identity.removeprefix("token:")

    # Only gate users who have enrolled TOTP
    enrolled = await redis.exists(f"mgmt:totp:{user_id}")
    if not enrolled:
        return current_user

    # Enrolled: session must have completed verification
    verified = await redis.get(mfa_session_key(token))
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA verification required. POST /auth/mfa/totp/verify to proceed.",
        )

    return current_user


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
async def login(
    request: Request,
    response: Response,
    redis=Depends(get_redis),
) -> Response:
    """Validate credentials and set an httpOnly JWT cookie.

    On success: sets cookie and redirects to /.
    On failure: returns 401 JSON.
    """
    ip = _client_ip(request)
    await _check_rate_limit(ip, redis)

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
        await _record_failure(ip, redis)
        logger.warning(
            "auth | event=login_failed | ip=%s | username=%s", ip, creds.username
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    await _record_success(ip, redis)
    token_str = _create_access_token(creds.username)
    logger.info("auth | event=login_success | ip=%s | username=%s", ip, creds.username)

    resp = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=token_str,
        httponly=True,
        samesite="lax",
        secure=_should_set_secure_cookie(request),
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
