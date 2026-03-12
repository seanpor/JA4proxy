"""Phase 13 — Management UI FastAPI Server.

Provides the REST API backend for the JA4Proxy management interface:
- Bearer token authentication with Redis-backed rate limiting
- Ban / CIDR management
- JA4 fingerprint intelligence (blacklist / whitelist / candidates)
- Blocking dial control with safety acknowledgement
- Security policy bypass management
- Configuration management (thresholds, country blocklist, feature flags)
- Audit log
- Server-Sent Events live feed
- Health and readiness endpoints
- Prometheus metrics via /metrics
- React SPA served from management/static/ (catch-all, mounted last)
"""

import asyncio
import ipaddress
import logging
import os
import sys
from typing import Any, Dict, Optional

import redis.asyncio as aioredis
import redis.exceptions as redis_exc
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from prometheus_fastapi_instrumentator import Instrumentator

from .models import BanAddRequest, BanEntry, BypassEntry, DialResponse, FingerprintEntry

logger = logging.getLogger("management")

# Legacy HTTPBearer instance (used by old-style routers that import `authenticate`)
_bearer_scheme = HTTPBearer(auto_error=False)


def _get_client_ip(request: Request) -> str:
    """Extract client IP, honouring X-Forwarded-For for proxy deployments."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _build_redis_client() -> aioredis.Redis:
    """Create a Redis client from the REDIS_URL environment variable.

    Defaults to redis://localhost:6379 for local development.
    The connection pool is lazy — no socket is opened until the first command.
    """
    url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    return aioredis.from_url(url, decode_responses=True)


async def authenticate(
    request: Request,
    authorization: Optional[str] = None,
) -> bool:
    """Legacy Bearer-token authentication used by older router modules.

    Newer routers use ``management.auth.require_api_key`` via FastAPI Depends.
    This function is kept for backwards compatibility with routers that call it
    directly with an ``Authorization`` header string.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[len("Bearer "):]
    configured_key = os.environ.get("UI_API_KEY", "")

    if not configured_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key not configured",
        )

    if token != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return True


async def create_app() -> FastAPI:
    """Build and return the configured FastAPI application.

    Raises SystemExit(1) if ``UI_API_KEY`` is not set in the environment —
    the server must not start without a key.
    """
    # ── Startup guard ────────────────────────────────────────────────────────
    if not os.environ.get("UI_API_KEY", ""):
        logger.critical(
            "management | event=startup_abort | reason=UI_API_KEY_not_set"
        )
        sys.exit(1)

    # ── App creation ─────────────────────────────────────────────────────────
    app = FastAPI(
        title="JA4Proxy Management UI",
        description="Enterprise management interface for JA4Proxy",
        version="13.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # ── Redis ────────────────────────────────────────────────────────────────
    # Connection pool is lazy; no actual socket opened here.
    # Tests override app.state.redis immediately after create_app() returns.
    app.state.redis = await _build_redis_client()

    # ── Runtime configuration ─────────────────────────────────────────────────
    app.state.config = {
        "management_ui": {
            "allowed_cidr": os.environ.get("MANAGEMENT_ALLOWED_CIDR", ""),
            "max_sse_subscribers": int(os.environ.get("MAX_SSE_SUBSCRIBERS", "50")),
            "max_dial_changes_per_hour": int(os.environ.get("MAX_DIAL_CHANGES_PER_HOUR", "10")),
            "max_auth_failures_per_minute": int(os.environ.get("MAX_AUTH_FAILURES_PER_MINUTE", "10")),
        }
    }

    # ── Allowed-CIDR middleware ───────────────────────────────────────────────
    @app.middleware("http")
    async def enforce_allowed_cidr(request: Request, call_next):
        """Block requests from outside the configured management CIDR.

        Health and readiness endpoints are always exempt so load-balancers can
        probe them without network restrictions.
        """
        if request.url.path in ("/health", "/ready", "/metrics"):
            return await call_next(request)

        allowed_cidr = app.state.config["management_ui"].get("allowed_cidr", "")
        if allowed_cidr:
            client_ip = _get_client_ip(request)
            try:
                network = ipaddress.ip_network(allowed_cidr, strict=False)
                addr = ipaddress.ip_address(client_ip)
                if addr not in network:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Access denied: IP not in allowed CIDR"},
                    )
            except ValueError:
                # Malformed CIDR in config — fail open (don't lock out operators)
                pass

        return await call_next(request)

    # ── Security headers ─────────────────────────────────────────────────────
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        # CSP: allow inline scripts/styles needed by the React SPA
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'"
        )
        return response

    # ── CORS ─────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Global Redis error handler ────────────────────────────────────────────
    @app.exception_handler(redis_exc.RedisError)
    async def _redis_error_handler(request: Request, exc: redis_exc.RedisError):
        return JSONResponse(
            status_code=503,
            content={"detail": "Redis unavailable"},
        )

    # ── Prometheus instrumentation ───────────────────────────────────────────
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")

    # ── API routers ───────────────────────────────────────────────────────────
    # IMPORTANT: routers must be included BEFORE mounting StaticFiles at "/".
    # Starlette matches routes in insertion order; a catch-all mount at "/"
    # would intercept every request if registered first.
    from management.routers import (  # noqa: PLC0415
        audit,
        auth,
        bans,
        config,
        dial,
        events,
        fingerprints,
        health,
        integrations,
        policy,
    )

    app.include_router(auth.router, prefix="/api/v1", tags=["auth"])
    app.include_router(bans.router, prefix="/api/v1", tags=["bans"])
    app.include_router(dial.router, prefix="/api/v1", tags=["dial"])
    app.include_router(policy.router, prefix="/api/v1", tags=["policy"])
    app.include_router(fingerprints.router, prefix="/api/v1", tags=["fingerprints"])
    app.include_router(config.router, prefix="/api/v1", tags=["config"])
    app.include_router(integrations.router, prefix="/api/v1", tags=["integrations"])
    app.include_router(audit.router, prefix="/api/v1", tags=["audit"])
    app.include_router(events.router, prefix="/api/v1", tags=["events"])
    app.include_router(health.router, tags=["health"])

    # ── React SPA static files (mounted last — catch-all) ────────────────────
    from fastapi.staticfiles import StaticFiles  # noqa: PLC0415

    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount(
            "/",
            StaticFiles(directory=static_dir, html=True),
            name="static",
        )

    return app


if __name__ == "__main__":
    import uvicorn

    _app = asyncio.run(create_app())
    uvicorn.run(
        _app,
        host="0.0.0.0",
        port=int(os.environ.get("MANAGEMENT_PORT", "8090")),
        log_level="info",
        access_log=True,
    )
