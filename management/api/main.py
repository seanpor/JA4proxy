"""FastAPI application factory for the management UI.

This module is the entry point for the management service. It creates the
FastAPI application, wires all routes, mounts templates and static files,
and manages the Redis connection lifecycle via the lifespan context manager.

Usage (as a module)
-------------------
    uvicorn management.api.main:app --host 0.0.0.0 --port 8090

Usage (programmatic — for testing)
-----------------------------------
    from management.api.main import create_app
    app = create_app()

Architecture
------------
- Single FastAPI service serves both the HTML UI and the JSON API.
- All routes require JWT authentication (httpOnly cookie ``token``).
- Auth router handles /auth/login and /auth/logout (public).
- API routes live under /api/v1/.
- HTML pages live under / (served by Jinja2).
- Static files served from /static.
- Redis connection managed via lifespan.
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import redis_client
from .auth import router as auth_router
from .middleware.csrf import CSRFMiddleware
from .routes import (
    audit,
    bans,
    canonical_lists,
    compliance,
    config_ops,
    connections,
    dial,
    events,
    health,
    lists,
    metrics,
    mfa_totp,
    nodes,
    pages,
    partials,
    threat_intel,  # phase-85
    tokens,
    webhooks,
)
from .routes import (
    oidc as oidc_routes,
)
from .routes import (
    saml as saml_routes,
)
from .routes import (
    webauthn as webauthn_routes,
)
from .routes.canonical_lists import migrate_legacy_entries

logger = logging.getLogger(__name__)

# Paths relative to this file's package location
_PACKAGE_DIR = Path(__file__).parent.parent  # management/
_TEMPLATES_DIR = _PACKAGE_DIR / "templates"
_STATIC_DIR = _PACKAGE_DIR / "static"


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage resource lifecycle: Redis connect on startup, close on shutdown."""
    # Only init Redis if not already injected (e.g. in tests)
    if redis_client.get_redis_client() is None:
        await redis_client.init_redis()

    # Migrate legacy plain SET entries to full Hash records
    r = redis_client.get_redis_client()
    if r is not None:
        for list_name in ("allowlist", "blocklist", "watchlist", "ip"):
            try:
                await migrate_legacy_entries(r, list_name)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "management | event=migration_error | list=%s | error=%s",
                    list_name,
                    exc,
                )

    logger.info("management | event=startup | service=management_ui")
    yield
    await redis_client.close_redis()
    logger.info("management | event=shutdown | service=management_ui")


def _is_production() -> bool:
    """True if ENVIRONMENT is set to a production-equivalent value."""
    env = os.environ.get("ENVIRONMENT", "").strip().lower()
    return env in {"production", "prod"}


def _enforce_no_test_mode_in_production() -> None:
    """Refuse to build the app when test-mode bypasses are armed in production.

    JA4PROXY-2026-0023 — MANAGEMENT_TEST_MODE=1 enables a hardcoded JWT secret
    and skips OIDC signature verification. These flags must never activate
    alongside ENVIRONMENT=production. If an operator (or attacker-controlled
    env) sets both, fail loudly at startup so the condition cannot go
    unnoticed.

    Phase 122 M-1: also refuses to start when MANAGEMENT_SAML_STRICT=false
    in production — SAML signature verification must not be disabled.
    """
    if _is_production() and os.environ.get("MANAGEMENT_TEST_MODE") == "1":
        raise RuntimeError(
            "refusing to start: ENVIRONMENT=production and MANAGEMENT_TEST_MODE=1 "
            "are mutually exclusive (test mode disables authentication checks). "
            "Unset MANAGEMENT_TEST_MODE or set ENVIRONMENT to dev/staging."
        )
    if (
        _is_production()
        and os.environ.get("MANAGEMENT_DISABLE_CSRF") == "1"
    ):
        raise RuntimeError(
            "refusing to start: ENVIRONMENT=production and MANAGEMENT_DISABLE_CSRF=1 "
            "are mutually exclusive (CSRF bypass is a test-only escape hatch)."
        )
    if (
        _is_production()
        and os.environ.get("MANAGEMENT_SAML_STRICT", "true").lower() != "true"
    ):
        raise RuntimeError(
            "refusing to start: ENVIRONMENT=production and MANAGEMENT_SAML_STRICT=false "
            "are mutually exclusive (SAML signature verification must not be disabled "
            "in production). Unset MANAGEMENT_SAML_STRICT or set it to 'true'."
        )


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI instance.
    """
    _enforce_no_test_mode_in_production()

    # Phase 122 C-1: disable OpenAPI docs in production to prevent
    # unauthenticated API surface reconnaissance.
    docs_url = None if _is_production() else "/api/docs"
    redoc_url = None if _is_production() else "/api/redoc"
    openapi_url = None if _is_production() else "/openapi.json"

    app = FastAPI(
        title="JA4proxy Management UI",
        description="Management interface for JA4proxy TLS security proxy",
        version="1.0.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=_lifespan,
    )

    # ── CORS (management UI is same-origin in production; wide open in dev) ──
    # Phase 122 H-1: validate origins — reject wildcard and non-HTTPS origins
    # in production when credentials are enabled.
    cors_origins_raw = os.environ.get("MANAGEMENT_CORS_ORIGINS", "http://localhost:8090")
    cors_origins = [o.strip() for o in cors_origins_raw.split(",") if o.strip()]
    if _is_production():
        for origin in cors_origins:
            if origin == "*":
                raise RuntimeError(
                    "refusing to start: MANAGEMENT_CORS_ORIGINS contains wildcard '*' "
                    "with allow_credentials=True in production. Specify explicit origins."
                )
            if origin.startswith("http://") and "localhost" not in origin and "127.0.0.1" not in origin:
                logger.warning(
                    "management | event=cors_insecure_origin | origin=%s | "
                    "recommendation=use HTTPS in production",
                    origin,
                )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["*"],
    )

    # phase-101 H8: CSRF double-submit + HMAC on /api/v1/* mutating routes
    app.add_middleware(CSRFMiddleware)

    # ── Templates ─────────────────────────────────────────────────────────────
    if _TEMPLATES_DIR.exists():
        templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
        pages.set_templates(templates)
        partials.set_templates(templates)
    else:
        logger.warning("management | event=templates_missing | path=%s", _TEMPLATES_DIR)

    # ── Static files ──────────────────────────────────────────────────────────
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ── Routers ───────────────────────────────────────────────────────────────
    # Public routes (no auth required)
    app.include_router(auth_router)
    app.include_router(mfa_totp.router)
    app.include_router(webauthn_routes.router)
    app.include_router(saml_routes.router)
    app.include_router(oidc_routes.router)

    # API routes (auth enforced per-route via Depends)
    app.include_router(health.router)
    app.include_router(dial.router)
    app.include_router(canonical_lists.router)
    app.include_router(lists.router)
    app.include_router(bans.router)
    app.include_router(events.router)
    app.include_router(config_ops.router)
    app.include_router(audit.router)
    app.include_router(partials.router)
    app.include_router(tokens.router)
    app.include_router(connections.router)
    app.include_router(nodes.router)
    app.include_router(webhooks.router)
    app.include_router(metrics.router)
    app.include_router(compliance.router)  # phase-84
    app.include_router(threat_intel.router)  # phase-85

    # HTML page routes (auth enforced per-route via Depends)
    app.include_router(pages.router)

    return app


# Module-level app instance for uvicorn
app = create_app()
