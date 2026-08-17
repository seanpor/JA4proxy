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

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..tasks.dial_revert import run_dial_revert_poller
from . import redis_client
from .auth import router as auth_router
from .environment import is_explicit_nonproduction, is_production
from .middleware.csrf import CSRFMiddleware
from .routes import (
    attack,  # phase-247
    attack_mode,  # phase-247
    audit,
    bans,
    canonical_lists,
    compliance,
    config_ops,
    connections,
    dial,
    edl,  # phase-316e
    events,
    health,
    lists,
    metrics,
    mfa_totp,
    nodes,
    pages,
    partials,
    snapshots,
    threat_intel,  # phase-85
    tokens,
    webhooks,
)
from .routes import datacenter_policy as datacenter_policy_routes  # phase-249
from .routes import (
    offense as offense_routes,  # phase-248
)
from .routes import (
    oidc as oidc_routes,
)
from .routes import (
    saml as saml_routes,
)
from .routes import (
    tls_health as tls_health_routes,
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

    # Phase 237: start dial revert poller
    poller = asyncio.create_task(run_dial_revert_poller(redis_client.get_redis_client))

    logger.info("management | event=startup | service=management_ui")
    yield
    poller.cancel()
    await redis_client.close_redis()
    logger.info("management | event=shutdown | service=management_ui")


def _enforce_no_test_mode_in_production() -> None:
    """Refuse to build the app when test-mode bypasses are armed in production.

    JA4PROXY-2026-0023 — MANAGEMENT_TEST_MODE=1 enables a hardcoded JWT secret
    and skips OIDC signature verification. These flags must never activate
    unless ENVIRONMENT is an explicit, known dev/test value. If an operator
    (or attacker-controlled env) sets both, fail loudly at startup so the
    condition cannot go unnoticed.

    JA4PROXY-2026-0093 (phase-521) — ``is_production()`` used to return False
    for anything other than exactly ``production``/``prod``, so this guard
    was a no-op for an unset or unrecognised ENVIRONMENT (e.g. a DMZ
    deployment with ENVIRONMENT unset or "dmz"). ``is_production()`` now
    treats every non-explicit-dev/test value as production, so the guard
    fires there too.

    Phase 122 M-1: also refuses to start when MANAGEMENT_SAML_STRICT=false
    in production — SAML signature verification must not be disabled.
    """
    if is_production() and os.environ.get("MANAGEMENT_TEST_MODE") == "1":
        raise RuntimeError(
            "refusing to start: ENVIRONMENT is not an explicit dev/test value and "
            "MANAGEMENT_TEST_MODE=1 is set — these are mutually exclusive (test "
            "mode disables authentication checks). Unset MANAGEMENT_TEST_MODE or "
            "set ENVIRONMENT to one of dev/development/test/testing/local/ci."
        )
    if (
        is_production()
        and os.environ.get("MANAGEMENT_DISABLE_CSRF") == "1"
    ):
        raise RuntimeError(
            "refusing to start: ENVIRONMENT is not an explicit dev/test value and "
            "MANAGEMENT_DISABLE_CSRF=1 is set — these are mutually exclusive "
            "(CSRF bypass is a test-only escape hatch)."
        )
    if (
        is_production()
        and os.environ.get("MANAGEMENT_SAML_STRICT", "true").lower() != "true"
    ):
        raise RuntimeError(
            "refusing to start: ENVIRONMENT is not an explicit dev/test value and "
            "MANAGEMENT_SAML_STRICT=false is set — these are mutually exclusive "
            "(SAML signature verification must not be disabled in production). "
            "Unset MANAGEMENT_SAML_STRICT or set it to 'true'."
        )


# JA4PROXY-2026-0096 — the quickstart docker-compose.yml ships this literal as
# the default MANAGEMENT_JWT_SECRET so `docker compose up` works out of the
# box. It is committed and public in this repository, so a deployment that
# never overrides it signs admin JWTs with a known key.
_QUICKSTART_JWT_SECRET = "ja4proxy-quickstart-secret-change-me"
_MIN_JWT_SECRET_LENGTH = 32


def _enforce_strong_secrets() -> None:
    """Refuse to boot on the committed quickstart secret / default password.

    JA4PROXY-2026-0096 — ``docker-compose.yml`` (the quickstart file an
    operator under incident pressure copies) defaults
    ``MANAGEMENT_JWT_SECRET`` to a literal that is public in this repo, and
    ``MANAGEMENT_ADMIN_PASSWORD`` to ``changeme``. Nothing previously
    refused to boot on those values, so a deployment that forgets to
    override them signs admin JWTs with a known key / accepts a known
    password. This compounds JA4PROXY-2026-0093's fail-open-by-default
    theme, so it reuses the same fail-closed rule: the guard is skipped
    only when ENVIRONMENT is an explicit dev/test value (the quickstart
    itself sets ``ENVIRONMENT=dev``, so `make start` / CI still boot).
    """
    if is_explicit_nonproduction():
        return

    secret = os.environ.get("MANAGEMENT_JWT_SECRET", "")
    if not secret:
        raise RuntimeError(
            "refusing to start: MANAGEMENT_JWT_SECRET is not set. Set it to a "
            "cryptographically random string (e.g. openssl rand -hex 32)."
        )
    if secret == _QUICKSTART_JWT_SECRET:
        raise RuntimeError(
            "refusing to start: MANAGEMENT_JWT_SECRET is still the committed "
            "quickstart default, which is public in this repository. Set it "
            "to a cryptographically random string (e.g. openssl rand -hex 32)."
        )
    if len(secret) < _MIN_JWT_SECRET_LENGTH:
        raise RuntimeError(
            f"refusing to start: MANAGEMENT_JWT_SECRET is shorter than "
            f"{_MIN_JWT_SECRET_LENGTH} characters. Set it to a cryptographically "
            f"random string (e.g. openssl rand -hex 32)."
        )

    if (
        not os.environ.get("MANAGEMENT_ADMIN_PASSWORD_HASH")
        and os.environ.get("MANAGEMENT_ADMIN_PASSWORD") == "changeme"
    ):
        raise RuntimeError(
            "refusing to start: MANAGEMENT_ADMIN_PASSWORD is still the "
            "quickstart default 'changeme'. Set MANAGEMENT_ADMIN_PASSWORD_HASH "
            "to a bcrypt hash (preferred) or MANAGEMENT_ADMIN_PASSWORD to a "
            "strong, unique password."
        )


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI instance.
    """
    _enforce_no_test_mode_in_production()
    _enforce_strong_secrets()

    # Phase 122 C-1: disable OpenAPI docs in production to prevent
    # unauthenticated API surface reconnaissance.
    docs_url = None if is_production() else "/api/docs"
    redoc_url = None if is_production() else "/api/redoc"
    openapi_url = None if is_production() else "/openapi.json"

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
    if is_production():
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

    # ── Prometheus instrumentation ───────────────────────────────────────────
    # management_ui_rules.yml has alerted on ja4proxy_mgmt_* for months with
    # nothing emitting them. See management/api/prometheus_metrics.py.
    import time as _time

    from starlette.responses import Response as _Response

    from . import prometheus_metrics as _m

    @app.middleware("http")
    async def _record_request_metrics(request, call_next):
        start = _time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # An unhandled exception is a 5xx from the client's point of view;
            # counting it only on the success path would hide the worst case.
            path = _m.normalise_path(request.url.path)
            _m.REQUESTS.labels(request.method, path, "5xx").inc()
            raise
        elapsed_ms = (_time.perf_counter() - start) * 1000.0
        path = _m.normalise_path(request.url.path)
        bucket = f"{response.status_code // 100}xx"
        _m.REQUESTS.labels(request.method, path, bucket).inc()
        _m.REQUEST_DURATION_MS.labels(request.method, path).observe(elapsed_ms)
        if response.status_code in (401, 403):
            _m.AUTH_FAILURES.labels("401" if response.status_code == 401 else "403").inc()
        return response

    @app.get("/metrics", include_in_schema=False)
    async def _prometheus_metrics() -> _Response:
        """Prometheus scrape endpoint.

        Unauthenticated, matching every other exporter on the internal
        monitoring network (analytics, node-exporter, redis-exporter). It
        exposes counters and latencies only — no request bodies, no identities,
        and paths are normalised so IDs never become label values.
        """
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return _Response(generate_latest(_m.REGISTRY), media_type=CONTENT_TYPE_LATEST)


    # ── Templates ─────────────────────────────────────────────────────────────
    if _TEMPLATES_DIR.exists():
        templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
        pages.set_templates(templates)
        partials.set_templates(templates)
        tls_health_routes.set_templates(templates)
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
    app.include_router(edl.router)  # phase-316e
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
    app.include_router(snapshots.router)  # phase-237
    app.include_router(tls_health_routes.router)  # phase-237
    app.include_router(attack_mode.router)  # phase-247
    app.include_router(attack.router)  # phase-247 / phase-250
    app.include_router(offense_routes.router)  # phase-248
    app.include_router(datacenter_policy_routes.router)  # phase-249

    # HTML page routes (auth enforced per-route via Depends)
    app.include_router(pages.router)

    return app


# Module-level app instance for uvicorn
app = create_app()
