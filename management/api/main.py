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
from .routes import (
    audit,
    bans,
    config_ops,
    dial,
    events,
    health,
    lists,
    pages,
    partials,
)

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
    logger.info("management | event=startup | service=management_ui")
    yield
    await redis_client.close_redis()
    logger.info("management | event=shutdown | service=management_ui")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI instance.
    """
    app = FastAPI(
        title="JA4proxy Management UI",
        description="Management interface for JA4proxy TLS security proxy",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        lifespan=_lifespan,
    )

    # ── CORS (management UI is same-origin in production; wide open in dev) ──
    cors_origins = os.environ.get("MANAGEMENT_CORS_ORIGINS", "http://localhost:8090")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins.split(","),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    # ── Templates ─────────────────────────────────────────────────────────────
    if _TEMPLATES_DIR.exists():
        templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
        pages.set_templates(templates)
        partials.set_templates(templates)
    else:
        logger.warning(
            "management | event=templates_missing | path=%s", _TEMPLATES_DIR
        )

    # ── Static files ──────────────────────────────────────────────────────────
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ── Routers ───────────────────────────────────────────────────────────────
    # Public routes (no auth required)
    app.include_router(auth_router)

    # API routes (auth enforced per-route via Depends)
    app.include_router(health.router)
    app.include_router(dial.router)
    app.include_router(lists.router)
    app.include_router(bans.router)
    app.include_router(events.router)
    app.include_router(config_ops.router)
    app.include_router(audit.router)
    app.include_router(partials.router)

    # HTML page routes (auth enforced per-route via Depends)
    app.include_router(pages.router)

    return app


# Module-level app instance for uvicorn
app = create_app()
