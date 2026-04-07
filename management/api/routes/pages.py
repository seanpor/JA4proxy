"""HTML page routes — serves Jinja2 templates for the management UI.

All page routes require authentication. Unauthenticated requests are
redirected to /login.

Templates are rendered from management/templates/ and are expected to
exist when this service is deployed. The template files are owned by
the frontend implementation agent — this module only wires the routes.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..auth import COOKIE_NAME, _decode_token, get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(tags=["pages"])

# Templates instance is set by main.py after mounting the templates directory
_templates: Optional[Jinja2Templates] = None


def set_templates(templates: Jinja2Templates) -> None:
    """Called by main.py to inject the Jinja2Templates instance."""
    global _templates
    _templates = templates


def _get_templates() -> Jinja2Templates:
    if _templates is None:
        raise RuntimeError("Templates not initialised. Call set_templates() first.")
    return _templates


def _get_optional_user(request: Request) -> Optional[str]:
    """Return the username if authenticated, None otherwise. Never raises."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        payload = _decode_token(token)
        return payload.get("sub")
    except Exception:  # noqa: BLE001
        return None


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    """Render the login page. If already authenticated, redirect to /."""
    user = _get_optional_user(request)
    if user:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/", status_code=302)

    templates = _get_templates()
    return templates.TemplateResponse(request, "login.html", {})


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the main dashboard page."""
    templates = _get_templates()
    return templates.TemplateResponse(request, "dashboard.html", {"user": current_user[0]})


@router.get("/lists", response_class=HTMLResponse)
async def lists_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the JA4 / IP list management page."""
    templates = _get_templates()
    return templates.TemplateResponse(request, "lists.html", {"user": current_user[0]})


@router.get("/bans", response_class=HTMLResponse)
async def bans_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the active bans management page."""
    templates = _get_templates()
    return templates.TemplateResponse(request, "bans.html", {"user": current_user[0]})


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the audit log page."""
    templates = _get_templates()
    return templates.TemplateResponse(request, "audit.html", {"user": current_user[0]})
