"""HTML page routes — serves Jinja2 templates for the management UI.

All page routes require authentication. Unauthenticated requests are
redirected to /login.

Templates are rendered from management/templates/ and are expected to
exist when this service is deployed. The template files are owned by
the frontend implementation agent — this module only wires the routes.
"""

import logging
import urllib.parse
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..auth import COOKIE_NAME, _decode_token, get_current_user
from ..redis_client import get_redis

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


def _extract_user_and_role(current_user) -> tuple[str, str]:
    """Extract username and role string from the auth tuple.

    get_current_user() returns (username, Role). This helper unpacks the
    tuple and returns both values, converting Role to its string value
    so Jinja2 templates can use simple string comparisons.
    """
    username = current_user[0]
    role = current_user[1].value  # Role is a str Enum; .value gives 'auditor' etc.
    return username, role


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
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request, "dashboard.html", {"user": user, "role": role}
    )


@router.get("/lists", response_class=HTMLResponse)
async def lists_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the JA4 / IP list management page."""
    templates = _get_templates()
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request, "lists.html", {"user": user, "role": role}
    )


@router.get("/bans", response_class=HTMLResponse)
async def bans_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the active bans management page."""
    templates = _get_templates()
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request, "bans.html", {"user": user, "role": role}
    )


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the audit log page."""
    templates = _get_templates()
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request, "audit.html", {"user": user, "role": role}
    )


@router.get("/threat-intel", response_class=HTMLResponse)
async def threat_intel_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the Phase 85 threat intelligence feeds page."""
    templates = _get_templates()
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request, "threat_intel.html", {"user": user, "role": role}
    )


@router.get("/ip/{ip:path}", response_class=HTMLResponse)
async def ip_detail_page(
    request: Request,
    ip: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Render the forensics page for an IP address.

    Uses ``:path`` converter to preserve dots and colons in IPv4/IPv6.
    """
    templates = _get_templates()
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request,
        "ip_detail.html",
        {
            "user": user,
            "role": role,
            "ip": urllib.parse.unquote(ip),
        },
    )


@router.get("/intelligence-review", response_class=HTMLResponse)
async def intelligence_review_page(
    request: Request,
    current_user=Depends(get_current_user),
) -> HTMLResponse:
    """Render the Intelligence Review page (MEDIUM and LOW findings).

    Requires analyst or admin role. Auditors do not have access.
    Role check is done in the template (role is passed from current_user).
    """
    templates = _get_templates()
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request,
        "intelligence_review.html",
        {"user": user, "role": role},
    )


@router.get("/fingerprint/{ja4}", response_class=HTMLResponse)
async def fingerprint_detail_page(
    request: Request,
    ja4: str,
    current_user=Depends(get_current_user),
    redis=Depends(get_redis),
) -> HTMLResponse:
    """Render the forensics page for a JA4 fingerprint."""
    templates = _get_templates()
    user, role = _extract_user_and_role(current_user)
    return templates.TemplateResponse(
        request,
        "fingerprint.html",
        {
            "user": user,
            "role": role,
            "ja4": ja4,
        },
    )
