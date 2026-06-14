"""TDD tests for HTML page routes — /login, /, /lists, /bans, /audit, /threat-intel.

These tests verify that every Jinja2-rendered page:
  1. Returns HTTP 200 with Content-Type text/html for authenticated requests.
  2. Contains at least one landmark string proving the correct template was
     rendered (not a redirect page or an error page).
  3. Returns 401 for unauthenticated requests (not 500 — a crash is worse
     than an auth failure).

Regression: these tests were absent in the initial TDD pass. The missing
coverage allowed a Starlette TemplateResponse API mismatch
(TemplateResponse(name, context) vs TemplateResponse(request, name, context))
to reach production undetected. Any change to page routes or templates must
keep all tests here green.
"""

import pytest
from httpx import AsyncClient


def _is_html(response) -> bool:
    return "text/html" in response.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# Login page (public — no auth required)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_page_renders(test_client: AsyncClient) -> None:
    """GET /login returns 200 with HTML (no auth needed)."""
    response = await test_client.get("/login")
    assert response.status_code == 200
    assert _is_html(
        response
    ), f"Expected text/html, got: {response.headers.get('content-type')}"


@pytest.mark.asyncio
async def test_login_page_contains_form(test_client: AsyncClient) -> None:
    """Login page must contain a password input field."""
    response = await test_client.get("/login")
    assert response.status_code == 200
    body = response.text
    assert "password" in body.lower(), "Login page must contain a password field"
    assert "username" in body.lower(), "Login page must contain a username field"


@pytest.mark.asyncio
async def test_login_page_contains_branding(test_client: AsyncClient) -> None:
    """Login page must contain JA4proxy branding."""
    response = await test_client.get("/login")
    assert "JA4" in response.text or "ja4" in response.text.lower()


# ---------------------------------------------------------------------------
# Dashboard (requires auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_renders(authenticated_client: AsyncClient) -> None:
    """GET / returns 200 with HTML for authenticated user."""
    response = await authenticated_client.get("/")
    assert response.status_code == 200
    assert _is_html(
        response
    ), f"Expected text/html, got: {response.headers.get('content-type')}"


@pytest.mark.asyncio
async def test_dashboard_contains_key_sections(
    authenticated_client: AsyncClient,
) -> None:
    """Dashboard must contain nav links and meaningful content."""
    response = await authenticated_client.get("/")
    body = response.text
    # Should contain at least the product name
    assert "JA4" in body or "ja4" in body.lower()


@pytest.mark.asyncio
async def test_dashboard_requires_auth(test_client: AsyncClient) -> None:
    """GET / without token must return 401, NOT 500."""
    response = await test_client.get("/")
    assert response.status_code == 401, (
        f"Unauthenticated / returned {response.status_code}; "
        "expected 401. A 500 means the route crashed before auth was checked."
    )


# ---------------------------------------------------------------------------
# Lists page (requires auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lists_page_renders(authenticated_client: AsyncClient) -> None:
    """GET /lists returns 200 with HTML."""
    response = await authenticated_client.get("/lists")
    assert response.status_code == 200
    assert _is_html(response)


@pytest.mark.asyncio
async def test_lists_page_contains_list_ui(authenticated_client: AsyncClient) -> None:
    """Lists page must reference fingerprint or allowlist concepts."""
    response = await authenticated_client.get("/lists")
    body = response.text.lower()
    assert any(
        word in body
        for word in ("whitelist", "blacklist", "allowlist", "fingerprint", "list")
    ), "Lists page must contain list management UI elements"


@pytest.mark.asyncio
async def test_lists_page_requires_auth(test_client: AsyncClient) -> None:
    """GET /lists without token must return 401, NOT 500."""
    response = await test_client.get("/lists")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Bans page (requires auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bans_page_renders(authenticated_client: AsyncClient) -> None:
    """GET /bans returns 200 with HTML."""
    response = await authenticated_client.get("/bans")
    assert response.status_code == 200
    assert _is_html(response)


@pytest.mark.asyncio
async def test_bans_page_contains_ban_ui(authenticated_client: AsyncClient) -> None:
    """Bans page must reference bans."""
    response = await authenticated_client.get("/bans")
    assert "ban" in response.text.lower()


@pytest.mark.asyncio
async def test_bans_page_requires_auth(test_client: AsyncClient) -> None:
    """GET /bans without token must return 401, NOT 500."""
    response = await test_client.get("/bans")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Audit page (requires auth)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_page_renders(authenticated_client: AsyncClient) -> None:
    """GET /audit returns 200 with HTML."""
    response = await authenticated_client.get("/audit")
    assert response.status_code == 200
    assert _is_html(response)


@pytest.mark.asyncio
async def test_audit_page_contains_audit_ui(authenticated_client: AsyncClient) -> None:
    """Audit page must reference audit or log concepts."""
    response = await authenticated_client.get("/audit")
    assert "audit" in response.text.lower() or "log" in response.text.lower()


@pytest.mark.asyncio
async def test_audit_page_requires_auth(test_client: AsyncClient) -> None:
    """GET /audit without token must return 401, NOT 500."""
    response = await test_client.get("/audit")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Threat-intel page (requires auth) — Phase 85 route
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_threat_intel_page_renders(authenticated_client: AsyncClient) -> None:
    """GET /threat-intel returns 200 with HTML."""
    response = await authenticated_client.get("/threat-intel")
    assert response.status_code == 200
    assert _is_html(response)


@pytest.mark.asyncio
async def test_threat_intel_page_contains_landmark(
    authenticated_client: AsyncClient,
) -> None:
    """Threat-intel page must render the threat_intel.html template landmark."""
    response = await authenticated_client.get("/threat-intel")
    assert "Threat Intelligence" in response.text


@pytest.mark.asyncio
async def test_threat_intel_page_requires_auth(test_client: AsyncClient) -> None:
    """GET /threat-intel without token must return 401, NOT 500."""
    response = await test_client.get("/threat-intel")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 401 quality gate: unauthenticated HTML pages must NEVER return 5xx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/lists", "/bans", "/audit", "/threat-intel"])
async def test_unauthenticated_page_never_crashes(
    test_client: AsyncClient, path: str
) -> None:
    """No page route may return a 5xx to an unauthenticated client.

    A 500 before auth runs means the route crashed during dependency resolution
    or template setup — auth didn't even get a chance to run. This is always a
    bug.
    """
    response = await test_client.get(path)
    assert response.status_code < 500, (
        f"GET {path} returned {response.status_code} to an unauthenticated "
        "client. Auth must run before any other code that can crash."
    )
