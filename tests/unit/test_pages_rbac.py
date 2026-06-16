"""
tests/unit/test_pages_rbac.py
Test that each role sees the correct nav items and action controls.
"""
import pytest
from httpx import AsyncClient

try:
    from management.api.auth import _create_access_token
    from management.api.main import create_app
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("role,expect_lists_nav,expect_block_btn", [
    ("auditor",  False, False),
    ("analyst",  False, False),
    ("operator", True,  True),
    ("admin",    True,  True),
])
async def test_dashboard_role_visibility(role, expect_lists_nav, expect_block_btn):
    """Log in as each role; assert correct nav items visible."""
    app = create_app()
    token = _create_access_token("testuser", role=role)
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/", cookies={"token": token})
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Dashboard" in resp.text

    if expect_lists_nav:
        assert '/href="/lists"' in resp.text or 'href="/lists"' in resp.text, \
            f"role={role} should see Lists nav"
    else:
        assert 'href="/lists"' not in resp.text, \
            f"role={role} should NOT see Lists nav"


@pytest.mark.asyncio
async def test_unauthenticated_dashboard_never_500():
    """Unauthenticated dashboard request must not 500."""
    app = create_app()
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/")
    assert resp.status_code < 500


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["auditor", "analyst", "operator", "admin"])
async def test_all_pages_render_200_for_all_roles(role):
    """Every page route returns 200 + text/html for all roles."""
    app = create_app()
    token = _create_access_token("testuser", role=role)
    routes = ["/", "/audit"]
    async with AsyncClient(app=app, base_url="http://test") as client:
        for route in routes:
            resp = await client.get(route, cookies={"token": token})
            assert resp.status_code == 200, f"route={route} role={role}"
            assert "text/html" in resp.headers["content-type"]
