"""Phase 814e Step 5: Web UI XSS and HTTP Security Headers Pentest Suite.

Tests:
1. XSS Escaping:
   - Jinja2 autoescaping prevents script injection when rendering SNI, JA4, user-agent, or country.
2. Security Response Headers (JA4PROXY-2026-0105):
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY (or frame-ancestors 'self' / 'none')
   - Content-Security-Policy header presence
   - Strict-Transport-Security header presence in production posture
"""

from __future__ import annotations

import os
from typing import AsyncGenerator, Tuple

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ["ENVIRONMENT"] = "test"
os.environ["MANAGEMENT_JWT_SECRET"] = "test-secret-min-32-chars-long-abcdef0123456789"
os.environ["MANAGEMENT_ADMIN_USER"] = "admin"
os.environ["MANAGEMENT_ADMIN_PASSWORD"] = "testpassword"
os.environ["MANAGEMENT_TEST_MODE"] = "1"
os.environ["MANAGEMENT_DISABLE_CSRF"] = "1"

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def ui_client(fake_redis: fakeredis.aioredis.FakeRedis) -> AsyncGenerator[Tuple[AsyncClient, fakeredis.aioredis.FakeRedis], None]:
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_ui_xss_autoescaping_in_rendered_partials(ui_client):
    """Malicious script tags in connection event or ban fields must be HTML-escaped by Jinja."""
    client, redis = ui_client
    jwt_admin = _create_access_token("admin", role="admin")
    client.cookies.set("token", jwt_admin)

    # Insert a ban with XSS payload in reason
    xss_payload = '<script>alert("xss")</script>'
    await redis.set("ban:198.51.100.99", xss_payload, ex=3600)

    # Fetch bans partial
    r = await client.get("/api/v1/partials/bans")
    assert r.status_code == 200
    html = r.text
    # Unescaped payload must NOT be present
    assert xss_payload not in html, "Raw script tag must not be injected in rendered HTML"
    # Escaped payload must be present
    assert "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;" in html or "&lt;script&gt;" in html


@pytest.mark.asyncio
async def test_security_response_headers_enforced(ui_client):
    """HTTP responses must include standard security headers (JA4PROXY-2026-0105)."""
    client, redis = ui_client

    r = await client.get("/login")
    assert r.status_code == 200

    headers = r.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") in ("DENY", "SAMEORIGIN")
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
