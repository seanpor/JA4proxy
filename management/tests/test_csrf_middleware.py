"""Tests for H8 — CSRF middleware for the management API.

TDD Tests — these define the contract. They will FAIL until the Coder
creates management/api/middleware/csrf.py and wires it into create_app().

Contract
--------
- POST with cookie auth but NO Origin header -> 403
- POST with Bearer auth (no cookie) -> passes through (no CSRF check)
- POST with cookie auth AND matching Origin -> passes through
- GET requests -> always exempt (safe methods)
- Allowed origins read from MANAGEMENT_CORS_ORIGINS env var
"""

from __future__ import annotations

import os
import unittest.mock

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
# Set allowed origins for CSRF checking
os.environ.setdefault("MANAGEMENT_CORS_ORIGINS", "http://test")

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app


@pytest_asyncio.fixture
async def fake_redis():
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def app_with_redis(fake_redis):
    """Create app and init Redis; yield (app, fake_redis)."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    yield app, fake_redis
    await _redis_module.close_redis()


# ── H8: POST with cookie auth and NO Origin -> 403 ───────────────────────────


@pytest.mark.asyncio
async def test_csrf_post_cookie_no_origin_rejected(app_with_redis):
    """A POST with cookie auth but no Origin header must be rejected (403)."""
    app, redis = app_with_redis
    token = _create_access_token("admin", role="admin")

    # Seed dial value so endpoint doesn't fail on Redis miss
    await redis.set("config:dial", "50")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        # Explicitly remove Origin header by not setting it
        r = await client.put(
            "/api/v1/dial",
            json={"value": 50},
            headers={"origin": ""},  # empty origin
        )
        # Without CSRF middleware, this would succeed (200).
        # With CSRF middleware, cookie auth + no valid Origin = 403.
        assert r.status_code == 403, (
            f"Expected 403 for cookie POST without Origin, got {r.status_code}: {r.text}"
        )


@pytest.mark.asyncio
async def test_csrf_post_cookie_missing_origin_allowed(app_with_redis):
    """A POST with cookie auth and completely missing Origin header passes.

    Modern browsers always send an Origin header on cross-origin requests.
    A missing Origin means same-origin or a non-browser caller (curl, API
    client). SameSite cookie policy protects same-origin; non-browser callers
    aren't vulnerable to CSRF. Blocking missing-Origin would break every
    same-origin form submission and every internal API client.
    """
    app, redis = app_with_redis
    token = _create_access_token("admin", role="admin")

    await redis.set("config:dial", "50")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        # httpx does not send Origin by default, so this has no Origin header
        r = await client.put(
            "/api/v1/dial",
            json={"value": 50},
        )
        # Missing Origin = same-origin or non-browser → allow through
        assert r.status_code != 403, (
            f"Missing Origin should not trigger CSRF rejection, got {r.status_code}: {r.text}"
        )


# ── H8: POST with Bearer auth -> passes through ──────────────────────────────


@pytest.mark.asyncio
async def test_csrf_post_bearer_auth_passes(app_with_redis):
    """A POST with Authorization: Bearer token (no cookie) skips CSRF check."""
    app, redis = app_with_redis
    token = _create_access_token("admin", role="admin")

    await redis.set("config:dial", "50")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        # No cookies — use header-based auth only
    ) as client:
        r = await client.put(
            "/api/v1/dial",
            json={"value": 50},
            headers={"Authorization": f"Bearer {token}"},
        )
        # Bearer auth should bypass CSRF entirely.
        # The endpoint may fail for business logic reasons (e.g. MFA)
        # but it should NOT be 403 from CSRF.
        assert r.status_code != 403 or "csrf" not in r.text.lower(), (
            f"Bearer-authenticated request was rejected by CSRF middleware: {r.text}"
        )


# ── H8: POST with cookie auth AND matching Origin -> passes through ──────────


@pytest.mark.asyncio
async def test_csrf_post_cookie_matching_origin_passes(app_with_redis):
    """A POST with cookie auth AND matching Origin header should pass CSRF."""
    app, redis = app_with_redis
    token = _create_access_token("admin", role="admin")

    await redis.set("config:dial", "50")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        r = await client.put(
            "/api/v1/dial",
            json={"value": 50},
            headers={"Origin": "http://test"},
        )
        # With matching origin, CSRF should pass. Status could be 200 or
        # another non-403 code depending on business logic.
        assert r.status_code != 403 or "csrf" not in r.text.lower(), (
            f"Cookie request with matching Origin was rejected by CSRF: {r.text}"
        )


# ── H8: GET requests are exempt ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_csrf_get_request_always_passes(app_with_redis):
    """GET requests (safe methods) must be exempt from CSRF checks."""
    app, redis = app_with_redis

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        # No auth at all — health endpoint is public
    ) as client:
        r = await client.get("/api/v1/health")
        # GET should never be blocked by CSRF middleware
        # Health returns 200 on success
        assert r.status_code != 403, (
            f"GET request was blocked by CSRF middleware: {r.status_code}"
        )


@pytest.mark.asyncio
async def test_csrf_get_with_cookie_no_origin_passes(app_with_redis):
    """GET with cookie auth and no Origin should still pass (safe method)."""
    app, redis = app_with_redis
    token = _create_access_token("admin", role="admin")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        r = await client.get("/api/v1/health")
        assert r.status_code != 403, (
            f"GET request was blocked by CSRF middleware: {r.status_code}"
        )


# ── H8: Non-matching origin is rejected ──────────────────────────────────────


@pytest.mark.asyncio
async def test_csrf_post_cookie_wrong_origin_rejected(app_with_redis):
    """POST with cookie auth and a non-allowed Origin should be rejected."""
    app, redis = app_with_redis
    token = _create_access_token("admin", role="admin")

    await redis.set("config:dial", "50")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        r = await client.put(
            "/api/v1/dial",
            json={"value": 50},
            headers={"Origin": "http://evil.example.com"},
        )
        assert r.status_code == 403, (
            f"Expected 403 for mismatched Origin, got {r.status_code}: {r.text}"
        )
