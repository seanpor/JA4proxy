"""Shared pytest fixtures for management API tests.

Fixtures
--------
fake_redis        : FakeRedis async client — no real Redis required
auth_token        : Valid JWT token string
auth_cookie       : Dict suitable for use as cookies={"token": ...}
test_app          : FastAPI app with fake_redis injected
test_client       : HTTPX AsyncClient pointed at test_app (unauthenticated)
authenticated_client : HTTPX AsyncClient with auth cookie pre-set
"""

import os
from typing import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Set test-mode env vars before importing any management module
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import _create_access_token  # noqa: E402
from management.api.main import create_app  # noqa: E402

# JA4PROXY-2026-0021 — rate-limit state now lives in Redis, not a module-level
# dict. The per-test `fake_redis` fixture is isolated (fresh FakeServer per
# test), so no cross-test cleanup is needed for rate-limit keys.


@pytest.fixture(autouse=True)
def _stub_webhook_dns_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve any hostname to a single public IP during tests.

    JA4PROXY-2026-0007 added real DNS resolution inside the webhook URL
    validator. CI sandboxes and offline dev environments have no public DNS,
    so without a stub every test that creates a webhook with a hostname
    would flake. IP-literal checks (the actual SSRF surface) still run
    unpatched because they never call the resolver.
    """
    from management.api.routes import webhooks as _webhooks

    monkeypatch.setattr(_webhooks, "_resolve_host", lambda host: ["1.1.1.1"])


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Return a fresh FakeRedis async client for each test.

    Isolated: each test gets its own server instance so tests cannot
    interfere with each other.
    """
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest.fixture()
def auth_token() -> str:
    """Return a valid JWT token for the test admin user."""
    return _create_access_token("admin")


@pytest.fixture()
def auth_cookie(auth_token: str) -> dict[str, str]:
    """Return a cookie dict with a valid auth token."""
    return {"token": auth_token}


@pytest_asyncio.fixture()
async def test_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Unauthenticated HTTPX async client backed by a fresh FastAPI app."""
    app = create_app()

    # Inject fake Redis before the lifespan runs
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

    await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def authenticated_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
    auth_cookie: dict[str, str],
) -> AsyncGenerator[AsyncClient, None]:
    """Authenticated HTTPX async client with valid JWT cookie pre-set."""
    app = create_app()

    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=auth_cookie,
    ) as client:
        yield client

    await _redis_module.close_redis()
