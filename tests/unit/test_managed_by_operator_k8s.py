"""Phase 94a — Tests for the `operator_k8s` ManagedBy enum extension.

These tests verify:
1. POST /api/v1/allowlist with managed_by=operator_k8s returns 201.
2. GET /api/v1/allowlist?managed_by=operator_k8s returns only entries with that value.
3. All other enum values still work (regression).
"""

from __future__ import annotations

import os
from typing import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio

# Environment must be set before any management module import.
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from httpx import ASGITransport, AsyncClient  # noqa: E402

try:
    from management.api import redis_client as _redis_module
    from management.api.auth import _create_access_token
    from management.api.main import create_app
except ImportError:  # pragma: no cover
    pytest.skip(
        "Management API not importable; this test runs after Phase 79.",
        allow_module_level=True,
    )


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Fresh isolated FakeRedis async client per test."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


async def _make_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
    cookies: dict[str, str] | None = None,
) -> AsyncClient:
    """Build an httpx AsyncClient with redis pre-injected and cookies attached."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookies or {},
    )


@pytest_asyncio.fixture()
async def operator_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Operator-cookie-authenticated client (can write to allowlist)."""
    ac = await _make_client(
        fake_redis,
        cookies={"token": _create_access_token("op-user", role="operator")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest_asyncio.fixture()
async def auditor_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Auditor-cookie-authenticated client (can read allowlist)."""
    ac = await _make_client(
        fake_redis,
        cookies={"token": _create_access_token("audit-user", role="auditor")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


# ── Test 1: POST with managed_by=operator_k8s → 201 ─────────────────────────


@pytest.mark.asyncio
async def test_post_allowlist_with_operator_k8s_returns_201(
    operator_client: AsyncClient,
) -> None:
    """POST /api/v1/allowlist with managed_by=operator_k8s → 201."""
    body = {
        "entry": "t13d1516h2_aabbccddeeff_001122334455",
        "managed_by": "operator_k8s",
        "note": "K8s operator managed entry",
    }
    resp = await operator_client.post("/api/v1/allowlist", json=body)
    assert resp.status_code == 201, (
        f"Expected 201, got {resp.status_code}: {resp.text[:200]}"
    )
    data = resp.json()
    assert data["managed_by"] == "operator_k8s"
    assert data["entry"] == "t13d1516h2_aabbccddeeff_001122334455"


# ── Test 2: GET filter by managed_by=operator_k8s ────────────────────────────


@pytest.mark.asyncio
async def test_get_allowlist_filter_by_operator_k8s(
    operator_client: AsyncClient,
    auditor_client: AsyncClient,
) -> None:
    """GET /api/v1/allowlist?managed_by=operator_k8s returns only operator_k8s entries."""
    # Post two entries with different managed_by values
    entry_k8s = {
        "entry": "t13d1516h2_aabbccddeeff_001122334455",
        "managed_by": "operator_k8s",
        "note": "K8s operator entry",
    }
    entry_api = {
        "entry": "t13d1516h2_aabbccddeeff_112233445566",
        "managed_by": "api",
        "note": "API entry",
    }

    resp1 = await operator_client.post("/api/v1/allowlist", json=entry_k8s)
    assert resp1.status_code in (200, 201)

    resp2 = await operator_client.post("/api/v1/allowlist", json=entry_api)
    assert resp2.status_code in (200, 201)

    # Filter by operator_k8s
    resp = await auditor_client.get("/api/v1/allowlist?managed_by=operator_k8s")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["count"] >= 1
    for entry in data["entries"]:
        assert entry["managed_by"] == "operator_k8s", (
            f"Expected all entries to have managed_by=operator_k8s, got {entry['managed_by']}"
        )


# ── Test 3: Regression — all other enum values still work ────────────────────

_MANAGED_BY_VALUES = [
    "terraform",
    "operator",
    "api",
    "analytics",
    "legacy",
    "migration",
    "feed",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("managed_by", _MANAGED_BY_VALUES)
async def test_post_allowlist_existing_enum_values_still_work(
    operator_client: AsyncClient,
    managed_by: str,
) -> None:
    """POST /api/v1/allowlist with each existing managed_by value → 200 or 201."""
    body = {
        "entry": f"t13d1516h2_aabbccddeeff_{managed_by}",
        "managed_by": managed_by,
        "note": f"Regression test for {managed_by}",
    }
    resp = await operator_client.post("/api/v1/allowlist", json=body)
    assert resp.status_code in (200, 201), (
        f"Expected 200 or 201 for managed_by={managed_by}, got {resp.status_code}: {resp.text[:200]}"
    )
    data = resp.json()
    assert data["managed_by"] == managed_by
