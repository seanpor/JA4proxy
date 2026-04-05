"""TDD tests for the health endpoint.

Covers
------
- GET /api/v1/health returns status, redis, proxy_instances, geoip, uptime_seconds
- Redis available → status=ok, redis=ok
- Redis unavailable → status=degraded, redis=unavailable (NOT 500)
- All fields present in response
- Public endpoint — no authentication required (used by Docker healthcheck)
"""

import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_health_returns_ok_with_redis(test_client: AsyncClient) -> None:
    """Health endpoint returns ok status when Redis is available."""
    r = await test_client.get("/api/v1/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["redis"] == "ok"


@pytest.mark.asyncio
async def test_health_response_has_all_fields(
    test_client: AsyncClient,
) -> None:
    """Health response includes all required fields."""
    r = await test_client.get("/api/v1/health")
    assert r.status_code == 200
    data = r.json()

    required_fields = {"status", "redis", "proxy_instances", "geoip", "uptime_seconds"}
    assert required_fields.issubset(set(data.keys()))


@pytest.mark.asyncio
async def test_health_uptime_is_positive(test_client: AsyncClient) -> None:
    """uptime_seconds is a non-negative number."""
    r = await test_client.get("/api/v1/health")
    data = r.json()
    assert data["uptime_seconds"] >= 0


@pytest.mark.asyncio
async def test_health_proxy_instances_is_int(test_client: AsyncClient) -> None:
    """proxy_instances is a non-negative integer."""
    r = await test_client.get("/api/v1/health")
    data = r.json()
    assert isinstance(data["proxy_instances"], int)
    assert data["proxy_instances"] >= 0


@pytest.mark.asyncio
async def test_health_redis_unavailable_returns_degraded(
    test_client: AsyncClient,
) -> None:
    """When Redis ping fails, health returns degraded but NOT 500."""
    from management.api import redis_client as rc
    from unittest.mock import AsyncMock

    # Patch the Redis client to raise on ping
    original = rc.get_redis_client()
    broken_mock = AsyncMock()
    broken_mock.ping.side_effect = Exception("Redis connection refused")
    broken_mock.keys.side_effect = Exception("Redis connection refused")
    rc._redis_client = broken_mock

    try:
        r = await test_client.get("/api/v1/health")
    finally:
        rc._redis_client = original

    # Should NOT be 500 — must fail open
    assert r.status_code == 200
    data = r.json()
    assert data["redis"] == "unavailable"
    assert data["status"] == "degraded"


@pytest.mark.asyncio
async def test_health_is_public(test_client: AsyncClient) -> None:
    """Health endpoint is public — no auth token needed (used by Docker healthcheck)."""
    r = await test_client.get(
        "/api/v1/health", headers={"Accept": "application/json"}
    )
    assert r.status_code == 200, (
        f"Health endpoint returned {r.status_code}; expected 200. "
        "Docker healthcheck calls /api/v1/health without a token — it must be public."
    )


@pytest.mark.asyncio
async def test_health_geoip_field_present(test_client: AsyncClient) -> None:
    """geoip field is present in the response."""
    r = await test_client.get("/api/v1/health")
    data = r.json()
    assert "geoip" in data
    # Value can be "ok" or "unavailable"
    assert data["geoip"] in ("ok", "unavailable")
