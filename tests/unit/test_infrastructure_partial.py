"""
tests/unit/test_infrastructure_partial.py
Unit tests for the /api/v1/partials/infrastructure endpoint.

These tests mock Redis so they do not require a running Redis instance.
"""
from unittest.mock import AsyncMock

import pytest
from httpx import AsyncClient, ASGITransport

try:
    from management.api.auth import _create_access_token
    from management.api.main import create_app
    from management.api.redis_client import get_redis
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


def _redis_override(mock_redis):
    async def _override():
        yield mock_redis
    return _override


@pytest.mark.asyncio
async def test_infrastructure_returns_200():
    """Infrastructure endpoint returns 200 + HTML."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    mock_redis = AsyncMock()
    mock_redis.info = AsyncMock(return_value={
        "used_memory": 1_000_000,
        "used_memory_human": "1.00M",
        "maxmemory": 8_000_000,
        "maxmemory_human": "8.00M",
        "total_system_memory": 16_000_000_000,
    })
    mock_redis.scan = AsyncMock(return_value=(0, []))
    mock_redis.get = AsyncMock(return_value=None)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/infrastructure",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_redis_memory_percentage_computed():
    """Redis memory usage percentage is computed and rendered."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    mock_redis = AsyncMock()
    mock_redis.info = AsyncMock(return_value={
        "used_memory": 4_000_000,
        "used_memory_human": "4.00M",
        "maxmemory": 8_000_000,
        "maxmemory_human": "8.00M",
    })
    mock_redis.scan = AsyncMock(return_value=(0, []))
    mock_redis.get = AsyncMock(return_value=None)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/infrastructure",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert "4.00M" in resp.text
    assert "8.00M" in resp.text
    assert "50.0" in resp.text


@pytest.mark.asyncio
async def test_proxy_shows_unknown_when_no_heartbeat():
    """Proxy shows 'Unknown' when no heartbeat keys exist (Phase 239 deferred)."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    mock_redis = AsyncMock()
    mock_redis.info = AsyncMock(return_value={
        "used_memory": 0,
        "used_memory_human": "0B",
        "maxmemory": 0,
        "maxmemory_human": "0B",
    })
    mock_redis.scan = AsyncMock(return_value=(0, []))
    mock_redis.get = AsyncMock(return_value=None)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/infrastructure",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert "Unknown" in resp.text


@pytest.mark.asyncio
async def test_proxy_shows_up_when_heartbeat_exists():
    """Proxy shows UP when heartbeat keys exist."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    mock_redis = AsyncMock()
    mock_redis.info = AsyncMock(return_value={
        "used_memory": 0,
        "used_memory_human": "0B",
        "maxmemory": 0,
    })
    mock_redis.scan = AsyncMock(return_value=(0, ["proxy:heartbeat:node1"]))
    mock_redis.ttl = AsyncMock(return_value=45)
    mock_redis.get = AsyncMock(return_value=None)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/infrastructure",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert "UP" in resp.text


@pytest.mark.asyncio
async def test_evictions_shown_when_nonzero():
    """Evictions count is shown when evicted_keys > 0."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    mock_redis = AsyncMock()
    mock_redis.info = AsyncMock(side_effect=[
        {"used_memory": 1_000_000, "used_memory_human": "1.00M", "maxmemory": 8_000_000},
        {"evicted_keys": 42},
    ])
    mock_redis.scan = AsyncMock(return_value=(0, []))
    mock_redis.get = AsyncMock(return_value=None)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/infrastructure",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert "42" in resp.text
