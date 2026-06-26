"""Tests for Phase 248 offense counter API endpoints.

Tests cover: GET/DELETE /api/v1/ip/{ip}/offense
"""

import json

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_offense_unknown_ip(authenticated_client: AsyncClient) -> None:
    """GET returns 0 for an IP with no offense key."""
    r = await authenticated_client.get("/api/v1/ip/1.2.3.4/offense")
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == "1.2.3.4"
    assert data["offense_count"] == 0
    assert data["current_action"] == "active"
    assert data["ban_expires"] is None


@pytest.mark.asyncio
async def test_get_offense_with_count(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """GET returns correct count when offense:{ip} key exists."""
    await fake_redis.set("offense:10.0.0.1", "5")
    r = await authenticated_client.get("/api/v1/ip/10.0.0.1/offense")
    assert r.status_code == 200
    assert r.json()["offense_count"] == 5


@pytest.mark.asyncio
async def test_get_offense_banned_ip(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """GET shows banned status when ban:{ip} key exists."""
    await fake_redis.set("offense:10.0.0.2", "7")
    await fake_redis.set("ban:10.0.0.2", '{"reason":"auto"}', ex=3600)
    r = await authenticated_client.get("/api/v1/ip/10.0.0.2/offense")
    data = r.json()
    assert data["offense_count"] == 7
    assert data["current_action"] == "banned"
    assert data["ban_expires"] is not None


@pytest.mark.asyncio
async def test_delete_resets_offense(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """DELETE removes the offense:{ip} key and returns count=0."""
    await fake_redis.set("offense:10.1.1.1", "9")
    r = await authenticated_client.delete("/api/v1/ip/10.1.1.1/offense")
    assert r.status_code == 200
    assert r.json()["offense_count"] == 0
    assert await fake_redis.get("offense:10.1.1.1") is None


@pytest.mark.asyncio
async def test_delete_writes_audit_log(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """DELETE writes an audit log entry."""
    await fake_redis.set("offense:10.2.2.2", "3")
    await authenticated_client.delete("/api/v1/ip/10.2.2.2/offense")
    entries = [
        json.loads(e)
        for e in await fake_redis.lrange("management:audit_log", 0, -1)
    ]
    assert any(e.get("action_type") == "offense.reset" for e in entries)


@pytest.mark.asyncio
async def test_invalid_ip_returns_422(authenticated_client: AsyncClient) -> None:
    """Invalid IP returns 422."""
    r = await authenticated_client.get("/api/v1/ip/not-an-ip/offense")
    assert r.status_code == 422
