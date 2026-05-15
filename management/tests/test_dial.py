"""TDD tests for the dial API endpoints.

Covers
------
- GET  /api/v1/dial — returns current value (default 0)
- PUT  /api/v1/dial — updates value, validates range, validates max ±10 change
- Audit log entry created on every PUT
- Requires authentication
"""

import json

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_dial_default(authenticated_client: AsyncClient) -> None:
    """GET /api/v1/dial returns 0 when no value is stored."""
    response = await authenticated_client.get("/api/v1/dial")
    assert response.status_code == 200
    data = response.json()
    assert data["value"] == 0


@pytest.mark.asyncio
async def test_get_dial_returns_stored_value(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """GET /api/v1/dial returns the value currently in Redis."""
    await fake_redis.set("config:dial", "42")
    response = await authenticated_client.get("/api/v1/dial")
    assert response.status_code == 200
    assert response.json()["value"] == 42


@pytest.mark.asyncio
async def test_put_dial_success(authenticated_client: AsyncClient) -> None:
    """PUT /api/v1/dial with a valid value updates the dial."""
    # First set to 10 so we can change by ≤ 10
    r1 = await authenticated_client.put("/api/v1/dial", json={"value": 10})
    assert r1.status_code == 200

    # Now update to 15 (change of +5, within ±10)
    r2 = await authenticated_client.put("/api/v1/dial", json={"value": 15})
    assert r2.status_code == 200
    assert r2.json()["value"] == 15

    # Verify GET reflects new value
    r3 = await authenticated_client.get("/api/v1/dial")
    assert r3.json()["value"] == 15


@pytest.mark.asyncio
async def test_put_dial_first_change_from_zero(
    authenticated_client: AsyncClient,
) -> None:
    """First dial change from 0 can go up to 10 (max ±10)."""
    response = await authenticated_client.put("/api/v1/dial", json={"value": 10})
    assert response.status_code == 200
    assert response.json()["value"] == 10


@pytest.mark.asyncio
async def test_put_dial_rejects_above_100(authenticated_client: AsyncClient) -> None:
    """PUT /api/v1/dial with value > 100 returns 422."""
    response = await authenticated_client.put("/api/v1/dial", json={"value": 101})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_put_dial_rejects_below_0(authenticated_client: AsyncClient) -> None:
    """PUT /api/v1/dial with value < 0 returns 422."""
    response = await authenticated_client.put("/api/v1/dial", json={"value": -1})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_put_dial_rejects_change_greater_than_10(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """PUT /api/v1/dial rejects a change of more than ±10 from current value."""
    await fake_redis.set("config:dial", "50")
    # Try to jump from 50 to 65 (change of +15)
    response = await authenticated_client.put("/api/v1/dial", json={"value": 65})
    assert response.status_code == 400
    assert "10" in response.json()["detail"]


@pytest.mark.asyncio
async def test_put_dial_rejects_decrease_greater_than_10(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """PUT /api/v1/dial rejects a decrease of more than 10."""
    await fake_redis.set("config:dial", "50")
    # Try to drop from 50 to 35 (change of -15)
    response = await authenticated_client.put("/api/v1/dial", json={"value": 35})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_put_dial_creates_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """PUT /api/v1/dial writes an audit log entry with old and new values."""
    await fake_redis.set("config:dial", "5")
    await authenticated_client.put("/api/v1/dial", json={"value": 10})

    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    # MFA/SSO Hardening C5: enhanced audit schema
    assert entry["action_type"] == "dial.changed"
    assert entry["before_value"]["value"] == 5
    assert entry["after_value"]["value"] == 10
    assert "timestamp" in entry
    assert "actor_id" in entry


@pytest.mark.asyncio
async def test_get_dial_requires_auth(test_client: AsyncClient) -> None:
    """GET /api/v1/dial without auth returns 401."""
    response = await test_client.get(
        "/api/v1/dial", headers={"Accept": "application/json"}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_put_dial_requires_auth(test_client: AsyncClient) -> None:
    """PUT /api/v1/dial without auth returns 401."""
    response = await test_client.put(
        "/api/v1/dial",
        json={"value": 10},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_dial_exact_10_change_allowed(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """A change of exactly ±10 is allowed."""
    await fake_redis.set("config:dial", "40")
    response = await authenticated_client.put("/api/v1/dial", json={"value": 50})
    assert response.status_code == 200
    assert response.json()["value"] == 50
