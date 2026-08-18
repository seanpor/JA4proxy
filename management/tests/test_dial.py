"""TDD tests for the dial API endpoints.

Covers
------
- GET  /api/v1/dial — returns current value (default 0)
- PUT  /api/v1/dial — updates value, validates range, validates max ±10 change
- POST /api/v1/dial/emergency — bypasses ±10 limit, requires auto-revert
- Audit log entry created on every PUT/POST
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
async def test_put_dial_respects_the_configured_cap(
    authenticated_client: AsyncClient,
    fake_redis,
    monkeypatch,
) -> None:
    """The cap is configurable (management.max_dial_change), not hardcoded 10.

    It WAS hardcoded at 10, which made every console preset unreachable:
    Monitor 0, Low 25, Mid 50 and High 75 are all >10 from a standing start, so
    the Apply button stayed disabled and the dial could not be moved at all.
    Default is now 100 (no step limit); these tests pin that the configured
    value is what gets enforced, whatever it is set to.
    """
    from management.api.routes import dial as dial_mod

    monkeypatch.setattr(dial_mod, "_max_dial_change", lambda: 10)
    await fake_redis.set("config:dial", "50")
    response = await authenticated_client.put("/api/v1/dial", json={"value": 65})
    assert response.status_code == 400
    assert "10" in response.json()["detail"]


@pytest.mark.asyncio
async def test_put_dial_allows_large_change_when_cap_is_high(
    authenticated_client: AsyncClient,
    fake_redis,
    monkeypatch,
) -> None:
    """With the default cap of 100, a preset-sized jump must succeed."""
    from management.api.routes import dial as dial_mod

    monkeypatch.setattr(dial_mod, "_max_dial_change", lambda: 100)
    await fake_redis.set("config:dial", "0")
    response = await authenticated_client.put("/api/v1/dial", json={"value": 75})
    assert response.status_code == 200, response.text
    assert response.json()["value"] == 75


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


# ── Emergency Dial Override (Phase 245.4) ────────────────────────────────────


@pytest.mark.asyncio
async def test_emergency_dial_with_value(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """POST /api/v1/dial/emergency bypasses the ±10 limit."""
    await fake_redis.set("config:dial", "0")
    response = await authenticated_client.post(
        "/api/v1/dial/emergency", json={"value": 75}
    )
    assert response.status_code == 200
    assert response.json()["value"] == 75
    assert await fake_redis.get("config:dial") == "75"


@pytest.mark.asyncio
async def test_emergency_dial_schedules_revert(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Emergency dial always schedules an auto-revert."""
    await fake_redis.set("config:dial", "10")
    await authenticated_client.post(
        "/api/v1/dial/emergency", json={"value": 80, "revert_after_hours": 2}
    )
    raw = await fake_redis.get("config:dial_override")
    assert raw is not None
    rec = json.loads(raw)
    assert rec["original_value"] == 10
    assert rec["override_value"] == 80


@pytest.mark.asyncio
async def test_emergency_dial_preset_block_known_bad(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Preset 'block_known_bad' sets dial to 50."""
    response = await authenticated_client.post(
        "/api/v1/dial/emergency", json={"preset": "block_known_bad"}
    )
    assert response.status_code == 200
    assert response.json()["value"] == 50


@pytest.mark.asyncio
async def test_emergency_dial_preset_active_defense(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Preset 'active_defense' sets dial to 75."""
    response = await authenticated_client.post(
        "/api/v1/dial/emergency", json={"preset": "active_defense"}
    )
    assert response.status_code == 200
    assert response.json()["value"] == 75


@pytest.mark.asyncio
async def test_emergency_dial_preset_lockdown(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Preset 'lockdown' sets dial to 90."""
    response = await authenticated_client.post(
        "/api/v1/dial/emergency", json={"preset": "lockdown"}
    )
    assert response.status_code == 200
    assert response.json()["value"] == 90


@pytest.mark.asyncio
async def test_emergency_dial_rejects_both_value_and_preset(
    authenticated_client: AsyncClient,
) -> None:
    """Cannot provide both value and preset."""
    response = await authenticated_client.post(
        "/api/v1/dial/emergency",
        json={"value": 50, "preset": "lockdown"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_emergency_dial_rejects_neither_value_nor_preset(
    authenticated_client: AsyncClient,
) -> None:
    """Must provide either value or preset."""
    response = await authenticated_client.post(
        "/api/v1/dial/emergency", json={}
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_emergency_dial_rejects_invalid_preset(
    authenticated_client: AsyncClient,
) -> None:
    """Unknown preset is rejected by validation."""
    response = await authenticated_client.post(
        "/api/v1/dial/emergency", json={"preset": "nuke_everything"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_emergency_dial_revert_hours_max_4(
    authenticated_client: AsyncClient,
) -> None:
    """revert_after_hours > 4 is rejected."""
    response = await authenticated_client.post(
        "/api/v1/dial/emergency",
        json={"value": 75, "revert_after_hours": 5},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_emergency_dial_creates_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Emergency dial writes an audit entry with action_type 'dial.emergency'."""
    await authenticated_client.post(
        "/api/v1/dial/emergency", json={"preset": "lockdown"}
    )
    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    assert entry["action_type"] == "dial.emergency"
    assert entry["after_value"]["preset"] == "lockdown"
    assert entry["after_value"]["value"] == 90


@pytest.mark.asyncio
async def test_emergency_dial_requires_auth(test_client: AsyncClient) -> None:
    """POST /api/v1/dial/emergency without auth returns 401."""
    response = await test_client.post(
        "/api/v1/dial/emergency",
        json={"value": 75},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401
