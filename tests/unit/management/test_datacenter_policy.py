"""Tests for Phase 249 datacenter policy API endpoints (CI-safe)."""

import pytest

try:
    from management.api.main import create_app  # noqa: F401
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


@pytest.mark.asyncio
async def test_get_returns_default_policy(auditor_client, fake_redis):
    """GET returns default policy when no Redis key is set."""
    r = await auditor_client.get("/api/v1/datacenter-policy")
    assert r.status_code == 200
    data = r.json()
    assert data["action"] == "score"
    assert isinstance(data["exceptions"], list)


@pytest.mark.asyncio
async def test_put_valid_action_score(admin_client, fake_redis):
    """PUT with valid action=score → 200."""
    r = await admin_client.put(
        "/api/v1/datacenter-policy",
        json={"action": "score"},
    )
    assert r.status_code == 200
    assert r.json()["action"] == "score"


@pytest.mark.asyncio
async def test_put_invalid_action_returns_422(admin_client, fake_redis):
    """PUT with invalid action → 422."""
    r = await admin_client.put(
        "/api/v1/datacenter-policy",
        json={"action": "nuke"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_put_writes_redis_key(admin_client, fake_redis):
    """PUT writes config:datacenter_policy to Redis."""
    import json
    r = await admin_client.put(
        "/api/v1/datacenter-policy",
        json={"action": "tarpit"},
    )
    assert r.status_code == 200
    stored = json.loads(await fake_redis.get("config:datacenter_policy"))
    assert stored["action"] == "tarpit"


@pytest.mark.asyncio
async def test_put_writes_audit_log(admin_client, fake_redis):
    """PUT writes audit log entry."""
    import json
    await admin_client.put(
        "/api/v1/datacenter-policy",
        json={"action": "block"},
    )
    entries = [
        json.loads(e)
        for e in await fake_redis.lrange("management:audit_log", 0, -1)
    ]
    assert any(e.get("action_type") == "datacenter_policy.updated" for e in entries)


@pytest.mark.asyncio
async def test_put_requires_admin(auditor_client, fake_redis):
    """PUT requires admin — auditor gets 403."""
    r = await auditor_client.put(
        "/api/v1/datacenter-policy",
        json={"action": "tarpit"},
    )
    assert r.status_code in (401, 403)
