"""Tests for Phase 247 Attack Mode API endpoints."""

import json

import pytest

try:
    from management.api.main import create_app  # noqa: F401
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


@pytest.mark.asyncio
async def test_get_attack_mode_inactive(auditor_client, fake_redis):
    """GET returns active=false when key not set."""
    r = await auditor_client.get("/api/v1/attack-mode")
    assert r.status_code == 200
    assert r.json()["active"] is False


@pytest.mark.asyncio
async def test_post_activate_attack_mode(admin_client, fake_redis):
    """POST activates attack mode: dial set to 75, key stored with TTL."""
    r = await admin_client.post("/api/v1/attack-mode")
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is True
    assert data["dial"] == 75
    assert data["original_dial"] == 0
    assert data["reverts_at"] is not None

    raw = await fake_redis.get("attack_mode:active")
    assert raw is not None
    assert json.loads(raw)["original_dial"] == 0

    ttl = await fake_redis.ttl("attack_mode:active")
    assert 0 < ttl <= 14400

    assert await fake_redis.get("config:dial") == "75"


@pytest.mark.asyncio
async def test_post_activate_idempotent(admin_client, fake_redis):
    """Second POST returns current state without error."""
    await admin_client.post("/api/v1/attack-mode")
    r2 = await admin_client.post("/api/v1/attack-mode")
    assert r2.status_code == 200
    assert r2.json()["active"] is True
    assert "already active" in r2.json()["message"].lower()


@pytest.mark.asyncio
async def test_delete_restores_original_dial(admin_client, fake_redis):
    """DELETE restores dial to original_dial, not always 0."""
    await fake_redis.set("config:dial", "50")

    r_post = await admin_client.post("/api/v1/attack-mode")
    assert r_post.json()["original_dial"] == 50

    r_del = await admin_client.delete("/api/v1/attack-mode")
    assert r_del.status_code == 200
    data = r_del.json()
    assert data["active"] is False
    assert data["dial"] == 50

    assert await fake_redis.get("attack_mode:active") is None
    assert await fake_redis.get("config:dial") == "50"


@pytest.mark.asyncio
async def test_delete_when_not_active(admin_client, fake_redis):
    """DELETE when not active returns 200 gracefully."""
    r = await admin_client.delete("/api/v1/attack-mode")
    assert r.status_code == 200
    assert r.json()["active"] is False


@pytest.mark.asyncio
async def test_get_shows_active_when_key_present(auditor_client, fake_redis):
    """GET returns active=true when attack_mode:active key exists."""
    await fake_redis.set(
        "attack_mode:active",
        json.dumps({"original_dial": 10, "activated_at": "2026-06-25T02:00:00+00:00"}),
        ex=14400,
    )
    r = await auditor_client.get("/api/v1/attack-mode")
    data = r.json()
    assert data["active"] is True
    assert data["original_dial"] == 10
    assert data["reverts_at"] is not None


@pytest.mark.asyncio
async def test_post_requires_admin(auditor_client, fake_redis):
    """POST requires admin — auditor gets 403."""
    r = await auditor_client.post("/api/v1/attack-mode")
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_activate_writes_audit_log(admin_client, fake_redis):
    """POST writes an audit log entry."""
    await admin_client.post("/api/v1/attack-mode")
    entries = await fake_redis.lrange("management:audit_log", 0, -1)
    assert any(json.loads(e).get("action_type") == "attack_mode.activated"
               for e in entries)


@pytest.mark.asyncio
async def test_deactivate_writes_audit_log(admin_client, fake_redis):
    """DELETE writes an audit log entry."""
    await admin_client.post("/api/v1/attack-mode")
    await admin_client.delete("/api/v1/attack-mode")
    entries = [json.loads(e) for e in await fake_redis.lrange("management:audit_log", 0, -1)]
    assert any(e["action_type"] == "attack_mode.deactivated" for e in entries)
