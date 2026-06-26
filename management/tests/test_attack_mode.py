"""Tests for Phase 247 Attack Mode API endpoints.

Tests cover: POST/DELETE/GET /api/v1/attack-mode
"""

import json

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_attack_mode_inactive(authenticated_client: AsyncClient) -> None:
    """GET returns active=false when key not set."""
    r = await authenticated_client.get("/api/v1/attack-mode")
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is False


@pytest.mark.asyncio
async def test_post_activate_attack_mode(authenticated_client: AsyncClient, fake_redis) -> None:
    """POST activates attack mode: dial set to 75, key stored with TTL."""
    r = await authenticated_client.post("/api/v1/attack-mode")
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is True
    assert data["dial"] == 75
    assert data["original_dial"] == 0
    assert data["reverts_at"] is not None

    # Verify Redis state.
    raw = await fake_redis.get("attack_mode:active")
    assert raw is not None
    stored = json.loads(raw)
    assert stored["original_dial"] == 0

    ttl = await fake_redis.ttl("attack_mode:active")
    assert 0 < ttl <= 14400

    dial_val = await fake_redis.get("config:dial")
    assert dial_val == "75"


@pytest.mark.asyncio
async def test_post_activate_idempotent(authenticated_client: AsyncClient, fake_redis) -> None:
    """Second POST returns current state without resetting TTL."""
    r1 = await authenticated_client.post("/api/v1/attack-mode")
    assert r1.status_code == 200

    r2 = await authenticated_client.post("/api/v1/attack-mode")
    assert r2.status_code == 200
    assert r2.json()["active"] is True
    assert "already active" in r2.json()["message"].lower()


@pytest.mark.asyncio
async def test_delete_restores_original_dial(authenticated_client: AsyncClient, fake_redis) -> None:
    """DELETE restores dial to original_dial, not always 0."""
    # Set dial to 50 first.
    await fake_redis.set("config:dial", "50")

    r_post = await authenticated_client.post("/api/v1/attack-mode")
    assert r_post.status_code == 200
    assert r_post.json()["original_dial"] == 50

    r_del = await authenticated_client.delete("/api/v1/attack-mode")
    assert r_del.status_code == 200
    data = r_del.json()
    assert data["active"] is False
    assert data["dial"] == 50

    # Verify Redis.
    assert await fake_redis.get("attack_mode:active") is None
    assert await fake_redis.get("config:dial") == "50"


@pytest.mark.asyncio
async def test_delete_when_not_active(authenticated_client: AsyncClient) -> None:
    """DELETE when not active returns 200 gracefully."""
    r = await authenticated_client.delete("/api/v1/attack-mode")
    assert r.status_code == 200
    assert r.json()["active"] is False


@pytest.mark.asyncio
async def test_get_shows_active_when_key_present(authenticated_client: AsyncClient, fake_redis) -> None:
    """GET returns active=true when attack_mode:active key exists."""
    await fake_redis.set(
        "attack_mode:active",
        json.dumps({"original_dial": 10, "activated_at": "2026-06-25T02:00:00+00:00"}),
        ex=14400,
    )
    r = await authenticated_client.get("/api/v1/attack-mode")
    assert r.status_code == 200
    data = r.json()
    assert data["active"] is True
    assert data["original_dial"] == 10
    assert data["reverts_at"] is not None


@pytest.mark.asyncio
async def test_post_requires_admin(test_client: AsyncClient, auth_cookie: dict) -> None:
    """POST requires admin role (auditor-only cookie should fail with 403)."""
    from management.api.auth import _create_access_token
    auditor_token = _create_access_token("admin", role="auditor")
    r = await test_client.post(
        "/api/v1/attack-mode",
        cookies={"token": auditor_token},
    )
    assert r.status_code in (401, 403)


@pytest.mark.asyncio
async def test_activate_writes_audit_log(authenticated_client: AsyncClient, fake_redis) -> None:
    """POST writes an audit log entry."""
    await authenticated_client.post("/api/v1/attack-mode")
    audit_raw = await fake_redis.lrange("management:audit_log", 0, 0)
    assert audit_raw, "Expected audit log entry"
    entry = json.loads(audit_raw[0])
    assert entry["action_type"] == "attack_mode.activated"


@pytest.mark.asyncio
async def test_deactivate_writes_audit_log(authenticated_client: AsyncClient, fake_redis) -> None:
    """DELETE writes an audit log entry."""
    await authenticated_client.post("/api/v1/attack-mode")
    await authenticated_client.delete("/api/v1/attack-mode")
    entries = [json.loads(e) for e in await fake_redis.lrange("management:audit_log", 0, -1)]
    action_types = [e["action_type"] for e in entries]
    assert "attack_mode.deactivated" in action_types
