"""Tests for dial auto-revert (Phase 237 Step B)."""

import json
import time

import pytest

try:
    from management.api.main import create_app
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


@pytest.mark.asyncio
async def test_revert_override_written_on_put(admin_client, fake_redis):
    """PUT /api/v1/dial with revert_after_hours writes config:dial_override."""
    await fake_redis.set("config:dial", "50")
    body = {"value": 75, "revert_after_hours": 2}
    resp = await admin_client.put("/api/v1/dial", json=body)
    assert resp.status_code == 200

    raw = await fake_redis.get("config:dial_override")
    assert raw is not None, "config:dial_override must be set"
    rec = json.loads(raw)
    assert rec["original_value"] == 50
    assert rec["override_value"] == 75
    assert rec["expires_at_epoch"] > int(time.time())


@pytest.mark.asyncio
async def test_revert_override_cleared_without_revert(admin_client, fake_redis):
    """PUT without revert_after_hours deletes any existing override."""
    await fake_redis.set("config:dial_override", json.dumps({
        "original_value": 0, "override_value": 75, "expires_at_epoch": 9999999999,
    }))
    body = {"value": 50}
    resp = await admin_client.put("/api/v1/dial", json=body)
    assert resp.status_code == 200

    raw = await fake_redis.get("config:dial_override")
    assert raw is None, "override must be deleted when no revert is requested"


@pytest.mark.asyncio
async def test_cancel_revert_endpoint(admin_client, fake_redis):
    """DELETE /api/v1/dial/revert removes the override record."""
    await fake_redis.set("config:dial_override", json.dumps({
        "original_value": 0, "override_value": 75, "expires_at_epoch": 9999999999,
    }))
    resp = await admin_client.delete("/api/v1/dial/revert")
    assert resp.status_code == 200

    raw = await fake_redis.get("config:dial_override")
    assert raw is None
