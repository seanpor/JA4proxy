"""Tests for GET /api/v1/snapshot (shift handover snapshot)."""

import json

import pytest

try:
    from management.api.main import create_app
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


@pytest.mark.asyncio
async def test_snapshot_all_fields_present(operator_client):
    """Snapshot endpoint returns all required handover fields."""
    response = await operator_client.get("/api/v1/snapshot")
    assert response.status_code == 200
    data = response.json()

    required_fields = [
        "generated_at",
        "generated_by",
        "dial",
        "active_bans",
        "active_ban_count",
        "watchlist_count",
        "top_threats_1h",
        "active_analytics_findings",
        "system_health",
    ]
    for field in required_fields:
        assert field in data, f"Missing required field: {field}"

    assert "value" in data["dial"]
    assert "updated_at" in data["dial"]
    assert "redis" in data["system_health"]


@pytest.mark.asyncio
async def test_snapshot_requires_operator_role(auditor_client):
    """Auditor role must not be able to download the snapshot."""
    response = await auditor_client.get("/api/v1/snapshot")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_snapshot_shows_active_bans(operator_client, fake_redis):
    """Active bans appear in the snapshot."""
    await fake_redis.set("ban:203.0.113.42", "test ban reason", ex=3600)
    response = await operator_client.get("/api/v1/snapshot")
    assert response.status_code == 200
    data = response.json()
    assert data["active_ban_count"] >= 1
    ips = [b["ip"] for b in data["active_bans"]]
    assert "203.0.113.42" in ips


@pytest.mark.asyncio
async def test_snapshot_content_disposition(operator_client):
    """Response includes a Content-Disposition attachment header."""
    response = await operator_client.get("/api/v1/snapshot")
    assert response.status_code == 200
    cd = response.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "ja4proxy-snapshot" in cd
