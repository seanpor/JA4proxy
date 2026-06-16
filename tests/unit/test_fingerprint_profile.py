"""Unit tests for GET /api/v1/fingerprints/{ja4}/profile.

These tests mock Redis so they do not require a running Redis instance.
"""
import json
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

try:
    from management.api.auth import _create_access_token
    from management.api.main import create_app
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


def _make_entry(ts_ms, ip, ja4, action, score):
    """Build a Redis stream entry matching the Go proxy's event:connection format."""
    entry_id = f"{ts_ms}-0"
    payload = json.dumps({
        "@timestamp": "2026-06-15T12:00:00.000000+00:00",
        "event.action": action,
        "event.risk_score": score,
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": ja4,
    })
    return (entry_id, {"event": payload})


@pytest.mark.asyncio
async def test_fingerprint_profile_returns_aggregated_data():
    """Profile endpoint aggregates events for a given JA4 fingerprint."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    entries = [
        _make_entry(1000, "1.2.3.4", "ja4_test", "allow", 10),
        _make_entry(2000, "5.6.7.8", "ja4_test", "flag", 50),
        _make_entry(3000, "1.2.3.4", "ja4_test", "block", 90),
        _make_entry(4000, "9.9.9.9", "ja4_other", "allow", 0),
    ]

    with patch("management.api.routes.connections.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=list(reversed(entries)))
        mock_redis.exists = AsyncMock(return_value=False)
        mock_redis.sismember = AsyncMock(return_value=False)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/fingerprints/ja4_test/profile",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ja4"] == "ja4_test"
    assert data["total_events"] == 3
    assert data["unique_ips"] == 2
    assert len(data["ips_sample"]) == 2
    assert data["action_counts"]["allow"] == 1
    assert data["action_counts"]["flag"] == 1
    assert data["action_counts"]["block"] == 1
    assert data["is_banned"] is False
    assert data["is_allowlisted"] is False


@pytest.mark.asyncio
async def test_fingerprint_profile_empty():
    """Profile for a never-seen JA4 returns all zeros."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    with patch("management.api.routes.connections.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=[])
        mock_redis.exists = AsyncMock(return_value=False)
        mock_redis.sismember = AsyncMock(return_value=False)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/fingerprints/ja4_ghost/profile",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ja4"] == "ja4_ghost"
    assert data["total_events"] == 0
    assert data["unique_ips"] == 0
    assert data["ips_sample"] == []


@pytest.mark.asyncio
async def test_fingerprint_profile_unauthorised():
    """Unauthenticated request returns 401."""
    app = create_app()

    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/fingerprints/ja4_test/profile"
        )

    assert resp.status_code == 401
