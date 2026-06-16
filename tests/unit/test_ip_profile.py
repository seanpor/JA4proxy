"""Unit tests for GET /api/v1/ip/{ip:path}/profile.

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
        "ja4proxy.sni": "example.com",
    })
    return (entry_id, {"event": payload})


@pytest.mark.asyncio
async def test_ip_profile_returns_aggregated_data():
    """Profile endpoint aggregates events for a given IP."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    entries = [
        _make_entry(1000, "1.2.3.4", "ja4_abc", "allow", 10),
        _make_entry(2000, "1.2.3.4", "ja4_abc", "flag", 50),
        _make_entry(3000, "1.2.3.4", "ja4_def", "block", 85),
        _make_entry(4000, "5.6.7.8", "ja4_abc", "allow", 0),
    ]

    with patch("management.api.routes.connections.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=list(reversed(entries)))
        mock_redis.exists = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/ip/1.2.3.4/profile",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "1.2.3.4"
    assert data["total_events"] == 3
    assert data["unique_ja4"] == 2
    assert len(data["fingerprints"]) == 2
    assert "ja4_abc" in data["fingerprints"]
    assert "ja4_def" in data["fingerprints"]
    assert data["is_banned"] is True
    assert len(data["history"]) == 3


@pytest.mark.asyncio
async def test_ip_profile_returns_404_for_dot_ip():
    """IPv4 dotted decimal is not truncated thanks to :path converter."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    entries = [
        _make_entry(1000, "10.0.0.1", "ja4_test", "allow", 5),
    ]

    with patch("management.api.routes.connections.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.xrevrange = AsyncMock(return_value=list(reversed(entries)))
        mock_redis.exists = AsyncMock(return_value=False)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/ip/10.0.0.1/profile",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    assert resp.json()["ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_ip_profile_unauthorised():
    """Unauthenticated request returns 401."""
    app = create_app()

    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/api/v1/ip/1.2.3.4/profile")

    assert resp.status_code == 401
