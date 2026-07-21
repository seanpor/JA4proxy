"""Unit tests for GET /api/v1/ip/{ip:path}/profile.

These tests mock Redis so they do not require a running Redis instance.
"""
import json
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

try:
    from management.api.auth import _create_access_token
    from management.api.main import create_app
    from management.api.redis_client import get_redis
except ImportError:
    pytest.skip("Management API not importable", allow_module_level=True)


def _make_entry(ts_ms, ip, ja4, action, score):
    """Build a Redis stream entry matching the Go proxy's event:connection format."""
    from datetime import datetime, timezone
    entry_id = f"{ts_ms}-0"
    # Use a timestamp within the last hour so the route's 24h cutoff doesn't filter it
    ts = datetime.now(timezone.utc).isoformat()
    payload = json.dumps({
        "@timestamp": ts,
        "event.action": action,
        "event.risk_score": score,
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": ja4,
        "ja4proxy.sni": "example.com",
    })
    return (entry_id, {"event": payload})


def _redis_override(mock_redis):
    async def _override():
        yield mock_redis
    return _override


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

    mock_redis = AsyncMock()
    mock_redis.xrevrange = AsyncMock(return_value=list(reversed(entries)))
    mock_redis.exists = AsyncMock(return_value=True)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/ip/1.2.3.4/profile",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

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

    mock_redis = AsyncMock()
    mock_redis.xrevrange = AsyncMock(return_value=list(reversed(entries)))
    mock_redis.exists = AsyncMock(return_value=False)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/ip/10.0.0.1/profile",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    assert resp.json()["ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_ip_profile_unauthorised():
    """Unauthenticated request returns 401."""
    app = create_app()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/v1/ip/1.2.3.4/profile")

    assert resp.status_code == 401
