"""
tests/unit/test_triage_queue.py
Unit tests for the /api/v1/partials/triage-queue endpoint.

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


def _make_stream_entry(ip, score, ts_ms=None):
    """Build a fake Redis stream entry matching the Go proxy's payload shape."""
    ts_ms = ts_ms or 1_746_000_000_000
    entry_id = f"{ts_ms}-0"
    payload = json.dumps({
        "event.action": "flag",
        "event.risk_score": score,
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": "t13d1516h2_8daaf6152771_b1ff8ab2d16f",
        "@timestamp": "2026-06-12T08:00:00Z",
    })
    fields = {"event": payload}
    return (entry_id, fields)


@pytest.mark.asyncio
async def test_triage_queue_returns_200():
    """Triage queue endpoint returns 200 + HTML."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.xrevrange = AsyncMock(return_value=[])
        mock_redis.smembers = AsyncMock(return_value=set())
        mock_redis.scan = AsyncMock(return_value=(0, []))
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/triage-queue",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_dismiss_returns_200():
    """Dismiss endpoint writes Redis key with 4h TTL and returns 200."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.set = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/triage/dismiss/1.2.3.4",
                cookies={"token": token},
            )

    assert resp.status_code == 200
    mock_redis.set.assert_called_once()
    args, kwargs = mock_redis.set.call_args
    assert "dismissed:triage:1.2.3.4" in args or "dismissed:triage:1.2.3.4" in kwargs.values()


@pytest.mark.asyncio
async def test_dismiss_invalid_ip_returns_400():
    """Dismiss with invalid IP returns 400."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/triage/dismiss/not-an-ip",
                cookies={"token": token},
            )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_dismissed_ip_excluded_from_queue():
    """An IP with dismissed:triage key is excluded from results."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    entries = [
        _make_stream_entry("10.0.0.1", 50, ts_ms=1_746_000_000_000),
        _make_stream_entry("10.0.0.2", 45, ts_ms=1_746_000_000_001),
    ]

    def get_side_effect(key):
        if key == "dismissed:triage:10.0.0.1":
            return "1"
        return None

    with patch("management.api.routes.partials.get_redis") as mock_get_redis:
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(side_effect=get_side_effect)
        mock_redis.xrevrange = AsyncMock(return_value=entries)
        mock_redis.smembers = AsyncMock(return_value=set())
        mock_redis.scan = AsyncMock(return_value=(0, []))
        mock_get_redis.return_value = mock_redis

        async with AsyncClient(app=app, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/triage-queue",
                cookies={"token": token},
            )

    assert "10.0.0.2" not in resp.text or "No IPs in the grey zone" in resp.text
