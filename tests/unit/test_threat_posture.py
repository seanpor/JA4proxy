"""
tests/unit/test_threat_posture.py
Unit tests for the /api/v1/partials/threat-posture endpoint.

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


def _make_stream_entry(ip, ja4, score, action, ts_ms=None):
    """Build a fake Redis stream entry matching the Go proxy's payload shape.

    The Go proxy writes a single 'event' field whose value is a JSON string
    of flat, dot-delimited ECS keys (cmd/ja4pd/main.go):
      event.action, event.risk_score, source.ip, ja4proxy.fingerprint.ja4, @timestamp
    """
    import time
    ts_ms = ts_ms or int(time.time() * 1000)
    entry_id = f"{ts_ms}-0"
    payload = json.dumps({
        "event.action": action,
        "event.risk_score": score,
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": ja4,
        "@timestamp": "2026-06-12T08:00:00Z",
    })
    fields = {"event": payload}
    return (entry_id, fields)


def _redis_override(mock_redis):
    """Return a FastAPI dependency override that yields mock_redis."""
    async def _override():
        yield mock_redis
    return _override


@pytest.mark.asyncio
async def test_top_n_ip_computation():
    """Top 10 IPs are sorted by max score, highest first."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    entries = []
    for i in range(15):
        entries.append(_make_stream_entry(
            ip=f"10.0.0.{i+1}",
            ja4="t13d1516h2_8daaf6152771_b1ff8ab2d16f",
            score=float(i * 5),
            action="allow",
        ))

    mock_redis = AsyncMock()
    mock_redis.xrevrange = AsyncMock(return_value=list(reversed(entries)))
    mock_redis.xlen = AsyncMock(return_value=15)
    mock_redis.hget = AsyncMock(return_value=None)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=15m",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    text = resp.text
    pos_highest = text.find("10.0.0.15")
    pos_second  = text.find("10.0.0.14")
    assert pos_highest != -1, "Highest-scoring IP must appear in response"
    assert pos_second != -1, "Second-highest-scoring IP must appear in response"
    assert pos_highest < pos_second, "Highest-scoring IP must appear before second-highest"


@pytest.mark.asyncio
async def test_invalid_window_defaults_to_15m():
    """An invalid window parameter falls back to 15m silently."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    mock_redis = AsyncMock()
    mock_redis.xrevrange = AsyncMock(return_value=[])
    mock_redis.xlen = AsyncMock(return_value=0)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=BOGUS",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_ja4_label_shown_when_present():
    """JA4 label from config:ja4_labels hash is shown in the rendered HTML."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")
    fp = "t13d1516h2_8daaf6152771_b1ff8ab2d16f"
    label = "Chrome 120 / Windows"

    entries = [_make_stream_entry("1.2.3.4", fp, 50, "flag")]

    mock_redis = AsyncMock()
    mock_redis.xrevrange = AsyncMock(return_value=entries)
    mock_redis.xlen = AsyncMock(return_value=1)
    mock_redis.hget = AsyncMock(return_value=label)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=15m",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert label in resp.text, "Human-readable JA4 label should appear in HTML"


@pytest.mark.asyncio
async def test_stream_depth_warning_shown_above_80k():
    """Stream depth warning badge appears when stream_depth > 80000."""
    app = create_app()
    token = _create_access_token("analyst", role="analyst")

    mock_redis = AsyncMock()
    mock_redis.xrevrange = AsyncMock(return_value=[])
    mock_redis.xlen = AsyncMock(return_value=85000)
    app.dependency_overrides[get_redis] = _redis_override(mock_redis)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/partials/threat-posture?window=15m",
                cookies={"token": token},
            )
    finally:
        app.dependency_overrides.clear()

    assert "⚠" in resp.text
