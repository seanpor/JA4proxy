"""Tests for Phase 247 attack aggregation API.

Tests cover: GET /api/v1/attack/top
"""

import json
import time

import pytest
from httpx import AsyncClient


def _make_event(ip: str, score: int = 50, action: str = "flag", ja4: str = "t13d190900") -> str:
    """Return a JSON string for the 'event' field in the stream."""
    return json.dumps({
        "@timestamp": "2099-01-01T00:00:00Z",  # far future — always in window
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": ja4,
        "event.risk_score": score,
        "event.action": action,
    })


def _make_old_event(ip: str) -> str:
    """Return an event with a timestamp well outside the 300s window."""
    return json.dumps({
        "@timestamp": "2000-01-01T00:00:00Z",
        "source.ip": ip,
        "ja4proxy.fingerprint.ja4": "",
        "event.risk_score": 10,
        "event.action": "allow",
    })


@pytest.mark.asyncio
async def test_top_attackers_empty_stream(authenticated_client: AsyncClient) -> None:
    """Empty stream returns empty attackers list."""
    r = await authenticated_client.get("/api/v1/attack/top")
    assert r.status_code == 200
    data = r.json()
    assert data["attackers"] == []
    assert data["window_seconds"] == 300


@pytest.mark.asyncio
async def test_top_attackers_aggregates_by_ip(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """IPs with multiple events are counted correctly."""
    for i in range(3):
        await fake_redis.xadd("events:connection", {"event": _make_event("10.0.0.1", score=80)})
    await fake_redis.xadd("events:connection", {"event": _make_event("10.0.0.2", score=60)})

    r = await authenticated_client.get("/api/v1/attack/top")
    assert r.status_code == 200
    attackers = r.json()["attackers"]

    # Should be sorted by connection_count desc.
    assert len(attackers) == 2
    assert attackers[0]["ip"] == "10.0.0.1"
    assert attackers[0]["connection_count"] == 3
    assert attackers[0]["max_score"] == 80
    assert attackers[1]["ip"] == "10.0.0.2"
    assert attackers[1]["connection_count"] == 1


@pytest.mark.asyncio
async def test_old_events_excluded(authenticated_client: AsyncClient, fake_redis) -> None:
    """Events with timestamps outside the 300s window are not included."""
    await fake_redis.xadd("events:connection", {"event": _make_old_event("10.0.0.99")})

    r = await authenticated_client.get("/api/v1/attack/top")
    assert r.status_code == 200
    ips = [a["ip"] for a in r.json()["attackers"]]
    assert "10.0.0.99" not in ips


@pytest.mark.asyncio
async def test_banned_ip_shows_status(authenticated_client: AsyncClient, fake_redis) -> None:
    """Banned IP has current_status=banned and non-null ban_expires."""
    await fake_redis.xadd("events:connection", {"event": _make_event("10.0.0.5")})
    await fake_redis.set("ban:10.0.0.5", "test ban", ex=3600)

    r = await authenticated_client.get("/api/v1/attack/top")
    assert r.status_code == 200
    attackers = r.json()["attackers"]
    hit = next((a for a in attackers if a["ip"] == "10.0.0.5"), None)
    assert hit is not None
    assert hit["current_status"] == "banned"
    assert hit["ban_expires"] is not None


@pytest.mark.asyncio
async def test_active_ip_shows_status(authenticated_client: AsyncClient, fake_redis) -> None:
    """Active (not banned) IP has current_status=active and null ban_expires."""
    await fake_redis.xadd("events:connection", {"event": _make_event("10.0.0.6")})

    r = await authenticated_client.get("/api/v1/attack/top")
    assert r.status_code == 200
    attackers = r.json()["attackers"]
    hit = next((a for a in attackers if a["ip"] == "10.0.0.6"), None)
    assert hit is not None
    assert hit["current_status"] == "active"
    assert hit["ban_expires"] is None


@pytest.mark.asyncio
async def test_block_count_only_counts_blocking_actions(
    authenticated_client: AsyncClient, fake_redis
) -> None:
    """block_count counts block/ban/tarpit actions only."""
    await fake_redis.xadd("events:connection", {"event": _make_event("10.1.1.1", action="block")})
    await fake_redis.xadd("events:connection", {"event": _make_event("10.1.1.1", action="allow")})
    await fake_redis.xadd("events:connection", {"event": _make_event("10.1.1.1", action="flag")})

    r = await authenticated_client.get("/api/v1/attack/top")
    hit = next(a for a in r.json()["attackers"] if a["ip"] == "10.1.1.1")
    assert hit["block_count"] == 1
    assert hit["connection_count"] == 3


@pytest.mark.asyncio
async def test_redis_unavailable_returns_empty(
    test_client: AsyncClient, auth_cookie: dict, fake_redis
) -> None:
    """Redis read failure returns 200 with empty list (fail open)."""
    # Close the connection to simulate unavailability.
    await fake_redis.aclose()
    r = await test_client.get("/api/v1/attack/top", cookies=auth_cookie)
    assert r.status_code == 200
    assert r.json()["attackers"] == []
