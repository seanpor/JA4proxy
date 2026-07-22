"""Tests for Compliance Reporting additions to GET /api/v1/connections.

Tests the ?until=, ?page_token=, and raised ?limit= parameters.

Quality bar
-----------
- ?until= excludes events AT OR AFTER the cutoff (exclusive upper bound).
- ?since= + ?until= together form a precise time window.
- Cursor-based pagination returns stable pages (new events don't affect existing cursor).
- limit > _MAX_LIMIT (10,000) is rejected with 422.
- since >= until is rejected with 422.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api import redis_client as _redis_module
from management.api.auth import _create_access_token
from management.api.main import create_app

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def analyst_client_redis():
    server = fakeredis.FakeServer()
    fake_r = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    app = create_app()
    await _redis_module.init_redis(override_client=fake_r)
    token = _create_access_token("analyst", role="analyst")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        yield client, fake_r
    await _redis_module.close_redis()


def _ts(year: int, month: int, day: int) -> str:
    return datetime(year, month, day, 12, 0, 0, tzinfo=timezone.utc).isoformat()


async def _seed_event(redis, ip: str, ts: str, action: str = "block") -> str:
    """Add one event to the stream. Returns the stream entry ID.

    Writes the ECS-dotted JSON-in-"event" format the Go proxy actually
    produces (management/api/routes/connections.py's _parse_entry()), not
    the flat-field legacy shape.
    """
    entry_id = await redis.xadd(
        "events:connection",
        {
            "event": json.dumps(
                {
                    "@timestamp": ts,
                    "source.ip": ip,
                    "ja4proxy.fingerprint.ja4": "t13abc",
                    "event.risk_score": 50,
                    "event.action": action,
                }
            )
        },
    )
    return entry_id


# ── ?until= filter ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_until_excludes_events_at_or_after_cutoff(analyst_client_redis):
    """Events with timestamp >= until must NOT appear in results."""
    client, redis = analyst_client_redis

    # Three events before March, two on or after March 1
    await _seed_event(redis, "1.1.1.1", _ts(2026, 1, 15))
    await _seed_event(redis, "2.2.2.2", _ts(2026, 2, 10))
    await _seed_event(redis, "3.3.3.3", _ts(2026, 2, 28))
    await _seed_event(redis, "4.4.4.4", _ts(2026, 3, 1))  # AT cutoff — excluded
    await _seed_event(redis, "5.5.5.5", _ts(2026, 4, 1))  # after cutoff — excluded

    r = await client.get("/api/v1/connections?until=2026-03-01T00:00:00Z&limit=100")
    assert r.status_code == 200

    data = r.json()
    returned_ips = {c["ip"] for c in data["connections"]}
    assert "4.4.4.4" not in returned_ips, "Event AT the cutoff was included"
    assert "5.5.5.5" not in returned_ips, "Event AFTER the cutoff was included"
    assert "1.1.1.1" in returned_ips
    assert "2.2.2.2" in returned_ips
    assert "3.3.3.3" in returned_ips
    assert data["count"] == 3


@pytest.mark.asyncio
async def test_since_and_until_form_precise_window(analyst_client_redis):
    """Only events strictly within [since, until) are returned."""
    client, redis = analyst_client_redis

    await _seed_event(redis, "jan", _ts(2026, 1, 15))
    await _seed_event(redis, "feb", _ts(2026, 2, 15))
    await _seed_event(redis, "mar", _ts(2026, 3, 15))
    await _seed_event(redis, "apr", _ts(2026, 4, 15))
    await _seed_event(redis, "may", _ts(2026, 5, 15))

    r = await client.get(
        "/api/v1/connections"
        "?since=2026-02-01T00:00:00Z"
        "&until=2026-04-01T00:00:00Z"
        "&limit=100"
    )
    assert r.status_code == 200

    data = r.json()
    ips = {c["ip"] for c in data["connections"]}
    assert ips == {"feb", "mar"}, f"Unexpected IPs in window: {ips}"


# ── Cursor-based pagination ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pagination_returns_correct_page_sizes(analyst_client_redis):
    """Pagination returns limit-sized pages and a next_page_token when has_more."""
    client, redis = analyst_client_redis

    # Seed 5 events
    for i in range(5):
        await _seed_event(redis, f"10.0.0.{i}", _ts(2026, 1, i + 1))

    # First page: limit=2
    r = await client.get("/api/v1/connections?limit=2")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 2
    assert data["has_more"] is True
    assert data["next_page_token"] is not None
    assert data["total_in_window"] == 5


@pytest.mark.asyncio
async def test_pagination_all_pages_cover_all_events(analyst_client_redis):
    """Iterating through all pages retrieves every event exactly once."""
    client, redis = analyst_client_redis

    # Seed 7 events
    all_ips = {f"10.{i}.0.0" for i in range(7)}
    for i, ip in enumerate(sorted(all_ips)):
        await _seed_event(redis, ip, _ts(2026, 1, i + 1))

    collected_ips: set[str] = set()
    page_token: str | None = None

    for _ in range(10):  # safety limit
        url = "/api/v1/connections?limit=3"
        if page_token:
            url += f"&page_token={page_token}"

        r = await client.get(url)
        assert r.status_code == 200
        data = r.json()

        for conn in data["connections"]:
            ip = conn["ip"]
            assert ip not in collected_ips, f"Duplicate IP {ip} in pagination"
            collected_ips.add(ip)

        page_token = data.get("next_page_token")
        if not data["has_more"]:
            break

    assert (
        collected_ips == all_ips
    ), f"Pagination missed events. Got {collected_ips}, expected {all_ips}"


@pytest.mark.asyncio
async def test_pagination_last_page_has_more_false(analyst_client_redis):
    """The final page has has_more=false and next_page_token=null."""
    client, redis = analyst_client_redis

    await _seed_event(redis, "1.1.1.1", _ts(2026, 1, 1))
    await _seed_event(redis, "2.2.2.2", _ts(2026, 1, 2))

    # Get first page
    r1 = await client.get("/api/v1/connections?limit=1")
    token = r1.json()["next_page_token"]

    # Get second (last) page
    r2 = await client.get(f"/api/v1/connections?limit=1&page_token={token}")
    data = r2.json()
    assert data["has_more"] is False
    assert data["next_page_token"] is None
    assert data["count"] == 1


@pytest.mark.asyncio
async def test_pagination_cursor_stable_after_new_events(analyst_client_redis):
    """Adding new events after getting a page_token must not change the next page."""
    client, redis = analyst_client_redis

    # Seed 4 events
    for i in range(4):
        await _seed_event(redis, f"1.0.0.{i}", _ts(2026, 1, i + 1))

    # Get first page
    r1 = await client.get("/api/v1/connections?limit=2")
    data1 = r1.json()
    assert data1["has_more"] is True
    token = data1["next_page_token"]
    first_page_ips = {c["ip"] for c in data1["connections"]}

    # Add new event AFTER getting the cursor
    await _seed_event(redis, "99.99.99.99", _ts(2026, 6, 1))

    # Get next page using the cursor
    r2 = await client.get(f"/api/v1/connections?limit=2&page_token={token}")
    data2 = r2.json()
    second_page_ips = {c["ip"] for c in data2["connections"]}

    # The new event should NOT appear in the second page (cursor is position-stable)
    assert (
        "99.99.99.99" not in second_page_ips
    ), "New event appeared in a paginated result set (cursor not stable)"
    # No overlap between pages
    assert first_page_ips.isdisjoint(second_page_ips), "Duplicate events across pages"


# ── Validation ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_limit_above_maximum_rejected(analyst_client_redis):
    """limit > 10,000 must return 422 Unprocessable Entity."""
    client, _ = analyst_client_redis
    r = await client.get("/api/v1/connections?limit=50000")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_until_before_since_rejected(analyst_client_redis):
    """since >= until must return 422 Unprocessable Entity."""
    client, _ = analyst_client_redis
    r = await client.get(
        "/api/v1/connections"
        "?since=2026-04-01T00:00:00Z"
        "&until=2026-01-01T00:00:00Z"
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_backwards_compatibility_truncated_field(analyst_client_redis):
    """The legacy 'truncated' field must still be present for backwards compatibility."""
    client, _ = analyst_client_redis
    r = await client.get("/api/v1/connections")
    assert r.status_code == 200
    assert "truncated" in r.json()
