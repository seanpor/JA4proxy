"""Tests for management.compliance.purge.GDPRPurge.

Quality bar
-----------
- Every test verifies Redis STATE before and after the purge (not just return values).
- Tests check that PROTECTED data (active bans, recent events) is NOT deleted.
- Partial-error resilience: one failing category must not abort the others.
- Completion keys (last_run, last_summary) are verified as valid data, not just existence.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import pytest
import pytest_asyncio

from management.compliance.purge import GDPRPurge

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def redis_client():
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


def _old_stream_id() -> str:
    """Stream ID from 200 days ago (well outside any retention window)."""
    ts_ms = int((datetime.now(timezone.utc) - timedelta(days=200)).timestamp() * 1000)
    return f"{ts_ms}-0"


def _recent_stream_id() -> str:
    """Stream ID from 1 hour ago (within any reasonable retention window)."""
    ts_ms = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp() * 1000)
    return f"{ts_ms}-0"


def _old_epoch_ms() -> int:
    """Epoch ms from 200 days ago."""
    return int((datetime.now(timezone.utc) - timedelta(days=200)).timestamp() * 1000)


def _recent_epoch_ms() -> int:
    """Epoch ms from 1 hour ago."""
    return int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp() * 1000)


# ── Stream purge ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_stream_removes_old_events(redis_client):
    """Events with IDs older than the retention window are removed from the stream."""
    old_id = _old_stream_id()
    recent_id = _recent_stream_id()

    # Seed one old event and one recent event
    await redis_client.xadd("ja4proxy:events", {"ip": "1.2.3.4", "action_taken": "blocked"}, id=old_id)
    await redis_client.xadd("ja4proxy:events", {"ip": "5.6.7.8", "action_taken": "allowed"}, id=recent_id)

    assert await redis_client.xlen("ja4proxy:events") == 2

    purge = GDPRPurge(redis_client, {"connection_log_retention_days": 90})
    summary = await purge.run()

    assert await redis_client.xlen("ja4proxy:events") == 1
    assert summary.connection_events_deleted == 1
    # Verify the remaining event is the recent one (ip 5.6.7.8)
    remaining = await redis_client.xrange("ja4proxy:events")
    assert len(remaining) == 1
    assert remaining[0][1]["ip"] == "5.6.7.8"


@pytest.mark.asyncio
async def test_purge_stream_preserves_recent_events(redis_client):
    """Events within the retention window are not touched."""
    recent_id = _recent_stream_id()
    await redis_client.xadd("ja4proxy:events", {"ip": "1.2.3.4", "action_taken": "blocked"}, id=recent_id)

    before_count = await redis_client.xlen("ja4proxy:events")

    purge = GDPRPurge(redis_client, {"connection_log_retention_days": 90})
    summary = await purge.run()

    assert await redis_client.xlen("ja4proxy:events") == before_count
    assert summary.connection_events_deleted == 0


@pytest.mark.asyncio
async def test_purge_stream_empty_stream_no_error(redis_client):
    """Purging an empty stream is a no-op and returns 0 deleted."""
    purge = GDPRPurge(redis_client)
    summary = await purge.run()
    assert summary.connection_events_deleted == 0
    assert "stream" not in [e["category"] for e in summary.errors]


# ── Beaconing purge ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_beaconing_removes_old_entries(redis_client):
    """Old members in beacon sorted sets are removed."""
    old_ms = _old_epoch_ms()
    recent_ms = _recent_epoch_ms()
    key = "beacon:1.2.3.4:t13d1516h2"

    await redis_client.zadd(key, {f"ts:{old_ms}": old_ms})
    await redis_client.zadd(key, {f"ts:{recent_ms}": recent_ms})

    assert await redis_client.zcard(key) == 2

    purge = GDPRPurge(redis_client, {"analytics_retention_days": 90})
    summary = await purge.run()

    assert await redis_client.zcard(key) == 1
    assert summary.beaconing_records_cleaned >= 1
    # Confirm the remaining member has the recent score
    members = await redis_client.zrangebyscore(key, "-inf", "+inf", withscores=True)
    assert len(members) == 1
    assert members[0][1] == recent_ms


@pytest.mark.asyncio
async def test_purge_beaconing_preserves_recent_entries(redis_client):
    """Members within the retention window are untouched."""
    recent_ms = _recent_epoch_ms()
    key = "beacon:1.2.3.4:t13abc"
    await redis_client.zadd(key, {f"ts:{recent_ms}": recent_ms})

    purge = GDPRPurge(redis_client, {"analytics_retention_days": 90})
    summary = await purge.run()

    assert await redis_client.zcard(key) == 1
    assert summary.beaconing_records_cleaned == 0


# ── RV hash purge ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_rv_deletes_old_hash(redis_client):
    """rv:{ip} hash with first_seen older than retention is deleted."""
    await redis_client.hset("rv:1.2.3.4", "first_seen", "2020-01-01T00:00:00Z")
    await redis_client.hset("rv:1.2.3.4", "total", "5")

    purge = GDPRPurge(redis_client, {"analytics_retention_days": 90})
    summary = await purge.run()

    assert not await redis_client.exists("rv:1.2.3.4")
    assert summary.rv_hashes_deleted >= 1


@pytest.mark.asyncio
async def test_purge_rv_preserves_recent_hash(redis_client):
    """rv:{ip} hash with first_seen within retention window is not deleted."""
    recent_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    await redis_client.hset("rv:5.6.7.8", "first_seen", recent_ts)
    await redis_client.hset("rv:5.6.7.8", "total", "3")

    purge = GDPRPurge(redis_client, {"analytics_retention_days": 90})
    summary = await purge.run()

    assert await redis_client.exists("rv:5.6.7.8")
    assert summary.rv_hashes_deleted == 0


@pytest.mark.asyncio
async def test_purge_rv_no_first_seen_field_preserved(redis_client):
    """rv:{ip} hash with no first_seen field is preserved (age unknown)."""
    await redis_client.hset("rv:9.8.7.6", "total", "1")  # no first_seen

    purge = GDPRPurge(redis_client)
    summary = await purge.run()

    assert await redis_client.exists("rv:9.8.7.6")
    assert summary.rv_hashes_deleted == 0


# ── Ban preservation ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_does_not_delete_active_ban(redis_client):
    """Active ban keys (ban:{ip} with TTL) must survive the purge.

    The purge only touches the data categories it owns — it has no logic to
    delete ban keys at all.  This test guards against that regression.
    """
    await redis_client.set("ban:1.2.3.4", "scanning activity", ex=3600)

    purge = GDPRPurge(redis_client)
    await purge.run()

    assert await redis_client.exists("ban:1.2.3.4"), "Active ban was deleted by purge!"
    ttl = await redis_client.ttl("ban:1.2.3.4")
    assert ttl > 0, "Active ban TTL was removed by purge!"


# ── Monthly aggregates ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_monthly_aggregates_removes_old(redis_client):
    """Aggregate hashes older than retention are deleted."""
    await redis_client.hset("reporting:monthly:2020-01", "connections_total", "100")

    purge = GDPRPurge(redis_client, {"monthly_aggregate_retention_months": 24})
    summary = await purge.run()

    assert not await redis_client.exists("reporting:monthly:2020-01")
    assert summary.monthly_aggregates_deleted >= 1


@pytest.mark.asyncio
async def test_purge_monthly_aggregates_preserves_recent(redis_client):
    """Aggregate hashes within the retention window are kept."""
    current_month = datetime.now(timezone.utc).strftime("%Y-%m")
    key = f"reporting:monthly:{current_month}"
    await redis_client.hset(key, "connections_total", "500")

    purge = GDPRPurge(redis_client, {"monthly_aggregate_retention_months": 24})
    summary = await purge.run()

    assert await redis_client.exists(key)
    assert summary.monthly_aggregates_deleted == 0


# ── Completion keys ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_writes_last_run_key(redis_client):
    """gdpr:purge:last_run is set after run() and contains a valid ISO-8601 timestamp."""
    purge = GDPRPurge(redis_client)
    await purge.run()

    val = await redis_client.get("gdpr:purge:last_run")
    assert val is not None and len(val) > 0
    # Parse it — must not raise
    dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
    # Must be recent (within 60 seconds)
    assert (datetime.now(timezone.utc) - dt).total_seconds() < 60


@pytest.mark.asyncio
async def test_purge_writes_last_summary_key(redis_client):
    """gdpr:purge:last_summary is valid JSON with all required fields."""
    purge = GDPRPurge(redis_client)
    await purge.run()

    val = await redis_client.get("gdpr:purge:last_summary")
    assert val is not None
    data = json.loads(val)
    # All required top-level keys must be present
    for key in [
        "connection_events_deleted",
        "beaconing_records_cleaned",
        "rv_hashes_deleted",
        "monthly_aggregates_deleted",
        "errors",
    ]:
        assert key in data, f"Missing key '{key}' in last_summary"
    # Counts must be non-negative integers
    assert isinstance(data["connection_events_deleted"], int)
    assert data["connection_events_deleted"] >= 0


# ── Summary fields ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_summary_to_dict_all_fields(redis_client):
    """PurgeSummary.to_dict() returns all required keys with correct types."""
    purge = GDPRPurge(redis_client)
    summary = await purge.run()
    d = summary.to_dict()

    required_keys = [
        "connection_events_deleted",
        "beaconing_records_cleaned",
        "rv_hashes_deleted",
        "monthly_aggregates_deleted",
        "errors",
    ]
    for k in required_keys:
        assert k in d, f"Missing '{k}' in summary dict"
    assert isinstance(d["errors"], list)
    assert all(isinstance(n, int) for n in [
        d["connection_events_deleted"],
        d["beaconing_records_cleaned"],
        d["rv_hashes_deleted"],
        d["monthly_aggregates_deleted"],
    ])


# ── Partial error resilience ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_purge_partial_error_still_completes(redis_client):
    """If one purge category fails, the others still run and last_run is still written."""
    # Seed data that the rv_hash purge would normally delete
    await redis_client.hset("rv:1.2.3.4", "first_seen", "2020-01-01T00:00:00Z")

    purge = GDPRPurge(redis_client)

    # Make _purge_stream raise to simulate a Redis error in that category
    _original_purge_stream = purge._purge_stream
    async def failing_purge_stream(cutoff_ms):
        raise RuntimeError("simulated stream error")
    purge._purge_stream = failing_purge_stream

    summary = await purge.run()

    # Must not raise — fail-open
    assert len(summary.errors) >= 1
    assert any(e["category"] == "stream" for e in summary.errors)

    # Other categories still ran — rv hash was deleted
    assert not await redis_client.exists("rv:1.2.3.4"), "rv hash not deleted despite partial error"

    # Completion keys still written
    assert await redis_client.get("gdpr:purge:last_run") is not None


@pytest.mark.asyncio
async def test_purge_all_categories_error_still_writes_completion(redis_client):
    """Even if all purge categories fail, completion keys must still be written."""
    purge = GDPRPurge(redis_client)

    async def always_fail(cutoff):
        raise RuntimeError("total failure")

    purge._purge_stream = always_fail
    purge._purge_beaconing = always_fail
    purge._purge_rv_hashes = always_fail
    purge._purge_monthly_aggregates = always_fail

    summary = await purge.run()

    assert len(summary.errors) == 4
    assert await redis_client.get("gdpr:purge:last_run") is not None
    assert await redis_client.get("gdpr:purge:last_summary") is not None
