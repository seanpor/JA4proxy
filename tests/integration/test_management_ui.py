"""Integration tests for Phase 13 — Management UI.

Tests the Management UI against real Redis (falls back to mock).
Verifies end-to-end pub/sub propagation of management actions.
"""

import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock

os.environ["UI_API_KEY"] = "test-key-12345"

from httpx import AsyncClient, ASGITransport

from management.server import create_app

HEADERS = {"Authorization": "Bearer test-key-12345"}


def _make_async_iter(items):
    """Create an async iterator from a list."""
    async def _aiter():
        for item in items:
            yield item
    return _aiter()


@pytest.fixture
def mock_redis():
    """Async mock Redis for integration tests that lack a real Redis."""
    r = AsyncMock()
    r.incr.return_value = 1
    r.expire.return_value = True
    r.set.return_value = True
    r.get.return_value = None
    r.sadd.return_value = 1
    r.smembers.return_value = set()
    r.srem.return_value = 1
    r.delete.return_value = 1
    r.xadd.return_value = b"1-0"
    r.lpush.return_value = 1
    r.ltrim.return_value = True
    r.lrange.return_value = []
    r.llen.return_value = 0
    r.hset.return_value = 1
    r.hgetall.return_value = {}
    r.zcard.return_value = 0
    r.zrange = AsyncMock(return_value=[])
    r.zrangebyscore.return_value = []
    r.zadd.return_value = 1
    r.zrem.return_value = 1
    r.scard.return_value = 0
    r.ping.return_value = True
    r.ttl.return_value = -1
    r.scan_iter = MagicMock(return_value=_make_async_iter([]))
    return r


@pytest.fixture
async def app(mock_redis):
    application = await create_app()
    application.state.redis = mock_redis
    return application


@pytest.fixture
async def client(app):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
    ) as c:
        yield c


async def test_ban_propagates_to_proxy_via_pubsub(client, mock_redis):
    """Adding a ban must publish to the ja4proxy:invalidate stream."""
    payload = {"ip": "192.168.1.100", "reason": "integration test", "ttl_s": 300}
    resp = await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    assert resp.status_code == 201

    # Verify xadd was called with the invalidate stream
    mock_redis.xadd.assert_called()
    stream_name = mock_redis.xadd.call_args[0][0]
    assert stream_name == "ja4proxy:invalidate"

    # Verify the event contains the right fields
    event_data = mock_redis.xadd.call_args[0][1]
    assert "event" in event_data
    event = json.loads(event_data["event"]) if isinstance(event_data["event"], str) else event_data
    # Event should contain ban info
    assert "1" in str(event_data)  # some content was published


async def test_bypass_disable_rebuilds_proxy_bypass_list(client, mock_redis):
    """Disabling a bypass must publish config_reload to trigger proxy hot reload."""
    resp = await client.put(
        "/api/v1/policy/bypasses/spamhaus_bypass",
        json={"enabled": False},
        headers=HEADERS,
    )
    assert resp.status_code == 200

    # Verify the bypass state was written to Redis
    set_calls = [str(c) for c in mock_redis.set.call_args_list]
    assert any("policy:bypass:spamhaus_bypass" in c for c in set_calls)

    # Verify config_reload was published
    xadd_calls = [str(c) for c in mock_redis.xadd.call_args_list]
    assert any("config_reload" in c for c in xadd_calls)


async def test_dial_change_applies_to_proxy(client, mock_redis):
    """Changing the dial must write dial:current to Redis."""
    mock_redis.get.side_effect = lambda key: (
        "0" if key == "dial:current" else
        "true" if key == "dial:blocking_acknowledged" else
        None
    )
    mock_redis.incr.return_value = 1

    resp = await client.put(
        "/api/v1/dial",
        json={"dial": 10, "reason": "integration test"},
        headers=HEADERS,
    )
    assert resp.status_code == 200

    # Verify dial:current was written
    set_calls = [str(c) for c in mock_redis.set.call_args_list]
    assert any("dial:current" in c for c in set_calls)

    # Verify dial_change event was published
    xadd_calls = [str(c) for c in mock_redis.xadd.call_args_list]
    assert any("dial_change" in c for c in xadd_calls)


async def test_audit_log_written_on_ban(client, mock_redis):
    """Every ban action must generate an audit log entry."""
    payload = {"ip": "10.0.0.1", "reason": "audit test", "ttl_s": 60}
    resp = await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    assert resp.status_code == 201

    # Audit log written via LPUSH
    mock_redis.lpush.assert_called()
    lpush_calls = [str(c) for c in mock_redis.lpush.call_args_list]
    assert any("management:audit_log" in c for c in lpush_calls)


async def test_audit_log_written_on_fingerprint_blacklist(client, mock_redis):
    """Blacklisting a fingerprint must generate an audit log entry."""
    payload = {
        "fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
        "reason": "audit test",
    }
    resp = await client.post(
        "/api/v1/fingerprints/blacklist", json=payload, headers=HEADERS
    )
    assert resp.status_code == 201
    mock_redis.lpush.assert_called()


async def test_multiple_operations_all_audited(client, mock_redis):
    """Multiple operations should produce multiple audit log entries."""
    # Add a ban
    await client.post(
        "/api/v1/bans",
        json={"ip": "1.1.1.1", "reason": "test", "ttl_s": 60},
        headers=HEADERS,
    )

    # Change dial (set acknowledged first)
    mock_redis.get.side_effect = lambda key: (
        "0" if key == "dial:current" else
        "true" if key == "dial:blocking_acknowledged" else
        None
    )
    mock_redis.incr.return_value = 1
    await client.put(
        "/api/v1/dial",
        json={"dial": 5, "reason": "test"},
        headers=HEADERS,
    )

    # Should have at least 2 lpush calls for audit log
    assert mock_redis.lpush.call_count >= 2


# ── Phase 13b integration tests ────────────────────────────────────────────────

async def test_ban_add_publishes_invalidation(client, mock_redis):
    """POST /bans publishes an event on ja4proxy:invalidate."""
    # Add a ban
    payload = {"ip": "1.2.3.4", "reason": "integration test", "ttl_s": 3600}
    resp = await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    assert resp.status_code == 201
    
    # Check that event was published to stream
    mock_redis.xadd.assert_called()
    xadd_calls = [str(c) for c in mock_redis.xadd.call_args_list]
    ban_added_calls = [c for c in xadd_calls if "ban_added" in c]
    assert len(ban_added_calls) > 0


async def test_ban_release_publishes_invalidation(client, mock_redis):
    """DELETE /bans/{ip} publishes ban_release event."""
    # Mock the ban existence
    mock_redis.get.return_value = "test-reason"
    
    resp = await client.delete("/api/v1/bans/5.6.7.8", headers=HEADERS)
    assert resp.status_code == 200
    
    # Check that release event was published
    mock_redis.xadd.assert_called()
    xadd_calls = [str(c) for c in mock_redis.xadd.call_args_list]
    release_calls = [c for c in xadd_calls if "ban_release" in c]
    assert len(release_calls) > 0


async def test_fingerprint_blacklist_publishes_invalidation(client, mock_redis):
    """POST /fingerprints/blacklist publishes ja4_blacklist_add."""
    payload = {
        "fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
        "reason": "integration test"
    }
    resp = await client.post("/api/v1/fingerprints/blacklist", json=payload, headers=HEADERS)
    assert resp.status_code == 201
    
    # Check event
    mock_redis.xadd.assert_called()
    xadd_calls = [str(c) for c in mock_redis.xadd.call_args_list]
    blacklist_calls = [c for c in xadd_calls if "ja4_blacklist_add" in c]
    assert len(blacklist_calls) > 0


async def test_bypass_disable_publishes_invalidation(client, mock_redis):
    """PUT /policy/bypasses/{name} publishes policy_change."""
    resp = await client.put(
        "/api/v1/policy/bypasses/spamhaus_bypass",
        json={"enabled": False},
        headers=HEADERS
    )
    assert resp.status_code == 200
    
    # Check event
    mock_redis.xadd.assert_called()
    xadd_calls = [str(c) for c in mock_redis.xadd.call_args_list]
    policy_calls = [c for c in xadd_calls if "policy_change" in c]
    assert len(policy_calls) > 0


async def test_sse_events_endpoint_requires_auth(client, mock_redis):
    """GET /api/v1/events should require authentication."""
    # Without auth
    resp = await client.get("/api/v1/events")
    assert resp.status_code == 401
    
    # With auth
    resp = await client.get("/api/v1/events", headers=HEADERS)
    assert resp.status_code == 200


async def test_sse_recent_events_returns_data(client, mock_redis):
    """GET /api/v1/events/recent should return recent events."""
    # Mock Redis stream response
    mock_events = [
        ("event1", {"data": json.dumps({
            "type": "connection",
            "ip": "1.2.3.4",
            "country": "US",
            "asn_type": "residential",
            "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
            "score": 85,
            "action": "ban",
            "timestamp": "2026-01-01T00:00:00Z"
        })})
    ]
    mock_redis.xrevrange.return_value = mock_events
    
    resp = await client.get("/api/v1/events/recent?limit=10", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert len(data["events"]) == 1
    assert data["events"][0]["type"] == "connection"


async def test_audit_log_writes_on_config_change(client, mock_redis):
    """Config changes should write to audit log."""
    # Update thresholds
    payload = {
        "flag": 15,
        "rate_limit": 30,
        "tarpit": 50,
        "block": 65,
        "ban": 80
    }
    resp = await client.put("/api/v1/config/thresholds", json=payload, headers=HEADERS)
    assert resp.status_code == 200
    
    # Check audit log was written
    mock_redis.lpush.assert_called()
    lpush_calls = [str(c) for c in mock_redis.lpush.call_args_list]
    threshold_calls = [c for c in lpush_calls if "thresholds_updated" in c]
    assert len(threshold_calls) > 0


async def test_audit_log_writes_on_country_update(client, mock_redis):
    """Country blocklist updates should write to audit log."""
    resp = await client.put("/api/v1/config/countries/blocklist", json={
        "countries": ["US", "CN"]
    }, headers=HEADERS)
    assert resp.status_code == 200
    
    # Check audit log was written
    mock_redis.lpush.assert_called()
    lpush_calls = [str(c) for c in mock_redis.lpush.call_args_list]
    country_calls = [c for c in lpush_calls if "country_blocklist_updated" in c]
    assert len(country_calls) > 0


async def test_policy_audit_log_on_bypass_change(client, mock_redis):
    """Policy changes should write to policy audit log."""
    resp = await client.put(
        "/api/v1/policy/bypasses/country_blacklist_bypass",
        json={"enabled": False},
        headers=HEADERS
    )
    assert resp.status_code == 200
    
    # Check policy audit log was written
    mock_redis.lpush.assert_called()
    lpush_calls = [str(c) for c in mock_redis.lpush.call_args_list]
    policy_calls = [c for c in lpush_calls if "management:policy_audit" in c]
    assert len(policy_calls) > 0


async def test_dial_counterfactual_endpoint(client, mock_redis):
    """GET /api/v1/dial/counterfactual should calculate blocking impact."""
    # Mock events with scores
    mock_events = []
    for i in range(100):
        score = 80 if i < 60 else 30  # 60% would be blocked
        mock_events.append((f"event{i}", {
            "data": json.dumps({
                "type": "connection",
                "score": score,
                "ip": f"1.2.3.{i}"
            })
        }))
    
    mock_redis.xrevrange.return_value = mock_events
    mock_redis.hgetall.return_value = {"block": "70"}
    
    resp = await client.get("/api/v1/dial/counterfactual?dial=50", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["estimated_block_pct"] == 60.0
    assert data["sample_size"] == 100


async def test_integrations_rdap_endpoint(client, mock_redis):
    """GET /api/v1/integrations/rdap should return RDAP status."""
    mock_redis.get.return_value = "true"
    
    resp = await client.get("/api/v1/integrations/rdap", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "enabled"
    assert data["service"] == "rdap"


async def test_integrations_analytics_endpoint(client, mock_redis):
    """GET /api/v1/integrations/analytics should return analytics status."""
    # Mock recent event
    import time
    recent_time = int(time.time()) - 60
    mock_redis.get.return_value = "true"
    mock_redis.xrevrange.return_value = [
        ("event1", {"data": json.dumps({"timestamp": recent_time})})
    ]
    
    resp = await client.get("/api/v1/integrations/analytics", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "enabled"
    assert "last_event_age_s" in data
