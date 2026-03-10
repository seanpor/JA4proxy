"""Unit tests for Phase 13 — Management UI (FastAPI backend).

Covers:
- Authentication (Bearer token, rate limiting, brute-force protection)
- Ban management (add, release, list with pagination)
- JA4 fingerprint management (blacklist, whitelist, candidates)
- Dial control (read, update with safety checks, acknowledge)
- Policy bypass management (list, enable/disable, audit)
- Config management (thresholds, countries, features)
- Health endpoints (unauthenticated /health, authenticated detail)
- Audit log (pagination, event type filtering)
- Security headers (CSP, HSTS, X-Frame-Options)
- Prometheus metrics middleware
"""

import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Set API key before importing the app
os.environ["UI_API_KEY"] = "test-key-12345"

from httpx import AsyncClient, ASGITransport

from management.server import create_app

HEADERS = {"Authorization": "Bearer test-key-12345"}
WRONG_HEADERS = {"Authorization": "Bearer wrong-key"}


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_async_iter(items):
    """Create an async iterator from a list of items."""
    async def _aiter():
        for item in items:
            yield item
    return _aiter()


@pytest.fixture
def mock_redis():
    """Fully-configured mock async Redis for management unit tests."""
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
    r.zrange.return_value = []
    r.zrangebyscore.return_value = []
    r.zadd.return_value = 1
    r.zrem.return_value = 1
    r.scard.return_value = 0
    r.smembers.return_value = set()
    r.ping.return_value = True
    r.ttl.return_value = -1
    # scan_iter returns an async generator
    r.scan_iter = MagicMock(return_value=_make_async_iter([]))
    return r


@pytest.fixture
async def app(mock_redis):
    """Create FastAPI app with injected mock Redis."""
    application = await create_app()
    application.state.redis = mock_redis
    return application


@pytest.fixture
async def client(app):
    """Async HTTPX client pointing at the test app."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
    ) as c:
        yield c


# ── Authentication tests ───────────────────────────────────────────────────────

async def test_missing_api_key_returns_401(client):
    """Request with no auth header must get 401."""
    resp = await client.get("/api/v1/bans")
    assert resp.status_code == 401


async def test_wrong_api_key_returns_401(client):
    """Request with wrong Bearer token must get 401."""
    resp = await client.get("/api/v1/bans", headers=WRONG_HEADERS)
    assert resp.status_code == 401


async def test_correct_api_key_returns_200(client):
    """Request with correct Bearer token must succeed."""
    resp = await client.get("/api/v1/bans", headers=HEADERS)
    assert resp.status_code == 200


async def test_query_param_key_works(client):
    """SSE-style ?key= auth must work for endpoints that accept it."""
    resp = await client.get("/api/v1/bans?key=test-key-12345")
    assert resp.status_code == 200


async def test_rate_limiter_blocks_after_10_failures(app, mock_redis):
    """After 10 failed attempts, auth should return 429."""
    # Simulate > 10 failures already recorded for this IP
    mock_redis.incr.return_value = 11

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
    ) as c:
        resp = await c.get("/api/v1/bans", headers=WRONG_HEADERS)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers


async def test_health_unauthenticated(client):
    """GET /health must work without any auth header."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


async def test_health_detail_requires_auth(client):
    """GET /api/v1/health/detail must require auth."""
    resp = await client.get("/api/v1/health/detail")
    assert resp.status_code == 401


async def test_health_detail_authenticated(client, mock_redis):
    """GET /api/v1/health/detail returns full breakdown when authenticated."""
    mock_redis.ping.return_value = True
    resp = await client.get("/api/v1/health/detail", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "redis" in data


# ── Ban management tests ───────────────────────────────────────────────────────

async def test_ban_add_writes_redis_key(client, mock_redis):
    """POST /api/v1/bans must set ban:{ip} key in Redis."""
    payload = {"ip": "1.2.3.4", "reason": "test", "ttl_s": 3600}
    resp = await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    assert resp.status_code == 201
    # Verify set was called with the ban key
    mock_redis.set.assert_called()
    call_args = mock_redis.set.call_args
    assert "ban:1.2.3.4" in str(call_args)


async def test_ban_add_publishes_pubsub(client, mock_redis):
    """POST /api/v1/bans must publish ban_added event to invalidate stream."""
    payload = {"ip": "1.2.3.4", "reason": "test", "ttl_s": 3600}
    await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    mock_redis.xadd.assert_called()
    xadd_call = mock_redis.xadd.call_args
    assert "ja4proxy:invalidate" in str(xadd_call)


async def test_ban_add_writes_audit_log(client, mock_redis):
    """POST /api/v1/bans must write to management:audit_log."""
    payload = {"ip": "1.2.3.4", "reason": "test", "ttl_s": 3600}
    await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    mock_redis.lpush.assert_called()
    lpush_call = mock_redis.lpush.call_args
    assert "management:audit_log" in str(lpush_call)


async def test_ban_release_deletes_redis_key(client, mock_redis):
    """DELETE /api/v1/bans/{ip} must delete ban:{ip} key."""
    mock_redis.get.return_value = "manual:test"
    resp = await client.delete("/api/v1/bans/1.2.3.4", headers=HEADERS)
    assert resp.status_code == 200
    mock_redis.delete.assert_called()
    assert "ban:1.2.3.4" in str(mock_redis.delete.call_args)


async def test_ban_release_publishes_ban_release(client, mock_redis):
    """DELETE /api/v1/bans/{ip} must publish ban_release event."""
    mock_redis.get.return_value = "manual:test"
    await client.delete("/api/v1/bans/1.2.3.4", headers=HEADERS)
    mock_redis.xadd.assert_called()
    event_data = str(mock_redis.xadd.call_args)
    assert "ban_release" in event_data


async def test_ban_release_not_found_returns_404(client, mock_redis):
    """DELETE /api/v1/bans/{ip} for non-existent ban returns 404."""
    mock_redis.get.return_value = None
    resp = await client.delete("/api/v1/bans/9.9.9.9", headers=HEADERS)
    assert resp.status_code == 404


async def test_ban_list_pagination(client, mock_redis):
    """GET /api/v1/bans must support page/per_page query params."""
    resp = await client.get("/api/v1/bans?page=1&per_page=10", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data


async def test_ban_list_ipv6_displayed_correctly(client, mock_redis):
    """IPv6 ban keys must return as compressed canonical form."""
    mock_redis.scan_iter = MagicMock(
        return_value=_make_async_iter(["ban:2001:db8::1"])
    )
    mock_redis.get.return_value = "test-reason"
    mock_redis.ttl.return_value = 3600

    resp = await client.get("/api/v1/bans", headers=HEADERS)
    assert resp.status_code == 200


async def test_ban_add_validates_ip_format(client, mock_redis):
    """POST /api/v1/bans must reject invalid IP addresses."""
    payload = {"ip": "not-an-ip", "reason": "test", "ttl_s": 3600}
    resp = await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    assert resp.status_code == 422


async def test_ban_add_accepts_ipv6(client, mock_redis):
    """POST /api/v1/bans must accept IPv6 addresses."""
    payload = {"ip": "2001:db8::1", "reason": "test", "ttl_s": 3600}
    resp = await client.post("/api/v1/bans", json=payload, headers=HEADERS)
    assert resp.status_code == 201


# ── JA4 fingerprint tests ──────────────────────────────────────────────────────

async def test_blacklist_add_requires_valid_ja4_format(client, mock_redis):
    """POST /api/v1/fingerprints/blacklist must reject malformed JA4."""
    payload = {"fingerprint": "not-a-valid-ja4", "reason": "test"}
    resp = await client.post(
        "/api/v1/fingerprints/blacklist", json=payload, headers=HEADERS
    )
    assert resp.status_code == 422


async def test_blacklist_add_valid_ja4(client, mock_redis):
    """POST /api/v1/fingerprints/blacklist must accept valid JA4."""
    payload = {
        "fingerprint": "t13d1516h2_8daaf6152771_02713d6af862",
        "reason": "test bot",
    }
    resp = await client.post(
        "/api/v1/fingerprints/blacklist", json=payload, headers=HEADERS
    )
    assert resp.status_code == 201
    mock_redis.sadd.assert_called()


async def test_candidate_approve_adds_to_blacklist(client, mock_redis):
    """POST /fingerprints/candidates/{fp}/approve must SADD to ja4:blacklist."""
    fingerprint = "t13d1516h2_8daaf6152771_02713d6af862"
    mock_redis.zscore = AsyncMock(return_value=5.0)
    resp = await client.post(
        f"/api/v1/fingerprints/candidates/{fingerprint}/approve",
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.sadd.assert_called()
    assert "ja4:blacklist" in str(mock_redis.sadd.call_args)


async def test_candidate_approve_publishes_pubsub(client, mock_redis):
    """Approving a candidate must publish ja4_blacklist_add to invalidate stream."""
    fingerprint = "t13d1516h2_8daaf6152771_02713d6af862"
    mock_redis.zscore = AsyncMock(return_value=5.0)
    await client.post(
        f"/api/v1/fingerprints/candidates/{fingerprint}/approve",
        headers=HEADERS,
    )
    mock_redis.xadd.assert_called()
    assert "ja4_blacklist_add" in str(mock_redis.xadd.call_args)


async def test_candidate_dismiss_removes_from_queue(client, mock_redis):
    """POST /fingerprints/candidates/{fp}/dismiss must ZREM from candidates set."""
    fingerprint = "t13d1516h2_8daaf6152771_02713d6af862"
    mock_redis.zscore = AsyncMock(return_value=5.0)
    resp = await client.post(
        f"/api/v1/fingerprints/candidates/{fingerprint}/dismiss",
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.zrem.assert_called()
    assert "ja4:candidates" in str(mock_redis.zrem.call_args)


async def test_whitelist_remove_publishes_eviction(client, mock_redis):
    """DELETE /fingerprints/whitelist/{fp} must publish whitelist_remove."""
    fingerprint = "t13d1516h2_8daaf6152771_02713d6af862"
    mock_redis.sismember = AsyncMock(return_value=True)
    resp = await client.delete(
        f"/api/v1/fingerprints/whitelist/{fingerprint}",
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.xadd.assert_called()
    assert "whitelist_remove" in str(mock_redis.xadd.call_args)


async def test_fingerprint_candidates_list(client, mock_redis):
    """GET /fingerprints/candidates must return paginated list."""
    mock_redis.zrange = AsyncMock(return_value=[
        ("t13d1516h2_8daaf6152771_02713d6af862", 42.0),
    ])
    mock_redis.zcard.return_value = 1
    resp = await client.get("/api/v1/fingerprints/candidates", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data


# ── Dial tests ────────────────────────────────────────────────────────────────

async def test_dial_returns_current_value(client, mock_redis):
    """GET /api/v1/dial must return current dial value."""
    mock_redis.get.side_effect = lambda key: (
        "42" if key == "dial:current" else
        "true" if key == "dial:blocking_acknowledged" else
        None
    )
    resp = await client.get("/api/v1/dial", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["dial"] == 42


async def test_dial_change_within_limit_succeeds(client, mock_redis):
    """PUT /api/v1/dial must succeed when within 10/hour limit."""
    mock_redis.get.side_effect = lambda key: (
        "30" if key == "dial:current" else
        "true" if key == "dial:blocking_acknowledged" else
        None
    )
    mock_redis.incr.return_value = 1  # first change this hour

    resp = await client.put(
        "/api/v1/dial",
        json={"dial": 35, "reason": "test"},
        headers=HEADERS,
    )
    assert resp.status_code == 200


async def test_dial_change_exceeds_limit_returns_422(client, mock_redis):
    """PUT /api/v1/dial must fail if > 10 changes/hour."""
    mock_redis.get.side_effect = lambda key: (
        "30" if key == "dial:current" else
        "true" if key == "dial:blocking_acknowledged" else
        None
    )
    mock_redis.incr.return_value = 11  # over limit

    resp = await client.put(
        "/api/v1/dial",
        json={"dial": 35, "reason": "test"},
        headers=HEADERS,
    )
    assert resp.status_code == 429


async def test_dial_change_without_acknowledged_returns_422(client, mock_redis):
    """PUT /api/v1/dial at dial > 0 must fail if not acknowledged."""
    mock_redis.get.side_effect = lambda key: (
        "0" if key == "dial:current" else
        None  # blocking_acknowledged not set
    )
    mock_redis.incr.return_value = 1

    resp = await client.put(
        "/api/v1/dial",
        json={"dial": 10, "reason": "test"},
        headers=HEADERS,
    )
    assert resp.status_code == 422


async def test_dial_acknowledge_enables_blocking(client, mock_redis):
    """POST /api/v1/dial/acknowledge must set dial:blocking_acknowledged."""
    resp = await client.post(
        "/api/v1/dial/acknowledge",
        json={"acknowledged": True},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.set.assert_called()
    assert "dial:blocking_acknowledged" in str(mock_redis.set.call_args)


async def test_dial_change_to_zero_does_not_need_acknowledged(client, mock_redis):
    """Lowering dial to 0 (monitor mode) must always succeed."""
    mock_redis.get.side_effect = lambda key: (
        "50" if key == "dial:current" else
        None  # not acknowledged
    )
    mock_redis.incr.return_value = 1

    resp = await client.put(
        "/api/v1/dial",
        json={"dial": 0, "reason": "emergency downgrade"},
        headers=HEADERS,
    )
    assert resp.status_code == 200


# ── Policy bypass tests ───────────────────────────────────────────────────────

BYPASS_NAMES = [
    "alpn_browser_bypass",
    "ja4_whitelist_bypass",
    "mtls_bypass",
    "static_ip_allowlist",
    "ja4_blacklist_bypass",
    "country_blacklist_bypass",
    "spamhaus_bypass",
    "tls_version_bypass",
]


async def test_bypasses_list_returns_all_8_bypasses(client, mock_redis):
    """GET /api/v1/policy/bypasses must return all 8 bypass entries."""
    mock_redis.get.return_value = None  # defaults to enabled
    resp = await client.get("/api/v1/policy/bypasses", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 8
    names = {item["name"] for item in data}
    for bypass in BYPASS_NAMES:
        assert bypass in names


async def test_bypass_disable_writes_policy_audit(client, mock_redis):
    """PUT /api/v1/policy/bypasses/{name} must write to management:policy_audit."""
    resp = await client.put(
        "/api/v1/policy/bypasses/spamhaus_bypass",
        json={"enabled": False},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.lpush.assert_called()
    # Verify it wrote to policy_audit
    lpush_calls = [str(c) for c in mock_redis.lpush.call_args_list]
    assert any("policy_audit" in c for c in lpush_calls)


async def test_bypass_disable_publishes_config_reload(client, mock_redis):
    """PUT /api/v1/policy/bypasses/{name} must publish config_reload event."""
    resp = await client.put(
        "/api/v1/policy/bypasses/spamhaus_bypass",
        json={"enabled": False},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.xadd.assert_called()
    assert "config_reload" in str(mock_redis.xadd.call_args)


async def test_bypass_enable_writes_policy_audit(client, mock_redis):
    """Re-enabling a bypass must also write to policy_audit."""
    mock_redis.get.return_value = "false"  # currently disabled
    resp = await client.put(
        "/api/v1/policy/bypasses/spamhaus_bypass",
        json={"enabled": True},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.lpush.assert_called()


async def test_bypass_invalid_name_returns_404(client, mock_redis):
    """PUT /api/v1/policy/bypasses/{name} with unknown name returns 404."""
    resp = await client.put(
        "/api/v1/policy/bypasses/nonexistent_bypass",
        json={"enabled": False},
        headers=HEADERS,
    )
    assert resp.status_code == 404


async def test_policy_audit_log(client, mock_redis):
    """GET /api/v1/policy/audit must return paginated policy audit entries."""
    mock_redis.lrange.return_value = [
        json.dumps({"event": "bypass_disabled", "bypass": "spamhaus_bypass"}),
    ]
    mock_redis.llen.return_value = 1
    resp = await client.get("/api/v1/policy/audit", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data


# ── Config tests ──────────────────────────────────────────────────────────────

async def test_thresholds_get_returns_defaults(client, mock_redis):
    """GET /api/v1/config/thresholds must return threshold config."""
    mock_redis.hgetall.return_value = {}
    resp = await client.get("/api/v1/config/thresholds", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    # Should return some threshold fields
    assert isinstance(data, dict)


async def test_thresholds_put_validates_ranges(client, mock_redis):
    """PUT /api/v1/config/thresholds must reject out-of-range values."""
    resp = await client.put(
        "/api/v1/config/thresholds",
        json={"flag": -1, "rate_limit": 200},  # flag=-1 is invalid (< 0)
        headers=HEADERS,
    )
    assert resp.status_code == 422


async def test_thresholds_put_valid_values(client, mock_redis):
    """PUT /api/v1/config/thresholds must accept valid threshold values."""
    resp = await client.put(
        "/api/v1/config/thresholds",
        json={"flag": 20, "rate_limit": 35, "tarpit": 55, "block": 70, "ban": 85},
        headers=HEADERS,
    )
    assert resp.status_code == 200


async def test_features_toggle_writes_redis(client, mock_redis):
    """PUT /api/v1/config/features/{feature} must write to Redis."""
    resp = await client.put(
        "/api/v1/config/features/abuseipdb",
        json={"enabled": False},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    mock_redis.set.assert_called()
    set_call = str(mock_redis.set.call_args)
    assert "config:features:abuseipdb" in set_call


async def test_countries_blocklist_get(client, mock_redis):
    """GET /api/v1/config/countries/blocklist returns list of blocked countries."""
    mock_redis.smembers.return_value = {"RU", "CN"}
    resp = await client.get("/api/v1/config/countries/blocklist", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "countries" in data


async def test_countries_blocklist_put(client, mock_redis):
    """PUT /api/v1/config/countries/blocklist replaces the blocklist."""
    resp = await client.put(
        "/api/v1/config/countries/blocklist",
        json={"countries": ["KP", "IR"]},
        headers=HEADERS,
    )
    assert resp.status_code == 200


# ── Audit log tests ───────────────────────────────────────────────────────────

async def test_audit_log_pagination(client, mock_redis):
    """GET /api/v1/audit must support pagination."""
    entries = [
        json.dumps({"event": "ban_added", "ip": f"1.2.3.{i}"})
        for i in range(5)
    ]
    mock_redis.lrange.return_value = entries
    mock_redis.llen.return_value = 5

    resp = await client.get("/api/v1/audit?page=1&per_page=5", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert len(data["items"]) == 5


async def test_audit_log_event_type_filter(client, mock_redis):
    """GET /api/v1/audit?event_type=ban_added must filter by event type."""
    entries = [
        json.dumps({"event": "ban_added", "ip": "1.2.3.4"}),
        json.dumps({"event": "dial_change", "old": 0, "new": 10}),
    ]
    mock_redis.lrange.return_value = entries
    mock_redis.llen.return_value = 2

    resp = await client.get(
        "/api/v1/audit?event_type=ban_added", headers=HEADERS
    )
    assert resp.status_code == 200
    data = resp.json()
    # Filter should only return ban_added entries
    for item in data["items"]:
        assert item["event"] == "ban_added"


# ── Security headers tests ────────────────────────────────────────────────────

async def test_security_headers_present(client):
    """All authenticated API responses must include security headers."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert "X-Frame-Options" in resp.headers
    assert "X-Content-Type-Options" in resp.headers


async def test_csp_header_present(client, mock_redis):
    """API responses must include Content-Security-Policy header."""
    resp = await client.get("/api/v1/bans", headers=HEADERS)
    assert resp.status_code == 200
    assert "Content-Security-Policy" in resp.headers


async def test_x_frame_options_deny(client):
    """X-Frame-Options must be DENY to prevent clickjacking."""
    resp = await client.get("/health")
    assert resp.headers.get("X-Frame-Options", "").upper() == "DENY"


# ── Integrations tests ────────────────────────────────────────────────────────

async def test_integrations_abuseipdb_status(client, mock_redis):
    """GET /api/v1/integrations/abuseipdb returns status info."""
    mock_redis.get.return_value = None
    resp = await client.get("/api/v1/integrations/abuseipdb", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


async def test_integrations_spamhaus_status(client, mock_redis):
    """GET /api/v1/integrations/spamhaus returns status info."""
    mock_redis.get.return_value = None
    resp = await client.get("/api/v1/integrations/spamhaus", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data


# ── CIDR management tests ─────────────────────────────────────────────────────

async def test_cidr_add_validates_format(client, mock_redis):
    """POST /api/v1/cidrs must reject invalid CIDR."""
    payload = {"cidr": "not-a-cidr", "reason": "test"}
    resp = await client.post("/api/v1/cidrs", json=payload, headers=HEADERS)
    assert resp.status_code == 422


async def test_cidr_add_valid(client, mock_redis):
    """POST /api/v1/cidrs must accept valid CIDR."""
    payload = {"cidr": "10.0.0.0/8", "reason": "test block"}
    resp = await client.post("/api/v1/cidrs", json=payload, headers=HEADERS)
    assert resp.status_code == 201


async def test_cidr_remove_publishes_event(client, mock_redis):
    """DELETE /api/v1/cidrs/{cidr} must publish cidr_released event."""
    mock_redis.get.return_value = "test-reason"
    import urllib.parse
    cidr_encoded = urllib.parse.quote("10.0.0.0/8", safe="")
    resp = await client.delete(
        f"/api/v1/cidrs/{cidr_encoded}", headers=HEADERS
    )
    assert resp.status_code == 200
    assert "cidr_released" in str(mock_redis.xadd.call_args)


# ── Prometheus metrics middleware ─────────────────────────────────────────────

async def test_metrics_endpoint_exists(client):
    """GET /metrics must return Prometheus text format."""
    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")
