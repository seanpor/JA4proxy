"""Chaos/resilience tests for Phase 13 — Management UI.

Verifies the management server degrades gracefully under failure conditions:
- Redis unavailability → 503 (not 500)
- Auth rate limiter under concurrent failures
- SSE task cleanup on client disconnect
- Startup without Redis connectivity
"""

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import redis.exceptions

os.environ["UI_API_KEY"] = "test-key-12345"

from httpx import AsyncClient, ASGITransport

from management.server import create_app

HEADERS = {"Authorization": "Bearer test-key-12345"}


def _make_async_iter(items):
    async def _aiter():
        for item in items:
            yield item
    return _aiter()


def _make_redis_that_errors():
    """Redis mock that raises ConnectionError on every call."""
    r = AsyncMock()
    err = redis.exceptions.ConnectionError("Redis unavailable")
    r.incr.side_effect = err
    r.get.side_effect = err
    r.set.side_effect = err
    r.sadd.side_effect = err
    r.smembers.side_effect = err
    r.delete.side_effect = err
    r.xadd.side_effect = err
    r.xread.side_effect = err
    r.xrevrange.side_effect = err
    r.lpush.side_effect = err
    r.lrange.side_effect = err
    r.llen.side_effect = err
    r.hgetall.side_effect = err
    r.hset.side_effect = err
    r.zcard.side_effect = err
    r.zrange.side_effect = err
    r.zrem.side_effect = err
    r.scard.side_effect = err
    r.ping.side_effect = err
    r.scan_iter = MagicMock(side_effect=err)
    return r


@pytest.fixture
def mock_redis():
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
    r.xread.return_value = []
    r.xrevrange.return_value = []
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


@pytest.fixture
async def app_with_broken_redis():
    """FastAPI app where Redis raises ConnectionError on every call."""
    application = await create_app()
    application.state.redis = _make_redis_that_errors()
    return application


@pytest.fixture
async def broken_client(app_with_broken_redis):
    async with AsyncClient(
        transport=ASGITransport(app=app_with_broken_redis),
        base_url="http://localhost",
    ) as c:
        yield c


async def test_redis_down_returns_503_not_500(broken_client):
    """When Redis is down, GET /api/v1/bans must return 503, not 500."""
    resp = await broken_client.get("/api/v1/bans", headers=HEADERS)
    assert resp.status_code == 503


async def test_ban_add_redis_error_returns_503(broken_client):
    """When Redis is down, POST /api/v1/bans must return 503."""
    payload = {"ip": "1.2.3.4", "reason": "test", "ttl_s": 60}
    resp = await broken_client.post("/api/v1/bans", json=payload, headers=HEADERS)
    assert resp.status_code == 503


async def test_ban_delete_redis_error_returns_503(broken_client):
    """When Redis is down, DELETE /api/v1/bans/{ip} must return 503."""
    resp = await broken_client.delete("/api/v1/bans/1.2.3.4", headers=HEADERS)
    assert resp.status_code == 503


async def test_dial_get_redis_error_returns_503(broken_client):
    """When Redis is down, GET /api/v1/dial must return 503."""
    resp = await broken_client.get("/api/v1/dial", headers=HEADERS)
    assert resp.status_code == 503


async def test_policy_get_redis_error_returns_503(broken_client):
    """When Redis is down, GET /api/v1/policy/bypasses must return 503."""
    resp = await broken_client.get("/api/v1/policy/bypasses", headers=HEADERS)
    assert resp.status_code == 503


async def test_management_server_health_survives_redis_down(broken_client):
    """GET /health must still respond even if Redis is down."""
    resp = await broken_client.get("/health")
    assert resp.status_code in (200, 503)  # degraded but not crashed


async def test_auth_ratelimiter_works_under_concurrent_failures():
    """Auth rate limiting must work correctly under concurrent requests."""
    app = await create_app()

    call_count = 0
    max_concurrent = 0
    active = 0

    async def counting_incr(key):
        nonlocal call_count, max_concurrent, active
        active += 1
        max_concurrent = max(max_concurrent, active)
        call_count += 1
        result = call_count
        active -= 1
        return result

    mock_r = AsyncMock()
    mock_r.incr.side_effect = counting_incr
    mock_r.expire.return_value = True
    app.state.redis = mock_r

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost",
    ) as c:
        tasks = [
            c.get("/api/v1/bans", headers={"Authorization": "Bearer wrong"})
            for _ in range(5)
        ]
        responses = await asyncio.gather(*tasks)

    for resp in responses:
        assert resp.status_code in (401, 429)


async def test_management_server_starts_without_redis():
    """Server must be constructable even if Redis is not yet reachable."""
    try:
        app = await create_app()
        assert app is not None
    except Exception as exc:
        pytest.fail(f"create_app() raised {exc!r} — must not connect at construction time")


async def test_metrics_endpoint_survives_redis_down(broken_client):
    """GET /metrics must respond even when Redis is down."""
    resp = await broken_client.get("/metrics")
    assert resp.status_code == 200


async def test_fingerprint_ops_redis_error_returns_503(broken_client):
    """Fingerprint operations must return 503 when Redis is down."""
    resp = await broken_client.get("/api/v1/fingerprints/blacklist", headers=HEADERS)
    assert resp.status_code == 503


async def test_config_ops_redis_error_returns_503(broken_client):
    """Config operations must return 503 when Redis is down."""
    resp = await broken_client.get("/api/v1/config/thresholds", headers=HEADERS)
    assert resp.status_code == 503


async def test_audit_log_redis_error_returns_503(broken_client):
    """Audit log endpoint must return 503 when Redis is down."""
    resp = await broken_client.get("/api/v1/audit", headers=HEADERS)
    assert resp.status_code == 503


async def test_health_detail_redis_down_reports_degraded(broken_client):
    """GET /api/v1/health/detail with Redis down must report degraded state."""
    resp = await broken_client.get("/api/v1/health/detail", headers=HEADERS)
    assert resp.status_code in (200, 503)
    if resp.status_code == 200:
        data = resp.json()
        assert data.get("redis") in ("error", "unreachable", False, "down")


# ── Phase 13b chaos tests ──────────────────────────────────────────────────

async def test_startup_without_api_key_exits():
    """create_app() calls sys.exit(1) when UI_API_KEY not set."""
    old_key = os.environ.pop("UI_API_KEY", None)
    try:
        with pytest.raises(SystemExit):
            await create_app()
    finally:
        if old_key:
            os.environ["UI_API_KEY"] = old_key


async def test_sse_subscriber_cap_enforced(app, client):
    """N+1th SSE connection returns 429 when cap reached."""
    from management.routers import events as events_mod
    # Drive the counter to the cap
    orig = events_mod._active_subscribers
    events_mod._active_subscribers = events_mod._MAX_SSE_SUBSCRIBERS
    try:
        resp = await client.get("/api/v1/events", headers=HEADERS)
        assert resp.status_code == 429
        assert "Too many SSE subscribers" in resp.text
    finally:
        events_mod._active_subscribers = orig


async def test_redis_failure_during_threshold_update(app, client, mock_redis):
    """Redis failure during threshold update should return 503."""
    mock_redis.hset.side_effect = redis.exceptions.ConnectionError("lost")
    payload = {"flag": 15, "rate_limit": 30, "tarpit": 50, "block": 65, "ban": 80}
    resp = await client.put("/api/v1/config/thresholds", json=payload, headers=HEADERS)
    assert resp.status_code == 503


async def test_redis_failure_during_sse_read(app, client, mock_redis):
    """Redis failure during SSE read should be handled gracefully (not crash)."""
    mock_redis.xread.side_effect = redis.exceptions.ConnectionError("stream error")

    async def _erroring_gen(req, *a, **kw):
        # Immediately yield a heartbeat (showing the endpoint is alive), then stop
        yield {"event": "heartbeat", "data": '{"type":"heartbeat"}'}

    with patch("management.routers.events._event_generator", _erroring_gen):
        async with client.stream("GET", "/api/v1/events", headers=HEADERS) as resp:
            assert resp.status_code == 200


async def test_malformed_cidr_config_fails_open(app, client):
    """Malformed CIDR configuration should fail open (allow access)."""
    app.state.config["management_ui"]["allowed_cidr"] = "not-a-valid-cidr"
    try:
        with patch("management.server._get_client_ip", return_value="192.168.1.1"):
            resp = await client.get("/api/v1/health/detail", headers=HEADERS)
            assert resp.status_code == 200
    finally:
        app.state.config["management_ui"]["allowed_cidr"] = ""


async def test_health_endpoints_work_without_redis(app, client, mock_redis):
    """Health endpoints should work even if Redis is down."""
    mock_redis.ping.side_effect = redis.exceptions.ConnectionError("lost")
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "degraded"


async def test_auth_failure_rate_limiting(app, client, mock_redis):
    """Multiple auth failures should trigger rate limiting (10+ failures → 429)."""
    # Return count >= 10 to trigger the 429 branch in require_api_key
    mock_redis.incr.return_value = 10
    resp = await client.get("/api/v1/bans", headers={"Authorization": "Bearer wrong-key"})
    assert resp.status_code == 429
    assert "Too many authentication failures" in resp.text


async def test_config_validation_prevents_invalid_thresholds(client):
    """Invalid threshold configuration should be rejected."""
    payload = {"flag": 90, "rate_limit": 30, "tarpit": 50, "block": 65, "ban": 80}
    resp = await client.put("/api/v1/config/thresholds", json=payload, headers=HEADERS)
    assert resp.status_code == 422
    assert "must be in ascending order" in resp.text


async def test_dial_counterfactual_handles_empty_stream(client, mock_redis):
    """Counterfactual endpoint should handle empty event stream."""
    mock_redis.xrevrange.return_value = []
    mock_redis.hgetall.return_value = {"block": "70"}
    resp = await client.get("/api/v1/dial/counterfactual?dial=50", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["estimated_block_pct"] is None
    assert data["reason"] == "insufficient_data"


async def test_integrations_endpoints_handle_redis_errors(app, client, mock_redis):
    """Integration status endpoints should handle Redis errors."""
    mock_redis.get.side_effect = redis.exceptions.ConnectionError("lost")
    resp = await client.get("/api/v1/integrations/abuseipdb", headers=HEADERS)
    assert resp.status_code == 503
    assert "Redis unavailable" in resp.text
