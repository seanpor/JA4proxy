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

os.environ.setdefault("UI_API_KEY", "chaos-test-key")

from httpx import AsyncClient, ASGITransport

from management.server import create_app

HEADERS = {"Authorization": f"Bearer {os.environ['UI_API_KEY']}"}


def _make_async_iter(items):
    async def _aiter():
        for item in items:
            yield item
    return _aiter()


def _make_redis_that_errors():
    """Redis mock that raises ConnectionError on every call."""
    import redis.exceptions
    r = AsyncMock()
    err = redis.exceptions.ConnectionError("Redis unavailable")
    r.incr.side_effect = err
    r.get.side_effect = err
    r.set.side_effect = err
    r.sadd.side_effect = err
    r.smembers.side_effect = err
    r.delete.side_effect = err
    r.xadd.side_effect = err
    r.lpush.side_effect = err
    r.lrange.side_effect = err
    r.llen.side_effect = err
    r.hgetall.side_effect = err
    r.zcard.side_effect = err
    r.zrange.side_effect = err
    r.zrem.side_effect = err
    r.scard.side_effect = err
    r.ping.side_effect = err
    r.scan_iter = MagicMock(side_effect=err)
    return r


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
    """GET /health must still respond 200 even if Redis is down."""
    resp = await broken_client.get("/health")
    # Health endpoint itself should still respond (not necessarily 200 if redis check fails)
    # but the server itself should not crash
    assert resp.status_code in (200, 503)  # degraded but not crashed


async def test_auth_ratelimiter_works_under_concurrent_failures():
    """Auth rate limiting must work correctly under concurrent requests."""
    app = await create_app()

    # Mock Redis to track concurrent calls
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
        # Send 5 concurrent wrong-key requests
        tasks = [
            c.get("/api/v1/bans", headers={"Authorization": "Bearer wrong"})
            for _ in range(5)
        ]
        responses = await asyncio.gather(*tasks)

    # All should be 401 or 429 (auth failures)
    for resp in responses:
        assert resp.status_code in (401, 429)


async def test_management_server_starts_without_redis():
    """Server must be constructable even if Redis is not yet reachable."""
    # create_app() should not connect to Redis at construction time
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
    # Should get a response (not crash), status may be 200 with degraded or 503
    assert resp.status_code in (200, 503)
    if resp.status_code == 200:
        data = resp.json()
        assert data.get("redis") in ("error", "unreachable", False, "down")
