"""Tests for H7 — Manual-poll rate limit on POST /api/v1/threat-intel/feeds/{feed_id}/poll.

TDD Tests — these define the contract. They will FAIL until the Coder
implements the rate limiter in management/api/routes/threat_intel.py.

Contract
--------
- 6 calls within 60s -> all succeed (HTTP 202)
- 7th call within 60s -> HTTP 429 with Retry-After header
- After the window expires -> calls succeed again
- Redis key: ratelimit:ti_feeds:manual:{identity}
- Prometheus counter: ja4proxy_ti_feeds_manual_poll_ratelimited_total incremented on breach
"""

from __future__ import annotations

import os
import time
import unittest.mock

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

# The endpoint calls _load_feed_configs() to validate feed_id exists.
# We mock it to return a known feed so the request reaches the rate limiter.
_FAKE_FEEDS = [{"id": "test-feed-1", "name": "Test Feed", "enabled": True}]


@pytest_asyncio.fixture
async def fake_redis():
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def operator_client(fake_redis):
    """Authenticated operator client with fakeredis."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    token = _create_access_token("test-operator", role="operator")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        yield client, fake_redis
    await _redis_module.close_redis()


# ── H7: 6 calls within window succeed ────────────────────────────────────────


@pytest.mark.asyncio
async def test_manual_poll_first_six_calls_succeed(operator_client):
    """First 6 manual poll calls within the window should all return 202."""
    client, redis = operator_client

    with unittest.mock.patch(
        "management.api.routes.threat_intel._load_feed_configs",
        return_value=_FAKE_FEEDS,
    ):
        for i in range(6):
            r = await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")
            assert r.status_code == 202, (
                f"Call {i + 1}/6 returned {r.status_code}, expected 202: {r.text}"
            )


# ── H7: 7th call within window returns 429 ───────────────────────────────────


@pytest.mark.asyncio
async def test_manual_poll_seventh_call_returns_429(operator_client):
    """The 7th call within 60s should be rate-limited with HTTP 429."""
    client, redis = operator_client

    with unittest.mock.patch(
        "management.api.routes.threat_intel._load_feed_configs",
        return_value=_FAKE_FEEDS,
    ):
        # Burn through the 6 allowed calls
        for _ in range(6):
            r = await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")
            assert r.status_code == 202

        # 7th call must be rejected
        r = await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")
        assert r.status_code == 429, (
            f"7th call returned {r.status_code}, expected 429: {r.text}"
        )


# ── H7: Retry-After header present on 429 ────────────────────────────────────


@pytest.mark.asyncio
async def test_manual_poll_429_includes_retry_after_header(operator_client):
    """HTTP 429 response must include a Retry-After header."""
    client, redis = operator_client

    with unittest.mock.patch(
        "management.api.routes.threat_intel._load_feed_configs",
        return_value=_FAKE_FEEDS,
    ):
        for _ in range(6):
            await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")

        r = await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")
        assert r.status_code == 429
        assert "retry-after" in r.headers, (
            f"429 response missing Retry-After header. Headers: {dict(r.headers)}"
        )
        retry_after = int(r.headers["retry-after"])
        assert 0 < retry_after <= 60, (
            f"Retry-After should be between 1 and 60, got {retry_after}"
        )


# ── H7: After window expires, calls succeed again ────────────────────────────


@pytest.mark.asyncio
async def test_manual_poll_succeeds_after_window_expires(operator_client):
    """After the 60s window expires, the rate limit resets."""
    client, redis = operator_client

    with unittest.mock.patch(
        "management.api.routes.threat_intel._load_feed_configs",
        return_value=_FAKE_FEEDS,
    ):
        # Burn through quota
        for _ in range(6):
            await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")

        # Confirm 7th is blocked
        r = await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")
        assert r.status_code == 429

        # Simulate window expiry by deleting the rate-limit key from Redis
        # The key pattern is ratelimit:ti_feeds:manual:{identity}
        keys = []
        async for key in redis.scan_iter("ratelimit:ti_feeds:manual:*"):
            keys.append(key)
        for key in keys:
            await redis.delete(key)

        # Now the next call should succeed
        r = await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")
        assert r.status_code == 202, (
            f"Call after window expiry returned {r.status_code}, expected 202"
        )


# ── H7: Redis key is correctly named ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_manual_poll_rate_limit_key_format(operator_client):
    """The rate limit key must be ratelimit:ti_feeds:manual:{identity}."""
    client, redis = operator_client

    with unittest.mock.patch(
        "management.api.routes.threat_intel._load_feed_configs",
        return_value=_FAKE_FEEDS,
    ):
        await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")

        # Check that the expected Redis key was created
        keys = []
        async for key in redis.scan_iter("ratelimit:ti_feeds:manual:*"):
            keys.append(key)

        assert len(keys) >= 1, "No rate-limit key found in Redis"
        assert any(
            "ratelimit:ti_feeds:manual:test-operator" in k for k in keys
        ), f"Expected key containing 'ratelimit:ti_feeds:manual:test-operator', found: {keys}"


# ── H7: Prometheus counter incremented on breach ─────────────────────────────


@pytest.mark.asyncio
async def test_manual_poll_prometheus_counter_on_breach(operator_client):
    """ja4proxy_ti_feeds_manual_poll_ratelimited_total must be incremented on 429."""
    client, redis = operator_client

    with unittest.mock.patch(
        "management.api.routes.threat_intel._load_feed_configs",
        return_value=_FAKE_FEEDS,
    ):
        # Burn through quota
        for _ in range(6):
            await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")

        # Trigger rate limit
        r = await client.post("/api/v1/threat-intel/feeds/test-feed-1/poll")
        assert r.status_code == 429

    # Check Prometheus metric exists and has been incremented
    try:
        from prometheus_client import REGISTRY

        metric = REGISTRY._names_to_collectors.get(
            "ja4proxy_ti_feeds_manual_poll_ratelimited_total"
        )
        assert metric is not None, (
            "Prometheus counter ja4proxy_ti_feeds_manual_poll_ratelimited_total not registered"
        )
    except ImportError:
        pytest.skip("prometheus_client not available")
