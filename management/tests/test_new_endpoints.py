"""TDD tests for MFA/SSO Hardening Cluster 4 — New REST Endpoints.

Seven endpoint groups are tested here.  All tests are written to FAIL
against the current codebase — none of the routes exist yet.

Sections
--------
A  /api/v1/connections          — connection history from Redis Stream
B  /api/v1/fingerprints/{ja4}   — fingerprint detail and history
C  /api/v1/nodes                — live proxy node list + reload
D  /api/v1/webhooks             — webhook subscription CRUD
E  /api/v1/metrics/summary      — operational metrics snapshot
F  /api/v1/health/deep          — deep health check (Redis + latency)
G  /api/v1/ready                — readiness probe (no auth)

All tests are async, use pytest-asyncio, and seed/query Redis via
fakeredis.  Auth assertions use the cookie-free _bearer_client pattern
so that role checks are exercised and not masked by admin-cookie fallback.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Tuple

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ── Env vars must precede any management import ───────────────────────────────

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import _create_access_token  # noqa: E402
from management.api.main import create_app  # noqa: E402

# ── Stream / Redis constants ──────────────────────────────────────────────────
#
# The Go proxy writes ECS-dotted JSON under a single "event" field — see
# management/api/routes/connections.py's _parse_entry(). Matches the pattern
# already correct in management/tests/test_attack.py.

_STREAM_KEY = "events:connection"


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Isolated FakeRedis server — each test gets a clean slate."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


# ── Helper: create a token of the given role via the admin client ─────────────


async def _make_token(
    admin_client: AsyncClient, role: str, name: str | None = None
) -> str:
    """Seed a bearer token with *role* and return the plaintext."""
    token_name = name or f"new-endpoints-test-{role}-{time.time_ns()}"
    r = await admin_client.post(
        "/api/v1/tokens",
        json={"name": token_name, "role": role},
    )
    assert (
        r.status_code == 201
    ), f"Expected 201 creating {role} token, got {r.status_code}: {r.text}"
    return r.json()["token"]


@asynccontextmanager
async def _bearer_client(
    role: str,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[Tuple[AsyncClient, str], None]:
    """Yield a cookie-free AsyncClient and a valid bearer token of *role*.

    Uses the same double-app pattern as test_resource_model.py so that
    cookie auth (which always grants admin) cannot mask missing role checks.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    admin_cookie = {"token": _create_access_token("admin", role="admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as admin_client:
        plaintext = await _make_token(admin_client, role)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, plaintext

    await _redis_module.close_redis()


# Helper: XADD a connection event to the stream


async def _xadd_event(
    redis: fakeredis.aioredis.FakeRedis,
    ip: str = "1.2.3.4",
    ja4: str = "t13d_default",
    risk_score: int = 42,
    action_taken: str = "allow",
    timestamp: str = "2026-04-07T10:00:00Z",
) -> str:
    """Add one connection event to the stream; return the entry ID.

    Writes the ECS-dotted JSON-in-"event" format the Go proxy actually
    produces (management/api/routes/connections.py's _parse_entry()), not
    the flat-field legacy shape.
    """
    return await redis.xadd(
        _STREAM_KEY,
        {
            "event": json.dumps(
                {
                    "@timestamp": timestamp,
                    "source.ip": ip,
                    "ja4proxy.fingerprint.ja4": ja4,
                    "event.risk_score": risk_score,
                    "event.action": action_taken,
                }
            )
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Section A — /api/v1/connections
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_connections_empty_stream(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Empty stream returns connections=[], count=0 and no error."""
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/connections",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["connections"] == []
        assert data["count"] == 0


@pytest.mark.asyncio
async def test_get_connections_returns_seeded_events(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Seeding 3 events returns all 3 with correct fields in the response."""
    await _xadd_event(fake_redis, ip="10.0.0.1", ja4="t13d_aaa")
    await _xadd_event(fake_redis, ip="10.0.0.2", ja4="t13d_bbb")
    await _xadd_event(fake_redis, ip="10.0.0.3", ja4="t13d_ccc")

    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/connections",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 3
        assert len(data["connections"]) == 3
        returned_ips = {conn["ip"] for conn in data["connections"]}
        returned_ja4s = {conn["ja4"] for conn in data["connections"]}
        assert returned_ips == {
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
        }, f"Expected IPs {{10.0.0.1, 10.0.0.2, 10.0.0.3}}, got {returned_ips}"
        assert returned_ja4s == {
            "t13d_aaa",
            "t13d_bbb",
            "t13d_ccc",
        }, f"Expected ja4s {{t13d_aaa, t13d_bbb, t13d_ccc}}, got {returned_ja4s}"
        for conn in data["connections"]:
            assert conn.get("risk_score") is not None
            assert conn.get("action_taken") is not None


@pytest.mark.asyncio
async def test_get_connections_filter_by_ip(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """?ip=1.2.3.4 returns only events whose ip matches."""
    await _xadd_event(fake_redis, ip="1.2.3.4", ja4="t13d_target")
    await _xadd_event(fake_redis, ip="9.9.9.9", ja4="t13d_other")
    await _xadd_event(fake_redis, ip="1.2.3.4", ja4="t13d_target2")

    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/connections?ip=1.2.3.4",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        for conn in data["connections"]:
            assert conn["ip"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_get_connections_filter_by_ja4(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """?ja4=t13d_abc returns only events with that fingerprint."""
    await _xadd_event(fake_redis, ip="1.1.1.1", ja4="t13d_abc")
    await _xadd_event(fake_redis, ip="2.2.2.2", ja4="t13d_xyz")
    await _xadd_event(fake_redis, ip="3.3.3.3", ja4="t13d_abc")

    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/connections?ja4=t13d_abc",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        for conn in data["connections"]:
            assert conn["ja4"] == "t13d_abc"


@pytest.mark.asyncio
async def test_get_connections_limit_param(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """?limit=3 with 10-event stream returns 3 entries and truncated=True; all 10 visible without limit."""
    for i in range(10):
        await _xadd_event(fake_redis, ip=f"10.0.0.{i}", ja4="t13d_limit_test")

    async with _bearer_client("analyst", fake_redis) as (client, token):
        # Prove 10 exist (no limit)
        r_all = await client.get(
            "/api/v1/connections",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r_all.status_code == 200
        assert (
            r_all.json()["count"] == 10
        ), "All 10 seeded events must be returned without limit"

        # With limit=3
        r = await client.get(
            "/api/v1/connections?limit=3",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert len(data["connections"]) == 3
        assert data["count"] == 3
        assert (
            data["truncated"] is True
        ), "truncated must be True when limit < total stream length"
        for conn in data["connections"]:
            assert conn["ip"].startswith("10.0.0.")


@pytest.mark.asyncio
async def test_get_connections_requires_analyst(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """An auditor-role bearer token is rejected with 403."""
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/connections",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_connections_no_auth(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A request with no credentials returns 401."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/api/v1/connections",
                headers={"Accept": "application/json"},
            )
            assert r.status_code == 401
    finally:
        await _redis_module.close_redis()


# ═══════════════════════════════════════════════════════════════════════════════
# Section B — /api/v1/fingerprints/{ja4}
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_fingerprint_detail(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Seeding 2 IPs for same JA4 returns total_connections==2, len(unique_ips)==2."""
    await _xadd_event(
        fake_redis,
        ip="10.1.1.1",
        ja4="t13d_fp1",
        action_taken="allow",
        timestamp="2026-04-07T09:00:00Z",
    )
    await _xadd_event(
        fake_redis,
        ip="10.1.1.2",
        ja4="t13d_fp1",
        action_taken="block",
        timestamp="2026-04-07T10:00:00Z",
    )

    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/fingerprints/t13d_fp1",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["fingerprint"] == "t13d_fp1"
        assert data["total_connections"] == 2
        assert len(data["unique_ips"]) == 2
        assert set(data["unique_ips"]) == {"10.1.1.1", "10.1.1.2"}
        # last_seen should reflect the most recent timestamp
        assert data["last_seen"] == "2026-04-07T10:00:00Z"
        # actions dict should contain allow and block counts
        assert "actions" in data
        assert data["actions"].get("allow", 0) == 1
        assert data["actions"].get("block", 0) == 1


@pytest.mark.asyncio
async def test_get_fingerprint_unknown_returns_404(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A fingerprint that has never appeared in the stream returns 404."""
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/fingerprints/t13d_never_seen",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_fingerprint_history(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The /history sub-route returns 3 events in chronological order."""
    seeded_timestamps = [
        "2026-04-07T08:00:00Z",
        "2026-04-07T09:00:00Z",
        "2026-04-07T10:00:00Z",
    ]
    for ts in seeded_timestamps:
        await _xadd_event(fake_redis, ip="5.5.5.5", ja4="t13d_hist", timestamp=ts)

    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/fingerprints/t13d_hist/history",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["fingerprint"] == "t13d_hist"
        assert data["count"] == 3
        assert len(data["events"]) == 3
        # Chronological — earliest first
        returned_ts = [e["timestamp"] for e in data["events"]]
        assert returned_ts == sorted(
            returned_ts
        ), "Events must be in chronological order"
        assert set(returned_ts) == set(
            seeded_timestamps
        ), f"Returned timestamps {set(returned_ts)} must match seeded {set(seeded_timestamps)}"
        for e in data["events"]:
            assert e.get("ja4") == "t13d_hist" or e.get("fingerprint") == "t13d_hist"


@pytest.mark.asyncio
async def test_get_fingerprint_requires_analyst(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """An auditor bearer token is rejected with 403 for fingerprint detail."""
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/fingerprints/t13d_anyfp",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
# Section C — /api/v1/nodes
# ═══════════════════════════════════════════════════════════════════════════════


async def _seed_node(
    redis: fakeredis.aioredis.FakeRedis,
    host: str = "host1",
    port: str = "8080",
    version: str = "2.3.1",
    started_at: str = "2026-04-07T08:00:00Z",
    last_seen: str = "2026-04-07T10:00:00Z",
    connections_total: str = "500",
) -> None:
    """Write a synthetic node heartbeat Hash into fake_redis with TTL=60."""
    key = f"mgmt:node:{host}:{port}"
    await redis.hset(
        key,
        mapping={
            "host": host,
            "port": port,
            "version": version,
            "started_at": started_at,
            "last_seen": last_seen,
            "connections_total": connections_total,
        },
    )
    await redis.expire(key, 60)


@pytest.mark.asyncio
async def test_get_nodes_empty(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """With no heartbeat keys the response is nodes=[], count=0."""
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/nodes",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["nodes"] == []
        assert data["count"] == 0


@pytest.mark.asyncio
async def test_get_nodes_returns_live_nodes(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A seeded heartbeat Hash appears in the list with all expected fields."""
    await _seed_node(
        fake_redis,
        host="proxy-a",
        port="8080",
        version="2.3.1",
        connections_total="500",
        started_at="2026-04-07T08:00:00Z",
        last_seen="2026-04-07T10:00:00Z",
    )

    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/nodes",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        node = data["nodes"][0]
        assert node["host"] == "proxy-a"
        assert node["port"] in ("8080", 8080)
        assert (
            node["version"] == "2.3.1"
        ), f"version must be '2.3.1', got {node['version']!r}"
        assert (
            int(node.get("connections_total", -1)) == 500
        ), f"connections_total must be 500, got {node.get('connections_total')!r}"
        assert (
            node["started_at"] == "2026-04-07T08:00:00Z"
        ), f"started_at must be the seeded value, got {node['started_at']!r}"
        assert (
            node["last_seen"] == "2026-04-07T10:00:00Z"
        ), f"last_seen must be the seeded value, got {node['last_seen']!r}"


@pytest.mark.asyncio
async def test_get_nodes_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A request with no credentials returns 401 for the nodes endpoint."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/api/v1/nodes",
                headers={"Accept": "application/json"},
            )
            assert r.status_code == 401
    finally:
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_post_node_reload_publishes_to_channel(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/nodes/{host}/reload actually publishes a message to a Redis channel."""
    # Subscribe to the expected control channel before making the request
    pubsub = fake_redis.pubsub()
    await pubsub.psubscribe(
        "*reload*"
    )  # broad pattern to catch whatever channel name the impl uses
    await pubsub.get_message(timeout=0.1)  # drain subscription confirmation

    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/nodes/host1/reload",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data.get("published") is True
        assert data.get("host") == "host1"

    # Verify a message was actually published (not just response body faked)
    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
    assert msg is not None, (
        "Expected a Redis pub/sub message after node reload — "
        "implementation must call redis.publish(), not just return {'published': True}"
    )
    assert msg["type"] in ("message", "pmessage"), (
        f"Expected message type 'message' or 'pmessage', got {msg['type']!r}. "
        "psubscribe returns 'pmessage'; subscribe returns 'message'."
    )
    await pubsub.punsubscribe("*reload*")
    await pubsub.aclose()


@pytest.mark.asyncio
async def test_post_node_reload_requires_admin(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """An operator bearer token is rejected with 403 for node reload."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/nodes/host1/reload",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════════
# Section D — /api/v1/webhooks
# ═══════════════════════════════════════════════════════════════════════════════


async def _create_webhook(
    client: AsyncClient,
    token: str,
    url: str = "https://example.com/hook",
    events: list[str] | None = None,
) -> dict[str, Any]:
    """POST a webhook subscription and return the response body."""
    payload: dict[str, Any] = {
        "url": url,
        "events": events or ["connection.blocked", "ban.created"],
    }
    r = await client.post(
        "/api/v1/webhooks",
        json=payload,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
    return r.json()


@pytest.mark.asyncio
async def test_post_webhook_returns_secret_once(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Creating a webhook returns 201 with a non-empty secret field."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        data = await _create_webhook(client, token)
        assert "secret" in data
        assert data["secret"]  # non-empty
        assert "id" in data
        assert data["url"] == "https://example.com/hook"


@pytest.mark.asyncio
async def test_post_webhook_secret_not_in_subsequent_get(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/webhooks/{id} does not expose the secret or its hash."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _create_webhook(client, token)
        webhook_id = created["id"]

        r = await client.get(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "secret" not in data, "Plaintext secret must not appear in GET response"
        assert "secret_hash" not in data, (
            "Bcrypt hash (secret_hash) must not appear in GET response — "
            "if it does, clients can attempt offline cracking"
        )


@pytest.mark.asyncio
async def test_get_webhooks_empty(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """With no webhooks the list endpoint returns webhooks=[], count=0."""
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/webhooks",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["webhooks"] == []
        assert data["count"] == 0


@pytest.mark.asyncio
async def test_get_webhooks_shows_created(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A created webhook appears in the list with correct url and events."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        await _create_webhook(
            client,
            token,
            url="https://example.com/hook",
            events=["connection.blocked"],
        )

        r = await client.get(
            "/api/v1/webhooks",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        entry = data["webhooks"][0]
        assert entry["url"] == "https://example.com/hook"
        assert "connection.blocked" in entry["events"]
        assert "secret" not in entry


@pytest.mark.asyncio
async def test_put_webhook_updates_url(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """PUT /api/v1/webhooks/{id} updates the url and GET reflects the change."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _create_webhook(
            client, token, url="https://old.example.com/hook"
        )
        webhook_id = created["id"]

        r = await client.put(
            f"/api/v1/webhooks/{webhook_id}",
            json={
                "url": "https://new.example.com/hook",
                "events": ["ban.created"],
                "active": True,
            },
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200

        r2 = await client.get(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r2.status_code == 200
        assert r2.json()["url"] == "https://new.example.com/hook"

        # List must still have exactly 1 webhook (not a new record added)
        r_list = await client.get(
            "/api/v1/webhooks",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        list_data = r_list.json()
        assert (
            list_data["count"] == 1
        ), f"PUT must update in-place, not create a second record; count={list_data['count']}"
        urls_in_list = [w["url"] for w in list_data["webhooks"]]
        assert (
            "https://old.example.com/hook" not in urls_in_list
        ), "Old URL must be gone from list after PUT"
        assert "https://new.example.com/hook" in urls_in_list


@pytest.mark.asyncio
async def test_delete_webhook_is_idempotent(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Deleting a webhook twice returns 204 both times."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _create_webhook(client, token)
        webhook_id = created["id"]

        r1 = await client.delete(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r1.status_code == 204

        r2 = await client.delete(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r2.status_code == 204


@pytest.mark.asyncio
async def test_delete_webhook_removes_from_list(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """After deletion the webhook no longer appears in GET /api/v1/webhooks."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _create_webhook(client, token)
        webhook_id = created["id"]

        await client.delete(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

        r = await client.get(
            "/api/v1/webhooks",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        ids = [w["id"] for w in data["webhooks"]]
        assert webhook_id not in ids


@pytest.mark.asyncio
async def test_post_webhook_requires_operator(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """An auditor bearer token is rejected with 403 when creating a webhook."""
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/webhooks",
            json={"url": "https://example.com/hook", "events": ["ban.created"]},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403


@pytest.mark.asyncio
async def test_get_webhooks_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A request with no credentials returns 401 for the webhook list."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/api/v1/webhooks",
                headers={"Accept": "application/json"},
            )
            assert r.status_code == 401
    finally:
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_webhook_secret_stored_as_bcrypt(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The stored secret_hash in Redis starts with the bcrypt prefix $2b$."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _create_webhook(client, token)
        webhook_id = created["id"]

        raw = await fake_redis.hgetall(f"webhook:{webhook_id}")
        assert (
            "secret_hash" in raw
        ), f"Expected secret_hash in Hash, got keys: {list(raw)}"
        assert raw["secret_hash"].startswith(
            "$2b$"
        ), f"Expected bcrypt hash starting with $2b$, got: {raw['secret_hash'][:10]!r}"


# ═══════════════════════════════════════════════════════════════════════════════
# Section E — /api/v1/metrics/summary
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_metrics_summary_shape(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Response contains dial==25, active_bans (int), events_stream_length (int), timestamp."""
    await fake_redis.set("config:dial", "25")

    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/metrics/summary",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["dial"] == 25
        assert isinstance(data["active_bans"], int)
        assert isinstance(data["events_stream_length"], int)
        assert data["timestamp"]  # non-empty string


@pytest.mark.asyncio
async def test_get_metrics_summary_reflects_ban_count(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """active_bans reflects the number of ban:* keys currently in Redis."""
    await fake_redis.set("config:dial", "0")
    await fake_redis.set("ban:1.2.3.4", "manual", ex=3600)
    await fake_redis.set("ban:5.6.7.8", "manual", ex=3600)
    await fake_redis.set("ban:10.0.0.1", "manual", ex=3600)
    # Noise keys that must not inflate ban count
    await fake_redis.set("allowlist:192.168.0.1", "1")
    await fake_redis.set("config:dial", "50")
    await fake_redis.hset("mgmt:token:someid", mapping={"id": "x"})

    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/metrics/summary",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert (
            data["active_bans"] == 3
        ), f"active_bans must count only ban:* keys, not noise keys; got {data['active_bans']}"


@pytest.mark.asyncio
async def test_get_metrics_summary_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A request with no credentials returns 401 for the metrics summary."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/api/v1/metrics/summary",
                headers={"Accept": "application/json"},
            )
            assert r.status_code == 401
    finally:
        await _redis_module.close_redis()


# ═══════════════════════════════════════════════════════════════════════════════
# Section F — /api/v1/health/deep
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_health_deep_ok_when_redis_connected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """With a reachable Redis the deep health check returns status==ok."""
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/health/deep",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["redis"]["status"] == "ok"


@pytest.mark.asyncio
async def test_health_deep_has_timestamp(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The deep health response always includes a non-empty timestamp string."""
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/health/deep",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "timestamp" in data
        assert data["timestamp"]  # non-empty


@pytest.mark.asyncio
async def test_health_deep_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A request with no credentials returns 401 for the deep health endpoint."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get(
                "/api/v1/health/deep",
                headers={"Accept": "application/json"},
            )
            assert r.status_code == 401
    finally:
        await _redis_module.close_redis()


# ═══════════════════════════════════════════════════════════════════════════════
# Section G — /api/v1/ready
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_ready_ok_when_redis_reachable(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """With Redis reachable and config:dial present GET /api/v1/ready returns 200."""
    await fake_redis.set("config:dial", "0")
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get("/api/v1/ready")
            assert r.status_code == 200
            data = r.json()
            assert data["ready"] is True
    finally:
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_ready_no_auth_required(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The readiness probe is public — no cookie or bearer token needed."""
    await fake_redis.set("config:dial", "0")
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            # Deliberately send no Authorization header and no cookie
            r = await client.get("/api/v1/ready")
            # Must be 200, not 401 or 403
            assert r.status_code == 200
    finally:
        await _redis_module.close_redis()


# ═══════════════════════════════════════════════════════════════════════════════
# MT1 — Filter by action_taken
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_connections_filter_by_action(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """?action=block returns only blocked connections; allow events are excluded."""
    await _xadd_event(fake_redis, ip="1.1.1.1", ja4="t13d_act", action_taken="allow")
    await _xadd_event(fake_redis, ip="2.2.2.2", ja4="t13d_act", action_taken="block")
    await _xadd_event(fake_redis, ip="3.3.3.3", ja4="t13d_act", action_taken="block")

    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/connections?action=block",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2
        for conn in data["connections"]:
            assert (
                conn["action_taken"] == "block"
            ), f"Filter ?action=block must exclude allow events; got: {conn['action_taken']}"
        returned_ips = {conn["ip"] for conn in data["connections"]}
        assert "1.1.1.1" not in returned_ips, "IP with allow action must be excluded"


# ═══════════════════════════════════════════════════════════════════════════════
# MT2 — Webhook events filter is enforced
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_webhook_events_list_is_stored_correctly(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The events subscription list is stored and returned correctly, not silently ignored."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/webhooks",
            json={
                "url": "https://events-test.example.com/hook",
                "events": ["ban.created", "dial.changed"],
            },
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201
        webhook_id = r.json()["id"]

        # Retrieve and verify events are stored correctly
        r2 = await client.get(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r2.status_code == 200
        data = r2.json()
        assert "events" in data, "Webhook must return events subscription list"
        returned_events = set(data["events"])
        assert returned_events == {
            "ban.created",
            "dial.changed",
        }, f"Stored events must match submitted events; got {returned_events}"


# ═══════════════════════════════════════════════════════════════════════════════
# MT3 — Node reload unknown host behavior
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_post_node_reload_unknown_host(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST reload for a host with no heartbeat key returns 200 or 404 (not 500)."""
    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/nodes/nonexistent-host/reload",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 404), (
            f"Reload for unknown host must return 200 (published anyway) or 404, "
            f"not 500; got {r.status_code}: {r.text[:200]}"
        )
        # Must not crash with a server error
        assert r.status_code != 500


# ═══════════════════════════════════════════════════════════════════════════════
# MT4 — Metrics events_stream_length reflects real count
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_metrics_summary_events_stream_length(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """events_stream_length reflects the actual number of events in the stream."""
    await fake_redis.set("config:dial", "0")
    for i in range(5):
        await _xadd_event(fake_redis, ip=f"10.0.{i}.1", ja4="t13d_metrics")

    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/metrics/summary",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["events_stream_length"] == 5, (
            f"events_stream_length must equal the number of stream entries (5), "
            f"got {data['events_stream_length']}. A stub returning 0 would fail this."
        )


# ═══════════════════════════════════════════════════════════════════════════════
# MT5 — Deleted webhook GET by ID returns 404
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_delete_webhook_get_by_id_returns_404(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """After DELETE, GET /api/v1/webhooks/{id} returns 404 (not stale Hash data)."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _create_webhook(client, token)
        webhook_id = created["id"]

        await client.delete(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )

        r = await client.get(
            f"/api/v1/webhooks/{webhook_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 404, (
            f"GET after DELETE must return 404; got {r.status_code}. "
            "The Hash record may have been deleted without removing the index entry, "
            "or vice versa."
        )
