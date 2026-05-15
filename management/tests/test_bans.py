"""TDD tests for the bans API endpoints.

Covers
------
- GET  /api/v1/bans — lists all active bans
- POST /api/v1/bans/{ip} — creates a ban with TTL and reason
- DELETE /api/v1/bans/{ip} — lifts a ban
- PATCH /api/v1/bans/{ip} — extends an existing ban's TTL (100-J)
- TTL is applied correctly (ban key expires)
- Audit entries created for all write operations
- All routes require authentication
"""

import json
import os

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

TEST_IP = "1.2.3.4"
TEST_IP_V6 = "2001:db8::1"


@pytest.mark.asyncio
async def test_get_bans_empty(authenticated_client: AsyncClient) -> None:
    """GET /api/v1/bans returns empty list when no bans exist."""
    r = await authenticated_client.get("/api/v1/bans")
    assert r.status_code == 200
    data = r.json()
    assert data["bans"] == []
    assert data["count"] == 0


@pytest.mark.asyncio
async def test_create_ban(authenticated_client: AsyncClient) -> None:
    """POST /api/v1/bans/{ip} creates a ban."""
    r = await authenticated_client.post(
        f"/api/v1/bans/{TEST_IP}",
        json={"ttl": 3600, "reason": "manual test"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == TEST_IP
    assert data["ttl"] == 3600
    assert data["reason"] == "manual test"


@pytest.mark.asyncio
async def test_create_ban_appears_in_list(authenticated_client: AsyncClient) -> None:
    """A newly created ban appears in GET /api/v1/bans."""
    await authenticated_client.post(
        f"/api/v1/bans/{TEST_IP}",
        json={"ttl": 3600, "reason": "test reason"},
    )

    r = await authenticated_client.get("/api/v1/bans")
    data = r.json()
    assert data["count"] == 1
    ban = data["bans"][0]
    assert ban["ip"] == TEST_IP
    assert ban["reason"] == "test reason"
    assert ban["ttl_remaining"] is not None
    assert ban["ttl_remaining"] > 0


@pytest.mark.asyncio
async def test_create_ban_default_values(authenticated_client: AsyncClient) -> None:
    """POST /api/v1/bans/{ip} with no body uses default TTL=3600 and reason='manual'."""
    r = await authenticated_client.post(f"/api/v1/bans/{TEST_IP}")
    assert r.status_code == 200
    data = r.json()
    assert data["ttl"] == 3600
    assert data["reason"] == "manual"


@pytest.mark.asyncio
async def test_delete_ban(authenticated_client: AsyncClient) -> None:
    """DELETE /api/v1/bans/{ip} removes a ban."""
    # Create ban
    await authenticated_client.post(
        f"/api/v1/bans/{TEST_IP}",
        json={"ttl": 3600, "reason": "to be lifted"},
    )

    # Lift it
    r = await authenticated_client.delete(f"/api/v1/bans/{TEST_IP}")
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == TEST_IP

    # Verify it's gone
    r2 = await authenticated_client.get("/api/v1/bans")
    assert r2.json()["count"] == 0


@pytest.mark.asyncio
async def test_delete_nonexistent_ban_returns_404(
    authenticated_client: AsyncClient,
) -> None:
    """DELETE /api/v1/bans/{ip} for an IP that isn't banned returns 404."""
    r = await authenticated_client.delete("/api/v1/bans/9.9.9.9")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ban_ttl_set_in_redis(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Creating a ban sets the correct TTL on the Redis key."""
    await authenticated_client.post(
        f"/api/v1/bans/{TEST_IP}",
        json={"ttl": 1800, "reason": "test"},
    )

    key = f"ban:{TEST_IP}"
    ttl = await fake_redis.ttl(key)
    # TTL should be roughly 1800 (allow small margin for test execution time)
    assert 1790 <= ttl <= 1800


@pytest.mark.asyncio
async def test_ban_reason_stored_in_redis(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Ban reason is stored as the value of the ban:{ip} Redis key."""
    reason = "detected scanning"
    await authenticated_client.post(
        f"/api/v1/bans/{TEST_IP}",
        json={"ttl": 3600, "reason": reason},
    )

    value = await fake_redis.get(f"ban:{TEST_IP}")
    assert value == reason


@pytest.mark.asyncio
async def test_create_ban_creates_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Creating a ban writes an audit log entry."""
    await authenticated_client.post(
        f"/api/v1/bans/{TEST_IP}",
        json={"ttl": 3600, "reason": "audit_test"},
    )

    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    # MFA/SSO Hardening C5: enhanced audit schema uses action_type/actor_id/resource_id
    assert entry["action_type"] == "ban.created"
    assert entry["after_value"]["ip"] == TEST_IP


@pytest.mark.asyncio
async def test_delete_ban_creates_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Lifting a ban writes an audit log entry."""
    await fake_redis.set(f"ban:{TEST_IP}", "manual", ex=3600)
    await authenticated_client.delete(f"/api/v1/bans/{TEST_IP}")

    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    # MFA/SSO Hardening C5: enhanced audit schema
    assert entry["action_type"] == "ban.deleted"
    assert entry["before_value"]["ip"] == TEST_IP


@pytest.mark.asyncio
async def test_ipv6_ban(authenticated_client: AsyncClient) -> None:
    """Bans work for IPv6 addresses."""
    import urllib.parse

    encoded = urllib.parse.quote(TEST_IP_V6, safe="")
    r = await authenticated_client.post(
        f"/api/v1/bans/{encoded}",
        json={"ttl": 3600, "reason": "ipv6 test"},
    )
    assert r.status_code == 200
    assert r.json()["ip"] == TEST_IP_V6


@pytest.mark.asyncio
async def test_bans_require_auth(test_client: AsyncClient) -> None:
    """All ban endpoints require authentication."""
    for method, path in [
        ("GET", "/api/v1/bans"),
        ("POST", f"/api/v1/bans/{TEST_IP}"),
        ("DELETE", f"/api/v1/bans/{TEST_IP}"),
    ]:
        if method == "GET":
            r = await test_client.get(path, headers={"Accept": "application/json"})
        elif method == "POST":
            r = await test_client.post(path, headers={"Accept": "application/json"})
        else:
            r = await test_client.delete(path, headers={"Accept": "application/json"})
        assert r.status_code == 401, f"Expected 401 for {method} {path}"


# ── PATCH /api/v1/bans/{ip} — extend ban (100-J) ─────────────────────────────

# Import helpers needed for role-specific client fixtures
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import _create_access_token  # noqa: E402
from management.api.main import create_app  # noqa: E402


@pytest_asyncio.fixture()
async def analyst_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncClient:
    """Authenticated client with analyst (read-only) role."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    token = _create_access_token("analyst-user", role="analyst")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": token},
    ) as client:
        yield client
    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_patch_extends_ttl(
    authenticated_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """PATCH extends an existing ban's TTL by the requested amount."""
    # Create a ban with ttl=100
    await authenticated_client.post(
        f"/api/v1/bans/{TEST_IP}",
        json={"ttl": 100, "reason": "extend test"},
    )

    r = await authenticated_client.patch(
        f"/api/v1/bans/{TEST_IP}",
        json={"extend_ttl_seconds": 50},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ip"] == TEST_IP
    assert data["previous_ttl"] <= 100
    assert data["new_ttl"] == data["previous_ttl"] + 50
    assert "new_expires_at" in data

    # Redis TTL should be close to new_ttl
    ttl_in_redis = await fake_redis.ttl(f"ban:{TEST_IP}")
    assert ttl_in_redis > 0
    assert ttl_in_redis <= data["new_ttl"]


@pytest.mark.asyncio
async def test_patch_nonexistent_returns_404(
    authenticated_client: AsyncClient,
) -> None:
    """PATCH on an IP that isn't banned returns 404."""
    r = await authenticated_client.patch(
        "/api/v1/bans/9.9.9.9",
        json={"extend_ttl_seconds": 3600},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_patch_requires_operator_role(
    analyst_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst role cannot extend bans — requires operator."""
    # Pre-seed a ban directly in Redis so the analyst client encounters a real ban
    await fake_redis.set(f"ban:{TEST_IP}", "manual", ex=3600)

    r = await analyst_client.patch(
        f"/api/v1/bans/{TEST_IP}",
        json={"extend_ttl_seconds": 3600},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_patch_writes_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """PATCH writes a ban.extended audit entry with correct before/after values."""
    await fake_redis.set(f"ban:{TEST_IP}", "audit check", ex=200)

    r = await authenticated_client.patch(
        f"/api/v1/bans/{TEST_IP}",
        json={"extend_ttl_seconds": 100},
    )
    assert r.status_code == 200

    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    assert entry["action_type"] == "ban.extended"
    assert entry["resource_id"] == TEST_IP
    assert "ttl" in entry["before_value"]
    assert entry["after_value"]["extended_by"] == 100


@pytest.mark.asyncio
async def test_patch_rejects_extend_over_30_days(
    authenticated_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """extend_ttl_seconds > 30 days (2592000 s) is rejected with 422."""
    await fake_redis.set(f"ban:{TEST_IP}", "manual", ex=3600)

    r = await authenticated_client.patch(
        f"/api/v1/bans/{TEST_IP}",
        json={"extend_ttl_seconds": 86400 * 31},  # 31 days — over the limit
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_rejects_zero_extend(
    authenticated_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """extend_ttl_seconds=0 is rejected with 422 (must be > 0)."""
    await fake_redis.set(f"ban:{TEST_IP}", "manual", ex=3600)

    r = await authenticated_client.patch(
        f"/api/v1/bans/{TEST_IP}",
        json={"extend_ttl_seconds": 0},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_patch_ipv6_ban_extend(
    authenticated_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """PATCH works correctly for IPv6 addresses."""
    import urllib.parse

    encoded = urllib.parse.quote(TEST_IP_V6, safe="")
    # Create the IPv6 ban
    r_create = await authenticated_client.post(
        f"/api/v1/bans/{encoded}",
        json={"ttl": 300, "reason": "ipv6 extend test"},
    )
    assert r_create.status_code == 200

    r = await authenticated_client.patch(
        f"/api/v1/bans/{encoded}",
        json={"extend_ttl_seconds": 100},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == TEST_IP_V6
    assert data["new_ttl"] > 0


@pytest.mark.asyncio
async def test_patch_preserves_existing_reason(
    authenticated_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """PATCH does not overwrite the existing ban reason."""
    original_reason = "original reason"
    await fake_redis.set(f"ban:{TEST_IP}", original_reason, ex=3600)

    await authenticated_client.patch(
        f"/api/v1/bans/{TEST_IP}",
        json={"extend_ttl_seconds": 600, "reason": "ignored note"},
    )

    stored = await fake_redis.get(f"ban:{TEST_IP}")
    assert stored == original_reason


@pytest.mark.asyncio
async def test_patch_requires_auth(test_client: AsyncClient) -> None:
    """PATCH /api/v1/bans/{ip} requires authentication."""
    r = await test_client.patch(
        f"/api/v1/bans/{TEST_IP}",
        json={"extend_ttl_seconds": 3600},
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 401
