"""TDD tests for the bans API endpoints.

Covers
------
- GET  /api/v1/bans — lists all active bans
- POST /api/v1/bans/{ip} — creates a ban with TTL and reason
- DELETE /api/v1/bans/{ip} — lifts a ban
- TTL is applied correctly (ban key expires)
- Audit entries created for all write operations
- All routes require authentication
"""

import json

import pytest
from httpx import AsyncClient

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
    # Phase 79 C5: enhanced audit schema uses action_type/actor_id/resource_id
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
    # Phase 79 C5: enhanced audit schema
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
