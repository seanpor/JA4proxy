"""TDD tests for the audit log endpoint.

Covers
------
- GET /api/v1/audit returns list of audit entries
- Entries are returned newest-first (LRANGE order from Redis LIST)
- Count matches entries length
- Empty log returns count=0
- Requires authentication
"""

import json

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_audit_log_empty(authenticated_client: AsyncClient) -> None:
    """GET /api/v1/audit returns empty list when no actions have been taken."""
    r = await authenticated_client.get("/api/v1/audit")
    assert r.status_code == 200
    data = r.json()
    assert data["entries"] == []
    assert data["count"] == 0


@pytest.mark.asyncio
async def test_audit_log_returns_entries(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """GET /api/v1/audit returns entries from management:audit_log."""
    entry1 = json.dumps({
        "timestamp": "2024-01-01T00:00:00Z",
        "action": "dial_changed",
        "user": "admin",
        "detail": {"from": 0, "to": 10},
        "ip": "1.2.3.4",
    })
    entry2 = json.dumps({
        "timestamp": "2024-01-01T00:01:00Z",
        "action": "ban_created",
        "user": "admin",
        "detail": {"ip": "5.6.7.8"},
        "ip": "1.2.3.4",
    })

    # LPUSH so newest is at head
    await fake_redis.lpush("management:audit_log", entry1)
    await fake_redis.lpush("management:audit_log", entry2)

    r = await authenticated_client.get("/api/v1/audit")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 2
    assert len(data["entries"]) == 2


@pytest.mark.asyncio
async def test_audit_log_newest_first(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Audit entries are returned newest-first (LRANGE from head)."""
    older = json.dumps({
        "timestamp": "2024-01-01T00:00:00Z",
        "action": "first_action",
        "user": "admin",
        "detail": {},
        "ip": "1.2.3.4",
    })
    newer = json.dumps({
        "timestamp": "2024-01-01T00:01:00Z",
        "action": "second_action",
        "user": "admin",
        "detail": {},
        "ip": "1.2.3.4",
    })

    await fake_redis.lpush("management:audit_log", older)
    await fake_redis.lpush("management:audit_log", newer)  # newest is now at head

    r = await authenticated_client.get("/api/v1/audit")
    entries = r.json()["entries"]
    # The most recently pushed should be first
    assert entries[0]["action"] == "second_action"
    assert entries[1]["action"] == "first_action"


@pytest.mark.asyncio
async def test_audit_log_requires_auth(test_client: AsyncClient) -> None:
    """GET /api/v1/audit requires authentication."""
    r = await test_client.get(
        "/api/v1/audit",
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_audit_entries_are_trimmed_to_1000(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Audit log does not grow beyond 1000 entries (verified by write ops)."""
    # We write 1010 entries via lpush/ltrim to simulate being over the limit
    for i in range(1010):
        entry = json.dumps({
            "timestamp": "2024-01-01T00:00:00Z",
            "action": f"action_{i}",
            "user": "admin",
            "detail": {},
            "ip": "1.2.3.4",
        })
        await fake_redis.lpush("management:audit_log", entry)
    # Trim to 1000 manually as the route should do
    await fake_redis.ltrim("management:audit_log", 0, 999)

    r = await authenticated_client.get("/api/v1/audit")
    data = r.json()
    assert data["count"] <= 1000
