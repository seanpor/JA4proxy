"""TDD tests for the lists API endpoints.

Covers
------
- GET  /api/v1/lists/ja4/whitelist
- POST /api/v1/lists/ja4/whitelist/{entry}
- DELETE /api/v1/lists/ja4/whitelist/{entry}
- GET  /api/v1/lists/ja4/blacklist
- POST /api/v1/lists/ja4/blacklist/{entry}
- DELETE /api/v1/lists/ja4/blacklist/{entry}
- GET  /api/v1/lists/ip/allowlist
- POST /api/v1/lists/ip/allowlist/{entry}
- DELETE /api/v1/lists/ip/allowlist/{entry}
- Duplicate add is idempotent (200, not error)
- Delete of nonexistent entry returns 404
- Invalid list_type returns 404
- Audit log entries created for all write ops
- All routes require authentication
"""

import json

import pytest
from httpx import AsyncClient

# Test JA4 fingerprint fixture
VALID_JA4 = "t13d1516h2_8daaf6152771_b186095e22b6"
VALID_IP = "192.168.1.0/24"


@pytest.mark.asyncio
async def test_get_whitelist_empty(authenticated_client: AsyncClient) -> None:
    """GET whitelist returns empty list when nothing is stored."""
    r = await authenticated_client.get("/api/v1/lists/ja4/whitelist")
    assert r.status_code == 200
    data = r.json()
    assert data["entries"] == []
    assert data["count"] == 0


@pytest.mark.asyncio
async def test_add_to_whitelist(authenticated_client: AsyncClient) -> None:
    """POST to whitelist adds an entry."""
    r = await authenticated_client.post(
        f"/api/v1/lists/ja4/whitelist/{VALID_JA4}"
    )
    assert r.status_code == 200
    assert VALID_JA4 in r.json()["entry"]

    # Verify it shows up in GET
    r2 = await authenticated_client.get("/api/v1/lists/ja4/whitelist")
    assert VALID_JA4 in r2.json()["entries"]
    assert r2.json()["count"] == 1


@pytest.mark.asyncio
async def test_add_duplicate_to_whitelist_is_idempotent(
    authenticated_client: AsyncClient,
) -> None:
    """Adding the same entry twice is idempotent — returns 200 both times."""
    r1 = await authenticated_client.post(f"/api/v1/lists/ja4/whitelist/{VALID_JA4}")
    assert r1.status_code == 200

    r2 = await authenticated_client.post(f"/api/v1/lists/ja4/whitelist/{VALID_JA4}")
    assert r2.status_code == 200

    # Count should still be 1
    r3 = await authenticated_client.get("/api/v1/lists/ja4/whitelist")
    assert r3.json()["count"] == 1


@pytest.mark.asyncio
async def test_delete_from_whitelist(authenticated_client: AsyncClient) -> None:
    """DELETE removes an existing entry."""
    await authenticated_client.post(f"/api/v1/lists/ja4/whitelist/{VALID_JA4}")

    r = await authenticated_client.delete(f"/api/v1/lists/ja4/whitelist/{VALID_JA4}")
    assert r.status_code == 200

    # Verify it's gone
    r2 = await authenticated_client.get("/api/v1/lists/ja4/whitelist")
    assert VALID_JA4 not in r2.json()["entries"]


@pytest.mark.asyncio
async def test_delete_nonexistent_from_whitelist_returns_404(
    authenticated_client: AsyncClient,
) -> None:
    """DELETE of a nonexistent entry returns 404."""
    r = await authenticated_client.delete(
        "/api/v1/lists/ja4/whitelist/nonexistent_entry"
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_add_to_blacklist(authenticated_client: AsyncClient) -> None:
    """POST to blacklist adds an entry."""
    r = await authenticated_client.post(
        f"/api/v1/lists/ja4/blacklist/{VALID_JA4}"
    )
    assert r.status_code == 200

    r2 = await authenticated_client.get("/api/v1/lists/ja4/blacklist")
    assert VALID_JA4 in r2.json()["entries"]


@pytest.mark.asyncio
async def test_add_to_ip_allowlist(authenticated_client: AsyncClient) -> None:
    """POST to IP allowlist adds an entry."""
    import urllib.parse
    encoded_ip = urllib.parse.quote(VALID_IP, safe="")
    r = await authenticated_client.post(
        f"/api/v1/lists/ip/allowlist/{encoded_ip}"
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_get_ip_allowlist(authenticated_client: AsyncClient, fake_redis) -> None:
    """GET IP allowlist returns entries from static:allowlist Redis SET."""
    await fake_redis.sadd("static:allowlist", "10.0.0.1", "10.0.0.2")
    r = await authenticated_client.get("/api/v1/lists/ip/allowlist")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 2
    assert "10.0.0.1" in data["entries"]


@pytest.mark.asyncio
async def test_invalid_list_type_returns_404(authenticated_client: AsyncClient) -> None:
    """Unknown list_type returns 404."""
    r = await authenticated_client.get("/api/v1/lists/invalid/whitelist")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_add_to_whitelist_creates_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Adding an entry creates an audit log entry."""
    await authenticated_client.post(f"/api/v1/lists/ja4/whitelist/{VALID_JA4}")

    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    assert entry["action"] == "list_entry_added"
    assert VALID_JA4 in str(entry["detail"])


@pytest.mark.asyncio
async def test_delete_from_whitelist_creates_audit_entry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Removing an entry creates an audit log entry."""
    await fake_redis.sadd("ja4:whitelist", VALID_JA4)
    await authenticated_client.delete(f"/api/v1/lists/ja4/whitelist/{VALID_JA4}")

    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert len(entries) == 1
    entry = json.loads(entries[0])
    assert entry["action"] == "list_entry_removed"


@pytest.mark.asyncio
async def test_lists_require_auth(test_client: AsyncClient) -> None:
    """All list endpoints require authentication."""
    for method, path in [
        ("GET", "/api/v1/lists/ja4/whitelist"),
        ("POST", f"/api/v1/lists/ja4/whitelist/{VALID_JA4}"),
        ("DELETE", f"/api/v1/lists/ja4/whitelist/{VALID_JA4}"),
    ]:
        if method == "GET":
            r = await test_client.get(path, headers={"Accept": "application/json"})
        elif method == "POST":
            r = await test_client.post(path, headers={"Accept": "application/json"})
        else:
            r = await test_client.delete(path, headers={"Accept": "application/json"})
        assert r.status_code == 401, f"Expected 401 for {method} {path}"


@pytest.mark.asyncio
async def test_whitelist_and_blacklist_are_separate(
    authenticated_client: AsyncClient,
) -> None:
    """Whitelist and blacklist are independent sets."""
    await authenticated_client.post(f"/api/v1/lists/ja4/whitelist/{VALID_JA4}")

    r_black = await authenticated_client.get("/api/v1/lists/ja4/blacklist")
    assert VALID_JA4 not in r_black.json()["entries"]
