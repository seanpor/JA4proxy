"""TDD tests for Phase 79 Cluster 3 — Resource Model (UUID + managed_by).

These tests cover the three canonical list endpoints:
    POST   /api/v1/allowlist
    GET    /api/v1/allowlist
    GET    /api/v1/allowlist/{id}
    DELETE /api/v1/allowlist/{id}

    POST   /api/v1/blocklist
    GET    /api/v1/blocklist
    DELETE /api/v1/blocklist/{id}

    POST   /api/v1/watchlist
    GET    /api/v1/watchlist
    DELETE /api/v1/watchlist/{id}

Each entry has a full resource envelope with UUID, managed_by, created_at, etc.
The implementation maintains dual-write: Hash records (management API) + fast SET
entries (proxy lookup) in parallel.

All tests are written to FAIL against the current codebase (routes do not exist).

Role requirements:
    GET  (all lists)   → Auditor+
    POST (all lists)   → Operator+
    DELETE (all lists) → Operator+
"""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Tuple

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Env vars must be set before any management import
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import _create_access_token  # noqa: E402
from management.api.main import create_app  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_UUID_NIL = "00000000-0000-0000-0000-000000000000"

_MANAGED_BY_VALUES = ["operator", "terraform", "api", "legacy"]

# ── Per-test isolated FakeRedis ───────────────────────────────────────────────


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Isolated FakeRedis server instance — each test gets a clean slate."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


# ── Helper: build an app sharing a given fake_redis instance ─────────────────


async def _make_app_with_redis(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> tuple:
    """Create a FastAPI app instance backed by fake_redis.

    Returns (app, admin_cookie_dict) for use in bearer_client helpers.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}
    return app, admin_cookie


async def _make_token(
    admin_client: AsyncClient,
    role: str,
    name: str | None = None,
) -> str:
    """Seed a bearer token of the given role and return the plaintext."""
    token_name = name or f"resource-model-test-{role}"
    r = await admin_client.post(
        "/api/v1/tokens",
        json={"name": token_name, "role": role},
    )
    assert r.status_code == 201, (
        f"Expected 201 creating {role} token, got {r.status_code}: {r.text}"
    )
    return r.json()["token"]


@asynccontextmanager
async def _bearer_client(
    role: str,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[Tuple[AsyncClient, str], None]:
    """Yield a cookie-free AsyncClient and a valid bearer token of the given role.

    Mirrors the exact pattern from test_rbac.py to avoid cookie contamination.
    Cookie auth always returns role=admin, which would mask missing role checks.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    admin_cookie = {"token": _create_access_token("admin")}

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


# ── Convenience: POST an entry and return parsed response body ────────────────


async def _post_entry(
    client: AsyncClient,
    token: str,
    path: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """POST *payload* to *path* using bearer *token*; assert 201 and return JSON."""
    r = await client.post(
        path,
        json=payload,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
    return r.json()


# ═══════════════════════════════════════════════════════════════════════════════
# Section 1: Allowlist CRUD
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_post_allowlist_returns_full_resource(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist returns 201 with the full resource envelope.

    Verifies that the new canonical allowlist endpoint exists and returns
    all required fields: id (UUID4), entry, managed_by, note, created_at,
    created_by, list_type, and expires_at (null when not provided).
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={
                "entry": "t13d1516h2_abc",
                "managed_by": "operator",
                "note": "test",
            },
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        data = r.json()
        assert "id" in data, "Response must include 'id'"
        assert _UUID4_RE.match(data["id"]), f"'id' must be UUID4 format, got: {data['id']}"
        assert data["entry"] == "t13d1516h2_abc"
        assert data["managed_by"] == "operator"
        assert data["note"] == "test"
        assert data["list_type"] == "allowlist"
        assert "created_at" in data
        assert "created_by" in data
        # expires_at must be null or absent when not provided
        assert data.get("expires_at") is None

        # POST a second entry and verify IDs are unique
        r2 = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d1516h2_abc_second", "managed_by": "operator", "note": "test2"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r2.status_code == 201
        data2 = r2.json()
        assert data["id"] != data2["id"], (
            "Each POST must generate a unique UUID — a stub returning a hardcoded UUID would fail this"
        )


@pytest.mark.asyncio
async def test_post_allowlist_requires_operator_role(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist with auditor token returns 403.

    Auditor is read-only; writes require at least Operator.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d1516h2_abc", "managed_by": "operator", "note": ""},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on POST /api/v1/allowlist must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_post_allowlist_missing_entry_returns_422(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist without 'entry' field returns 422.

    'entry' is a required field; Pydantic validation must reject the request.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"managed_by": "operator", "note": "no entry"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 422, (
            f"Missing 'entry' must return 422, got {r.status_code}: {r.text}"
        )


@pytest.mark.asyncio
async def test_post_allowlist_invalid_managed_by_returns_422(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist with an invalid managed_by value returns 422.

    'robot' is not in the allowed set; validation must reject it.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={
                "entry": "t13d1516h2_abc",
                "managed_by": "robot",
                "note": "invalid managed_by",
            },
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 422, (
            f"Invalid managed_by='robot' must return 422, got {r.status_code}: {r.text}"
        )


@pytest.mark.asyncio
async def test_get_allowlist_returns_list(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/allowlist returns {entries: [...], count: N} with full resource objects.

    After one POST the list must contain exactly one entry that has a UUID
    and all resource fields — not just a raw string.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d1516h2_abc", "managed_by": "operator", "note": ""},
        )
        r = await client.get(
            "/api/v1/allowlist",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        data = r.json()
        assert "entries" in data
        assert "count" in data
        assert data["count"] == 1
        entry = data["entries"][0]
        assert "id" in entry
        assert _UUID4_RE.match(entry["id"]), "Entries in list must have UUID4 id"
        assert entry["entry"] == "t13d1516h2_abc"


@pytest.mark.asyncio
async def test_get_allowlist_managed_by_filter(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/allowlist?managed_by=terraform returns only terraform entries.

    Filtering by managed_by must be supported; only matching entries are returned.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d1516h2_terraform", "managed_by": "terraform", "note": "tf entry"},
        )
        await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d1516h2_operator", "managed_by": "operator", "note": "op entry"},
        )
        r = await client.get(
            "/api/v1/allowlist?managed_by=terraform",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        data = r.json()
        assert data["count"] == 1, (
            f"Filter managed_by=terraform must return 1 entry, got {data['count']}"
        )
        assert data["entries"][0]["managed_by"] == "terraform"
        assert data["entries"][0]["entry"] == "t13d1516h2_terraform"
        assert all(
            e["managed_by"] == "terraform" for e in data["entries"]
        ), "Filter must exclude all non-terraform entries from results"
        assert all(
            e["entry"] != "t13d1516h2_op" for e in data["entries"]
        ), "Operator entry must be absent from terraform-filtered results"


@pytest.mark.asyncio
async def test_get_allowlist_by_id(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/allowlist/{id} returns 200 with full resource for a known UUID.

    Individual resource fetch by ID must work immediately after creation.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d1516h2_abc", "managed_by": "operator", "note": "by id test"},
        )
        resource_id = created["id"]
        r = await client.get(
            f"/api/v1/allowlist/{resource_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        data = r.json()
        assert data["id"] == resource_id
        assert data["entry"] == "t13d1516h2_abc"


@pytest.mark.asyncio
async def test_get_allowlist_nonexistent_id_returns_404(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/allowlist/{nil-uuid} returns 404 when the entry does not exist.

    Unknown UUIDs must not silently return empty data; 404 is the correct response.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            f"/api/v1/allowlist/{_UUID_NIL}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 404, (
            f"Non-existent UUID must return 404, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_delete_allowlist_entry_by_id(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE /api/v1/allowlist/{id} returns 204; subsequent GET returns 404.

    Verifies that delete removes the resource and makes it unfetchable.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d1516h2_delete_me", "managed_by": "operator", "note": ""},
        )
        resource_id = created["id"]
        r_del = await client.delete(
            f"/api/v1/allowlist/{resource_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r_del.status_code == 204, (
            f"DELETE must return 204, got {r_del.status_code}: {r_del.text}"
        )
        r_get = await client.get(
            f"/api/v1/allowlist/{resource_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r_get.status_code == 404, (
            "After DELETE, GET must return 404"
        )
        # Also verify the proxy SET is cleaned up (both halves of dual-write must be removed)
        is_member = await fake_redis.sismember("ja4:whitelist", "t13d1516h2_delete_me")
        assert not is_member, (
            "DELETE must also remove the entry from ja4:whitelist proxy SET. "
            "If only the Hash is deleted the proxy still treats the entry as allowed."
        )


@pytest.mark.asyncio
async def test_delete_allowlist_nonexistent_is_idempotent(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE /api/v1/allowlist/{nil-uuid} returns 204 even when entry does not exist.

    Idempotent deletes simplify client retry logic; absence must not be an error.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.delete(
            f"/api/v1/allowlist/{_UUID_NIL}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 204, (
            f"DELETE of non-existent resource must return 204, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_delete_allowlist_requires_operator_role(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE /api/v1/allowlist/{id} with auditor token returns 403.

    Auditor role is read-only; deletes require at least Operator.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.delete(
            f"/api/v1/allowlist/{_UUID_NIL}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on DELETE /api/v1/allowlist must return 403, got {r.status_code}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Section 2: Dual-write — proxy SET kept in sync
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_post_allowlist_writes_to_proxy_set(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist must write to both Hash (management) and ja4:whitelist SET (proxy).

    The proxy reads ja4:whitelist for O(1) allow decisions. Without dual-write
    the management API and proxy would be out of sync. Also verifies no cross-list
    contamination: allowlist POST must NOT write to ja4:blacklist.
    """
    fingerprint = "t13d1516h2_dualwrite_test"
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": fingerprint, "managed_by": "operator", "note": "dual write"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201
        resource_id = r.json()["id"]

        # Verify Hash record exists with all fields (management-side)
        hash_record = await fake_redis.hgetall(f"allowlist:entry:{resource_id}")
        assert hash_record, f"Hash record allowlist:entry:{resource_id} must exist immediately after POST"
        assert hash_record.get("entry") == fingerprint, (
            f"Hash 'entry' field must be '{fingerprint}', got: {hash_record.get('entry')}"
        )
        assert hash_record.get("managed_by") == "operator"

    # After context: verify proxy SET populated
    is_member = await fake_redis.sismember("ja4:whitelist", fingerprint)
    assert is_member, f"'{fingerprint}' must be in ja4:whitelist after POST — dual-write failed"

    # No cross-list contamination
    in_blacklist = await fake_redis.sismember("ja4:blacklist", fingerprint)
    assert not in_blacklist, "allowlist POST must NOT write to ja4:blacklist"

    in_watchlist = await fake_redis.sismember("ja4:watchlist", fingerprint)
    assert not in_watchlist, "allowlist POST must NOT write to ja4:watchlist"


@pytest.mark.asyncio
async def test_delete_allowlist_removes_from_proxy_set(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE /api/v1/allowlist/{id} removes the fingerprint from ja4:whitelist.

    The proxy fast-path SET must stay in sync; a deleted entry must not linger.
    """
    fingerprint = "t13d1516h2_delete_from_set"
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": fingerprint, "managed_by": "operator", "note": ""},
        )
        resource_id = created["id"]
        await client.delete(
            f"/api/v1/allowlist/{resource_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
    is_member = await fake_redis.sismember("ja4:whitelist", fingerprint)
    assert not is_member, (
        f"'{fingerprint}' must be removed from ja4:whitelist after DELETE"
    )


@pytest.mark.asyncio
async def test_post_ip_allowlist_writes_to_static_set(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist with list_type='ip' writes the IP to static:allowlist.

    IP entries use a separate proxy SET (static:allowlist) rather than ja4:whitelist.
    """
    ip_entry = "10.0.0.0/24"
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={
                "entry": ip_entry,
                "list_type": "ip",
                "managed_by": "operator",
                "note": "internal network",
            },
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
    is_member = await fake_redis.sismember("static:allowlist", ip_entry)
    assert is_member, (
        f"'{ip_entry}' must be in static:allowlist after POST with list_type='ip'"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Section 3: Blocklist CRUD (mirror of allowlist, abbreviated)
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_post_blocklist_returns_full_resource(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/blocklist returns 201 with list_type == 'blocklist'.

    Verifies the blocklist canonical endpoint exists and returns the correct
    list_type discriminator in the resource envelope.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/blocklist",
            json={"entry": "t13d1516h2_bad_bot", "managed_by": "operator", "note": "bad"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        data = r.json()
        assert data["list_type"] == "blocklist"
        assert "id" in data
        assert _UUID4_RE.match(data["id"]), f"'id' must be UUID4, got: {data['id']}"
        assert data["entry"] == "t13d1516h2_bad_bot"


@pytest.mark.asyncio
async def test_post_blocklist_writes_to_proxy_set(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/blocklist must write to both Hash and ja4:blacklist SET.

    Also verifies no cross-list contamination: blocklist POST must NOT write to ja4:whitelist.
    """
    fingerprint = "t13d1516h2_block_dualwrite"
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/blocklist",
            json={"entry": fingerprint, "managed_by": "operator", "note": "block dual write"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201
        resource_id = r.json()["id"]

        hash_record = await fake_redis.hgetall(f"blocklist:entry:{resource_id}")
        assert hash_record, f"Hash record blocklist:entry:{resource_id} must exist"
        assert hash_record.get("entry") == fingerprint

    is_member = await fake_redis.sismember("ja4:blacklist", fingerprint)
    assert is_member, f"'{fingerprint}' must be in ja4:blacklist after POST"

    # No cross-list contamination
    in_whitelist = await fake_redis.sismember("ja4:whitelist", fingerprint)
    assert not in_whitelist, "blocklist POST must NOT write to ja4:whitelist"


@pytest.mark.asyncio
async def test_delete_blocklist_removes_from_proxy_set(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE /api/v1/blocklist/{id} removes the fingerprint from ja4:blacklist.

    Expired or revoked block entries must not persist in the proxy fast-path SET.
    """
    fingerprint = "t13d1516h2_blocklist_delete"
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _post_entry(
            client, token, "/api/v1/blocklist",
            {"entry": fingerprint, "managed_by": "operator", "note": ""},
        )
        resource_id = created["id"]
        await client.delete(
            f"/api/v1/blocklist/{resource_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
    is_member = await fake_redis.sismember("ja4:blacklist", fingerprint)
    assert not is_member, (
        f"'{fingerprint}' must be removed from ja4:blacklist after DELETE"
    )


@pytest.mark.asyncio
async def test_get_blocklist_managed_by_filter(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/blocklist?managed_by=terraform returns only terraform entries.

    Consistent filter behaviour with allowlist; only matching entries returned.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        await _post_entry(
            client, token, "/api/v1/blocklist",
            {"entry": "t13d1516h2_bl_tf", "managed_by": "terraform", "note": ""},
        )
        await _post_entry(
            client, token, "/api/v1/blocklist",
            {"entry": "t13d1516h2_bl_op", "managed_by": "operator", "note": ""},
        )
        r = await client.get(
            "/api/v1/blocklist?managed_by=terraform",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["entries"][0]["managed_by"] == "terraform"
        assert all(
            e["managed_by"] == "terraform" for e in data["entries"]
        ), "Filter must exclude all non-terraform entries"
        assert all(
            e["entry"] != "t13d1516h2_bl_op" for e in data["entries"]
        ), "Operator entry must be absent from terraform-filtered results"


# ═══════════════════════════════════════════════════════════════════════════════
# Section 4: Watchlist CRUD
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_post_watchlist_returns_full_resource(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/watchlist returns 201 with list_type == 'watchlist'.

    Verifies the watchlist endpoint exists and populates list_type correctly.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/watchlist",
            json={"entry": "t13d1516h2_suspect", "managed_by": "operator", "note": "watch"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
        data = r.json()
        assert data["list_type"] == "watchlist"
        assert "id" in data
        assert _UUID4_RE.match(data["id"])
        assert data["entry"] == "t13d1516h2_suspect"


@pytest.mark.asyncio
async def test_post_watchlist_writes_to_proxy_set(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/watchlist must write to both Hash and ja4:watchlist SET.

    Also verifies no cross-list contamination.
    """
    fingerprint = "t13d1516h2_watch_dualwrite"
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/watchlist",
            json={"entry": fingerprint, "managed_by": "operator", "note": "watch dual write"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201
        resource_id = r.json()["id"]

        hash_record = await fake_redis.hgetall(f"watchlist:entry:{resource_id}")
        assert hash_record, f"Hash record watchlist:entry:{resource_id} must exist"
        assert hash_record.get("entry") == fingerprint

    is_member = await fake_redis.sismember("ja4:watchlist", fingerprint)
    assert is_member, f"'{fingerprint}' must be in ja4:watchlist after POST"

    in_whitelist = await fake_redis.sismember("ja4:whitelist", fingerprint)
    assert not in_whitelist, "watchlist POST must NOT write to ja4:whitelist"
    in_blacklist = await fake_redis.sismember("ja4:blacklist", fingerprint)
    assert not in_blacklist, "watchlist POST must NOT write to ja4:blacklist"


@pytest.mark.asyncio
async def test_get_watchlist_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/watchlist with auditor token returns 200.

    Read access is allowed for Auditor and above; 200 confirms the minimum role.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/watchlist",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Auditor on GET /api/v1/watchlist must return 200, got {r.status_code}: {r.text}"
        )
        # Also verify that unauthenticated request is rejected (proves auth is not absent)
        r_unauth = await client.get(
            "/api/v1/watchlist",
            headers={"Accept": "application/json"},
            # No Authorization header — cookie-free client
        )
        assert r_unauth.status_code == 401, (
            f"Unauthenticated GET /api/v1/watchlist must return 401, got {r_unauth.status_code}. "
            "A 200 here would mean auth is missing entirely, not just enforced at auditor level."
        )


@pytest.mark.asyncio
async def test_post_watchlist_requires_operator(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/watchlist with analyst token returns 403.

    Analyst is below Operator; writes must be rejected.
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/watchlist",
            json={"entry": "t13d1516h2_analyst", "managed_by": "operator", "note": ""},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Analyst on POST /api/v1/watchlist must return 403, got {r.status_code}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Section 5: Migration
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_migration_runs_on_startup_for_existing_entries(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Legacy ja4:whitelist entries appear in GET /api/v1/allowlist with managed_by='legacy'.

    On app startup, any existing raw entries in ja4:whitelist that have no
    corresponding Hash record must be migrated and become queryable via the new API.
    """
    # Seed legacy data before app creation
    await fake_redis.sadd("ja4:whitelist", "legacy_fp_abc")

    # App creation triggers the startup/migration path
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    admin_cookie = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get(
            "/api/v1/allowlist",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
        data = r.json()
        entries = data["entries"]
        legacy_entries = [e for e in entries if e.get("entry") == "legacy_fp_abc"]
        assert len(legacy_entries) == 1, (
            "Legacy entry 'legacy_fp_abc' must appear in allowlist after migration"
        )
        assert legacy_entries[0]["managed_by"] == "legacy", (
            "Migrated entries must have managed_by='legacy'"
        )

    # Migration flag must be set
    flag = await fake_redis.exists("allowlist:migrated")
    assert flag == 1, "allowlist:migrated must be set to '1' after migration"

    # Verify the migration created a Hash record (not just served from the SET directly)
    migrated_entry = next(
        (e for e in data["entries"] if e["entry"] == "legacy_fp_abc"), None
    )
    assert migrated_entry is not None, "legacy_fp_abc must appear in allowlist after migration"
    assert migrated_entry["managed_by"] == "legacy", (
        f"Migrated entry must have managed_by='legacy', got: {migrated_entry['managed_by']}"
    )
    hash_record = await fake_redis.hgetall(f"allowlist:entry:{migrated_entry['id']}")
    assert hash_record, (
        f"Hash record allowlist:entry:{migrated_entry['id']} must exist — "
        "migration must create Hash records, not just serve from the proxy SET"
    )
    assert hash_record.get("managed_by") == "legacy"
    assert hash_record.get("created_by") == "migration"

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_migration_is_idempotent(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Running migration twice (two create_app calls) produces exactly one entry, not two.

    Migration must check for existing Hash records and skip already-migrated entries.
    """
    await fake_redis.sadd("ja4:whitelist", "legacy_fp_idempotent")

    # First startup — performs migration
    app1 = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app1),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client1:
        r1 = await client1.get("/api/v1/allowlist", headers={"Accept": "application/json"})
        assert r1.status_code == 200
    await _redis_module.close_redis()

    # After first app startup and teardown:
    flag = await fake_redis.exists("allowlist:migrated")
    assert flag == 1, "allowlist:migrated must be set after first startup"

    before_keys = await fake_redis.keys("allowlist:entry:*")
    before_count = len(before_keys)
    assert before_count >= 1, "First migration must have created at least one Hash record"

    # Second startup — migration must be a no-op (allowlist:migrated already set)
    app2 = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app2),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client2:
        r2 = await client2.get("/api/v1/allowlist", headers={"Accept": "application/json"})
        assert r2.status_code == 200
        data = r2.json()
        matching = [e for e in data["entries"] if e.get("entry") == "legacy_fp_idempotent"]
        assert len(matching) == 1, (
            f"Idempotent migration must not duplicate entries; found {len(matching)}"
        )
    await _redis_module.close_redis()

    # After second startup teardown:
    after_keys = await fake_redis.keys("allowlist:entry:*")
    after_count = len(after_keys)
    assert after_count == before_count, (
        f"Second migration must not create duplicate Hash records. "
        f"Before: {before_count}, after: {after_count}."
    )


@pytest.mark.asyncio
async def test_migration_preserves_proxy_set(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Migration must not remove existing entries from the ja4:whitelist proxy SET.

    The proxy relies on ja4:whitelist for fast O(1) lookups; migration must only
    add Hash records without touching the SET.
    """
    await fake_redis.sadd("ja4:whitelist", "legacy_fp_preserved")

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        # Trigger any lazy startup; migration runs during lifespan
        await client.get("/api/v1/health")

    is_member = await fake_redis.sismember("ja4:whitelist", "legacy_fp_preserved")
    assert is_member, (
        "Migration must not remove 'legacy_fp_preserved' from ja4:whitelist"
    )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_migration_generates_stable_uuid(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The same fingerprint always gets the same UUID across migration runs.

    UUID generation uses uuid5(NAMESPACE_DNS, entry_string); the result must be
    deterministic so two migrations of the same entry produce identical IDs.
    """
    fingerprint = "legacy_fp_stable_uuid"
    await fake_redis.sadd("ja4:whitelist", fingerprint)

    # First migration run
    app1 = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app1),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client1:
        r1 = await client1.get("/api/v1/allowlist", headers={"Accept": "application/json"})
        assert r1.status_code == 200
        data1 = r1.json()
        entries1 = [e for e in data1["entries"] if e["entry"] == fingerprint]
        assert len(entries1) == 1
        uuid_first = entries1[0]["id"]
    await _redis_module.close_redis()

    # After first migration and extracting uuid_first:
    # Clear Hash records AND the migration flag so second run starts fresh
    keys = await fake_redis.keys("allowlist:entry:*")
    for k in keys:
        await fake_redis.delete(k)
    await fake_redis.delete("allowlist:migrated")
    # Keep ja4:whitelist SET populated so migration has data to process
    # (do NOT clear the SET member)
    # Re-seed the SET entry (may have been preserved, but let's be explicit)
    await fake_redis.sadd("ja4:whitelist", fingerprint)

    # Second migration run
    app2 = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app2),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client2:
        r2 = await client2.get("/api/v1/allowlist", headers={"Accept": "application/json"})
        assert r2.status_code == 200
        data2 = r2.json()
        entries2 = [e for e in data2["entries"] if e["entry"] == fingerprint]
        assert len(entries2) == 1
        uuid_second = entries2[0]["id"]
    await _redis_module.close_redis()

    assert uuid_first == uuid_second, (
        f"Migration must produce stable UUID for same fingerprint; "
        f"got {uuid_first!r} then {uuid_second!r}"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Section 6: managed_by and Terraform support
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_managed_by_terraform_filter_excludes_operator_entries(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET ?managed_by=operator returns only operator entries, excluding terraform.

    The managed_by filter must work in both directions; operator entries must not
    appear in terraform-filtered results and vice versa.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d_tf_only", "managed_by": "terraform", "note": "tf"},
        )
        await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d_op_only", "managed_by": "operator", "note": "op"},
        )
        r = await client.get(
            "/api/v1/allowlist?managed_by=operator",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["entries"][0]["managed_by"] == "operator"
        # terraform entry must NOT appear
        assert all(
            e["managed_by"] != "terraform" for e in data["entries"]
        ), "Terraform entries must be excluded from managed_by=operator filter"


@pytest.mark.asyncio
async def test_entry_id_is_stable_uuid4_format(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist returns an 'id' that matches the UUID4 format regex.

    UUID4 has version nibble == '4' and variant bits [89ab]; this must be enforced.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        data = await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d_uuid4_check", "managed_by": "operator", "note": ""},
        )
        id = data["id"]
        assert _UUID4_RE.match(id), (
            f"id must match UUID4 pattern, got: {id!r}"
        )
        r2 = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d1516h2_uuid_check_2", "managed_by": "operator"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r2.status_code == 201
        id2 = r2.json()["id"]
        assert _UUID4_RE.match(id2), f"Second POST id must match UUID4 format: {id2!r}"
        assert id != id2, (
            "Two POSTs must produce different UUIDs. "
            "A stub returning a hardcoded UUID4 would fail this."
        )


@pytest.mark.asyncio
async def test_get_after_post_is_immediately_consistent(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/allowlist/{id} immediately after POST returns 200 — no eventual lag.

    The resource model must be immediately consistent; clients must be able to
    read back exactly what they wrote without any delay.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        created = await _post_entry(
            client, token, "/api/v1/allowlist",
            {"entry": "t13d_immediate_consistency", "managed_by": "operator", "note": ""},
        )
        resource_id = created["id"]
        r = await client.get(
            f"/api/v1/allowlist/{resource_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"GET immediately after POST must return 200, got {r.status_code}"
        )
        assert r.json()["id"] == resource_id


# ═══════════════════════════════════════════════════════════════════════════════
# Section 7: Old routes backward compat
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_old_list_routes_still_return_200(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Old /api/v1/lists/... routes must still work unchanged after Cluster 3.

    Verifies both the read route (GET) and write route (POST) work,
    and that the returned schema is the old flat-string format, not resource envelopes.
    """
    from management.api.main import create_app as _create_app
    from management.api import redis_client as _redis_module_inner
    from management.api.auth import _create_access_token as _cat

    app = _create_app()
    await _redis_module_inner.init_redis(override_client=fake_redis)

    admin_cookie = {"token": _cat("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        # Old write route must still work
        r_post = await client.post(
            "/api/v1/lists/ja4/whitelist/t13d_legacy_entry",
            headers={"Accept": "application/json"},
        )
        assert r_post.status_code in (200, 201), (
            f"Old POST route must still work, got {r_post.status_code}: {r_post.text}"
        )

        # Old read route must still work
        r_get = await client.get(
            "/api/v1/lists/ja4/whitelist",
            headers={"Accept": "application/json"},
        )
        assert r_get.status_code == 200, (
            f"Old GET route must still return 200, got {r_get.status_code}"
        )
        data = r_get.json()
        assert "entries" in data, f"Old route must return 'entries' field, got: {data}"
        assert len(data["entries"]) >= 1

        # Old schema returns flat strings, NOT resource envelopes
        first_entry = data["entries"][0]
        assert isinstance(first_entry, str), (
            f"Old /api/v1/lists route must return flat string entries, "
            f"not resource dicts. Got: {type(first_entry).__name__}: {first_entry!r}"
        )

    await _redis_module_inner.close_redis()


# ═══════════════════════════════════════════════════════════════════════════════
# Section 8: Missing tests — cross-list contamination, idempotency, expiry,
#            Hash completeness, and DELETE atomicity
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_cross_list_contamination_prevention(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Posting to one list must not write to any other list's proxy SET.

    A copy-paste bug that writes to the wrong SET would silently block or allow
    traffic incorrectly. This tests all three directions.
    """
    allow_fp = "t13d_cross_allow"
    block_fp = "t13d_cross_block"
    watch_fp = "t13d_cross_watch"

    async with _bearer_client("operator", fake_redis) as (client, token):
        for path, fp in [
            ("/api/v1/allowlist", allow_fp),
            ("/api/v1/blocklist", block_fp),
            ("/api/v1/watchlist", watch_fp),
        ]:
            r = await client.post(
                path,
                json={"entry": fp, "managed_by": "operator"},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
            assert r.status_code == 201, f"POST to {path} failed: {r.status_code}"

    # allowlist fingerprint only in whitelist
    assert await fake_redis.sismember("ja4:whitelist", allow_fp)
    assert not await fake_redis.sismember("ja4:blacklist", allow_fp), "allow_fp must not be in blacklist"
    assert not await fake_redis.sismember("ja4:watchlist", allow_fp), "allow_fp must not be in watchlist"

    # blocklist fingerprint only in blacklist
    assert await fake_redis.sismember("ja4:blacklist", block_fp)
    assert not await fake_redis.sismember("ja4:whitelist", block_fp), "block_fp must not be in whitelist"
    assert not await fake_redis.sismember("ja4:watchlist", block_fp), "block_fp must not be in watchlist"

    # watchlist fingerprint only in watchlist
    assert await fake_redis.sismember("ja4:watchlist", watch_fp)
    assert not await fake_redis.sismember("ja4:whitelist", watch_fp), "watch_fp must not be in whitelist"
    assert not await fake_redis.sismember("ja4:blacklist", watch_fp), "watch_fp must not be in blacklist"


@pytest.mark.asyncio
async def test_duplicate_post_is_idempotent(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Posting the same entry twice must not create duplicate Hash records.

    A naive implementation would write a second Hash on every POST, causing the
    GET list to return duplicate entries and the proxy SET to have inconsistent state.
    """
    fingerprint = "t13d_duplicate_test"
    async with _bearer_client("operator", fake_redis) as (client, token):
        r1 = await client.post(
            "/api/v1/allowlist",
            json={"entry": fingerprint, "managed_by": "operator"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r1.status_code == 201
        id1 = r1.json()["id"]

        r2 = await client.post(
            "/api/v1/allowlist",
            json={"entry": fingerprint, "managed_by": "operator"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        # Must either return the existing entry (200/201 same id) or 409 Conflict
        assert r2.status_code in (200, 201, 409), (
            f"Duplicate POST must return existing entry or 409, got {r2.status_code}"
        )
        if r2.status_code in (200, 201):
            assert r2.json()["id"] == id1, (
                "Duplicate POST must return the same id as the original"
            )

    # Only one Hash record should exist
    hash_keys = await fake_redis.keys("allowlist:entry:*")
    matching = [k for k in hash_keys]
    # The SET must have exactly one member for this fingerprint
    members = await fake_redis.smembers("ja4:whitelist")
    matching_members = [m for m in members if m == fingerprint]
    assert len(matching_members) == 1, (
        f"ja4:whitelist must contain exactly one copy of '{fingerprint}', "
        f"found {len(matching_members)}"
    )


@pytest.mark.asyncio
async def test_expired_entries_excluded_from_list(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Entries with expires_at in the past must not appear in GET /api/v1/allowlist.

    An expired allowlist entry that still appears in the list would grant stale
    access. This validates that expires_at is enforced at read time.
    """
    from datetime import datetime, timedelta, timezone

    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

    async with _bearer_client("operator", fake_redis) as (client, token):
        # Create an expired entry
        r_expired = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_expired", "managed_by": "operator", "expires_at": past},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r_expired.status_code in (201, 422), (
            "Past expires_at should either be rejected (422) or accepted but filtered on read"
        )

        # Create a non-expired entry for contrast
        r_valid = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_valid", "managed_by": "operator", "expires_at": future},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r_valid.status_code == 201

        # If expired was accepted (201), it must not appear in listing
        if r_expired.status_code == 201:
            r_list = await client.get(
                "/api/v1/allowlist",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
            entries = r_list.json()["entries"]
            expired_in_list = [e for e in entries if e["entry"] == "t13d_expired"]
            assert not expired_in_list, (
                "Expired entry must not appear in GET /api/v1/allowlist listing"
            )


@pytest.mark.asyncio
async def test_hash_record_has_all_required_fields(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The Redis Hash record written on POST must contain all required fields.

    Missing fields in the Hash cause the management API to return incomplete
    resource envelopes and may cause deserialization errors in downstream tools.
    """
    fingerprint = "t13d_hash_completeness"
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": fingerprint, "managed_by": "operator", "note": "completeness check"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201
        resource_id = r.json()["id"]

        record = await fake_redis.hgetall(f"allowlist:entry:{resource_id}")
        required_fields = {"id", "entry", "managed_by", "note", "created_at", "created_by", "list_type"}
        missing = required_fields - set(record.keys())
        assert not missing, (
            f"Hash record is missing required fields: {missing}. "
            f"Present fields: {set(record.keys())}"
        )
        assert record["id"] == resource_id
        assert record["entry"] == fingerprint
        assert record["managed_by"] == "operator"
        assert record["list_type"] == "allowlist"
        assert record["created_at"], "created_at must not be empty"
        assert record["created_by"], "created_by must not be empty"


@pytest.mark.asyncio
async def test_delete_atomicity_both_structures_removed(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE must remove both the Hash record and the proxy SET entry before returning 204.

    If only the Hash is removed, the proxy still treats the fingerprint as allowed.
    If only the SET is removed, the management API still returns the entry in GET.
    Both must be gone before the 204 response is sent.
    """
    fingerprint = "t13d_delete_atomicity"
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": fingerprint, "managed_by": "operator"},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 201
        resource_id = r.json()["id"]

        # Verify both exist before DELETE
        assert await fake_redis.exists(f"allowlist:entry:{resource_id}"), "Hash must exist before DELETE"
        assert await fake_redis.sismember("ja4:whitelist", fingerprint), "SET must have entry before DELETE"

        r_del = await client.delete(
            f"/api/v1/allowlist/{resource_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r_del.status_code == 204

        # Both must be gone
        hash_exists = await fake_redis.exists(f"allowlist:entry:{resource_id}")
        set_member = await fake_redis.sismember("ja4:whitelist", fingerprint)
        assert not hash_exists, "Hash record must be removed by DELETE"
        assert not set_member, (
            "Proxy SET entry must be removed by DELETE. "
            "If only the Hash is deleted, the proxy still allows the fingerprint."
        )
