"""TDD tests for MFA/SSO Hardening Cluster 5 — Audit Trail Enhancements.

Covers
------
Section 1: Audit entry schema (role, before/after values, actor_id, action_type,
           timestamp, resource_id, dial change, ban create)
Section 2: No-delete enforcement (append-only log)
Section 3: JSONL export (?format=jsonl)
Section 4: CSV export (?format=csv)
Section 5: Existing GET filters (action, actor, since) still work post-enhancement

All tests are written to FAIL against the current codebase.
No production code is written here.
"""

from __future__ import annotations

import csv
import io
import json
import os
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

# ── Helpers ───────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Isolated FakeRedis server instance — each test gets a clean slate."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


async def _make_token(
    admin_client: AsyncClient,
    role: str,
    name: str | None = None,
) -> str:
    """Seed a bearer token of the given role and return the plaintext."""
    token_name = name or f"audit-enhanced-test-{role}"
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
    token_name: str | None = None,
) -> AsyncGenerator[Tuple[AsyncClient, str], None]:
    """Yield a cookie-free AsyncClient and a valid bearer token of the given role.

    Mirrors the exact pattern from test_resource_model.py to avoid cookie
    contamination.  Cookie auth always returns role=admin, which would mask
    missing role checks.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as admin_client:
        plaintext = await _make_token(admin_client, role, token_name)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, plaintext

    await _redis_module.close_redis()


def _auth_headers(token: str, accept: str = "application/json") -> dict[str, str]:
    """Build Authorization + Accept headers for bearer-token requests."""
    return {"Authorization": f"Bearer {token}", "Accept": accept}


async def _seed_entry(
    fake_redis: fakeredis.aioredis.FakeRedis,
    **overrides: Any,
) -> None:
    """LPUSH a single audit entry with sane defaults, overridden by kwargs."""
    base: dict[str, Any] = {
        "timestamp": "2026-04-07T10:00:00.000Z",
        "actor_id": "token:alice",
        "actor_ip": "127.0.0.1",
        "action_type": "allowlist.created",
        "resource_type": "allowlist",
        "resource_id": "aaaaaaaa-0000-4000-8000-000000000001",
        "before_value": None,
        "after_value": {"entry": "t13d_abc", "managed_by": "operator"},
        "session_id": "sess-001",
        "role": "operator",
    }
    base.update(overrides)
    await fake_redis.lpush("management:audit_log", json.dumps(base))


# ══════════════════════════════════════════════════════════════════════════════
# Section 1: Audit entry schema
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_audit_entry_has_role_field(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/allowlist audit entry must include a 'role' field equal to operator."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_role_test", "managed_by": "operator"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201, f"POST failed: {r.status_code} {r.text}"

        raw_entries = await fake_redis.lrange("management:audit_log", 0, 0)
        assert raw_entries, "Expected at least one audit entry after POST"
        entry = json.loads(raw_entries[0])

        assert "role" in entry, f"Audit entry missing 'role' field: {entry}"
        assert (
            entry["role"] == "operator"
        ), f"Expected role='operator', got {entry['role']!r}"


@pytest.mark.asyncio
async def test_audit_entry_has_before_and_after_values(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Create → before_value is null; delete → after_value is null, before_value set."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        # ── Create ────────────────────────────────────────────────────────────
        r_create = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_before_after_test", "managed_by": "operator"},
            headers=_auth_headers(token),
        )
        assert r_create.status_code == 201, f"POST failed: {r_create.status_code}"
        resource_id = r_create.json()["id"]

        create_raw = await fake_redis.lrange("management:audit_log", 0, 0)
        assert create_raw, "No audit entry after POST"
        create_entry = json.loads(create_raw[0])

        assert (
            create_entry.get("before_value") is None
        ), f"before_value should be null on create, got {create_entry.get('before_value')!r}"
        assert (
            create_entry.get("after_value") is not None
        ), "after_value should not be null on create"

        # ── Delete ────────────────────────────────────────────────────────────
        r_delete = await client.delete(
            f"/api/v1/allowlist/{resource_id}",
            headers=_auth_headers(token),
        )
        assert r_delete.status_code == 204, f"DELETE failed: {r_delete.status_code}"

        delete_raw = await fake_redis.lrange("management:audit_log", 0, 0)
        assert delete_raw, "No audit entry after DELETE"
        delete_entry = json.loads(delete_raw[0])

        assert (
            delete_entry.get("after_value") is None
        ), f"after_value should be null on delete, got {delete_entry.get('after_value')!r}"
        assert (
            delete_entry.get("before_value") is not None
        ), "before_value should not be null on delete"


@pytest.mark.asyncio
async def test_audit_entry_has_actor_id(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Audit entry actor_id must contain the token name, not just 'admin'."""
    async with _bearer_client(
        "operator", fake_redis, token_name="audit-test-token"
    ) as (
        client,
        token,
    ):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_actor_id_test", "managed_by": "operator"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201, f"POST failed: {r.status_code}"

        raw_entries = await fake_redis.lrange("management:audit_log", 0, 0)
        assert raw_entries, "No audit entry after POST"
        entry = json.loads(raw_entries[0])

        actor_id = entry.get("actor_id", "")
        assert (
            "audit-test-token" in actor_id
        ), f"Expected actor_id to contain 'audit-test-token', got {actor_id!r}"


@pytest.mark.asyncio
async def test_audit_entry_has_action_type(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST sets action_type='allowlist.created'; DELETE sets action_type='allowlist.deleted'."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        # Create
        r_create = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_action_type_test", "managed_by": "operator"},
            headers=_auth_headers(token),
        )
        assert r_create.status_code == 201
        resource_id = r_create.json()["id"]

        create_raw = await fake_redis.lrange("management:audit_log", 0, 0)
        create_entry = json.loads(create_raw[0])
        assert (
            create_entry.get("action_type") == "allowlist.created"
        ), f"Expected 'allowlist.created', got {create_entry.get('action_type')!r}"

        # Delete
        r_delete = await client.delete(
            f"/api/v1/allowlist/{resource_id}",
            headers=_auth_headers(token),
        )
        assert r_delete.status_code == 204

        delete_raw = await fake_redis.lrange("management:audit_log", 0, 0)
        delete_entry = json.loads(delete_raw[0])
        assert (
            delete_entry.get("action_type") == "allowlist.deleted"
        ), f"Expected 'allowlist.deleted', got {delete_entry.get('action_type')!r}"


@pytest.mark.asyncio
async def test_audit_entry_has_timestamp(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Audit entry timestamp must be a non-empty ISO 8601 string."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_timestamp_test", "managed_by": "operator"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201

        raw_entries = await fake_redis.lrange("management:audit_log", 0, 0)
        assert raw_entries, "No audit entry after POST"
        entry = json.loads(raw_entries[0])

        ts = entry.get("timestamp", "")
        assert ts, "timestamp field is empty or missing"
        # Minimal ISO 8601 check: contains a 'T' separator and a digit year
        assert (
            "T" in ts and ts[:4].isdigit()
        ), f"timestamp does not look like ISO 8601: {ts!r}"


@pytest.mark.asyncio
async def test_audit_entry_has_resource_id(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Audit entry resource_id must match the id returned by POST."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/allowlist",
            json={"entry": "t13d_resource_id_test", "managed_by": "operator"},
            headers=_auth_headers(token),
        )
        assert r.status_code == 201
        returned_id = r.json()["id"]

        raw_entries = await fake_redis.lrange("management:audit_log", 0, 0)
        assert raw_entries, "No audit entry after POST"
        entry = json.loads(raw_entries[0])

        assert (
            entry.get("resource_id") == returned_id
        ), f"Expected resource_id={returned_id!r}, got {entry.get('resource_id')!r}"


@pytest.mark.asyncio
async def test_dial_change_audited(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """PUT /api/v1/dial writes audit entry with action_type='dial.changed' and role='admin'."""
    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.put(
            "/api/v1/dial",
            json={"value": 5},
            headers=_auth_headers(token),
        )
        assert (
            r.status_code == 200
        ), f"PUT /api/v1/dial failed: {r.status_code} {r.text}"

        raw_entries = await fake_redis.lrange("management:audit_log", 0, 0)
        assert raw_entries, "No audit entry after PUT /api/v1/dial"
        entry = json.loads(raw_entries[0])

        assert (
            entry.get("action_type") == "dial.changed"
        ), f"Expected action_type='dial.changed', got {entry.get('action_type')!r}"
        after_val = entry.get("after_value", {})
        assert after_val is not None, "after_value must not be null for dial change"
        assert (
            after_val.get("value") == 5
        ), f"Expected after_value to contain value=5, got {after_val!r}"
        assert (
            entry.get("role") == "admin"
        ), f"Expected role='admin', got {entry.get('role')!r}"


@pytest.mark.asyncio
async def test_ban_create_audited(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /api/v1/bans/10.1.1.1 writes audit entry with action_type='ban.created'."""
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/bans/10.1.1.1",
            json={"ttl": 3600, "reason": "test"},
            headers=_auth_headers(token),
        )
        # bans.create_ban uses FastAPI default status (200); no explicit status_code=201
        assert r.status_code == 200, f"POST bans failed: {r.status_code} {r.text}"

        raw_entries = await fake_redis.lrange("management:audit_log", 0, 0)
        assert raw_entries, "No audit entry after POST /api/v1/bans"
        entry = json.loads(raw_entries[0])

        assert (
            entry.get("action_type") == "ban.created"
        ), f"Expected action_type='ban.created', got {entry.get('action_type')!r}"
        after_val = entry.get("after_value", {})
        assert after_val is not None, "after_value must not be null for ban.created"
        assert (
            after_val.get("ip") == "10.1.1.1"
        ), f"Expected after_value to contain ip='10.1.1.1', got {after_val!r}"


# ══════════════════════════════════════════════════════════════════════════════
# Section 2: No-delete enforcement
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_audit_log_has_no_delete_endpoint(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE /api/v1/audit must return 405 or 404 — the audit log is append-only."""
    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.delete(
            "/api/v1/audit",
            headers=_auth_headers(token),
        )
        assert r.status_code in (
            404,
            405,
        ), f"DELETE /api/v1/audit should return 404 or 405, got {r.status_code}"


@pytest.mark.asyncio
async def test_audit_entries_not_cleared_on_second_read(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Reading the audit log twice returns the same entries both times (non-destructive)."""
    known_entry: dict[str, Any] = {
        "timestamp": "2026-04-07T10:00:00Z",
        "actor_id": "token:alice",
        "actor_ip": "127.0.0.1",
        "action_type": "allowlist.created",
        "resource_type": "allowlist",
        "resource_id": "aaaaaaaa-0000-4000-8000-000000000099",
        "before_value": None,
        "after_value": {"entry": "t13d_persist_test"},
        "session_id": "sess-persist",
        "role": "operator",
    }
    await fake_redis.lpush("management:audit_log", json.dumps(known_entry))

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    admin_cookie = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r1 = await client.get("/api/v1/audit")
        r2 = await client.get("/api/v1/audit")

    await _redis_module.close_redis()

    assert r1.status_code == 200
    assert r2.status_code == 200

    entries1 = r1.json()["entries"]
    entries2 = r2.json()["entries"]

    assert len(entries1) >= 1, "First read returned no entries"
    assert len(entries2) >= 1, "Second read returned no entries (log was cleared!)"

    # Both reads should return the same entry count
    assert len(entries1) == len(
        entries2
    ), f"Entry count differs between reads: {len(entries1)} vs {len(entries2)}"


# ══════════════════════════════════════════════════════════════════════════════
# Section 3: JSONL export
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_audit_jsonl_format(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?format=jsonl returns JSONL with one line per entry."""
    for i in range(3):
        await _seed_entry(
            fake_redis, action_type=f"action.{i}", resource_id=f"uuid-{i:04d}"
        )

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get("/api/v1/audit?format=jsonl")

    await _redis_module.close_redis()

    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"

    content_type = r.headers.get("content-type", "")
    acceptable_types = ("application/x-ndjson", "application/jsonl", "text/plain")
    assert any(
        t in content_type for t in acceptable_types
    ), f"Unexpected Content-Type for JSONL: {content_type!r}"

    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    assert len(lines) == 3, f"Expected 3 JSONL lines, got {len(lines)}"

    for line in lines:
        parsed = json.loads(line)  # must not raise
        assert "timestamp" in parsed, f"JSONL line missing 'timestamp': {line!r}"


@pytest.mark.asyncio
async def test_get_audit_jsonl_each_line_is_valid_json(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Each line in the JSONL response must parse as a JSON object."""
    await _seed_entry(fake_redis, action_type="action.first")
    await _seed_entry(fake_redis, action_type="action.second")

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get("/api/v1/audit?format=jsonl")

    await _redis_module.close_redis()

    assert r.status_code == 200
    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    assert len(lines) >= 2, f"Expected at least 2 lines, got {len(lines)}"

    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            pytest.fail(f"JSONL line is not valid JSON: {line!r} — {exc}")
        assert isinstance(obj, dict), f"JSONL line is not a JSON object: {obj!r}"


@pytest.mark.asyncio
async def test_get_audit_jsonl_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?format=jsonl without auth returns 401."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.get(
            "/api/v1/audit?format=jsonl",
            headers={"Accept": "application/json"},
        )

    await _redis_module.close_redis()

    assert r.status_code == 401, f"Expected 401 without auth, got {r.status_code}"


# ══════════════════════════════════════════════════════════════════════════════
# Section 4: CSV export
# ══════════════════════════════════════════════════════════════════════════════

_CSV_REQUIRED_HEADERS = {
    "timestamp",
    "actor_id",
    "action_type",
    "resource_type",
    "resource_id",
    "role",
}


@pytest.mark.asyncio
async def test_get_audit_csv_format(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?format=csv returns CSV with correct headers and 3 lines total."""
    await _seed_entry(fake_redis, action_type="action.a")
    await _seed_entry(fake_redis, action_type="action.b")

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get("/api/v1/audit?format=csv")

    await _redis_module.close_redis()

    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    assert "text/csv" in r.headers.get(
        "content-type", ""
    ), f"Expected text/csv Content-Type, got {r.headers.get('content-type')!r}"

    reader = csv.DictReader(io.StringIO(r.text))
    fieldnames = set(reader.fieldnames or [])
    missing = _CSV_REQUIRED_HEADERS - fieldnames
    assert not missing, f"CSV header row missing columns: {missing}"

    rows = list(reader)
    assert (
        len(rows) == 2
    ), f"Expected 2 data rows (1 header + 2 data = 3 lines), got {len(rows)}"


@pytest.mark.asyncio
async def test_get_audit_csv_header_row(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?format=csv with no entries still returns the header row."""
    # No entries seeded — log is empty
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get("/api/v1/audit?format=csv")

    await _redis_module.close_redis()

    assert r.status_code == 200
    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    assert (
        len(lines) == 1
    ), f"Expected exactly 1 line (header only) for empty log, got {len(lines)}: {lines!r}"

    # The single line should be the header
    header_cols = set(lines[0].split(","))
    assert (
        "timestamp" in header_cols or "timestamp" in lines[0]
    ), f"Header line does not contain 'timestamp': {lines[0]!r}"


@pytest.mark.asyncio
async def test_get_audit_csv_data_values(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """CSV data row must contain correct values for action_type and role."""
    await _seed_entry(
        fake_redis,
        action_type="dial.changed",
        role="admin",
        actor_id="token:superuser",
    )

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get("/api/v1/audit?format=csv")

    await _redis_module.close_redis()

    assert r.status_code == 200
    reader = csv.DictReader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 1, f"Expected 1 data row, got {len(rows)}"
    row = rows[0]

    assert (
        row.get("action_type") == "dial.changed"
    ), f"Expected action_type='dial.changed', got {row.get('action_type')!r}"
    assert row.get("role") == "admin", f"Expected role='admin', got {row.get('role')!r}"


@pytest.mark.asyncio
async def test_get_audit_csv_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?format=csv without auth returns 401."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.get(
            "/api/v1/audit?format=csv",
            headers={"Accept": "application/json"},
        )

    await _redis_module.close_redis()

    assert r.status_code == 401, f"Expected 401 without auth, got {r.status_code}"


# ══════════════════════════════════════════════════════════════════════════════
# Section 5: Existing audit GET filters (verify still work post-enhancement)
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_get_audit_filter_by_action(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?action=allowlist.created returns only matching entries.

    API design note: the query param is ``?action=`` (shorthand) but it filters
    on the ``action_type`` field in the stored JSON entry.  The Code Agent must
    map ``?action=<value>`` → ``entry['action_type'] == <value>`` when
    implementing the filter.
    """
    await _seed_entry(
        fake_redis, action_type="allowlist.created", resource_id="uuid-allow-1"
    )
    await _seed_entry(fake_redis, action_type="ban.created", resource_id="uuid-ban-1")
    await _seed_entry(
        fake_redis, action_type="allowlist.created", resource_id="uuid-allow-2"
    )

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get("/api/v1/audit?action=allowlist.created")

    await _redis_module.close_redis()

    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    entries = data["entries"]
    assert (
        len(entries) == 2
    ), f"Expected 2 allowlist.created entries, got {len(entries)}: {entries}"
    for entry in entries:
        assert (
            entry.get("action_type") == "allowlist.created"
        ), f"Unexpected action_type in filtered results: {entry.get('action_type')!r}"


@pytest.mark.asyncio
async def test_get_audit_filter_by_actor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?actor=alice returns only entries where actor_id contains 'alice'.

    API design note: the query param is ``?actor=`` (shorthand) but it filters
    on the ``actor_id`` field in the stored JSON entry.  The Code Agent must
    map ``?actor=<value>`` → ``<value> in entry['actor_id']`` when
    implementing the filter.
    """
    await _seed_entry(fake_redis, actor_id="token:alice", resource_id="uuid-alice-1")
    await _seed_entry(fake_redis, actor_id="token:bob", resource_id="uuid-bob-1")
    await _seed_entry(fake_redis, actor_id="token:alice", resource_id="uuid-alice-2")

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        r = await client.get("/api/v1/audit?actor=alice")

    await _redis_module.close_redis()

    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    entries = data["entries"]
    assert len(entries) == 2, f"Expected 2 alice entries, got {len(entries)}: {entries}"
    for entry in entries:
        assert "alice" in entry.get(
            "actor_id", ""
        ), f"Unexpected actor_id in filtered results: {entry.get('actor_id')!r}"


@pytest.mark.asyncio
async def test_get_audit_since_filter(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /api/v1/audit?since=<ts> returns only entries with timestamp >= ts."""
    ts_old = "2026-01-01T00:00:00.000Z"
    ts_mid = "2026-03-01T00:00:00.000Z"
    ts_new = "2026-04-07T10:00:00.000Z"

    await _seed_entry(fake_redis, timestamp=ts_old, resource_id="uuid-old")
    await _seed_entry(fake_redis, timestamp=ts_mid, resource_id="uuid-mid")
    await _seed_entry(fake_redis, timestamp=ts_new, resource_id="uuid-new")

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    admin_cookie = {"token": _create_access_token("admin")}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as client:
        # Request entries from mid timestamp onwards — should return mid + new
        r = await client.get(f"/api/v1/audit?since={ts_mid}")

    await _redis_module.close_redis()

    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    entries = data["entries"]
    assert (
        len(entries) == 2
    ), f"Expected 2 entries (mid + new), got {len(entries)}: {entries}"
    for entry in entries:
        assert (
            entry.get("timestamp", "") >= ts_mid
        ), f"Entry with timestamp {entry.get('timestamp')!r} is older than since={ts_mid!r}"
