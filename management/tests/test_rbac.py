"""TDD tests for Phase 79 Cluster 2 — RBAC Role Enforcement.

These tests are written to FAIL against the current codebase because
``require_role(minimum_role)`` does not yet exist and most endpoints
currently enforce no role beyond authentication.

Role hierarchy (low → high):
    auditor < analyst < operator < admin

Endpoint minimum-role matrix under test:
    GET  /api/v1/dial               → Auditor
    PUT  /api/v1/dial               → Admin
    GET  /api/v1/bans               → Auditor
    POST /api/v1/bans/{ip}          → Operator
    DELETE /api/v1/bans/{ip}        → Operator
    GET  /api/v1/lists/{type}/{name}               → Auditor
    POST /api/v1/lists/{type}/{name}/{entry}       → Operator
    DELETE /api/v1/lists/{type}/{name}/{entry}     → Operator
    GET  /api/v1/audit              → Auditor
    GET  /api/v1/events             → Analyst
    POST /api/v1/config/reload      → Admin

All tests are async (pytest-asyncio).  Bearer-only clients are used
throughout to avoid cookie contamination (lesson from Cluster 1 review).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Tuple

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

_ALL_ROLES = ["auditor", "analyst", "operator", "admin"]

# Concrete endpoints used as role-tier targets
_AUDITOR_GET_ENDPOINT = "/api/v1/dial"          # min=auditor (GET)
_ANALYST_GET_ENDPOINT = "/api/v1/events"        # min=analyst (GET)
_OPERATOR_POST_BAN = "/api/v1/bans/1.2.3.4"    # min=operator (POST)
_ADMIN_PUT_DIAL = "/api/v1/dial"                # min=admin (PUT)

# ── Per-test fake Redis ───────────────────────────────────────────────────────
#
# We do NOT use the conftest fake_redis fixture here because we build
# bearer-only clients that must share state with the admin client used
# to create the token.  Each helper below creates its own server instance.


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Isolated FakeRedis instance for each test in this module."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _make_token(
    admin_client: AsyncClient,
    role: str,
    fake_redis: fakeredis.aioredis.FakeRedis,
    name: str | None = None,
) -> str:
    """Create a bearer token of *role* via the tokens API and return the plaintext.

    Uses the same cookie-authenticated admin_client that created the app so
    the token hash lands in the shared fake_redis instance.
    """
    token_name = name or f"rbac-test-{role}"
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

    Creates a fresh app instance sharing fake_redis, seeds a bearer token via
    a temporary admin-cookie client, then yields a new client with NO cookies
    so tests exercise bearer-only authentication paths.

    This avoids cookie contamination: cookie auth always returns role=admin,
    which would mask missing role enforcement on all non-admin checks.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    admin_cookie = {"token": _create_access_token("admin")}

    # Use the admin cookie client only to seed the bearer token
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as admin_client:
        plaintext = await _make_token(admin_client, role, fake_redis)

    # Yield a clean, cookie-free client for the actual assertions
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client, plaintext

    await _redis_module.close_redis()


# ── Section 1: require_role dependency hierarchy ──────────────────────────────


@pytest.mark.asyncio
async def test_require_role_admin_accepts_admin_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Admin token on an admin-only endpoint must return 200.

    Verifies the happy-path for the top of the role hierarchy.
    """
    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.put(
            _ADMIN_PUT_DIAL,
            json={"value": 5},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Admin token on PUT /api/v1/dial must return 200, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert "value" in body, f"Expected DialValue body with 'value' field, got: {body}"
        assert isinstance(body["value"], int), f"'value' must be int, got: {type(body['value'])}"


@pytest.mark.asyncio
async def test_require_role_admin_rejects_operator_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator token on an admin-only endpoint must return 403.

    Operator is one level below admin; it must not satisfy the admin requirement.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.put(
            _ADMIN_PUT_DIAL,
            json={"value": 5},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Operator on admin-only PUT /api/v1/dial must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_require_role_admin_rejects_analyst_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst token on an admin-only endpoint must return 403.

    Analyst is two levels below admin; the dial is a security-critical control.
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.put(
            _ADMIN_PUT_DIAL,
            json={"value": 5},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Analyst on admin-only PUT /api/v1/dial must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_require_role_admin_rejects_auditor_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor token on an admin-only endpoint must return 403.

    Auditors are read-only; changing the dial must be completely out of reach.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.put(
            _ADMIN_PUT_DIAL,
            json={"value": 5},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on admin-only PUT /api/v1/dial must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_require_role_operator_accepts_operator_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator token on an operator-minimum endpoint must return 2xx.

    An operator satisfies an operator minimum — basic role match case.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            _OPERATOR_POST_BAN,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 201), (
            f"Operator on POST /api/v1/bans/ip must return 200/201, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert body.get("ip") == "1.2.3.4", f"Expected ban response with ip=1.2.3.4, got: {body}"


@pytest.mark.asyncio
async def test_require_role_operator_accepts_admin_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Admin token on an operator-minimum endpoint must return 2xx.

    Admin role exceeds the operator minimum; higher roles satisfy lower requirements.
    """
    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.post(
            _OPERATOR_POST_BAN,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 201), (
            f"Admin on operator-min POST /api/v1/bans/ip must return 200/201, got {r.status_code}"
        )
        body = r.json()
        assert body.get("ip") == "1.2.3.4", f"Expected ban response with ip=1.2.3.4, got: {body}"


@pytest.mark.asyncio
async def test_require_role_operator_rejects_analyst_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst token on an operator-minimum endpoint must return 403.

    Analysts can read; they must not be able to write bans.
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.post(
            _OPERATOR_POST_BAN,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Analyst on operator-min POST /api/v1/bans/ip must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_require_role_operator_rejects_auditor_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor token on an operator-minimum endpoint must return 403.

    Auditors are read-only; ban creation is a write operation.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.post(
            _OPERATOR_POST_BAN,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on operator-min POST /api/v1/bans/ip must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_require_role_analyst_accepts_analyst_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst token on an analyst-minimum endpoint must return 2xx.

    Basic role-match for the analyst tier — events stream is their primary perk.
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            _ANALYST_GET_ENDPOINT,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        # SSE endpoint returns 200; we only care it's not 4xx auth/authz error
        assert r.status_code == 200, (
            f"Expected 200, got {r.status_code}: {r.text[:200]}"
        )


@pytest.mark.asyncio
async def test_require_role_analyst_accepts_operator_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator token on an analyst-minimum endpoint must return 2xx.

    Operator exceeds analyst; higher roles satisfy lower requirements.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.get(
            _ANALYST_GET_ENDPOINT,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Expected 200, got {r.status_code}: {r.text[:200]}"
        )


@pytest.mark.asyncio
async def test_require_role_analyst_accepts_admin_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Admin token on an analyst-minimum endpoint must return 2xx.

    Admin is the highest role and satisfies every minimum.
    """
    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.get(
            _ANALYST_GET_ENDPOINT,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Expected 200, got {r.status_code}: {r.text[:200]}"
        )


@pytest.mark.asyncio
async def test_require_role_analyst_rejects_auditor_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor token on an analyst-minimum endpoint must return 403.

    The events stream is the privilege that distinguishes analyst from auditor.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            _ANALYST_GET_ENDPOINT,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on analyst-min GET /api/v1/events must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("role", _ALL_ROLES)
async def test_require_role_auditor_accepts_all_roles(
    role: str,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Every role can access an auditor-minimum endpoint.

    Auditor is the floor of the hierarchy; all authenticated tokens must be
    able to read audit-level data (GET /api/v1/dial).
    """
    async with _bearer_client(role, fake_redis) as (client, token):
        r = await client.get(
            _AUDITOR_GET_ENDPOINT,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Role '{role}' on auditor-min GET /api/v1/dial must return 200, "
            f"got {r.status_code}: {r.text}"
        )


# ── Section 2: Dial endpoint role enforcement ─────────────────────────────────


@pytest.mark.asyncio
async def test_get_dial_requires_auditor(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token can read the dial value.

    GET /api/v1/dial is read-only; the lowest role must be sufficient.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/dial",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Auditor reading dial must return 200, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert "value" in body, f"Expected DialValue body, got: {body}"
        assert isinstance(body["value"], int)


@pytest.mark.asyncio
async def test_put_dial_requires_admin(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator token on PUT /api/v1/dial must return 403.

    The dial controls blocking aggression — a security control that only
    admins may change.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.put(
            "/api/v1/dial",
            json={"value": 5},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Operator on PUT /api/v1/dial must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_put_dial_admin_token_succeeds(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Admin token on PUT /api/v1/dial must return 200.

    Admin is the only role permitted to change the dial value.
    """
    async with _bearer_client("admin", fake_redis) as (client, token):
        r = await client.put(
            "/api/v1/dial",
            json={"value": 5},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Admin on PUT /api/v1/dial must return 200, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert body.get("value") == 5, f"Expected dial set to 5, got: {body}"


@pytest.mark.asyncio
async def test_put_dial_analyst_token_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst token on PUT /api/v1/dial must return 403.

    Analysts can observe but must not influence the blocking dial.
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.put(
            "/api/v1/dial",
            json={"value": 5},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Analyst on PUT /api/v1/dial must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_put_dial_no_auth_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Unauthenticated request to PUT /api/v1/dial must return 401.

    No authentication presented means no identity; 401 must precede RBAC checks.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.put(
            "/api/v1/dial",
            json={"value": 5},
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 401, (
            f"Unauthenticated PUT /api/v1/dial must return 401, got {r.status_code}"
        )
    await _redis_module.close_redis()


# ── Section 3: Bans role enforcement ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_bans_auditor_can_read(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token can list all bans.

    GET /api/v1/bans is a read operation; auditor is the minimum role for reads.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/bans",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Auditor reading bans must return 200, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert "bans" in body, f"Expected BanList body with 'bans' field, got: {body}"
        assert "count" in body, f"Expected BanList body with 'count' field, got: {body}"


@pytest.mark.asyncio
async def test_post_ban_operator_can_write(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator bearer token can create a ban.

    Ban creation is a write/mutation operation; operator is the minimum write role.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/bans/10.0.0.1",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 201), (
            f"Operator on POST /api/v1/bans/ip must return 200/201, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert body.get("ip") == "10.0.0.1", f"Expected ban response with ip=10.0.0.1, got: {body}"


@pytest.mark.asyncio
async def test_post_ban_analyst_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst bearer token must be rejected when creating a ban.

    Analysts may observe but must not modify ban state.
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/bans/10.0.0.2",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Analyst on POST /api/v1/bans/ip must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_post_ban_auditor_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token must be rejected when creating a ban.

    Auditors are strictly read-only; any write must return 403.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/bans/10.0.0.3",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on POST /api/v1/bans/ip must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_delete_ban_operator_can_delete(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator bearer token can delete an existing ban."""
    await fake_redis.set("ban:10.0.0.5", "pre-seeded for delete test", ex=3600)

    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.delete(
            "/api/v1/bans/10.0.0.5",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 204), (
            f"Operator on DELETE /api/v1/bans/ip must return 200/204, "
            f"got {r.status_code}: {r.text}"
        )
        if r.status_code == 200:
            body = r.json()
            assert body.get("ip") == "10.0.0.5"


@pytest.mark.asyncio
async def test_delete_ban_analyst_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst bearer token must be rejected when attempting to delete a ban.

    Ban deletion is a write operation; analyst is below the operator minimum.
    """
    await fake_redis.set("ban:10.0.0.6", "pre-seeded", ex=3600)
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.delete(
            "/api/v1/bans/10.0.0.6",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Analyst on DELETE /api/v1/bans/ip must return 403, got {r.status_code}"
        )


# ── Section 4: Lists role enforcement ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_list_auditor_can_read(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token can read a list (GET /api/v1/lists/ja4/whitelist).

    Reading any list is a read operation; auditor is the minimum.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/lists/ja4/whitelist",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Auditor reading list must return 200, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert "entries" in body, f"Expected ListEntries body with 'entries' field, got: {body}"
        assert isinstance(body["entries"], list)


@pytest.mark.asyncio
async def test_post_list_entry_operator_can_write(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator bearer token can add an entry to a list.

    Adding entries is a mutation; operator is the minimum write role.
    """
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/lists/ja4/whitelist/t13d1715h2_5b57614c22b0_bca4e439f9ad",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 201), (
            f"Operator adding list entry must return 200/201, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert "entry" in body, f"Expected list entry response with 'entry' field, got: {body}"


@pytest.mark.asyncio
async def test_post_list_entry_analyst_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst bearer token must be rejected when adding a list entry.

    Analysts are below the operator threshold and may not mutate lists.
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/lists/ja4/whitelist/t13d1715h2_analyst_attempt",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Analyst adding list entry must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_delete_list_entry_operator_can_delete(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator bearer token can remove an entry from a list.

    Deletion is a mutation; operator is the minimum role.
    We pre-seed the Redis set so the DELETE is not a 404.
    """
    await fake_redis.sadd("ja4:whitelist", "t13d1715h2_delete_me_operator")
    async with _bearer_client("operator", fake_redis) as (client, token):
        r = await client.delete(
            "/api/v1/lists/ja4/whitelist/t13d1715h2_delete_me_operator",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 204), (
            f"Operator deleting list entry must return 200/204, got {r.status_code}: {r.text}"
        )
        if r.status_code == 200:
            body = r.json()
            assert "entry" in body, f"Expected list entry response body on 200, got: {body}"


@pytest.mark.asyncio
async def test_delete_list_entry_auditor_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token must be rejected when deleting a list entry.

    Auditors are read-only; any deletion must return 403 before any Redis
    operations are attempted.
    """
    await fake_redis.sadd("ja4:whitelist", "t13d1715h2_auditor_cant_touch")
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.delete(
            "/api/v1/lists/ja4/whitelist/t13d1715h2_auditor_cant_touch",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor deleting list entry must return 403, got {r.status_code}"
        )


# ── Section 5: Config reload role enforcement ─────────────────────────────────


@pytest.mark.asyncio
async def test_config_reload_operator_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator bearer token cannot trigger config reload — admin only."""
    async with _bearer_client("operator", fake_redis) as (client, op_token):
        r = await client.post(
            "/api/v1/config/reload",
            headers={"Authorization": f"Bearer {op_token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Operator must not trigger config reload; got {r.status_code}: {r.text}"
        )


@pytest.mark.asyncio
async def test_config_reload_admin_succeeds(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Admin bearer token can trigger config reload."""
    async with _bearer_client("admin", fake_redis) as (client, admin_token):
        r = await client.post(
            "/api/v1/config/reload",
            headers={"Authorization": f"Bearer {admin_token}", "Accept": "application/json"},
        )
        assert r.status_code in (200, 202), (
            f"Admin must be able to trigger config reload; got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert "message" in body, f"Expected response body with 'message' field, got: {body}"


@pytest.mark.asyncio
async def test_config_reload_auditor_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token must be rejected on POST /api/v1/config/reload.

    Config reload is admin-only; auditor is three levels below.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/config/reload",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on POST /api/v1/config/reload must return 403, got {r.status_code}"
        )


# ── Section 6: Audit log role enforcement ────────────────────────────────────


@pytest.mark.asyncio
async def test_get_audit_auditor_can_read(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token can access the audit log.

    The audit log is a read endpoint; auditor is the minimum authenticated role.
    Auditors need audit log access for compliance review.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/audit",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Auditor reading audit log must return 200, got {r.status_code}: {r.text}"
        )
        body = r.json()
        assert "entries" in body, f"Expected AuditLog body with 'entries' field, got: {body}"
        assert "count" in body, f"Expected AuditLog body with 'count' field, got: {body}"
        assert isinstance(body["entries"], list)


@pytest.mark.asyncio
async def test_get_audit_no_auth_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Unauthenticated request to GET /api/v1/audit must return 401.

    The audit log contains security-sensitive operational history;
    anonymous access must never be permitted.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.get(
            "/api/v1/audit",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 401, (
            f"Unauthenticated GET /api/v1/audit must return 401, got {r.status_code}"
        )
    await _redis_module.close_redis()


# ── Section 7: Events endpoint role enforcement ───────────────────────────────


@pytest.mark.asyncio
async def test_get_events_analyst_can_access(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Analyst bearer token can access the live events stream.

    The events stream is the privilege that distinguishes analyst from auditor.
    This test verifies the analyst minimum is honoured (not a 403).
    """
    async with _bearer_client("analyst", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/events",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 200, (
            f"Expected 200, got {r.status_code}: {r.text[:200]}"
        )


@pytest.mark.asyncio
async def test_get_events_auditor_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor bearer token must be rejected on GET /api/v1/events.

    The live events stream is an analyst-and-above feature; auditors cannot
    access it because it exposes real-time connection metadata.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.get(
            "/api/v1/events",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on GET /api/v1/events must return 403, got {r.status_code}"
        )


@pytest.mark.asyncio
async def test_get_events_no_auth_rejected(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Unauthenticated request to GET /api/v1/events must return 401.

    The events stream exposes live connection data; anonymous access is prohibited.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.get(
            "/api/v1/events",
            headers={"Accept": "application/json"},
        )
        assert r.status_code == 401, (
            f"Unauthenticated GET /api/v1/events must return 401, got {r.status_code}"
        )
    await _redis_module.close_redis()


# ── Section 8: Error response format ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_role_rejection_returns_403_not_404(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """An auditor hitting an operator endpoint must receive 403, not 404 or 500.

    403 Forbidden communicates that the route exists but the caller lacks
    permission.  404 would hide the route; 500 would indicate a server bug.
    The distinction matters for API clients that parse status codes.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/bans/192.168.1.1",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Role rejection must be exactly 403, not {r.status_code}. "
            "404 hides the route; 500 indicates a server bug."
        )


@pytest.mark.asyncio
async def test_403_response_has_detail_field(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A 403 response body must contain a 'detail' field.

    FastAPI standard error format includes a 'detail' key.  API clients
    depend on this field to display a human-readable rejection reason.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        r = await client.post(
            "/api/v1/bans/192.168.1.2",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403
        body = r.json()
        assert "detail" in body, (
            f"403 response must have a 'detail' field; got keys: {list(body.keys())}"
        )
        assert body["detail"], "The 'detail' field must not be empty"


# ── Section 9: Security boundary tests ───────────────────────────────────────


@pytest.mark.asyncio
async def test_operator_cannot_delete_tokens(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Operator cannot revoke bearer tokens — token management is admin-only.

    An operator who can revoke tokens could silence an admin's audit trail.
    """
    import uuid

    create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    # Create a dummy token ID in Redis for the operator to try to delete
    dummy_id = str(uuid.uuid4())
    await fake_redis.hset(f"mgmt:token:{dummy_id}", mapping={
        "id": dummy_id, "name": "victim", "role": "auditor",
        "hash": "fakehash", "created_at": "2026-01-01T00:00:00Z",
        "expires_at": "", "last_used_at": "",
    })
    await fake_redis.sadd("mgmt:token:idx", dummy_id)

    async with _bearer_client("operator", fake_redis) as (client, op_token):
        r = await client.delete(
            f"/api/v1/tokens/{dummy_id}",
            headers={"Authorization": f"Bearer {op_token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Operator must not delete tokens; got {r.status_code}. "
            "Token management must be admin-only."
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_role_preserved_across_token_rotation(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Rotating a token must preserve the original role — not silently promote to admin.

    An auditor token that rotates to admin would completely bypass RBAC.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        # Create an auditor token
        create_r = await admin_client.post(
            "/api/v1/tokens",
            json={"name": "auditor-to-rotate", "role": "auditor"},
        )
        assert create_r.status_code == 201
        original_id = create_r.json()["id"]

        # Rotate it
        rotate_r = await admin_client.post(f"/api/v1/tokens/{original_id}/rotate")
        assert rotate_r.status_code == 200
        new_id = rotate_r.json()["id"]
        new_plaintext = rotate_r.json()["token"]

        # Inspect the new token's role
        inspect_r = await admin_client.get(f"/api/v1/tokens/{new_id}")
        assert inspect_r.status_code == 200
        assert inspect_r.json()["role"] == "auditor", (
            f"Rotated token role must be 'auditor', got: {inspect_r.json()['role']}. "
            "Token rotation must not silently change the role."
        )

    # Also verify: the new token actually gets 403 on an operator endpoint (not 200)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.post(
            "/api/v1/bans/192.168.1.1",
            json={"ttl": 3600},
            headers={"Authorization": f"Bearer {new_plaintext}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Rotated auditor token must still get 403 on operator endpoint, got {r.status_code}. "
            "Role promotion through rotation is a security bug."
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_role_downgrade_in_redis_enforced_immediately(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A token whose role is downgraded in Redis is rejected on next request.

    RBAC must read role from Redis on each request, not cache it at token creation.
    An operator downgraded to auditor must immediately lose write access.
    """
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        create_r = await admin_client.post(
            "/api/v1/tokens", json={"name": "downgrade-test", "role": "operator"},
        )
        assert create_r.status_code == 201
        token_id = create_r.json()["id"]
        plaintext = create_r.json()["token"]

    # Downgrade role directly in Redis (simulating an admin emergency downgrade)
    await fake_redis.hset(f"mgmt:token:{token_id}", "role", "auditor")

    # The token must now be rejected on an operator endpoint
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.post(
            "/api/v1/bans/10.0.0.99",
            json={"ttl": 3600},
            headers={"Authorization": f"Bearer {plaintext}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Token with downgraded role must get 403, got {r.status_code}. "
            "Role must be read from Redis on each request, not cached."
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_auditor_delete_ban_403_regardless_of_ban_existence(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Auditor gets 403 on DELETE /api/v1/bans/{ip} even if the ban doesn't exist.

    If the RBAC check happens after the Redis lookup, a missing ban could
    produce a 404 before the 403 is raised, hiding the access control failure.
    """
    async with _bearer_client("auditor", fake_redis) as (client, token):
        # No ban pre-seeded — would 404 if handler checks Redis before role
        r = await client.delete(
            "/api/v1/bans/172.16.0.1",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        assert r.status_code == 403, (
            f"Auditor on DELETE /api/v1/bans must get 403, not {r.status_code}. "
            "RBAC check must occur before any Redis lookup."
        )


@pytest.mark.asyncio
async def test_expired_bearer_token_returns_401_not_403(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """An expired bearer token returns 401 (not authenticated), not 403 (not authorized).

    API clients use 401 vs 403 to decide whether to re-authenticate or escalate.
    A 403 on an expired token would incorrectly suggest the role is wrong.
    """
    from datetime import datetime, timedelta, timezone

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    # Create a token then backdate its expires_at in Redis
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        create_r = await admin_client.post(
            "/api/v1/tokens", json={"name": "expired-token-test", "role": "admin"},
        )
        assert create_r.status_code == 201
        token_id = create_r.json()["id"]
        plaintext = create_r.json()["token"]

    # Backdate the expiry
    past = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    await fake_redis.hset(f"mgmt:token:{token_id}", "expires_at", past)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.get(
            "/api/v1/dial",
            headers={"Authorization": f"Bearer {plaintext}", "Accept": "application/json"},
        )
        assert r.status_code == 401, (
            f"Expired bearer token must return 401, got {r.status_code}. "
            "An expired credential is an authentication failure, not an authorisation failure."
        )

    await _redis_module.close_redis()
