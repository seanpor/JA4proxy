"""TDD tests for the bearer token management API endpoints.

Covers
------
- POST /api/v1/tokens       — create a token (Admin only)
- GET  /api/v1/tokens       — list all tokens (Admin only; metadata only, no hash/plaintext)
- GET  /api/v1/tokens/{id}  — inspect a single token (Admin only; no hash)
- DELETE /api/v1/tokens/{id} — revoke a token (idempotent)
- POST /api/v1/tokens/{id}/rotate — issue replacement; old token expires after grace period

Bearer auth path:
- Authorization: Bearer <token> accepted on all protected endpoints
- Invalid / expired / revoked tokens → 401
- /api/v1/health is public (no auth required)
- Any valid bearer token allows access to /api/v1/dial (role enforcement is MFA/SSO Hardening Cluster 2)

All tests are written to FAIL against the current codebase (endpoints do not exist yet).
They document the contract that the implementation must satisfy.

Role vocabulary: auditor | analyst | operator | admin
Redis schema:
    mgmt:token:{id}  → Hash  {id, name, role, hash, created_at, expires_at, last_used_at}
    mgmt:token:idx   → SET of token IDs
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from httpx import AsyncClient

from management.api.auth import (
    _create_access_token,
)  # noqa: F401 — used in bearer tests

# ── Helpers ───────────────────────────────────────────────────────────────────

_VALID_ROLES = ["auditor", "analyst", "operator", "admin"]
_TOKEN_CREATE_PATH = "/api/v1/tokens"


def _now_plus(seconds: int) -> str:
    """Return an ISO 8601 UTC timestamp *seconds* from now."""
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.isoformat()


def _now_minus(seconds: int) -> str:
    """Return an ISO 8601 UTC timestamp *seconds* in the past."""
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.isoformat()


async def _create_token(
    client: AsyncClient,
    name: str = "test-token",
    role: str = "operator",
    expires_at: str | None = None,
) -> dict[str, Any]:
    """Helper: POST /api/v1/tokens and return the parsed JSON body."""
    body: dict[str, Any] = {"name": name, "role": role}
    if expires_at is not None:
        body["expires_at"] = expires_at
    r = await client.post(_TOKEN_CREATE_PATH, json=body)
    assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
    return r.json()


# ── Token creation ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_token_returns_201(authenticated_client: AsyncClient) -> None:
    """POST /api/v1/tokens with valid Admin cookie returns 201.

    The response must include id, name, role, created_at, expires_at, and the
    one-time plaintext token field.  This asserts the complete contract for
    the creation endpoint.
    """
    r = await authenticated_client.post(
        _TOKEN_CREATE_PATH,
        json={"name": "my-ci-token", "role": "operator"},
    )
    assert r.status_code == 201
    data = r.json()
    assert "id" in data
    assert "name" in data
    assert "role" in data
    assert "created_at" in data
    assert "expires_at" in data
    assert "token" in data  # plaintext — shown exactly once
    assert data["name"] == "my-ci-token"
    assert data["role"] == "operator"
    # The plaintext token must be a non-empty string
    assert isinstance(data["token"], str)
    assert len(data["token"]) > 16


@pytest.mark.asyncio
async def test_create_token_with_expiry(authenticated_client: AsyncClient) -> None:
    """POST /api/v1/tokens with a future expires_at stores and returns the submitted expiry."""
    from datetime import datetime, timezone

    future = _now_plus(86400)
    r = await authenticated_client.post(
        _TOKEN_CREATE_PATH,
        json={"name": "expiring-token", "role": "auditor", "expires_at": future},
    )
    assert r.status_code == 201
    data = r.json()
    assert data["expires_at"], "expires_at must not be null or empty"

    submitted_dt = datetime.fromisoformat(future)
    returned_dt = datetime.fromisoformat(data["expires_at"])
    diff = abs((returned_dt - submitted_dt).total_seconds())
    assert diff < 5, (
        f"Returned expires_at ({data['expires_at']}) differs too much from submitted "
        f"value ({future}); diff={diff}s. Implementation may be ignoring expires_at."
    )


@pytest.mark.asyncio
async def test_create_token_missing_name_returns_422(
    authenticated_client: AsyncClient,
) -> None:
    """POST /api/v1/tokens without a name field returns 422 Unprocessable Entity.

    The name field is mandatory — a token with no human-readable label is
    unmanageable in a multi-token environment.
    """
    r = await authenticated_client.post(
        _TOKEN_CREATE_PATH,
        json={"role": "operator"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_token_invalid_role_returns_422(
    authenticated_client: AsyncClient,
) -> None:
    """POST /api/v1/tokens with an unrecognised role value returns 422.

    Roles are an enum; accepting arbitrary strings would bypass role
    validation entirely.
    """
    r = await authenticated_client.post(
        _TOKEN_CREATE_PATH,
        json={"name": "bad-role-token", "role": "superuser"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize("role", _VALID_ROLES)
async def test_create_token_valid_roles(
    authenticated_client: AsyncClient, role: str
) -> None:
    """POST /api/v1/tokens accepts all four valid role values.

    Each role in the vocabulary must be accepted; none should return 422.
    """
    r = await authenticated_client.post(
        _TOKEN_CREATE_PATH,
        json={"name": f"token-for-{role}", "role": role},
    )
    assert r.status_code == 201
    assert r.json()["role"] == role


@pytest.mark.asyncio
async def test_create_token_past_expiry_returns_422(
    authenticated_client: AsyncClient,
) -> None:
    """POST /api/v1/tokens with expires_at in the past returns 422.

    Creating an already-expired token is a programming error and should be
    rejected immediately rather than silently stored as a permanently-invalid
    credential.
    """
    past = _now_minus(60)
    r = await authenticated_client.post(
        _TOKEN_CREATE_PATH,
        json={"name": "already-expired", "role": "operator", "expires_at": past},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_token_requires_auth(test_client: AsyncClient) -> None:
    """POST /api/v1/tokens without authentication returns 401.

    Token creation is an Admin-only operation.  Unauthenticated callers
    must be rejected before any token is created.
    """
    r = await test_client.post(
        _TOKEN_CREATE_PATH,
        json={"name": "sneaky-token", "role": "operator"},
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_token_plaintext_not_in_subsequent_get(
    authenticated_client: AsyncClient,
) -> None:
    """The plaintext token is returned only on creation; GET never returns it.

    Showing the plaintext on any subsequent call would defeat the purpose of
    storing only a bcrypt hash in Redis.
    """
    created = await _create_token(authenticated_client, name="once-only")
    token_id = created["id"]

    # Inspect via GET
    r = await authenticated_client.get(f"/api/v1/tokens/{token_id}")
    assert r.status_code == 200
    data = r.json()
    # 'token' (plaintext) must not appear; 'hash' must also not appear
    assert "token" not in data
    assert "hash" not in data


# ── Token listing ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_tokens_empty(authenticated_client: AsyncClient) -> None:
    """GET /api/v1/tokens returns an empty list when no tokens exist.

    The response must be a JSON object with a ``tokens`` list and a ``count``
    integer — matching the pattern established by the bans endpoint.
    """
    r = await authenticated_client.get(_TOKEN_CREATE_PATH)
    assert r.status_code == 200
    data = r.json()
    assert "tokens" in data
    assert data["tokens"] == []
    assert data["count"] == 0


@pytest.mark.asyncio
async def test_list_tokens_shows_created_token(
    authenticated_client: AsyncClient,
) -> None:
    """A newly created token appears in GET /api/v1/tokens.

    After creation the token must be enumerable by the listing endpoint.
    """
    created = await _create_token(authenticated_client, name="listed-token")
    r = await authenticated_client.get(_TOKEN_CREATE_PATH)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1
    ids = [t["id"] for t in data["tokens"]]
    assert created["id"] in ids


@pytest.mark.asyncio
async def test_list_tokens_no_hash_or_plaintext(
    authenticated_client: AsyncClient,
) -> None:
    """GET /api/v1/tokens never returns the hash or plaintext token for any entry.

    Listing must expose only metadata safe to display in a management UI.
    Returning the bcrypt hash or the original plaintext would be a security
    regression.
    """
    await _create_token(authenticated_client, name="safe-listing-check")
    r = await authenticated_client.get(_TOKEN_CREATE_PATH)
    assert r.status_code == 200
    for entry in r.json()["tokens"]:
        assert "hash" not in entry
        assert "token" not in entry


@pytest.mark.asyncio
async def test_list_tokens_requires_auth(test_client: AsyncClient) -> None:
    """GET /api/v1/tokens without authentication returns 401.

    The token index reveals what API clients are configured — this must be
    protected.
    """
    r = await test_client.get(
        _TOKEN_CREATE_PATH,
        headers={"Accept": "application/json"},
    )
    assert r.status_code == 401


# ── Token inspection ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_token_by_id(authenticated_client: AsyncClient) -> None:
    """GET /api/v1/tokens/{id} returns correct metadata for an existing token."""
    created = await _create_token(
        authenticated_client, name="inspectable", role="operator"
    )
    token_id = created["id"]

    r = await authenticated_client.get(f"/api/v1/tokens/{token_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == token_id
    assert data["name"] == "inspectable"
    assert data["role"] == "operator"  # value must round-trip, not just exist
    assert "created_at" in data
    assert "expires_at" in data
    assert "last_used_at" in data


@pytest.mark.asyncio
async def test_get_token_by_id_no_hash(authenticated_client: AsyncClient) -> None:
    """GET /api/v1/tokens/{id} never exposes the bcrypt hash.

    The hash is an internal implementation detail.  Exposing it would make
    offline cracking attacks trivially easy.
    """
    created = await _create_token(authenticated_client, name="no-hash-check")
    r = await authenticated_client.get(f"/api/v1/tokens/{created['id']}")
    assert r.status_code == 200
    assert "hash" not in r.json()


@pytest.mark.asyncio
async def test_get_nonexistent_token_returns_404(
    authenticated_client: AsyncClient,
) -> None:
    """GET /api/v1/tokens/{id} for an unknown ID returns 404.

    A missing token must not silently return an empty or default record.
    """
    r = await authenticated_client.get("/api/v1/tokens/nonexistent-uuid")
    assert r.status_code == 404


# ── Token revocation ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_token_returns_204(authenticated_client: AsyncClient) -> None:
    """DELETE /api/v1/tokens/{id} for an existing token returns 204 No Content.

    Revocation is a write operation with no meaningful body to return.
    """
    created = await _create_token(authenticated_client, name="to-be-deleted")
    r = await authenticated_client.delete(f"/api/v1/tokens/{created['id']}")
    assert r.status_code == 204


@pytest.mark.asyncio
async def test_delete_nonexistent_token_is_idempotent(
    authenticated_client: AsyncClient,
) -> None:
    """DELETE /api/v1/tokens/{id} for an unknown ID returns 204 (idempotent).

    Revoking a token that no longer exists should not raise an error.
    If the intended effect (token cannot be used) is already achieved, the
    operation is a no-op and must succeed.
    """
    r = await authenticated_client.delete("/api/v1/tokens/does-not-exist")
    assert r.status_code == 204


@pytest.mark.asyncio
async def test_deleted_token_not_in_listing(
    authenticated_client: AsyncClient,
) -> None:
    """After deletion a token no longer appears in GET /api/v1/tokens.

    The token index (mgmt:token:idx) must be kept in sync with the hash
    records.
    """
    created = await _create_token(authenticated_client, name="delete-then-list")
    await authenticated_client.delete(f"/api/v1/tokens/{created['id']}")

    r = await authenticated_client.get(_TOKEN_CREATE_PATH)
    ids = [t["id"] for t in r.json()["tokens"]]
    assert created["id"] not in ids


@pytest.mark.asyncio
async def test_deleted_token_get_returns_404(
    authenticated_client: AsyncClient,
) -> None:
    """After deletion GET /api/v1/tokens/{id} returns 404.

    Once revoked, the token metadata record must also be inaccessible.
    """
    created = await _create_token(authenticated_client, name="delete-then-get")
    await authenticated_client.delete(f"/api/v1/tokens/{created['id']}")

    r = await authenticated_client.get(f"/api/v1/tokens/{created['id']}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_deleted_token_bearer_auth_returns_401(fake_redis) -> None:
    """Using a revoked token as Bearer auth returns 401.

    This is the primary security property of revocation. Uses a cookie-free
    client to prevent the admin cookie from masking a missing revocation check.
    """
    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        created = await _create_token(admin_client, name="revoke-bearer-check")
        plaintext = created["token"]
        await admin_client.delete(f"/api/v1/tokens/{created['id']}")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext}",
                "Accept": "application/json",
            },
        )
        assert r.status_code == 401, (
            "Revoked bearer token must return 401; got 200 — "
            "revocation may not be removing the Redis hash."
        )

    await _redis_module.close_redis()


# ── Token rotation ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rotate_token_returns_200_with_new_token(
    authenticated_client: AsyncClient,
) -> None:
    """POST /api/v1/tokens/{id}/rotate returns 200 with a new plaintext token.

    Rotation is the safe way to cycle credentials without a gap — it issues a
    replacement before retiring the original.
    """
    created = await _create_token(authenticated_client, name="to-rotate")

    r = await authenticated_client.post(f"/api/v1/tokens/{created['id']}/rotate")
    assert r.status_code == 200
    data = r.json()
    assert "token" in data  # new plaintext
    assert "id" in data  # new ID
    assert data["id"] != created["id"]  # must be a different ID
    assert data["token"] != created["token"]  # must be a different secret


@pytest.mark.asyncio
async def test_rotate_token_old_id_marked_for_expiry(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """After rotation the old token ID has a TTL (grace period) in Redis.

    The old token must not be deleted immediately; it must remain valid for a
    60-second grace period so in-flight requests using the old credential do
    not suddenly fail.  The grace period is represented by a TTL on the hash
    key in Redis.
    """
    created = await _create_token(authenticated_client, name="rotation-grace")
    old_id = created["id"]

    await authenticated_client.post(f"/api/v1/tokens/{old_id}/rotate")

    # The old hash key must now have a TTL (not persistent)
    old_key = f"mgmt:token:{old_id}"
    ttl = await fake_redis.ttl(old_key)
    # TTL must be positive (key is expiring) and ≤ 60 s (the grace window)
    assert 0 < ttl <= 60


@pytest.mark.asyncio
async def test_rotate_token_new_token_usable_immediately(fake_redis) -> None:
    """The new token returned by rotation is usable for Bearer auth immediately.

    Uses a cookie-free client to guarantee authentication comes from the bearer
    token, not a residual admin cookie.
    """
    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        created = await _create_token(admin_client, name="rotation-immediate")
        rotate_resp = await admin_client.post(f"/api/v1/tokens/{created['id']}/rotate")
        assert rotate_resp.status_code == 200
        new_token = rotate_resp.json()["token"]

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {new_token}",
                "Accept": "application/json",
            },
        )
        assert (
            r.status_code == 200
        ), f"New bearer token from rotation must be immediately usable; got {r.status_code}."

    await _redis_module.close_redis()


# ── Bearer token authentication ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bearer_valid_token_grants_access(fake_redis) -> None:
    """A valid Bearer token allows access to a protected endpoint.

    Uses an explicitly cookie-free client to guarantee the 200 response
    comes from bearer token auth, not a residual admin cookie.
    """
    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        created = await _create_token(admin_client, name="bearer-valid")
        plaintext = created["token"]

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext}",
                "Accept": "application/json",
            },
        )
        assert r.status_code == 200, (
            f"Valid bearer token must grant access; got {r.status_code}. "
            "If bearer middleware is not yet implemented this must fail — "
            "not silently pass via cookie fallback."
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_bearer_invalid_token_returns_401(test_client: AsyncClient) -> None:
    """A request with a nonsense Bearer token is rejected with 401.

    Random strings that do not correspond to any stored token must not
    accidentally authenticate.
    """
    r = await test_client.get(
        "/api/v1/dial",
        headers={
            "Authorization": "Bearer totally-made-up-credential-xyz",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_bearer_expired_token_returns_401(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """A Bearer token whose expires_at is in the past returns 401.

    Time-bounded tokens must not be honoured after their expiry timestamp,
    even if the hash would otherwise match.
    """
    # Create a token that expires very soon, then manually backdate it in Redis
    created = await _create_token(
        authenticated_client,
        name="expiry-check",
        expires_at=_now_plus(3600),
    )
    token_id = created["id"]
    plaintext = created["token"]

    # Backdate the expiry to the past directly in Redis (simulates clock advancing)
    await fake_redis.hset(
        f"mgmt:token:{token_id}",
        "expires_at",
        _now_minus(10),
    )

    r = await authenticated_client.get(
        "/api/v1/dial",
        headers={
            "Authorization": f"Bearer {plaintext}",
            "Accept": "application/json",
        },
        cookies={},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_bearer_revoked_token_returns_401(
    authenticated_client: AsyncClient,
) -> None:
    """A revoked Bearer token returns 401 even with a correct hash.

    Revocation (DELETE) must invalidate the credential regardless of its
    cryptographic validity.
    """
    created = await _create_token(authenticated_client, name="revoke-auth-check")
    plaintext = created["token"]

    await authenticated_client.delete(f"/api/v1/tokens/{created['id']}")

    r = await authenticated_client.get(
        "/api/v1/dial",
        headers={
            "Authorization": f"Bearer {plaintext}",
            "Accept": "application/json",
        },
        cookies={},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_health_endpoint_is_public(test_client: AsyncClient) -> None:
    """GET /api/v1/health returns 200 without any authentication.

    The health endpoint is used by load balancers and orchestrators that do
    not have credentials.  It must never require auth.
    """
    r = await test_client.get("/api/v1/health")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_bearer_any_role_can_access_dial(fake_redis) -> None:
    """Any valid bearer token (regardless of role) can read GET /api/v1/dial.

    Uses a cookie-free client to verify that access comes from bearer auth,
    not the admin cookie.
    """
    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        created = await _create_token(
            admin_client, name="auditor-dial-check", role="auditor"
        )
        plaintext = created["token"]

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext}",
                "Accept": "application/json",
            },
        )
        assert r.status_code == 200, (
            f"An auditor-role bearer token must be sufficient to read /api/v1/dial; "
            f"got {r.status_code}."
        )

    await _redis_module.close_redis()


# ── Redis schema verification ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_token_stored_in_redis_hash(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Creating a token writes the expected fields to mgmt:token:{id}.

    Verifies the Redis schema contract so implementation can be validated
    independently of the HTTP layer.
    """
    created = await _create_token(authenticated_client, name="redis-schema-check")
    token_id = created["id"]
    key = f"mgmt:token:{token_id}"

    fields = await fake_redis.hgetall(key)
    assert fields, f"Expected Redis hash at {key}, found nothing"
    assert fields.get("id") == token_id
    assert fields.get("name") == "redis-schema-check"
    assert fields.get("role")
    assert fields.get("hash")  # bcrypt hash — present but not returned via API
    assert fields.get("created_at")
    assert "expires_at" in fields  # may be empty string for no-expiry tokens
    assert "last_used_at" in fields  # may be empty string on creation


@pytest.mark.asyncio
async def test_token_id_added_to_index_set(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Creating a token adds its ID to the mgmt:token:idx Redis SET.

    The index set is used for enumeration in GET /api/v1/tokens.  Without it,
    listing would require a full SCAN of all mgmt:token:* keys.
    """
    created = await _create_token(authenticated_client, name="index-set-check")
    token_id = created["id"]

    is_member = await fake_redis.sismember("mgmt:token:idx", token_id)
    assert is_member, f"Expected {token_id} in mgmt:token:idx"


@pytest.mark.asyncio
async def test_delete_token_removes_id_from_index_set(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Revoking a token removes its ID from mgmt:token:idx.

    Stale entries in the index would cause the listing endpoint to attempt
    fetching non-existent hashes, producing ghost entries or errors.
    """
    created = await _create_token(authenticated_client, name="index-cleanup-check")
    token_id = created["id"]

    await authenticated_client.delete(f"/api/v1/tokens/{token_id}")

    is_member = await fake_redis.sismember("mgmt:token:idx", token_id)
    assert (
        not is_member
    ), f"Expected {token_id} removed from mgmt:token:idx after deletion"


# ── Security property tests ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bcrypt_hash_stored_not_plaintext(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """The stored hash is a real bcrypt digest, not the plaintext token.

    Guards against an implementation that stores the raw token as the 'hash' field.
    bcrypt digests start with $2b$ or $2a$.
    """
    created = await _create_token(authenticated_client, name="bcrypt-format-check")
    fields = await fake_redis.hgetall(f"mgmt:token:{created['id']}")
    stored_hash = fields.get("hash", "")
    assert stored_hash.startswith(("$2b$", "$2a$")), (
        f"Stored hash does not look like a bcrypt digest: {stored_hash!r}. "
        "Implementation may be storing the plaintext token."
    )
    assert (
        stored_hash != created["token"]
    ), "Stored 'hash' is identical to the plaintext token — no hashing was done."


@pytest.mark.asyncio
async def test_bearer_hash_must_match(fake_redis) -> None:
    """A token whose hash doesn't match the presented credential is rejected.

    Guards against an implementation that accepts any token whose ID exists in
    Redis without actually verifying the bcrypt hash.
    """
    import datetime as _dt
    import uuid

    import bcrypt
    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    wrong_token = "wrong-secret-that-does-not-match-the-stored-hash-xxxxx"
    correct_secret = "correct-secret-long-enough-to-be-a-real-token-xxxxx"
    correct_hash = bcrypt.hashpw(correct_secret.encode(), bcrypt.gensalt()).decode()

    token_id = str(uuid.uuid4())
    await fake_redis.hset(
        f"mgmt:token:{token_id}",
        mapping={
            "id": token_id,
            "name": "hash-mismatch-test",
            "role": "operator",
            "hash": correct_hash,
            "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "expires_at": "",
            "last_used_at": "",
        },
    )
    await fake_redis.sadd("mgmt:token:idx", token_id)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {wrong_token}",
                "Accept": "application/json",
            },
        )
        assert r.status_code == 401, (
            "Token with non-matching hash must be rejected; got 200. "
            "Implementation may not be calling bcrypt.verify()."
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_last_used_at_updated_on_bearer_auth(fake_redis) -> None:
    """last_used_at in the Redis hash is updated when a bearer token authenticates.

    Without this, operators cannot tell if an old API token is still in active use.
    """
    from datetime import datetime, timezone

    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        created = await _create_token(admin_client, name="last-used-check")
        plaintext = created["token"]
        token_id = created["id"]

    fields_before = await fake_redis.hgetall(f"mgmt:token:{token_id}")
    last_used_before = fields_before.get("last_used_at", "")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext}",
                "Accept": "application/json",
            },
        )
        assert r.status_code == 200

    fields_after = await fake_redis.hgetall(f"mgmt:token:{token_id}")
    last_used_after = fields_after.get("last_used_at", "")

    assert last_used_after, "last_used_at must be set after a successful bearer auth"
    assert (
        last_used_after != last_used_before
    ), f"last_used_at not updated. Before: {last_used_before!r}, After: {last_used_after!r}"
    used_dt = datetime.fromisoformat(last_used_after)
    age_seconds = (datetime.now(timezone.utc) - used_dt).total_seconds()
    assert age_seconds < 5, f"last_used_at ({last_used_after}) is not recent"

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_rotate_token_old_token_works_during_grace_period(fake_redis) -> None:
    """The old token remains usable for Bearer auth during the rotation grace period.

    A TTL being set is necessary but not sufficient — the middleware must also
    actually accept the old credential while its key has a TTL > 0.
    """
    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        created = await _create_token(admin_client, name="grace-period-auth")
        old_plaintext = created["token"]
        old_id = created["id"]
        await admin_client.post(f"/api/v1/tokens/{old_id}/rotate")

    ttl = await fake_redis.ttl(f"mgmt:token:{old_id}")
    assert ttl > 0, "Old token key has no TTL; grace period not configured"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {old_plaintext}",
                "Accept": "application/json",
            },
        )
        assert r.status_code == 200, (
            f"Old bearer token must still work during grace period (TTL={ttl}s); "
            f"got {r.status_code}. Middleware may not accept grace-period keys."
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_two_tokens_authenticate_independently(fake_redis) -> None:
    """Two tokens with different IDs both authenticate correctly and independently.

    Guards against a stub that hardcodes one token, or an implementation where
    the lookup mechanism only works for a single token at a time.
    Revoking token A must not affect token B.
    """
    from httpx import ASGITransport

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        token_a = await _create_token(admin_client, name="token-a", role="auditor")
        token_b = await _create_token(admin_client, name="token-b", role="operator")

    plaintext_a = token_a["token"]
    plaintext_b = token_b["token"]

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r_a = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext_a}",
                "Accept": "application/json",
            },
        )
        r_b = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext_b}",
                "Accept": "application/json",
            },
        )
        assert r_a.status_code == 200, f"Token A failed: {r_a.status_code}"
        assert r_b.status_code == 200, f"Token B failed: {r_b.status_code}"

    # Revoke token A; token B must still work
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        await admin_client.delete(f"/api/v1/tokens/{token_a['id']}")

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as anon_client:
        r_a_after = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext_a}",
                "Accept": "application/json",
            },
        )
        r_b_after = await anon_client.get(
            "/api/v1/dial",
            headers={
                "Authorization": f"Bearer {plaintext_b}",
                "Accept": "application/json",
            },
        )
        assert r_a_after.status_code == 401, "Revoked token A must not authenticate"
        assert r_b_after.status_code == 200, "Unrevoked token B must still authenticate"

    await _redis_module.close_redis()
