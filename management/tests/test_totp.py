"""TDD tests for Phase 79 Cluster 6 — TOTP MFA.

Covers
------
Section 1: Setup endpoint (GET /auth/mfa/totp/setup)
  - Returns 200 with QR code PNG (base64-encoded) and 8 backup codes
  - Stores Fernet-encrypted TOTP secret in mgmt:totp:{user_id}
  - Backup codes stored bcrypt-hashed in mgmt:totp:backup:{user_id} LIST
  - Idempotent: second call regenerates secret and backup codes (rotation)
  - Requires authentication (401 without credentials)

Section 2: Verify endpoint (POST /auth/mfa/totp/verify)
  - Valid current TOTP code → 200 {"verified": true}
  - Wrong TOTP code → 401
  - No TOTP enrolled → 404
  - Requires authentication (401 without credentials)

Section 3: Backup code flow
  - Valid backup code passes verify → 200 {"verified": true, "backup_code_used": true}
  - Each backup code is single-use: second use of the same code → 401
  - Exhausted (all 8 used) → 401
  - Backup code attempt does not reveal remaining count in the 401 body

Section 4: Fernet encryption
  - Secret stored in Redis is NOT the raw base32 TOTP secret
  - Decrypted value IS a valid base32 TOTP secret (pyotp.TOTP can use it)
  - Wrong encryption key env var → setup returns 500 (key misconfiguration caught)

Section 5: MFA enforcement gate (Admin/Operator cannot skip)
  - Enrolled user who has NOT verified TOTP in this session gets 403 on
    protected Admin-role endpoints until they POST /auth/mfa/totp/verify
  - After verification the 403 becomes 200
  NOTE: Session-level MFA state is tracked via a short-lived Redis key
  mgmt:mfa:session:{session_token_hash} → "verified", TTL = 8h

All tests use fakeredis for Redis isolation.
Tests are written to FAIL against the current codebase (no TOTP routes exist yet).
"""

from __future__ import annotations

import base64
import os
from typing import AsyncGenerator

import bcrypt as _bcrypt
import fakeredis.aioredis
import pyotp
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

# Env vars before any management import
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

_TEST_FERNET_KEY = Fernet.generate_key().decode()
os.environ["MANAGEMENT_MFA_ENCRYPTION_KEY"] = _TEST_FERNET_KEY

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import _create_access_token  # noqa: E402
from management.api.main import create_app  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    """Isolated FakeRedis instance — each test gets a clean slate."""
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def admin_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Authenticated AsyncClient with admin cookie JWT."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    cookie = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookie,
    ) as client:
        yield client
    await _redis_module.close_redis()


# ── Section 1: Setup endpoint ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_totp_setup_returns_200(
    admin_client: AsyncClient,
) -> None:
    """GET /auth/mfa/totp/setup returns 200 for an authenticated user."""
    r = await admin_client.get("/auth/mfa/totp/setup")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_totp_setup_returns_qr_code(
    admin_client: AsyncClient,
) -> None:
    """GET /auth/mfa/totp/setup returns a base64-encoded PNG QR code."""
    r = await admin_client.get("/auth/mfa/totp/setup")
    assert r.status_code == 200
    data = r.json()
    assert "qr_code" in data, f"Response missing 'qr_code' field: {data}"

    # Must be valid base64
    try:
        raw = base64.b64decode(data["qr_code"])
    except Exception as exc:
        pytest.fail(f"qr_code is not valid base64: {exc}")

    # Must be a PNG (magic bytes: 0x89 0x50 0x4E 0x47)
    assert raw[:4] == b"\x89PNG", (
        f"qr_code bytes do not start with PNG magic: {raw[:8]!r}"
    )


@pytest.mark.asyncio
async def test_totp_setup_returns_backup_codes(
    admin_client: AsyncClient,
) -> None:
    """GET /auth/mfa/totp/setup returns exactly 8 backup codes."""
    r = await admin_client.get("/auth/mfa/totp/setup")
    assert r.status_code == 200
    data = r.json()
    assert "backup_codes" in data, f"Response missing 'backup_codes': {data}"
    codes = data["backup_codes"]
    assert isinstance(codes, list), f"backup_codes must be a list, got {type(codes)}"
    assert len(codes) == 8, f"Expected 8 backup codes, got {len(codes)}"
    # Each code must be a non-empty string
    for code in codes:
        assert isinstance(code, str) and len(code) >= 6, (
            f"Backup code too short or wrong type: {code!r}"
        )
    # All codes must be unique
    assert len(set(codes)) == 8, "Backup codes are not all unique"


@pytest.mark.asyncio
async def test_totp_setup_stores_encrypted_secret(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/mfa/totp/setup stores a Fernet-encrypted secret in mgmt:totp:{user_id}."""
    r = await admin_client.get("/auth/mfa/totp/setup")
    assert r.status_code == 200

    # The admin user ID is "admin" (from _create_access_token("admin"))
    stored = await fake_redis.get("mgmt:totp:admin")
    assert stored is not None, "Expected mgmt:totp:admin to be set in Redis"

    # Stored value must NOT be a raw base32 string
    # (raw pyotp secrets are 16–32 uppercase base32 chars)
    is_raw_base32 = stored.isupper() and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in stored)
    assert not is_raw_base32, (
        f"Secret appears to be stored unencrypted (raw base32): {stored!r}"
    )

    # Must decrypt to a valid TOTP secret
    fernet = Fernet(_TEST_FERNET_KEY.encode())
    decrypted = fernet.decrypt(stored.encode()).decode()
    # pyotp.TOTP should not raise on a valid base32 secret
    try:
        totp = pyotp.TOTP(decrypted)
        _ = totp.now()  # generates a valid code — raises if secret is malformed
    except Exception as exc:
        pytest.fail(f"Decrypted secret is not a valid TOTP secret: {exc}")


@pytest.mark.asyncio
async def test_totp_setup_stores_hashed_backup_codes(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/mfa/totp/setup stores bcrypt-hashed backup codes in Redis."""
    r = await admin_client.get("/auth/mfa/totp/setup")
    assert r.status_code == 200
    plaintext_codes = r.json()["backup_codes"]

    stored_hashes = await fake_redis.lrange("mgmt:totp:backup:admin", 0, -1)
    assert len(stored_hashes) == 8, (
        f"Expected 8 backup code hashes in Redis, got {len(stored_hashes)}"
    )

    # Each returned plaintext code must bcrypt-match exactly one stored hash
    for code in plaintext_codes:
        matched = any(
            _bcrypt.checkpw(code.encode(), h.encode())
            for h in stored_hashes
        )
        assert matched, (
            f"Plaintext backup code {code!r} does not match any stored hash"
        )


@pytest.mark.asyncio
async def test_totp_setup_requires_auth(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/mfa/totp/setup without authentication returns 401."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.get(
            "/auth/mfa/totp/setup",
            headers={"Accept": "application/json"},
        )
    await _redis_module.close_redis()
    assert r.status_code == 401, f"Expected 401 without auth, got {r.status_code}"


@pytest.mark.asyncio
async def test_totp_setup_is_idempotent_but_rotates(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Calling setup twice generates a new secret and new backup codes."""
    r1 = await admin_client.get("/auth/mfa/totp/setup")
    assert r1.status_code == 200
    codes1 = set(r1.json()["backup_codes"])
    secret1 = await fake_redis.get("mgmt:totp:admin")

    r2 = await admin_client.get("/auth/mfa/totp/setup")
    assert r2.status_code == 200
    codes2 = set(r2.json()["backup_codes"])
    secret2 = await fake_redis.get("mgmt:totp:admin")

    assert secret1 != secret2, "Second setup call should rotate the TOTP secret"
    assert codes1 != codes2, "Second setup call should generate new backup codes"


# ── Section 2: Verify endpoint ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_totp_verify_valid_code_returns_200(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/mfa/totp/verify with a valid TOTP code returns 200 {"verified": true}."""
    # First enroll
    r_setup = await admin_client.get("/auth/mfa/totp/setup")
    assert r_setup.status_code == 200

    # Retrieve and decrypt the stored secret to generate a valid code
    stored = await fake_redis.get("mgmt:totp:admin")
    fernet = Fernet(_TEST_FERNET_KEY.encode())
    secret = fernet.decrypt(stored.encode()).decode()
    valid_code = pyotp.TOTP(secret).now()

    r = await admin_client.post(
        "/auth/mfa/totp/verify",
        json={"code": valid_code},
    )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    assert r.json().get("verified") is True, (
        f"Expected {{\"verified\": true}}, got {r.json()}"
    )


@pytest.mark.asyncio
async def test_totp_verify_wrong_code_returns_401(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/mfa/totp/verify with an incorrect code returns 401."""
    await admin_client.get("/auth/mfa/totp/setup")

    r = await admin_client.post(
        "/auth/mfa/totp/verify",
        json={"code": "000000"},
    )
    assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_totp_verify_not_enrolled_returns_404(
    admin_client: AsyncClient,
) -> None:
    """POST /auth/mfa/totp/verify when TOTP not enrolled returns 404."""
    # No setup called — mgmt:totp:admin does not exist
    r = await admin_client.post(
        "/auth/mfa/totp/verify",
        json={"code": "123456"},
    )
    assert r.status_code == 404, (
        f"Expected 404 when not enrolled, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio
async def test_totp_verify_requires_auth(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/mfa/totp/verify without authentication returns 401."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.post(
            "/auth/mfa/totp/verify",
            json={"code": "123456"},
            headers={"Accept": "application/json"},
        )
    await _redis_module.close_redis()
    assert r.status_code == 401, f"Expected 401 without auth, got {r.status_code}"


# ── Section 3: Backup code flow ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_backup_code_valid_returns_200(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A valid backup code passed to /auth/mfa/totp/verify returns 200."""
    r_setup = await admin_client.get("/auth/mfa/totp/setup")
    assert r_setup.status_code == 200
    backup_code = r_setup.json()["backup_codes"][0]

    r = await admin_client.post(
        "/auth/mfa/totp/verify",
        json={"code": backup_code},
    )
    assert r.status_code == 200, f"Expected 200 for backup code, got {r.status_code}: {r.text}"
    body = r.json()
    assert body.get("verified") is True
    assert body.get("backup_code_used") is True, (
        f"Expected backup_code_used=true, got {body}"
    )


@pytest.mark.asyncio
async def test_backup_code_is_single_use(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A backup code returns 401 on second use (even if first use was successful)."""
    r_setup = await admin_client.get("/auth/mfa/totp/setup")
    backup_code = r_setup.json()["backup_codes"][0]

    # First use — must succeed
    r1 = await admin_client.post(
        "/auth/mfa/totp/verify",
        json={"code": backup_code},
    )
    assert r1.status_code == 200, f"First use failed: {r1.status_code}"

    # Second use of the SAME code must fail
    r2 = await admin_client.post(
        "/auth/mfa/totp/verify",
        json={"code": backup_code},
    )
    assert r2.status_code == 401, (
        f"Second use of same backup code should be 401, got {r2.status_code}"
    )


@pytest.mark.asyncio
async def test_backup_code_failure_does_not_reveal_count(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """401 response from failed backup code does not reveal remaining code count."""
    await admin_client.get("/auth/mfa/totp/setup")

    r = await admin_client.post(
        "/auth/mfa/totp/verify",
        json={"code": "INVALID-BACKUP-CODE"},
    )
    assert r.status_code in (401, 404), (
        f"Expected 401 or 404, got {r.status_code}"
    )
    body_text = r.text.lower()
    # Must not mention how many codes remain — "remaining" is the tell
    assert "remaining" not in body_text, (
        f"Response reveals remaining backup code count: {r.text!r}"
    )


@pytest.mark.asyncio
async def test_used_backup_code_removed_from_redis(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """After a backup code is used, the corresponding hash is removed from Redis."""
    r_setup = await admin_client.get("/auth/mfa/totp/setup")
    backup_code = r_setup.json()["backup_codes"][0]

    hashes_before = await fake_redis.lrange("mgmt:totp:backup:admin", 0, -1)
    assert len(hashes_before) == 8

    r = await admin_client.post("/auth/mfa/totp/verify", json={"code": backup_code})
    assert r.status_code == 200

    hashes_after = await fake_redis.lrange("mgmt:totp:backup:admin", 0, -1)
    assert len(hashes_after) == 7, (
        f"Expected 7 backup hashes after use, got {len(hashes_after)}"
    )


# ── Section 4: Fernet encryption ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_stored_secret_is_not_plaintext(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The value stored at mgmt:totp:{user} is not a raw pyotp base32 secret."""
    await admin_client.get("/auth/mfa/totp/setup")
    stored = await fake_redis.get("mgmt:totp:admin")
    assert stored is not None

    # Fernet tokens always start with "gAAAAA" (base64url-encoded version byte + timestamp).
    # A raw pyotp secret or base64-encoded secret would not have this prefix.
    assert stored.startswith("gAAAAA"), (
        f"Stored value is not a Fernet token (expected 'gAAAAA' prefix): {stored!r}"
    )


@pytest.mark.asyncio
async def test_fernet_decryption_yields_valid_totp_secret(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Fernet-decrypting mgmt:totp:{user} yields a secret that pyotp.TOTP accepts."""
    await admin_client.get("/auth/mfa/totp/setup")
    stored = await fake_redis.get("mgmt:totp:admin")

    fernet = Fernet(_TEST_FERNET_KEY.encode())
    decrypted = fernet.decrypt(stored.encode()).decode()

    # Must not raise and must generate a 6-digit string
    code = pyotp.TOTP(decrypted).now()
    assert code.isdigit() and len(code) == 6, (
        f"Decrypted TOTP secret yields malformed code: {code!r}"
    )


@pytest.mark.asyncio
async def test_totp_setup_fails_without_encryption_key(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/mfa/totp/setup returns 500 when MANAGEMENT_MFA_ENCRYPTION_KEY is unset."""
    original = os.environ.pop("MANAGEMENT_MFA_ENCRYPTION_KEY", None)
    try:
        app = create_app()
        await _redis_module.init_redis(override_client=fake_redis)
        cookie = {"token": _create_access_token("admin")}
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            cookies=cookie,
        ) as client:
            r = await client.get("/auth/mfa/totp/setup")
        await _redis_module.close_redis()
        assert r.status_code == 500, (
            f"Expected 500 without encryption key, got {r.status_code}: {r.text}"
        )
    finally:
        # Restore so other tests are not affected
        if original is not None:
            os.environ["MANAGEMENT_MFA_ENCRYPTION_KEY"] = original
        else:
            os.environ["MANAGEMENT_MFA_ENCRYPTION_KEY"] = _TEST_FERNET_KEY


# ── Section 5: MFA session enforcement ───────────────────────────────────────
#
# The session enforcement gate uses a short-lived Redis key:
#   mgmt:mfa:session:{sha256(jwt_token)} → "verified", TTL=8h
#
# Cookie-JWT users (browser) must complete TOTP verify before accessing
# Admin-role write endpoints (PATCH /api/v1/dial as representative example).
#
# Bearer-token users (API clients) are exempt: they authenticate via
# long-lived scoped tokens issued after TOTP enrollment. The MFA gate
# applies only to the interactive cookie-JWT login flow.


@pytest.mark.asyncio
async def test_admin_without_mfa_cannot_change_dial(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Admin cookie-JWT user who hasn't completed TOTP gets 403 on write endpoints."""
    # Enroll TOTP (setup) but do NOT call verify
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    jwt_token = _create_access_token("admin")
    cookie = {"token": jwt_token}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookie,
    ) as client:
        # Enroll
        r_setup = await client.get("/auth/mfa/totp/setup")
        assert r_setup.status_code == 200, "Setup failed"

        # Attempt write without MFA verification
        r = await client.put("/api/v1/dial", json={"value": 1})
        assert r.status_code == 403, (
            f"Expected 403 (MFA not verified) for dial change, got {r.status_code}: {r.text}"
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_admin_after_mfa_can_change_dial(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Admin who completes TOTP verify can then access write endpoints."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    jwt_token = _create_access_token("admin")
    cookie = {"token": jwt_token}

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=cookie,
    ) as client:
        # Enroll
        r_setup = await client.get("/auth/mfa/totp/setup")
        assert r_setup.status_code == 200

        # Generate valid code
        stored = await fake_redis.get("mgmt:totp:admin")
        fernet = Fernet(_TEST_FERNET_KEY.encode())
        secret = fernet.decrypt(stored.encode()).decode()
        valid_code = pyotp.TOTP(secret).now()

        # Verify MFA
        r_verify = await client.post("/auth/mfa/totp/verify", json={"code": valid_code})
        assert r_verify.status_code == 200, f"Verify failed: {r_verify.text}"

        # Should now be able to change dial
        r = await client.put("/api/v1/dial", json={"value": 1})
        assert r.status_code == 200, (
            f"Expected 200 after MFA verified, got {r.status_code}: {r.text}"
        )

    await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_bearer_token_user_not_subject_to_mfa_gate(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Bearer-token (API) users bypass the cookie-JWT MFA gate entirely."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    # Create an admin bearer token
    admin_cookie = {"token": _create_access_token("admin")}
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies=admin_cookie,
    ) as admin:
        r_token = await admin.post(
            "/api/v1/tokens",
            json={"name": "mfa-bypass-test", "role": "admin"},
        )
        assert r_token.status_code == 201
        bearer = r_token.json()["token"]

    # Use the bearer token on a cookie-free client — no TOTP enrolled, no verify
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        r = await client.put(
            "/api/v1/dial",
            json={"value": 1},
            headers={"Authorization": f"Bearer {bearer}"},
        )
        assert r.status_code == 200, (
            f"Bearer-token user should not be blocked by MFA gate, got {r.status_code}: {r.text}"
        )

    await _redis_module.close_redis()
