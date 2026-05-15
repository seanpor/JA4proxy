"""TDD tests for MFA/SSO Hardening Cluster 7 — WebAuthn/FIDO2 MFA.

Covers
------
Section 1: Registration begin (POST /auth/mfa/webauthn/register/begin)
  - Returns 200 with challenge options JSON (rp, user, challenge, pubKeyCredParams)
  - Stores challenge in Redis with 5-min TTL
  - Requires authentication (401 without credentials)

Section 2: Registration complete (POST /auth/mfa/webauthn/register/complete)
  - Valid attestation → 201, credential stored in Redis hash + user credential SET
  - No prior challenge (begin not called) → 400
  - Verification failure (bad attestation) → 400

Section 3: Authentication begin (POST /auth/mfa/webauthn/auth/begin)
  - Returns 200 with challenge JSON including allowCredentials for enrolled keys
  - No credentials enrolled → 404
  - Requires authentication (401 without credentials)

Section 4: Authentication complete (POST /auth/mfa/webauthn/auth/complete)
  - Valid assertion → 200 {"verified": true}, MFA session key set in Redis
  - No prior challenge (begin not called) → 400
  - Credential not found in Redis → 404
  - Assertion verification failure → 401
  - sign_count updated to new_sign_count after successful auth

Section 5: Credential management
  - User can have multiple credentials; register/begin excludes them from allowCredentials
  - Credential hash contains expected fields: user_id, public_key, sign_count, created_at

All tests use fakeredis for Redis isolation.
verify_registration_response and verify_authentication_response are mocked to avoid
requiring a real FIDO2 authenticator in CI.
"""

from __future__ import annotations

import json
import os
from typing import AsyncGenerator
from unittest.mock import patch

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationFormat,
    CredentialDeviceType,
    PublicKeyCredentialType,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration

# Env vars before any management import
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
os.environ.setdefault("MANAGEMENT_WEBAUTHN_RP_ID", "localhost")
os.environ.setdefault("MANAGEMENT_WEBAUTHN_ORIGIN", "http://localhost:8090")

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.auth import _create_access_token  # noqa: E402
from management.api.main import create_app  # noqa: E402

# ── Shared test fixtures / constants ─────────────────────────────────────────

_FAKE_CRED_ID = b"fake-credential-id-01"
_FAKE_CRED_ID_B64 = bytes_to_base64url(_FAKE_CRED_ID)
_FAKE_PUBLIC_KEY = b"fake-public-key-bytes-01"
_FAKE_PUBLIC_KEY_B64 = bytes_to_base64url(_FAKE_PUBLIC_KEY)

_FAKE_CRED_ID_2 = b"fake-credential-id-02"
_FAKE_CRED_ID_B64_2 = bytes_to_base64url(_FAKE_CRED_ID_2)


def _make_verified_registration(
    cred_id: bytes = _FAKE_CRED_ID,
    pub_key: bytes = _FAKE_PUBLIC_KEY,
) -> VerifiedRegistration:
    return VerifiedRegistration(
        credential_id=cred_id,
        credential_public_key=pub_key,
        sign_count=0,
        aaguid="00000000-0000-0000-0000-000000000000",
        fmt=AttestationFormat.NONE,
        credential_type=PublicKeyCredentialType.PUBLIC_KEY,
        user_verified=True,
        attestation_object=b"",
        credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
        credential_backed_up=False,
    )


def _make_verified_authentication(
    cred_id: bytes = _FAKE_CRED_ID,
    new_sign_count: int = 1,
) -> VerifiedAuthentication:
    return VerifiedAuthentication(
        credential_id=cred_id,
        new_sign_count=new_sign_count,
        credential_device_type=CredentialDeviceType.SINGLE_DEVICE,
        credential_backed_up=False,
        user_verified=True,
    )


async def _seed_credential(
    fake_redis: fakeredis.aioredis.FakeRedis,
    user_id: str = "admin",
    cred_id_b64: str = _FAKE_CRED_ID_B64,
    pub_key_b64: str = _FAKE_PUBLIC_KEY_B64,
    sign_count: int = 0,
) -> None:
    """Directly write a credential into Redis (simulates completed registration)."""
    await fake_redis.hset(
        f"mgmt:webauthn:credential:{cred_id_b64}",
        mapping={
            "user_id": user_id,
            "public_key": pub_key_b64,
            "sign_count": str(sign_count),
            "created_at": "2026-04-07T00:00:00+00:00",
        },
    )
    await fake_redis.sadd(f"mgmt:webauthn:user:{user_id}:credentials", cred_id_b64)


async def _seed_auth_challenge(
    fake_redis: fakeredis.aioredis.FakeRedis,
    user_id: str = "admin",
    challenge: bytes = b"test-auth-challenge",
) -> None:
    """Directly write an auth challenge into Redis (simulates auth/begin)."""
    await fake_redis.set(
        f"mgmt:webauthn:challenge:{user_id}",
        json.dumps(
            {"challenge": bytes_to_base64url(challenge), "type": "authentication"}
        ),
        ex=300,
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def admin_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
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


# ── Section 1: Registration begin ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_webauthn_register_begin_returns_200(
    admin_client: AsyncClient,
) -> None:
    """POST /auth/mfa/webauthn/register/begin returns 200 for an authenticated user."""
    r = await admin_client.post("/auth/mfa/webauthn/register/begin")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_webauthn_register_begin_returns_challenge_json(
    admin_client: AsyncClient,
) -> None:
    """Response contains rp, user, challenge, and pubKeyCredParams fields."""
    r = await admin_client.post("/auth/mfa/webauthn/register/begin")
    assert r.status_code == 200
    data = r.json()
    assert "challenge" in data, f"Missing 'challenge' in response: {data.keys()}"
    assert "rp" in data, f"Missing 'rp' in response: {data.keys()}"
    assert "user" in data, f"Missing 'user' in response: {data.keys()}"
    assert "pubKeyCredParams" in data, f"Missing 'pubKeyCredParams': {data.keys()}"


@pytest.mark.asyncio
async def test_webauthn_register_begin_stores_challenge_in_redis(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """register/begin stores a challenge in mgmt:webauthn:challenge:admin."""
    r = await admin_client.post("/auth/mfa/webauthn/register/begin")
    assert r.status_code == 200

    stored_raw = await fake_redis.get("mgmt:webauthn:challenge:admin")
    assert stored_raw is not None, "Expected mgmt:webauthn:challenge:admin to be set"
    stored = json.loads(stored_raw)
    assert stored.get("type") == "registration", f"Challenge type wrong: {stored}"
    assert "challenge" in stored, f"Challenge value missing from stored data: {stored}"


@pytest.mark.asyncio
async def test_webauthn_register_begin_challenge_has_ttl(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Challenge key has a TTL (5-minute maximum)."""
    await admin_client.post("/auth/mfa/webauthn/register/begin")
    ttl = await fake_redis.ttl("mgmt:webauthn:challenge:admin")
    assert 0 < ttl <= 300, f"Challenge TTL should be 0 < TTL <= 300, got {ttl}"


@pytest.mark.asyncio
async def test_webauthn_register_begin_requires_auth(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/mfa/webauthn/register/begin without auth returns 401."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.post(
            "/auth/mfa/webauthn/register/begin",
            headers={"Accept": "application/json"},
        )
    await _redis_module.close_redis()
    assert r.status_code == 401, f"Expected 401 without auth, got {r.status_code}"


# ── Section 2: Registration complete ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_webauthn_register_complete_valid_returns_201(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """register/complete with a valid (mocked) attestation returns 201."""
    # Begin first (stores challenge)
    r_begin = await admin_client.post("/auth/mfa/webauthn/register/begin")
    assert r_begin.status_code == 200

    with patch(
        "management.api.routes.webauthn.webauthn.verify_registration_response",
        return_value=_make_verified_registration(),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/register/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert r.status_code == 201, f"Expected 201, got {r.status_code}: {r.text}"
    assert r.json().get("registered") is True


@pytest.mark.asyncio
async def test_webauthn_register_complete_stores_credential(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """After register/complete, credential hash and user SET are in Redis."""
    await admin_client.post("/auth/mfa/webauthn/register/begin")

    with patch(
        "management.api.routes.webauthn.webauthn.verify_registration_response",
        return_value=_make_verified_registration(),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/register/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert r.status_code == 201

    # Credential hash must exist
    cred = await fake_redis.hgetall(f"mgmt:webauthn:credential:{_FAKE_CRED_ID_B64}")
    assert cred, f"Credential hash not found in Redis for id {_FAKE_CRED_ID_B64!r}"
    assert cred.get("user_id") == "admin"
    assert cred.get("sign_count") == "0"
    assert "public_key" in cred
    assert "created_at" in cred

    # User SET must contain the credential ID
    members = await fake_redis.smembers("mgmt:webauthn:user:admin:credentials")
    assert (
        _FAKE_CRED_ID_B64 in members
    ), f"Credential ID not found in user SET. Members: {members}"


@pytest.mark.asyncio
async def test_webauthn_register_complete_no_challenge_returns_400(
    admin_client: AsyncClient,
) -> None:
    """register/complete without calling begin first returns 400."""
    with patch(
        "management.api.routes.webauthn.webauthn.verify_registration_response",
        return_value=_make_verified_registration(),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/register/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert (
        r.status_code == 400
    ), f"Expected 400 with no challenge, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_webauthn_register_complete_verification_failure_returns_400(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """register/complete returns 400 when attestation verification raises."""
    await admin_client.post("/auth/mfa/webauthn/register/begin")

    with patch(
        "management.api.routes.webauthn.webauthn.verify_registration_response",
        side_effect=Exception("Invalid attestation"),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/register/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert (
        r.status_code == 400
    ), f"Expected 400 on verification failure, got {r.status_code}"


# ── Section 3: Authentication begin ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_webauthn_auth_begin_returns_200(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/begin returns 200 when at least one credential is enrolled."""
    await _seed_credential(fake_redis)
    r = await admin_client.post("/auth/mfa/webauthn/auth/begin")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_webauthn_auth_begin_returns_challenge_with_credentials(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/begin response has challenge and allowCredentials for enrolled keys."""
    await _seed_credential(fake_redis)
    r = await admin_client.post("/auth/mfa/webauthn/auth/begin")
    assert r.status_code == 200
    data = r.json()
    assert "challenge" in data, f"Missing 'challenge': {data.keys()}"
    assert "allowCredentials" in data, f"Missing 'allowCredentials': {data.keys()}"
    creds = data["allowCredentials"]
    assert len(creds) >= 1, f"Expected at least one allowCredential, got {creds}"


@pytest.mark.asyncio
async def test_webauthn_auth_begin_no_credentials_returns_404(
    admin_client: AsyncClient,
) -> None:
    """auth/begin returns 404 when no credentials are enrolled."""
    r = await admin_client.post("/auth/mfa/webauthn/auth/begin")
    assert (
        r.status_code == 404
    ), f"Expected 404 with no credentials, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_webauthn_auth_begin_requires_auth(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/mfa/webauthn/auth/begin without auth returns 401."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        r = await client.post(
            "/auth/mfa/webauthn/auth/begin",
            headers={"Accept": "application/json"},
        )
    await _redis_module.close_redis()
    assert r.status_code == 401, f"Expected 401 without auth, got {r.status_code}"


# ── Section 4: Authentication complete ───────────────────────────────────────


@pytest.mark.asyncio
async def test_webauthn_auth_complete_valid_returns_200(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/complete with valid (mocked) assertion returns 200 {"verified": true}."""
    await _seed_credential(fake_redis)
    await _seed_auth_challenge(fake_redis)

    with patch(
        "management.api.routes.webauthn.webauthn.verify_authentication_response",
        return_value=_make_verified_authentication(),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/auth/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    assert r.json().get("verified") is True


@pytest.mark.asyncio
async def test_webauthn_auth_complete_sets_mfa_session(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/complete sets mgmt:mfa:session:{sha256(jwt)} in Redis."""
    await _seed_credential(fake_redis)
    await _seed_auth_challenge(fake_redis)

    with patch(
        "management.api.routes.webauthn.webauthn.verify_authentication_response",
        return_value=_make_verified_authentication(),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/auth/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert r.status_code == 200

    # MFA session key must be set (pattern: mgmt:mfa:session:*)
    keys = await fake_redis.keys("mgmt:mfa:session:*")
    assert len(keys) >= 1, f"Expected at least one MFA session key, found: {keys}"
    val = await fake_redis.get(keys[0])
    assert val == "verified", f"Expected 'verified', got {val!r}"


@pytest.mark.asyncio
async def test_webauthn_auth_complete_updates_sign_count(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/complete updates the credential sign_count to new_sign_count."""
    await _seed_credential(fake_redis, sign_count=0)
    await _seed_auth_challenge(fake_redis)

    with patch(
        "management.api.routes.webauthn.webauthn.verify_authentication_response",
        return_value=_make_verified_authentication(new_sign_count=5),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/auth/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert r.status_code == 200

    updated = await fake_redis.hget(
        f"mgmt:webauthn:credential:{_FAKE_CRED_ID_B64}", "sign_count"
    )
    assert updated == "5", f"Expected sign_count='5', got {updated!r}"


@pytest.mark.asyncio
async def test_webauthn_auth_complete_no_challenge_returns_400(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/complete without calling auth/begin first returns 400."""
    await _seed_credential(fake_redis)

    with patch(
        "management.api.routes.webauthn.webauthn.verify_authentication_response",
        return_value=_make_verified_authentication(),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/auth/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert (
        r.status_code == 400
    ), f"Expected 400 with no challenge, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_webauthn_auth_complete_unknown_credential_returns_404(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/complete with an unregistered credential ID returns 404."""
    await _seed_auth_challenge(fake_redis)

    r = await admin_client.post(
        "/auth/mfa/webauthn/auth/complete",
        json={"id": "dW5rbm93bi1jcmVk", "type": "public-key"},
    )
    assert (
        r.status_code == 404
    ), f"Expected 404 for unknown credential, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_webauthn_auth_complete_verification_failure_returns_401(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/complete returns 401 when assertion verification raises."""
    await _seed_credential(fake_redis)
    await _seed_auth_challenge(fake_redis)

    with patch(
        "management.api.routes.webauthn.webauthn.verify_authentication_response",
        side_effect=Exception("Invalid assertion"),
    ):
        r = await admin_client.post(
            "/auth/mfa/webauthn/auth/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert (
        r.status_code == 401
    ), f"Expected 401 on verification failure, got {r.status_code}"


# ── Section 5: Credential management ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_webauthn_user_can_have_multiple_credentials(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A user can register multiple WebAuthn credentials."""
    # Register credential 1
    await admin_client.post("/auth/mfa/webauthn/register/begin")
    with patch(
        "management.api.routes.webauthn.webauthn.verify_registration_response",
        return_value=_make_verified_registration(cred_id=_FAKE_CRED_ID),
    ):
        r1 = await admin_client.post(
            "/auth/mfa/webauthn/register/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    assert r1.status_code == 201

    # Register credential 2
    await admin_client.post("/auth/mfa/webauthn/register/begin")
    with patch(
        "management.api.routes.webauthn.webauthn.verify_registration_response",
        return_value=_make_verified_registration(
            cred_id=_FAKE_CRED_ID_2,
            pub_key=b"fake-public-key-bytes-02",
        ),
    ):
        r2 = await admin_client.post(
            "/auth/mfa/webauthn/register/complete",
            json={"id": _FAKE_CRED_ID_B64_2, "type": "public-key"},
        )
    assert r2.status_code == 201

    members = await fake_redis.smembers("mgmt:webauthn:user:admin:credentials")
    assert len(members) == 2, f"Expected 2 credentials, got {len(members)}: {members}"


@pytest.mark.asyncio
async def test_webauthn_register_begin_excludes_existing_credentials(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """register/begin includes excludeCredentials listing already-registered keys."""
    await _seed_credential(fake_redis)
    r = await admin_client.post("/auth/mfa/webauthn/register/begin")
    assert r.status_code == 200
    data = r.json()
    # excludeCredentials must be present and list the seeded credential
    exclude = data.get("excludeCredentials", [])
    assert (
        len(exclude) >= 1
    ), f"Expected excludeCredentials to list existing credential, got {exclude!r}"


@pytest.mark.asyncio
async def test_webauthn_auth_complete_wrong_user_credential_returns_403(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """auth/complete returns 403 when the credential belongs to a different user.

    This verifies the ownership check in webauthn_auth_complete: user A cannot
    authenticate with a credential registered to user B.
    """
    # Seed credential owned by "other-user", not "admin"
    await _seed_credential(
        fake_redis, user_id="other-user", cred_id_b64=_FAKE_CRED_ID_B64
    )
    # Seed auth challenge for "admin" (the authenticated caller)
    await _seed_auth_challenge(fake_redis, user_id="admin")

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as client:
        r = await client.post(
            "/auth/mfa/webauthn/auth/complete",
            json={"id": _FAKE_CRED_ID_B64, "type": "public-key"},
        )
    await _redis_module.close_redis()
    assert r.status_code == 403, (
        f"Expected 403 when authenticating with another user's credential, "
        f"got {r.status_code}: {r.text}"
    )


# ── Section 6: Credential management — list and delete (Gap 3 — Production Readiness) ───


@pytest.mark.asyncio
async def test_webauthn_list_credentials_empty(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/mfa/webauthn/credentials returns empty list when no credentials enrolled."""
    r = await admin_client.get("/auth/mfa/webauthn/credentials")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    assert "credentials" in data, f"Expected 'credentials' key in response: {data}"
    assert (
        data["credentials"] == []
    ), f"Expected empty list for unenrolled user, got {data['credentials']}"


@pytest.mark.asyncio
async def test_webauthn_list_credentials_returns_enrolled(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/mfa/webauthn/credentials returns all credential IDs for the caller."""
    await _seed_credential(fake_redis, user_id="admin", cred_id_b64=_FAKE_CRED_ID_B64)
    await _seed_credential(fake_redis, user_id="admin", cred_id_b64=_FAKE_CRED_ID_B64_2)

    r = await admin_client.get("/auth/mfa/webauthn/credentials")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"
    data = r.json()
    cred_ids = {c["credential_id"] for c in data["credentials"]}
    assert (
        _FAKE_CRED_ID_B64 in cred_ids
    ), f"Expected {_FAKE_CRED_ID_B64!r} in credentials, got {cred_ids}"
    assert (
        _FAKE_CRED_ID_B64_2 in cred_ids
    ), f"Expected {_FAKE_CRED_ID_B64_2!r} in credentials, got {cred_ids}"


@pytest.mark.asyncio
async def test_webauthn_list_credentials_has_created_at(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Each credential in the list includes a created_at field."""
    await _seed_credential(fake_redis, user_id="admin", cred_id_b64=_FAKE_CRED_ID_B64)

    r = await admin_client.get("/auth/mfa/webauthn/credentials")
    assert r.status_code == 200
    data = r.json()
    assert len(data["credentials"]) == 1
    cred = data["credentials"][0]
    assert "created_at" in cred, f"Expected 'created_at' in credential entry: {cred}"


@pytest.mark.asyncio
async def test_webauthn_delete_credential_success(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE /auth/mfa/webauthn/credentials/{id} returns 204 and removes the credential."""
    await _seed_credential(fake_redis, user_id="admin", cred_id_b64=_FAKE_CRED_ID_B64)

    r = await admin_client.delete(f"/auth/mfa/webauthn/credentials/{_FAKE_CRED_ID_B64}")
    assert r.status_code == 204, f"Expected 204, got {r.status_code}: {r.text}"

    # Credential hash must be gone
    cred = await fake_redis.hgetall(f"mgmt:webauthn:credential:{_FAKE_CRED_ID_B64}")
    assert not cred, f"Credential hash should be deleted, but still exists: {cred}"

    # SET member must be removed
    members = await fake_redis.smembers("mgmt:webauthn:user:admin:credentials")
    assert (
        _FAKE_CRED_ID_B64 not in members
    ), f"Credential ID should be removed from user SET, but still in: {members}"


@pytest.mark.asyncio
async def test_webauthn_delete_credential_not_found(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE on a non-existent credential ID returns 404."""
    r = await admin_client.delete("/auth/mfa/webauthn/credentials/nonexistent-cred-id")
    assert (
        r.status_code == 404
    ), f"Expected 404 for missing credential, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_webauthn_delete_credential_wrong_user_returns_403(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """DELETE on another user's credential returns 403.

    User 'other-user' owns the credential; 'admin' tries to delete it.
    """
    await _seed_credential(
        fake_redis, user_id="other-user", cred_id_b64=_FAKE_CRED_ID_B64
    )

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as client:
        r = await client.delete(f"/auth/mfa/webauthn/credentials/{_FAKE_CRED_ID_B64}")
    await _redis_module.close_redis()

    assert (
        r.status_code == 403
    ), f"Expected 403 when deleting another user's credential, got {r.status_code}: {r.text}"
