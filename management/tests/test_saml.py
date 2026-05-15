"""TDD tests for MFA/SSO Hardening Cluster 8 — SAML 2.0 SSO.

Covers
------
Section 1: SP Metadata (GET /auth/sso/metadata)
  - Returns 200 with XML content-type when SAML is configured
  - Returns 503 when SAML IdP is not configured
  - No authentication required (public endpoint)

Section 2: Login redirect (GET /auth/sso/saml/login)
  - Returns 302 redirect to IdP SSO URL when configured
  - Stores nonce in mgmt:saml:nonce:{nonce} with 5-min TTL (CSRF protection)
  - Returns 503 when SAML IdP is not configured
  - No authentication required (public endpoint)

Section 3: ACS — Assertion Consumer Service (POST /auth/sso/saml/acs)
  - Valid mocked SAML response → 302 redirect with JWT cookie set
  - JWT cookie contains role derived from SAML group attribute
  - Authentication failure (is_authenticated=False) → 401
  - Unmapped SAML groups with no default_role → 403
  - Valid relay state/nonce required — missing or expired → 400
  - No authentication required (public endpoint)

Section 4: Role mapping
  - Security-Admins group → admin role
  - SecOps-Operators group → operator role
  - Unknown group with default_role=auditor → auditor role
  - Unknown group with no default_role → None (deny)
  - First matching group wins when user is in multiple groups

Tests mock OneLogin_Saml2_Auth for login and ACS flows.
Metadata uses real settings (no mock needed — validated with empty cert, strict=False).
All tests marked @pytest.mark.integration that need a live IdP are skipped in CI.
"""

from __future__ import annotations

import json
import os
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Configure SAML env vars before any management import
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
os.environ.setdefault("MANAGEMENT_SAML_STRICT", "false")
os.environ.setdefault(
    "MANAGEMENT_SAML_SP_ENTITY_ID", "http://localhost:8090/auth/sso/metadata"
)
os.environ.setdefault(
    "MANAGEMENT_SAML_SP_ACS_URL", "http://localhost:8090/auth/sso/saml/acs"
)
os.environ.setdefault("MANAGEMENT_SAML_IDP_ENTITY_ID", "http://mock-idp.test/saml")
os.environ.setdefault("MANAGEMENT_SAML_IDP_SSO_URL", "http://mock-idp.test/sso")
os.environ.setdefault("MANAGEMENT_SAML_IDP_CERT", "")
os.environ.setdefault(
    "MANAGEMENT_SAML_ROLE_MAPPING",
    json.dumps(
        {
            "Security-Admins": "admin",
            "SecOps-Operators": "operator",
            "SOC-Analysts": "analyst",
            "Audit-Team": "auditor",
        }
    ),
)
os.environ.setdefault("MANAGEMENT_SAML_DEFAULT_ROLE", "")
os.environ.setdefault("MANAGEMENT_SAML_GROUPS_ATTRIBUTE", "groups")

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.main import create_app  # noqa: E402
from management.api.models import Role  # noqa: E402
from management.api.routes.saml import _map_role  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture()
async def fake_redis() -> AsyncGenerator[fakeredis.aioredis.FakeRedis, None]:
    server = fakeredis.FakeServer()
    client = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture()
async def public_client(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> AsyncGenerator[AsyncClient, None]:
    """Unauthenticated client — SAML routes are public."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client
    await _redis_module.close_redis()


def _make_mock_saml_auth(
    authenticated: bool = True,
    nameid: str = "testuser@example.com",
    groups: list[str] | None = None,
    errors: list[str] | None = None,
) -> MagicMock:
    """Build a MagicMock that mimics OneLogin_Saml2_Auth."""
    mock = MagicMock()
    mock.process_response.return_value = None
    mock.is_authenticated.return_value = authenticated
    mock.get_nameid.return_value = nameid
    mock.get_attribute.return_value = groups or ["Security-Admins"]
    mock.get_errors.return_value = errors or []
    mock.login.return_value = "http://mock-idp.test/sso?SAMLRequest=FAKE"
    return mock


# ── Section 1: SP Metadata ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_saml_metadata_returns_200(
    public_client: AsyncClient,
) -> None:
    """GET /auth/sso/metadata returns 200 with XML when SAML is configured."""
    r = await public_client.get("/auth/sso/metadata")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_saml_metadata_content_type_is_xml(
    public_client: AsyncClient,
) -> None:
    """GET /auth/sso/metadata returns application/xml or text/xml content-type."""
    r = await public_client.get("/auth/sso/metadata")
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "xml" in ct.lower(), f"Expected XML content-type, got {ct!r}"


@pytest.mark.asyncio
async def test_saml_metadata_contains_sp_entity_id(
    public_client: AsyncClient,
) -> None:
    """SP metadata XML contains the configured entityID."""
    r = await public_client.get("/auth/sso/metadata")
    assert r.status_code == 200
    assert (
        "localhost:8090" in r.text or "auth/sso/metadata" in r.text
    ), f"SP entity ID not found in metadata: {r.text[:400]}"


@pytest.mark.asyncio
async def test_saml_metadata_not_configured_returns_503(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/metadata returns 503 when SAML IdP is not configured."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    saved = os.environ.pop("MANAGEMENT_SAML_IDP_ENTITY_ID", None)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get("/auth/sso/metadata")
        assert (
            r.status_code == 503
        ), f"Expected 503 when SAML not configured, got {r.status_code}: {r.text}"
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_SAML_IDP_ENTITY_ID"] = saved
        else:
            os.environ["MANAGEMENT_SAML_IDP_ENTITY_ID"] = "http://mock-idp.test/saml"
        await _redis_module.close_redis()


# ── Section 2: Login redirect ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_saml_login_redirects(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/saml/login returns a redirect to the IdP SSO URL."""
    mock_auth = _make_mock_saml_auth()
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.get("/auth/sso/saml/login", follow_redirects=False)
    assert r.status_code in (
        301,
        302,
        303,
        307,
        308,
    ), f"Expected redirect, got {r.status_code}: {r.text}"
    assert "mock-idp.test" in r.headers.get(
        "location", ""
    ), f"Expected redirect to mock IdP, got location={r.headers.get('location')!r}"


@pytest.mark.asyncio
async def test_saml_login_stores_nonce_in_redis(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/saml/login creates a nonce in mgmt:saml:nonce:* with 5-min TTL."""
    mock_auth = _make_mock_saml_auth()
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.get("/auth/sso/saml/login", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)

    keys = await fake_redis.keys("mgmt:saml:nonce:*")
    assert len(keys) == 1, f"Expected exactly one nonce key, found: {keys}"
    ttl = await fake_redis.ttl(keys[0])
    assert 0 < ttl <= 300, f"Nonce TTL should be ≤300s, got {ttl}"


@pytest.mark.asyncio
async def test_saml_login_not_configured_returns_503(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/saml/login returns 503 when SAML IdP is not configured."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    saved = os.environ.pop("MANAGEMENT_SAML_IDP_ENTITY_ID", None)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get("/auth/sso/saml/login", follow_redirects=False)
        assert (
            r.status_code == 503
        ), f"Expected 503 when SAML not configured, got {r.status_code}: {r.text}"
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_SAML_IDP_ENTITY_ID"] = saved
        else:
            os.environ["MANAGEMENT_SAML_IDP_ENTITY_ID"] = "http://mock-idp.test/saml"
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_saml_login_is_public(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/saml/login does not require JWT authentication."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    mock_auth = _make_mock_saml_auth()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        # No cookie — unauthenticated
    ) as client:
        with patch(
            "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
        ):
            r = await client.get("/auth/sso/saml/login", follow_redirects=False)
    await _redis_module.close_redis()
    # A public endpoint must not return 401 or 403
    assert r.status_code not in (
        401,
        403,
    ), f"Login endpoint should be public, got {r.status_code}"


# ── Section 3: ACS ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_saml_acs_valid_response_sets_cookie(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/sso/saml/acs with valid mocked response sets a JWT cookie."""
    # Seed a valid nonce
    nonce = "test-nonce-abc123"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(groups=["Security-Admins"])
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert r.status_code in (
        200,
        302,
    ), f"Expected redirect/200, got {r.status_code}: {r.text}"
    # JWT cookie must be set
    assert (
        "token" in r.cookies
    ), f"Expected 'token' cookie to be set. Cookies: {dict(r.cookies)}"


@pytest.mark.asyncio
async def test_saml_acs_role_embedded_in_token(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """After ACS, the issued JWT embeds the correct role from group mapping."""
    from jose import jwt as _jwt

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    nonce = "test-nonce-role"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(
        nameid="operator@example.com",
        groups=["SecOps-Operators"],
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        with patch(
            "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
        ):
            r = await client.post(
                "/auth/sso/saml/acs",
                data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
                follow_redirects=False,
            )
    await _redis_module.close_redis()

    assert r.status_code in (200, 302), f"Got {r.status_code}: {r.text}"
    token_value = r.cookies.get("token")
    assert token_value is not None, "No token cookie set"

    secret = os.environ.get(
        "MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production"
    )
    payload = _jwt.decode(token_value, secret, algorithms=["HS256"])
    assert (
        payload.get("role") == "operator"
    ), f"Expected role='operator' in JWT, got role={payload.get('role')!r}"


@pytest.mark.asyncio
async def test_saml_acs_auth_failed_returns_401(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/sso/saml/acs returns 401 when SAML authentication fails."""
    nonce = "test-nonce-fail"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(authenticated=False, errors=["invalid_response"])
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert (
        r.status_code == 401
    ), f"Expected 401 for failed SAML auth, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_saml_acs_nonce_consumed_on_auth_failure(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Nonce is consumed even when SAML authentication fails.

    This verifies that a SAML assertion replay attack cannot succeed: if the
    first ACS call fails (bad assertion), the nonce is already gone, so no
    second attempt is possible with the same nonce.
    """
    nonce = "test-nonce-consumed-on-fail"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(authenticated=False, errors=["invalid_response"])
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert r.status_code == 401

    # Nonce must no longer exist in Redis
    remaining = await fake_redis.get(f"mgmt:saml:nonce:{nonce}")
    assert (
        remaining is None
    ), f"Nonce should be consumed on auth failure, but key still exists: {remaining!r}"


@pytest.mark.asyncio
async def test_saml_acs_unmapped_group_returns_403(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/sso/saml/acs returns 403 when user's groups have no mapped role."""
    nonce = "test-nonce-403"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(groups=["Unknown-Group-No-Mapping"])
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert (
        r.status_code == 403
    ), f"Expected 403 for unmapped group, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_saml_acs_missing_relay_state_returns_400(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """POST /auth/sso/saml/acs without a valid RelayState (nonce) returns 400."""
    # No nonce seeded in Redis — stale or CSRF attempt
    mock_auth = _make_mock_saml_auth()
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": "nonexistent-nonce"},
            follow_redirects=False,
        )
    assert (
        r.status_code == 400
    ), f"Expected 400 for invalid relay state, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_saml_acs_nonce_is_single_use(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """A nonce can only be used once — second use returns 400."""
    nonce = "test-nonce-once"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth()
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r1 = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert r1.status_code in (200, 302), f"First ACS call failed: {r1.status_code}"

    # Second use of the same nonce
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r2 = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert (
        r2.status_code == 400
    ), f"Second use of same nonce should be 400, got {r2.status_code}"


# ── Section 4: Role mapping unit tests ───────────────────────────────────────


def test_map_role_admin_group() -> None:
    """Security-Admins group maps to admin role."""
    role = _map_role(["Security-Admins"])
    assert role == Role.admin, f"Expected admin, got {role}"


def test_map_role_operator_group() -> None:
    """SecOps-Operators group maps to operator role."""
    role = _map_role(["SecOps-Operators"])
    assert role == Role.operator, f"Expected operator, got {role}"


def test_map_role_analyst_group() -> None:
    """SOC-Analysts group maps to analyst role."""
    role = _map_role(["SOC-Analysts"])
    assert role == Role.analyst, f"Expected analyst, got {role}"


def test_map_role_unknown_no_default_returns_none() -> None:
    """Unknown group with no default_role returns None (deny)."""
    saved = os.environ.pop("MANAGEMENT_SAML_DEFAULT_ROLE", None)
    try:
        os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = ""
        role = _map_role(["Some-Unknown-Group"])
        assert role is None, f"Expected None for unmapped group, got {role}"
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = saved
        else:
            os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = ""


def test_map_role_default_role_applied() -> None:
    """Unknown group with MANAGEMENT_SAML_DEFAULT_ROLE=auditor returns auditor."""
    saved = os.environ.get("MANAGEMENT_SAML_DEFAULT_ROLE")
    try:
        os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = "auditor"
        role = _map_role(["Some-Unknown-Group"])
        assert role == Role.auditor, f"Expected auditor (default), got {role}"
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = saved
        else:
            os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = ""


def test_map_role_first_match_wins() -> None:
    """When user is in multiple groups, the first match in the list wins."""
    # User in both admin and analyst groups — order in the input list determines result
    role = _map_role(["SOC-Analysts", "Security-Admins"])
    # SOC-Analysts comes first in the input → analyst
    assert role == Role.analyst, f"Expected analyst (first match), got {role}"


def test_map_role_empty_groups_no_default() -> None:
    """Empty group list with no default returns None."""
    saved = os.environ.get("MANAGEMENT_SAML_DEFAULT_ROLE")
    try:
        os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = ""
        role = _map_role([])
        assert role is None, f"Expected None for empty groups, got {role}"
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = saved
        else:
            os.environ["MANAGEMENT_SAML_DEFAULT_ROLE"] = ""


# ── Section 8: Integration test stubs (Gap 5 — Production Readiness) ────────────────────


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("OKTA_METADATA_URL"),
    reason="OKTA_METADATA_URL not set — live Okta test skipped",
)
async def test_saml_live_okta_login() -> None:
    """Placeholder: end-to-end login against live Okta SAML IdP.

    To run: OKTA_METADATA_URL=https://... pytest -m integration
    """
    pytest.skip("Not yet implemented — stub for future live-IdP test")


# ── Section 9: Audit log events (Gap 2 — Production Readiness) ──────────────────────────


@pytest.mark.asyncio
async def test_saml_acs_success_writes_audit_entry(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Successful SAML ACS login writes an entry to management:audit_log.

    Verifies Gap 2: SSO login events must appear in the audit trail.
    Entry must have action_type='sso.login' and actor_id equal to the SAML NameID.
    """
    nonce = "test-nonce-audit"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(
        nameid="audited@example.com",
        groups=["Security-Admins"],
    )
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert r.status_code in (
        200,
        302,
    ), f"Expected login success, got {r.status_code}: {r.text}"

    # Audit entry must exist in Redis
    entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert entries, "Expected at least one audit entry in management:audit_log"

    entry = json.loads(entries[0])
    assert (
        entry.get("action_type") == "sso.login"
    ), f"Expected action_type='sso.login', got {entry.get('action_type')!r}"
    assert (
        entry.get("actor_id") == "audited@example.com"
    ), f"Expected actor_id='audited@example.com', got {entry.get('actor_id')!r}"
    assert (
        entry.get("resource_type") == "session"
    ), f"Expected resource_type='session', got {entry.get('resource_type')!r}"


@pytest.mark.asyncio
async def test_saml_acs_failure_does_not_write_audit_entry(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Failed SAML ACS (auth_failed) does NOT write an audit entry."""
    nonce = "test-nonce-noaudit"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(authenticated=False, errors=["bad_response"])
    with patch(
        "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
    ):
        r = await public_client.post(
            "/auth/sso/saml/acs",
            data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
            follow_redirects=False,
        )
    assert r.status_code == 401

    entries = await fake_redis.lrange("management:audit_log", 0, -1)
    for e in entries:
        parsed = json.loads(e)
        assert (
            parsed.get("action_type") != "sso.login"
        ), f"Failed login must not produce an audit entry: {parsed}"


# ── Section 10: SSO-delegated MFA trust (Gap 4 — Production Readiness) ──────────────────


@pytest.mark.asyncio
async def test_saml_acs_idp_mfa_trust_sets_session_key(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """When MANAGEMENT_SSO_TRUST_IDP_MFA=true and IdP asserts MFA, session MFA key is set.

    The authn context urn:...TimeSyncToken is an MFA context — mgmt:mfa:session:* must
    be set after ACS so the user does not need to complete a separate TOTP/WebAuthn step.
    """
    import hashlib

    from jose import jwt as _jwt

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    nonce = "test-nonce-mfa-trust"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(
        nameid="mfa-user@example.com",
        groups=["Security-Admins"],
    )
    mock_auth.get_last_authn_contexts.return_value = [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
    ]

    saved = os.environ.get("MANAGEMENT_SSO_TRUST_IDP_MFA")
    try:
        os.environ["MANAGEMENT_SSO_TRUST_IDP_MFA"] = "true"
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            with patch(
                "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
            ):
                r = await client.post(
                    "/auth/sso/saml/acs",
                    data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
                    follow_redirects=False,
                )
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_SSO_TRUST_IDP_MFA"] = saved
        else:
            os.environ.pop("MANAGEMENT_SSO_TRUST_IDP_MFA", None)
        await _redis_module.close_redis()

    assert r.status_code in (
        200,
        302,
    ), f"Expected login success, got {r.status_code}: {r.text}"

    token_value = r.cookies.get("token")
    assert token_value, "No token cookie issued"

    mfa_key = "mgmt:mfa:session:" + hashlib.sha256(token_value.encode()).hexdigest()
    value = await fake_redis.get(mfa_key)
    assert (
        value == "verified"
    ), f"Expected MFA session key set to 'verified' when IdP asserts MFA, got {value!r}"


@pytest.mark.asyncio
async def test_saml_acs_idp_mfa_trust_disabled_no_session_key(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """When MANAGEMENT_SSO_TRUST_IDP_MFA is not set (default), MFA session key is NOT set."""
    import hashlib

    nonce = "test-nonce-mfa-notrust"
    await fake_redis.set(f"mgmt:saml:nonce:{nonce}", "/", ex=300)

    mock_auth = _make_mock_saml_auth(
        nameid="mfa-user2@example.com",
        groups=["Security-Admins"],
    )
    mock_auth.get_last_authn_contexts.return_value = [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
    ]

    saved = os.environ.pop("MANAGEMENT_SSO_TRUST_IDP_MFA", None)
    try:
        with patch(
            "management.api.routes.saml.OneLogin_Saml2_Auth", return_value=mock_auth
        ):
            r = await public_client.post(
                "/auth/sso/saml/acs",
                data={"SAMLResponse": "ZmFrZQ==", "RelayState": nonce},
                follow_redirects=False,
            )
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_SSO_TRUST_IDP_MFA"] = saved

    assert r.status_code in (200, 302)
    token_value = r.cookies.get("token")
    if token_value:
        mfa_key = "mgmt:mfa:session:" + hashlib.sha256(token_value.encode()).hexdigest()
        value = await fake_redis.get(mfa_key)
        assert (
            value is None
        ), f"MFA session key must NOT be set when trust flag is off, got {value!r}"


# ── Section 11: config/proxy.yml role mapping (Gap 6 — Production Readiness) ────────────


def test_saml_map_role_from_proxy_config(tmp_path) -> None:
    """_map_role() honours sso.role_mapping from config/proxy.yml.

    When env var is empty, the config-file mapping is used as the base.
    """
    import yaml

    from management.api.proxy_config import _clear_cache as _clr
    from management.api.routes.saml import _map_role

    cfg = tmp_path / "proxy.yml"
    cfg.write_text("sso:\n  role_mapping:\n    Config-Group: auditor\n")

    saved_path = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    saved_env = os.environ.pop("MANAGEMENT_SAML_ROLE_MAPPING", None)
    _clr()
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg)
        os.environ["MANAGEMENT_SAML_ROLE_MAPPING"] = "{}"
        role = _map_role(["Config-Group"])
    finally:
        _clr()
        if saved_path is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved_path
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)
        if saved_env is not None:
            os.environ["MANAGEMENT_SAML_ROLE_MAPPING"] = saved_env
        else:
            os.environ["MANAGEMENT_SAML_ROLE_MAPPING"] = json.dumps(
                {
                    "Security-Admins": "admin",
                    "SecOps-Operators": "operator",
                    "SOC-Analysts": "analyst",
                }
            )

    from management.api.models import Role

    assert (
        role == Role.auditor
    ), f"Expected auditor from config file mapping, got {role}"


def test_saml_map_role_env_overrides_config(tmp_path) -> None:
    """Env var mapping takes precedence over config/proxy.yml for the same group."""
    from management.api.models import Role
    from management.api.proxy_config import _clear_cache as _clr
    from management.api.routes.saml import _map_role

    cfg = tmp_path / "proxy.yml"
    cfg.write_text("sso:\n  role_mapping:\n    Overlap-Group: auditor\n")

    saved_path = os.environ.get("MANAGEMENT_PROXY_CONFIG_PATH")
    saved_env = os.environ.get("MANAGEMENT_SAML_ROLE_MAPPING")
    _clr()
    try:
        os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = str(cfg)
        os.environ["MANAGEMENT_SAML_ROLE_MAPPING"] = json.dumps(
            {"Overlap-Group": "admin"}
        )
        role = _map_role(["Overlap-Group"])
    finally:
        _clr()
        if saved_path is not None:
            os.environ["MANAGEMENT_PROXY_CONFIG_PATH"] = saved_path
        else:
            os.environ.pop("MANAGEMENT_PROXY_CONFIG_PATH", None)
        if saved_env is not None:
            os.environ["MANAGEMENT_SAML_ROLE_MAPPING"] = saved_env
        else:
            os.environ["MANAGEMENT_SAML_ROLE_MAPPING"] = json.dumps(
                {
                    "Security-Admins": "admin",
                    "SecOps-Operators": "operator",
                    "SOC-Analysts": "analyst",
                }
            )

    assert (
        role == Role.admin
    ), f"Expected admin (env var wins over config file), got {role}"
