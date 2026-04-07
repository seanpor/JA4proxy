"""TDD tests for Phase 79 Cluster 9 — OIDC SSO.

Covers
------
Section 1: Login redirect (GET /auth/sso/oidc/login)
  - Returns 302 redirect to IdP authorization_endpoint
  - Stores state+code_verifier in mgmt:oidc:state:{state} with 5-min TTL
  - Authorization URL includes code_challenge (PKCE S256)
  - Returns 503 when OIDC is not configured
  - No authentication required (public endpoint)

Section 2: Callback (GET /auth/sso/oidc/callback)
  - Valid code + state → 302 redirect with JWT cookie set
  - JWT embeds correct role derived from OIDC groups claim
  - Missing or expired state → 400
  - State is single-use (second use → 400)
  - Unmapped groups with no default_role → 403
  - Token exchange failure → 401

Section 3: PKCE validation
  - code_verifier stored in state Redis key
  - code_challenge in authorization URL is S256 of code_verifier

Section 4: Role mapping (unit tests)
  - Known group → correct role (reads MANAGEMENT_OIDC_ROLE_MAPPING)
  - Unknown group + no default → None
  - Unknown group + default_role → that role
  - First match in groups list wins

All HTTP calls to the IdP (_fetch_oidc_discovery, _exchange_code_for_tokens)
are mocked to keep tests offline.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Configure OIDC env vars before any management import
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")
os.environ.setdefault("MANAGEMENT_OIDC_DISCOVERY_URL", "http://mock-idp.test/.well-known/openid-configuration")
os.environ.setdefault("MANAGEMENT_OIDC_CLIENT_ID", "ja4proxy-test")
os.environ.setdefault("MANAGEMENT_OIDC_CLIENT_SECRET", "test-secret-oidc")
os.environ.setdefault("MANAGEMENT_OIDC_REDIRECT_URI", "http://localhost:8090/auth/sso/oidc/callback")
os.environ.setdefault(
    "MANAGEMENT_OIDC_ROLE_MAPPING",
    json.dumps({
        "Security-Admins": "admin",
        "SecOps-Operators": "operator",
        "SOC-Analysts": "analyst",
        "Audit-Team": "auditor",
    }),
)
os.environ.setdefault("MANAGEMENT_OIDC_DEFAULT_ROLE", "")
os.environ.setdefault("MANAGEMENT_OIDC_GROUPS_CLAIM", "groups")

from management.api import redis_client as _redis_module  # noqa: E402
from management.api.main import create_app  # noqa: E402
from management.api.models import Role  # noqa: E402
from management.api.routes.oidc import _map_role  # noqa: E402

# ── Helpers ───────────────────────────────────────────────────────────────────

_FAKE_DISCOVERY = {
    "authorization_endpoint": "http://mock-idp.test/auth",
    "token_endpoint": "http://mock-idp.test/token",
    "jwks_uri": "http://mock-idp.test/certs",
    "issuer": "http://mock-idp.test",
}


def _fake_id_token(
    sub: str = "user-123",
    email: str = "user@example.com",
    groups: list[str] | None = None,
) -> str:
    """Build a fake (unsigned) JWT id_token for testing."""
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": sub,
            "email": email,
            "groups": groups or ["Security-Admins"],
            "exp": 9999999999,
            "iat": 1000000000,
        }).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.fakesignature"


def _fake_token_response(
    sub: str = "user-123",
    email: str = "user@example.com",
    groups: list[str] | None = None,
) -> dict:
    return {
        "access_token": "fake-access-token",
        "token_type": "Bearer",
        "id_token": _fake_id_token(sub, email, groups),
        "expires_in": 3600,
    }


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
    """Unauthenticated client — OIDC routes are public."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client
    await _redis_module.close_redis()


# ── Section 1: Login redirect ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oidc_login_redirects_to_idp(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/oidc/login returns a redirect to the IdP authorization endpoint."""
    with patch(
        "management.api.routes.oidc._fetch_oidc_discovery",
        new=AsyncMock(return_value=_FAKE_DISCOVERY),
    ):
        r = await public_client.get("/auth/sso/oidc/login", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308), (
        f"Expected redirect, got {r.status_code}: {r.text}"
    )
    location = r.headers.get("location", "")
    assert "mock-idp.test/auth" in location, (
        f"Expected redirect to IdP auth endpoint, got location={location!r}"
    )


@pytest.mark.asyncio
async def test_oidc_login_includes_state_in_redirect(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Login redirect URL contains a state parameter."""
    with patch(
        "management.api.routes.oidc._fetch_oidc_discovery",
        new=AsyncMock(return_value=_FAKE_DISCOVERY),
    ):
        r = await public_client.get("/auth/sso/oidc/login", follow_redirects=False)
    location = r.headers.get("location", "")
    assert "state=" in location, f"Expected 'state' in redirect URL, got {location!r}"


@pytest.mark.asyncio
async def test_oidc_login_stores_state_in_redis(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Login stores state+code_verifier in mgmt:oidc:state:* with 5-min TTL."""
    with patch(
        "management.api.routes.oidc._fetch_oidc_discovery",
        new=AsyncMock(return_value=_FAKE_DISCOVERY),
    ):
        r = await public_client.get("/auth/sso/oidc/login", follow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)

    keys = await fake_redis.keys("mgmt:oidc:state:*")
    assert len(keys) == 1, f"Expected one state key, found: {keys}"

    stored = json.loads(await fake_redis.get(keys[0]))
    assert "code_verifier" in stored, f"State must include code_verifier: {stored}"

    ttl = await fake_redis.ttl(keys[0])
    assert 0 < ttl <= 300, f"State TTL should be ≤300s, got {ttl}"


@pytest.mark.asyncio
async def test_oidc_login_redirect_contains_code_challenge(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Login redirect URL includes code_challenge (PKCE S256)."""
    with patch(
        "management.api.routes.oidc._fetch_oidc_discovery",
        new=AsyncMock(return_value=_FAKE_DISCOVERY),
    ):
        r = await public_client.get("/auth/sso/oidc/login", follow_redirects=False)
    location = r.headers.get("location", "")
    assert "code_challenge=" in location, (
        f"Expected code_challenge in redirect URL: {location!r}"
    )
    assert "code_challenge_method=S256" in location, (
        f"Expected code_challenge_method=S256: {location!r}"
    )


@pytest.mark.asyncio
async def test_oidc_login_not_configured_returns_503(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/oidc/login returns 503 when OIDC discovery URL is not set."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    saved = os.environ.pop("MANAGEMENT_OIDC_DISCOVERY_URL", None)
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            r = await client.get("/auth/sso/oidc/login", follow_redirects=False)
        assert r.status_code == 503, (
            f"Expected 503 when OIDC not configured, got {r.status_code}: {r.text}"
        )
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_OIDC_DISCOVERY_URL"] = saved
        else:
            os.environ["MANAGEMENT_OIDC_DISCOVERY_URL"] = "http://mock-idp.test/.well-known/openid-configuration"
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_oidc_login_is_public(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/oidc/login does not require JWT authentication."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        with patch(
            "management.api.routes.oidc._fetch_oidc_discovery",
            new=AsyncMock(return_value=_FAKE_DISCOVERY),
        ):
            r = await client.get("/auth/sso/oidc/login", follow_redirects=False)
    await _redis_module.close_redis()
    assert r.status_code not in (401, 403), (
        f"Login endpoint must be public, got {r.status_code}"
    )


# ── Section 2: Callback ───────────────────────────────────────────────────────


async def _do_login_get_state(
    client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> str:
    """Helper: call /login and return the stored state value."""
    with patch(
        "management.api.routes.oidc._fetch_oidc_discovery",
        new=AsyncMock(return_value=_FAKE_DISCOVERY),
    ):
        await client.get("/auth/sso/oidc/login", follow_redirects=False)
    keys = await fake_redis.keys("mgmt:oidc:state:*")
    assert keys, "No state key found after login"
    return keys[0].split(":")[-1]  # extract state value from key name


@pytest.mark.asyncio
async def test_oidc_callback_valid_sets_cookie(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """GET /auth/sso/oidc/callback with valid code+state sets JWT cookie."""
    state = await _do_login_get_state(public_client, fake_redis)

    with (
        patch(
            "management.api.routes.oidc._fetch_oidc_discovery",
            new=AsyncMock(return_value=_FAKE_DISCOVERY),
        ),
        patch(
            "management.api.routes.oidc._exchange_code_for_tokens",
            new=AsyncMock(return_value=_fake_token_response()),
        ),
    ):
        r = await public_client.get(
            f"/auth/sso/oidc/callback?code=authcode123&state={state}",
            follow_redirects=False,
        )
    assert r.status_code in (200, 302), f"Expected redirect, got {r.status_code}: {r.text}"
    assert "token" in r.cookies, (
        f"Expected 'token' cookie to be set. Cookies: {dict(r.cookies)}"
    )


@pytest.mark.asyncio
async def test_oidc_callback_role_embedded_in_jwt(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Callback JWT contains the role derived from OIDC groups claim."""
    from jose import jwt as _jwt

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        state = await _do_login_get_state(client, fake_redis)

        with (
            patch(
                "management.api.routes.oidc._fetch_oidc_discovery",
                new=AsyncMock(return_value=_FAKE_DISCOVERY),
            ),
            patch(
                "management.api.routes.oidc._exchange_code_for_tokens",
                new=AsyncMock(return_value=_fake_token_response(
                    sub="op@example.com",
                    groups=["SecOps-Operators"],
                )),
            ),
        ):
            r = await client.get(
                f"/auth/sso/oidc/callback?code=authcode123&state={state}",
                follow_redirects=False,
            )
    await _redis_module.close_redis()

    assert r.status_code in (200, 302), f"Got {r.status_code}: {r.text}"
    token_value = r.cookies.get("token")
    assert token_value is not None, "No token cookie"

    secret = os.environ.get("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
    payload = _jwt.decode(token_value, secret, algorithms=["HS256"])
    assert payload.get("role") == "operator", (
        f"Expected role='operator', got {payload.get('role')!r}"
    )


@pytest.mark.asyncio
async def test_oidc_callback_invalid_state_returns_400(
    public_client: AsyncClient,
) -> None:
    """GET /auth/sso/oidc/callback with unknown state returns 400."""
    r = await public_client.get(
        "/auth/sso/oidc/callback?code=authcode123&state=nonexistent-state",
        follow_redirects=False,
    )
    assert r.status_code == 400, (
        f"Expected 400 for unknown state, got {r.status_code}: {r.text}"
    )


@pytest.mark.asyncio
async def test_oidc_callback_state_is_single_use(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """State can only be used once — second callback use returns 400."""
    state = await _do_login_get_state(public_client, fake_redis)

    with (
        patch("management.api.routes.oidc._fetch_oidc_discovery", new=AsyncMock(return_value=_FAKE_DISCOVERY)),
        patch("management.api.routes.oidc._exchange_code_for_tokens", new=AsyncMock(return_value=_fake_token_response())),
    ):
        r1 = await public_client.get(
            f"/auth/sso/oidc/callback?code=authcode123&state={state}",
            follow_redirects=False,
        )
    assert r1.status_code in (200, 302), f"First callback failed: {r1.status_code}"

    # Second use of same state
    with (
        patch("management.api.routes.oidc._fetch_oidc_discovery", new=AsyncMock(return_value=_FAKE_DISCOVERY)),
        patch("management.api.routes.oidc._exchange_code_for_tokens", new=AsyncMock(return_value=_fake_token_response())),
    ):
        r2 = await public_client.get(
            f"/auth/sso/oidc/callback?code=authcode456&state={state}",
            follow_redirects=False,
        )
    assert r2.status_code == 400, (
        f"Second use of same state should be 400, got {r2.status_code}"
    )


@pytest.mark.asyncio
async def test_oidc_callback_unmapped_group_returns_403(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Callback returns 403 when OIDC groups have no role mapping."""
    state = await _do_login_get_state(public_client, fake_redis)

    with (
        patch("management.api.routes.oidc._fetch_oidc_discovery", new=AsyncMock(return_value=_FAKE_DISCOVERY)),
        patch(
            "management.api.routes.oidc._exchange_code_for_tokens",
            new=AsyncMock(return_value=_fake_token_response(groups=["Unknown-Group"])),
        ),
    ):
        r = await public_client.get(
            f"/auth/sso/oidc/callback?code=authcode123&state={state}",
            follow_redirects=False,
        )
    assert r.status_code == 403, f"Expected 403 for unmapped group, got {r.status_code}: {r.text}"


@pytest.mark.asyncio
async def test_oidc_callback_token_exchange_failure_returns_401(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Callback returns 401 when token exchange raises."""
    state = await _do_login_get_state(public_client, fake_redis)

    with (
        patch("management.api.routes.oidc._fetch_oidc_discovery", new=AsyncMock(return_value=_FAKE_DISCOVERY)),
        patch(
            "management.api.routes.oidc._exchange_code_for_tokens",
            new=AsyncMock(side_effect=Exception("token endpoint error")),
        ),
    ):
        r = await public_client.get(
            f"/auth/sso/oidc/callback?code=badcode&state={state}",
            follow_redirects=False,
        )
    assert r.status_code == 401, (
        f"Expected 401 for failed token exchange, got {r.status_code}: {r.text}"
    )


# ── Section 3: PKCE validation ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oidc_pkce_code_verifier_stored_in_state(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """State Redis entry contains a code_verifier for PKCE."""
    with patch(
        "management.api.routes.oidc._fetch_oidc_discovery",
        new=AsyncMock(return_value=_FAKE_DISCOVERY),
    ):
        r = await public_client.get("/auth/sso/oidc/login", follow_redirects=False)

    keys = await fake_redis.keys("mgmt:oidc:state:*")
    stored = json.loads(await fake_redis.get(keys[0]))
    verifier = stored.get("code_verifier", "")
    assert len(verifier) >= 43, (
        f"code_verifier too short (RFC 7636 min 43 chars): {verifier!r}"
    )


@pytest.mark.asyncio
async def test_oidc_pkce_challenge_is_s256_of_verifier(
    public_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """The code_challenge in the redirect URL is S256(code_verifier)."""
    with patch(
        "management.api.routes.oidc._fetch_oidc_discovery",
        new=AsyncMock(return_value=_FAKE_DISCOVERY),
    ):
        r = await public_client.get("/auth/sso/oidc/login", follow_redirects=False)

    keys = await fake_redis.keys("mgmt:oidc:state:*")
    stored = json.loads(await fake_redis.get(keys[0]))
    verifier = stored["code_verifier"]

    # Recompute S256 challenge
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )

    location = r.headers.get("location", "")
    assert expected in location, (
        f"Expected S256 code_challenge {expected!r} in URL: {location!r}"
    )


# ── Section 4: Role mapping unit tests ───────────────────────────────────────


def test_oidc_map_role_admin() -> None:
    role = _map_role(["Security-Admins"])
    assert role == Role.admin


def test_oidc_map_role_operator() -> None:
    role = _map_role(["SecOps-Operators"])
    assert role == Role.operator


def test_oidc_map_role_unknown_no_default_returns_none() -> None:
    saved = os.environ.get("MANAGEMENT_OIDC_DEFAULT_ROLE")
    try:
        os.environ["MANAGEMENT_OIDC_DEFAULT_ROLE"] = ""
        assert _map_role(["Unknown-Group"]) is None
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_OIDC_DEFAULT_ROLE"] = saved
        else:
            os.environ["MANAGEMENT_OIDC_DEFAULT_ROLE"] = ""


def test_oidc_map_role_default_applied() -> None:
    saved = os.environ.get("MANAGEMENT_OIDC_DEFAULT_ROLE")
    try:
        os.environ["MANAGEMENT_OIDC_DEFAULT_ROLE"] = "auditor"
        assert _map_role(["Unknown-Group"]) == Role.auditor
    finally:
        if saved is not None:
            os.environ["MANAGEMENT_OIDC_DEFAULT_ROLE"] = saved
        else:
            os.environ["MANAGEMENT_OIDC_DEFAULT_ROLE"] = ""


def test_oidc_map_role_first_match_wins() -> None:
    # SOC-Analysts is first in the input list → analyst wins over Security-Admins
    assert _map_role(["SOC-Analysts", "Security-Admins"]) == Role.analyst
