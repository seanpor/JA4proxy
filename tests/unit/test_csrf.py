"""PHASE_101 H8 — CSRF double-submit middleware unit tests.

Covers the happy / mismatch / expired / missing / bearer-exempt matrix
on the ``/api/v1/*`` mutating routes of the management API.
"""

from __future__ import annotations

import os
import time
from typing import AsyncGenerator

import fakeredis.aioredis
import pytest
import pytest_asyncio

# Management API expects these before any module import.
os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")


@pytest.fixture(autouse=True)
def _csrf_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """PHASE_101 H8 — this test file verifies CSRF enforcement, so clear
    any inherited bypass on a per-test basis. Done via monkeypatch (not a
    module-level os.environ.pop) so the env is restored after each test
    and does not leak into subsequent test files in the same process.
    """
    monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)

from httpx import ASGITransport, AsyncClient  # noqa: E402

try:
    from management.api import redis_client as _redis_module
    from management.api.auth import _create_access_token
    from management.api.main import create_app
    from management.api.middleware.csrf import (
        CSRF_COOKIE_NAME,
        CSRF_HEADER_NAME,
        TOKEN_VALIDITY_SECONDS,
        issue_token,
        verify_token,
    )
except ImportError:  # pragma: no cover
    pytest.skip(
        "Management API not importable; this test runs after Phase 79.",
        allow_module_level=True,
    )


# ── Token primitive tests (no HTTP) ─────────────────────────────────────────


def test_issue_and_verify_roundtrip() -> None:
    tok = issue_token("alice")
    assert verify_token(tok, "alice") is True


def test_verify_rejects_wrong_session() -> None:
    tok = issue_token("alice")
    assert verify_token(tok, "mallory") is False


def test_verify_rejects_tampered_signature() -> None:
    tok = issue_token("alice")
    payload, sig = tok.rsplit(".", 1)
    flipped = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    assert verify_token(f"{payload}.{flipped}", "alice") is False


def test_verify_rejects_expired_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # Freeze "now" far enough in the future that a freshly-minted token
    # is outside TOKEN_VALIDITY_SECONDS.
    tok = issue_token("alice")
    future = int(time.time()) + TOKEN_VALIDITY_SECONDS + 60
    monkeypatch.setattr(
        "management.api.middleware.csrf.time.time",
        lambda: future,
    )
    assert verify_token(tok, "alice") is False


def test_verify_rejects_malformed() -> None:
    assert verify_token("", "alice") is False
    assert verify_token("not-a-token", "alice") is False
    assert verify_token("one.two.three.four", "alice") is False


# ── HTTP integration tests against the real app ─────────────────────────────


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
    ac = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin", role="admin")},
    )
    try:
        async with ac:
            yield ac
    finally:
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_get_mints_csrf_cookie_and_header(
    admin_client: AsyncClient,
) -> None:
    """Every GET /api/v1/* response sets csrf_token cookie + header."""
    resp = await admin_client.get("/api/v1/health")
    assert resp.status_code == 200
    assert CSRF_HEADER_NAME in resp.headers, resp.headers
    cookie_val = resp.cookies.get(CSRF_COOKIE_NAME)
    assert cookie_val, f"cookie missing: {dict(resp.cookies)}"
    assert cookie_val == resp.headers[CSRF_HEADER_NAME]


@pytest.mark.asyncio
async def test_post_without_csrf_rejected_403(
    admin_client: AsyncClient,
) -> None:
    """POST /api/v1/* without cookie+header → 403 csrf_token_mismatch."""
    resp = await admin_client.post(
        "/api/v1/threat-intel/feeds/test-feed/poll"
    )
    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body == {"error": "csrf_token_mismatch"}


@pytest.mark.asyncio
async def test_post_with_cookie_header_mismatch_rejected(
    admin_client: AsyncClient,
) -> None:
    """Cookie and header present but not equal → 403."""
    # Prime the cookie via a GET.
    await admin_client.get("/api/v1/health")
    # Attach a different header.
    resp = await admin_client.post(
        "/api/v1/threat-intel/feeds/test-feed/poll",
        headers={CSRF_HEADER_NAME: "clearly-not-the-cookie"},
    )
    assert resp.status_code == 403
    assert resp.json() == {"error": "csrf_token_mismatch"}


@pytest.mark.asyncio
async def test_post_with_forged_random_token_rejected(
    admin_client: AsyncClient,
) -> None:
    """Identical cookie + header that don't verify under HMAC → 403.

    Double-submit alone is not enough; the signature gate catches a
    sibling-domain-injected cookie that the attacker has perfect
    knowledge of.
    """
    bogus = "AAAA.BBBB"
    admin_client.cookies.set(CSRF_COOKIE_NAME, bogus)
    resp = await admin_client.post(
        "/api/v1/threat-intel/feeds/test-feed/poll",
        headers={CSRF_HEADER_NAME: bogus},
    )
    assert resp.status_code == 403
    assert resp.json() == {"error": "csrf_token_mismatch"}


@pytest.mark.asyncio
async def test_post_with_valid_double_submit_passes(
    admin_client: AsyncClient,
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Matching cookie + header + valid HMAC → middleware lets the request through."""
    # GET primes the csrf_token cookie.
    get_resp = await admin_client.get("/api/v1/health")
    csrf_tok = get_resp.headers[CSRF_HEADER_NAME]

    # Force the cookie to the token we just received (httpx autostores it
    # but we pin explicitly for the test).
    admin_client.cookies.set(CSRF_COOKIE_NAME, csrf_tok)

    resp = await admin_client.post(
        "/api/v1/threat-intel/feeds/test-feed/poll",
        headers={CSRF_HEADER_NAME: csrf_tok},
    )
    # The endpoint itself may 404 (no such feed configured) or 202 —
    # but it must NOT be 403 from the CSRF middleware.
    assert resp.status_code != 403, (
        f"CSRF middleware should have passed request through; got "
        f"403 with body {resp.text[:200]}"
    )


@pytest.mark.asyncio
async def test_bearer_auth_bypasses_csrf(
    fake_redis: fakeredis.aioredis.FakeRedis,
) -> None:
    """Bearer-token callers are exempt — browsers can't forge Authorization header."""
    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)
    ac = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )
    try:
        async with ac:
            # No CSRF cookie, no CSRF header, but presents a bearer
            # (even a bogus one) — CSRF must not 403. The downstream
            # auth check will 401 because the bearer doesn't validate,
            # but that's the auth layer's job, not CSRF.
            resp = await ac.post(
                "/api/v1/threat-intel/feeds/test-feed/poll",
                headers={"Authorization": "Bearer totally-bogus"},
            )
            # Middleware must not 403.
            assert resp.status_code != 403 or resp.json() != {
                "error": "csrf_token_mismatch"
            }, f"CSRF should be bypassed for Bearer: got {resp.status_code} {resp.text[:200]}"
    finally:
        await _redis_module.close_redis()


@pytest.mark.asyncio
async def test_non_api_routes_are_unaffected(
    admin_client: AsyncClient,
) -> None:
    """POST /auth/logout is not under /api/v1/ → CSRF middleware no-ops."""
    resp = await admin_client.post("/auth/logout", follow_redirects=False)
    # Not a 403 from CSRF — it should redirect (302) or succeed.
    assert resp.status_code in (200, 302), resp.text
