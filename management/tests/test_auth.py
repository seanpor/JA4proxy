"""TDD tests for management API authentication.

Covers
------
- POST /auth/login  (JSON body)
- POST /auth/login  (form body)
- POST /auth/logout
- get_current_user dependency: missing token, expired token, invalid token → 401
- Rate limiting: 5 failures → lockout, 6th request → 429
- Successful login sets httpOnly cookie and redirects
"""

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from httpx import AsyncClient
from jose import jwt


@pytest.mark.asyncio
async def test_login_success_json(test_client: AsyncClient) -> None:
    """Valid credentials via JSON body returns 302 and sets token cookie."""
    response = await test_client.post(
        "/auth/login",
        json={"username": "admin", "password": "testpassword"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "token" in response.cookies
    assert response.headers["location"] == "/"


@pytest.mark.asyncio
async def test_login_success_form(test_client: AsyncClient) -> None:
    """Valid credentials via form body returns 302 and sets token cookie."""
    response = await test_client.post(
        "/auth/login",
        data={"username": "admin", "password": "testpassword"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "token" in response.cookies


@pytest.mark.asyncio
async def test_login_wrong_password(test_client: AsyncClient) -> None:
    """Wrong password returns 401."""
    response = await test_client.post(
        "/auth/login",
        json={"username": "admin", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    assert "Invalid" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_wrong_username(test_client: AsyncClient) -> None:
    """Wrong username returns 401."""
    response = await test_client.post(
        "/auth/login",
        json={"username": "notadmin", "password": "testpassword"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_rate_limit(test_client: AsyncClient) -> None:
    """Five consecutive failures from same IP trigger 429 lockout.

    JA4PROXY-2026-0021 — the limiter state lives in Redis now, and the
    fake_redis fixture is fresh-per-test, so no manual cleanup is needed.
    """
    # Send 5 failing requests
    for _ in range(5):
        r = await test_client.post(
            "/auth/login",
            json={"username": "admin", "password": "bad"},
        )
        # First 4 fail with 401, 5th may be 401 or 429 depending on timing
        assert r.status_code in (401, 429)

    # 6th attempt must be locked out
    r = await test_client.post(
        "/auth/login",
        json={"username": "admin", "password": "bad"},
    )
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_logout(authenticated_client: AsyncClient) -> None:
    """Logout clears the auth cookie and redirects to /login."""
    response = await authenticated_client.post(
        "/auth/logout",
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/login" in response.headers["location"]
    # Cookie should be cleared (empty or deleted)
    if "token" in response.cookies:
        assert response.cookies["token"] == ""


@pytest.mark.asyncio
async def test_protected_route_no_token(test_client: AsyncClient) -> None:
    """Protected route without token returns 401."""
    response = await test_client.get(
        "/api/v1/dial",
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_invalid_token(test_client: AsyncClient) -> None:
    """Protected route with invalid token returns 401."""
    response = await test_client.get(
        "/api/v1/dial",
        cookies={"token": "this.is.not.a.valid.jwt"},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_expired_token(test_client: AsyncClient) -> None:
    """Protected route with expired token returns 401."""
    from management.api.auth import ALGORITHM, _get_secret_key

    expired_payload = {
        "sub": "admin",
        "iat": datetime.now(timezone.utc) - timedelta(hours=10),
        "exp": datetime.now(timezone.utc) - timedelta(hours=2),
    }
    expired_token = jwt.encode(expired_payload, _get_secret_key(), algorithm=ALGORITHM)

    response = await test_client.get(
        "/api/v1/dial",
        cookies={"token": expired_token},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_wrong_secret(test_client: AsyncClient) -> None:
    """Token signed with wrong secret returns 401."""
    from datetime import datetime, timedelta, timezone

    from management.api.auth import ALGORITHM

    payload = {
        "sub": "admin",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    bad_token = jwt.encode(payload, "wrong-secret", algorithm=ALGORITHM)

    response = await test_client.get(
        "/api/v1/dial",
        cookies={"token": bad_token},
        headers={"Accept": "application/json"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_cookie_is_httponly(test_client: AsyncClient) -> None:
    """The token cookie must be httpOnly (not accessible via JS)."""
    response = await test_client.post(
        "/auth/login",
        json={"username": "admin", "password": "testpassword"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    # httpx stores the raw Set-Cookie header; check it contains HttpOnly
    set_cookie = response.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower()


@pytest.mark.asyncio
async def test_valid_token_allows_access(authenticated_client: AsyncClient) -> None:
    """Valid token allows access to protected endpoints."""
    response = await authenticated_client.get("/api/v1/dial")
    # Should succeed (200) or at most return a data-level error, not 401
    assert response.status_code != 401


# ── Bearer token auth middleware — additions for MFA/SSO Hardening Cluster 1 ───────────
#
# These tests document how the bearer token middleware interacts with the
# existing cookie-based auth path.  They are expected to FAIL until the
# bearer token implementation is in place.


@pytest.mark.asyncio
async def test_bearer_takes_precedence_over_cookie(
    authenticated_client: AsyncClient,
    fake_redis,
) -> None:
    """Bearer token wins over cookie; identity attributed to token, not admin session."""
    create_resp = await authenticated_client.post(
        "/api/v1/tokens",
        json={"name": "precedence-check", "role": "admin"},
    )
    assert create_resp.status_code == 201
    plaintext = create_resp.json()["token"]
    token_name = create_resp.json()["name"]

    # Issue a mutating action so an audit entry is written under the bearer identity.
    # Must use an admin-role token because PUT/PATCH dial requires admin.
    response = await authenticated_client.patch(
        "/api/v1/dial",
        json={"value": 5},
        headers={"Authorization": f"Bearer {plaintext}", "Accept": "application/json"},
    )
    assert response.status_code == 200

    # The audit log must attribute the action to the token identity, not "admin"
    import json as _json
    raw_entries = await fake_redis.lrange("management:audit_log", 0, 0)
    assert raw_entries, "No audit log entry was written"
    entry = _json.loads(raw_entries[0])
    # MFA/SSO Hardening C5: enhanced audit schema uses actor_id, not user
    assert entry.get("actor_id") != "admin", (
        f"Audit log actor_id is 'admin' — bearer identity did not take precedence. Entry: {entry}"
    )
    assert token_name in entry.get("actor_id", "") or "token:" in entry.get("actor_id", ""), (
        f"Expected audit log actor_id to reference the token identity, got: {entry.get('actor_id')}"
    )


@pytest.mark.asyncio
async def test_expired_cookie_valid_bearer_succeeds(fake_redis) -> None:
    """Expired cookie + valid Bearer token → 200. Expired cookie alone → 401.

    The middleware must fall through from expired cookie to bearer auth,
    not short-circuit on cookie failure.
    """
    from datetime import datetime, timedelta, timezone

    from httpx import ASGITransport
    from jose import jwt

    from management.api import redis_client as _redis_module
    from management.api.auth import ALGORITHM, _create_access_token, _get_secret_key
    from management.api.main import create_app
    from management.tests.test_tokens import _create_token

    expired_payload = {
        "sub": "admin",
        "iat": datetime.now(timezone.utc) - timedelta(hours=10),
        "exp": datetime.now(timezone.utc) - timedelta(hours=2),
    }
    expired_cookie = jwt.encode(expired_payload, _get_secret_key(), algorithm=ALGORITHM)

    app = create_app()
    await _redis_module.init_redis(override_client=fake_redis)

    # Seed a valid bearer token
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        cookies={"token": _create_access_token("admin")},
    ) as admin_client:
        created = await _create_token(admin_client, name="fallthrough-bearer")
        valid_bearer = created["token"]

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        # Expired cookie alone → 401
        r1 = await client.get(
            "/api/v1/dial",
            cookies={"token": expired_cookie},
            headers={"Accept": "application/json"},
        )
        assert r1.status_code == 401

        # Expired cookie + bad bearer → 401
        r2 = await client.get(
            "/api/v1/dial",
            cookies={"token": expired_cookie},
            headers={"Authorization": "Bearer not-a-real-token", "Accept": "application/json"},
        )
        assert r2.status_code == 401

        # Expired cookie + valid bearer → 200 (the load-bearing assertion)
        r3 = await client.get(
            "/api/v1/dial",
            cookies={"token": expired_cookie},
            headers={"Authorization": f"Bearer {valid_bearer}", "Accept": "application/json"},
        )
        assert r3.status_code == 200, (
            f"Expired cookie + valid bearer must return 200; got {r3.status_code}. "
            "Middleware must fall through from cookie failure to bearer auth."
        )

    await _redis_module.close_redis()
