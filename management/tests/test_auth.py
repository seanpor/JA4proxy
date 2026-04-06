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
    """Five consecutive failures from same IP trigger 429 lockout."""
    from management.api.auth import _login_failures

    # Clear any existing state for this test's IP
    _login_failures.pop("testclient", None)
    _login_failures.pop("unknown", None)

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
    from management.api.auth import ALGORITHM
    from datetime import datetime, timedelta, timezone

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
