"""Regression tests for JA4PROXY-2026-0024 — JWT cookie Secure flag not gated.

management/api/auth.py used to hardcode ``secure=False`` on the login cookie
regardless of environment or transport. In production — especially when TLS
terminates at an HAProxy front door and the app receives plaintext HTTP —
that meant the session cookie could be intercepted by anyone with a
network tap.

The hardening is a shared helper ``_should_set_secure_cookie(request)``
that returns True whenever the current request is HTTPS *or* the
deployment is marked as production. The local login, OIDC callback, and
SAML callback all use it, so all three cookie paths honour the same rule.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("MANAGEMENT_JWT_SECRET", "test-secret-do-not-use-in-production")
os.environ.setdefault("MANAGEMENT_ADMIN_USER", "admin")
os.environ.setdefault("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
os.environ.setdefault("MANAGEMENT_TEST_MODE", "1")

from management.api.auth import _should_set_secure_cookie  # noqa: E402


def _request_with_scheme(scheme: str) -> MagicMock:
    req = MagicMock()
    req.url = SimpleNamespace(scheme=scheme)
    return req


def test_regression_JA4PROXY_2026_0024_secure_on_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert _should_set_secure_cookie(_request_with_scheme("https")) is True


def test_regression_JA4PROXY_2026_0024_secure_on_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # TLS-terminating reverse proxy forwards as HTTP — cookie must still be
    # marked Secure because ENVIRONMENT=production.
    for env_val in ("production", "PRODUCTION", "prod"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        assert (
            _should_set_secure_cookie(_request_with_scheme("http")) is True
        ), f"ENVIRONMENT={env_val!r} must force secure cookies even on HTTP"


def test_regression_JA4PROXY_2026_0093_secure_on_unset_or_unrecognised_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JA4PROXY-2026-0093: unset/unrecognised ENVIRONMENT is production, so
    this hardening now also forces Secure for those values on plain HTTP —
    strictly safer than the pre-fix behaviour, which treated them as dev."""
    for env_val in ("", "staging", "dmz"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        assert (
            _should_set_secure_cookie(_request_with_scheme("http")) is True
        ), f"ENVIRONMENT={env_val!r} must be treated as production (fail closed)"


def test_regression_JA4PROXY_2026_0024_not_secure_on_dev_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Local dev over http://localhost must still allow the cookie through
    # (browsers reject Secure cookies on plain HTTP) — only for an EXPLICIT
    # dev/test ENVIRONMENT (JA4PROXY-2026-0093).
    for env_val in ("dev", "development", "test", "testing", "local", "ci"):
        monkeypatch.setenv("ENVIRONMENT", env_val)
        assert (
            _should_set_secure_cookie(_request_with_scheme("http")) is False
        ), f"ENVIRONMENT={env_val!r} on plain HTTP must leave Secure off"


def test_regression_JA4PROXY_2026_0024_login_endpoint_emits_secure_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: POST /auth/login in production must emit Secure on cookie."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    # JA4PROXY-2026-0096: must be >= 32 chars or create_app()'s secret-strength
    # guard rejects it before this test's actual assertion runs.
    monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "unit-test-production-secret-32chars")
    monkeypatch.setenv("MANAGEMENT_ADMIN_USER", "admin")
    monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "testpassword")
    monkeypatch.delenv("MANAGEMENT_TEST_MODE", raising=False)
    # phase-101 H8: prod create_app rejects MANAGEMENT_DISABLE_CSRF too.
    monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)
    # phase-122 M-1: prod create_app rejects MANAGEMENT_SAML_STRICT=false.
    monkeypatch.delenv("MANAGEMENT_SAML_STRICT", raising=False)

    # Import after env is set so create_app honours the prod config.
    import fakeredis
    import fakeredis.aioredis
    from fastapi.testclient import TestClient

    from management.api import redis_client as _redis_module
    from management.api.main import create_app

    server = fakeredis.FakeServer()
    fake_r = fakeredis.aioredis.FakeRedis(server=server, decode_responses=True)
    _redis_module._redis_client = fake_r

    app = create_app()
    with TestClient(app) as client:
        r = client.post(
            "/auth/login",
            data={"username": "admin", "password": "testpassword"},
            follow_redirects=False,
        )
        assert r.status_code in (200, 302), r.text
        set_cookie_header = r.headers.get("set-cookie", "")
        assert "token=" in set_cookie_header
        assert (
            "Secure" in set_cookie_header
        ), f"Secure flag missing in production Set-Cookie: {set_cookie_header!r}"
        assert "HttpOnly" in set_cookie_header

    _redis_module._redis_client = None
