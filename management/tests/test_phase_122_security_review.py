"""Phase 122 — Production Security Review regression tests.

Covers all findings from the internet-facing attack surface audit:

C-1: OpenAPI docs disabled in production
C-2: X-Forwarded-For trusted only from configured proxy CIDRs
H-1: CORS wildcard rejected in production
H-2: Login rate limiter fails closed on Redis errors
H-3: No f-string logging in proxy.py (regression scan)
H-4: Webhook dispatcher reuses authenticated Redis client (Go — tested separately)
H-5: OIDC test-mode signature bypass removed
M-1: SAML strict=false rejected in production
M-2: Analytics Redis URL constructed without password in f-string
M-3: Login page loads no external CDN resources
M-4: TAP enforcement bridge verifies HMAC on pub/sub messages
M-5: Health server defaults to 127.0.0.1
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── C-1: OpenAPI docs disabled in production ─────────────────────────────────


class TestOpenAPIDocsDisabledInProduction:
    """OpenAPI/Swagger docs must not be served in production."""

    def test_docs_disabled_when_environment_is_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "unit-test-secret-at-least-32-characters-long")
        monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "test")
        monkeypatch.delenv("MANAGEMENT_TEST_MODE", raising=False)
        monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)
        monkeypatch.delenv("MANAGEMENT_SAML_STRICT", raising=False)

        from management.api.main import create_app

        app = create_app()
        assert app.docs_url is None
        assert app.redoc_url is None
        assert app.openapi_url is None

    def test_docs_available_in_dev(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "dev")
        monkeypatch.setenv("MANAGEMENT_TEST_MODE", "1")
        monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "unit-test-secret-at-least-32-characters-long")
        monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "test")
        monkeypatch.setenv("MANAGEMENT_DISABLE_CSRF", "1")

        from management.api.main import create_app

        app = create_app()
        assert app.docs_url == "/api/docs"
        assert app.redoc_url == "/api/redoc"


# ── C-2: X-Forwarded-For trusted only from configured proxy CIDRs ────────────


class TestXFFTrustedProxyCheck:
    """X-Forwarded-For must only be trusted from configured proxy CIDRs."""

    def test_xff_ignored_when_no_trusted_cidrs_configured(self):
        from management.api.auth import _client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "10.0.0.1"}
        request.client = MagicMock()
        request.client.host = "192.168.1.100"

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MANAGEMENT_TRUSTED_PROXY_CIDRS", None)
            ip = _client_ip(request)

        assert ip == "192.168.1.100"

    def test_xff_trusted_when_peer_in_cidr(self):
        from management.api.auth import _client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "203.0.113.50, 10.0.0.1"}
        request.client = MagicMock()
        request.client.host = "10.0.0.1"

        with patch.dict(
            os.environ, {"MANAGEMENT_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}
        ):
            ip = _client_ip(request)

        assert ip == "203.0.113.50"

    def test_xff_rejected_when_peer_not_in_cidr(self):
        from management.api.auth import _client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "127.0.0.1"}
        request.client = MagicMock()
        request.client.host = "203.0.113.99"

        with patch.dict(
            os.environ, {"MANAGEMENT_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"}
        ):
            ip = _client_ip(request)

        assert ip == "203.0.113.99"

    def test_xff_multiple_cidrs(self):
        from management.api.auth import _client_ip

        request = MagicMock()
        request.headers = {"X-Forwarded-For": "203.0.113.50"}
        request.client = MagicMock()
        request.client.host = "172.16.0.5"

        with patch.dict(
            os.environ,
            {"MANAGEMENT_TRUSTED_PROXY_CIDRS": "10.0.0.0/8, 172.16.0.0/12"},
        ):
            ip = _client_ip(request)

        assert ip == "203.0.113.50"

    def test_socket_ip_returned_when_no_xff(self):
        from management.api.auth import _client_ip

        request = MagicMock()
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "192.168.1.50"

        ip = _client_ip(request)
        assert ip == "192.168.1.50"


# ── H-2: Rate limiter fails closed ──────────────────────────────────────────


class TestRateLimiterFailsClosed:
    """Login rate limiter must return 503 when Redis is unavailable."""

    @pytest.mark.asyncio
    async def test_check_rate_limit_raises_503_on_redis_error(self):
        from fastapi import HTTPException

        from management.api.auth import _check_rate_limit

        mock_redis = AsyncMock()
        mock_redis.ttl.side_effect = ConnectionError("Redis down")

        with pytest.raises(HTTPException) as exc_info:
            await _check_rate_limit("1.2.3.4", mock_redis)

        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_record_failure_raises_503_on_redis_error(self):
        from fastapi import HTTPException

        from management.api.auth import _record_failure

        mock_redis = AsyncMock()
        mock_redis.incr.side_effect = ConnectionError("Redis down")

        with pytest.raises(HTTPException) as exc_info:
            await _record_failure("1.2.3.4", mock_redis)

        assert exc_info.value.status_code == 503


# ── H-3: No f-string logging in proxy.py ─────────────────────────────────────
#
# REMOVED (phase-806): proxy.py (the Python proxy) was deleted when the Go
# rewrite (Phase 15) became the sole production proxy. The f-string-logging
# anti-pattern this guarded against is Python-specific and has no Go
# equivalent to port a test to — Go's log/slog doesn't have this failure mode.

# ── H-5: OIDC test-mode bypass removed ───────────────────────────────────────


class TestOIDCTestModeBypassRemoved:
    """_extract_claims must not skip signature verification in test mode."""

    def test_no_test_mode_branch_in_extract_claims(self):
        import inspect

        from management.api.routes.oidc import _extract_claims

        source = inspect.getsource(_extract_claims)
        assert "is_test_mode" not in source, (
            "_extract_claims still contains test-mode bypass. "
            "All environments must verify ID token signatures."
        )
        assert "Test mode" not in source, (
            "_extract_claims still contains test-mode bypass comment. "
            "All environments must verify ID token signatures via JWKS."
        )


# ── M-1: SAML strict production guard ───────────────────────────────────────


class TestSAMLStrictProductionGuard:
    """MANAGEMENT_SAML_STRICT=false must be rejected in production."""

    def test_saml_strict_false_rejected_in_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("MANAGEMENT_SAML_STRICT", "false")
        monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "unit-test-secret-at-least-32-characters-long")
        monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "test")
        monkeypatch.delenv("MANAGEMENT_TEST_MODE", raising=False)
        monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)

        from management.api.main import create_app

        with pytest.raises(RuntimeError, match="SAML_STRICT"):
            create_app()

    def test_saml_strict_true_allowed_in_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("MANAGEMENT_SAML_STRICT", "true")
        monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "unit-test-secret-at-least-32-characters-long")
        monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "test")
        monkeypatch.delenv("MANAGEMENT_TEST_MODE", raising=False)
        monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)

        from management.api.main import create_app

        app = create_app()
        assert app is not None


# ── M-2: Analytics Redis URL no password in f-string ─────────────────────────


class TestAnalyticsRedisURL:
    """Analytics node must not embed Redis password in f-string."""

    def test_no_password_fstring_in_analytics_main(self):
        analytics_path = (
            Path(__file__).resolve().parents[2] / "src" / "analytics" / "main.py"
        )
        content = analytics_path.read_text()
        assert "redis://:" not in content, (
            "Analytics main.py still constructs Redis URL with password in f-string. "
            "Use urllib.parse.urlunparse with discrete parameters."
        )


# ── M-3: Login page loads no external CDN resources ─────────────────────────


class TestLoginPageNoExternalCDN:
    """Login page must not load JavaScript or CSS from external CDNs."""

    def test_no_cdn_references_in_login_template(self):
        template_path = (
            Path(__file__).resolve().parents[2]
            / "management"
            / "templates"
            / "login.html"
        )
        content = template_path.read_text()
        assert "cdn.tailwindcss.com" not in content, (
            "Login page still loads Tailwind CSS from external CDN"
        )
        assert "unpkg.com" not in content, (
            "Login page still loads Alpine.js from external CDN"
        )
        assert "integrity=" not in content or "sha384-" not in content.split("integrity=")[0].split(">")[-1], (
            "Login page contains a suspicious SRI hash"
        )


# ── M-4: TAP enforcement bridge HMAC verification ───────────────────────────
#
# REMOVED (phase-806): src/tap/enforcement_bridge.py (Python TAP mode, Phase
# 20) was deleted when Phase 316 replaced it with the Go TAP sensor
# (cmd/ja4-tap, internal/tap/). This is NOT a like-for-like port: grep across
# internal/tap/*.go and cmd/ja4-tap/main.go finds zero pub/sub subscription
# anywhere — the Go sensor only ever writes findings/bans to Redis, it never
# consumes externally-published ban commands the way EnforcementBridge did
# (subscribe to ja4proxy:bans, HMAC-verify, fan out to iptables/BGP/webhook).
# That capability appears to be a genuine gap, not a rename — flagged for
# tracking (see docs/phases/PHASE_803.md or a new finding), not something
# phase-806 resolves. There is no Go code to write a replacement test against.

# ── M-5: Health server defaults to 127.0.0.1 ────────────────────────────────
#
# REMOVED (phase-806): src/security/health.py (Python) was deleted; the Go
# TAP sensor's equivalent (cmd/ja4-tap/main.go, -metrics-addr flag) has no
# hardcoded default at all — the server doesn't start unless an address is
# explicitly supplied (empty = disabled), which is arguably a stronger
# secure-by-default posture than the old hardcoded "127.0.0.1" fallback.
# No default-binding logic exists to write an equivalent test against.

# ── H-1: CORS wildcard rejected in production ────────────────────────────────


class TestCORSWildcardRejectedInProduction:
    """CORS wildcard '*' must be rejected when credentials are enabled in production."""

    def test_cors_wildcard_raises_in_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("MANAGEMENT_CORS_ORIGINS", "*")
        monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "unit-test-secret-at-least-32-characters-long")
        monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "test")
        monkeypatch.delenv("MANAGEMENT_TEST_MODE", raising=False)
        monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)
        monkeypatch.delenv("MANAGEMENT_SAML_STRICT", raising=False)

        from management.api.main import create_app

        with pytest.raises(RuntimeError, match="wildcard"):
            create_app()

    def test_cors_explicit_origins_allowed_in_production(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("MANAGEMENT_CORS_ORIGINS", "https://mgmt.example.com")
        monkeypatch.setenv("MANAGEMENT_JWT_SECRET", "unit-test-secret-at-least-32-characters-long")
        monkeypatch.setenv("MANAGEMENT_ADMIN_PASSWORD", "test")
        monkeypatch.delenv("MANAGEMENT_TEST_MODE", raising=False)
        monkeypatch.delenv("MANAGEMENT_DISABLE_CSRF", raising=False)
        monkeypatch.delenv("MANAGEMENT_SAML_STRICT", raising=False)

        from management.api.main import create_app

        app = create_app()
        assert app is not None
