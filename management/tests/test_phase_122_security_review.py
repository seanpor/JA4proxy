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

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

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


class TestNoFStringLogging:
    """proxy.py must not contain f-string logging calls (Phase 18 standard)."""

    def test_no_fstring_logging_in_proxy(self):
        proxy_path = Path(__file__).resolve().parents[2] / "proxy.py"
        content = proxy_path.read_text()
        pattern = re.compile(r'self\.logger\.\w+\(f["\']')
        matches = pattern.findall(content)
        assert len(matches) == 0, (
            f"Found {len(matches)} f-string logging calls in proxy.py. "
            "Use lazy %s formatting per AGENTS.md Phase 18."
        )


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


class TestEnforcementBridgeHMAC:
    """Enforcement bridge must verify HMAC on pub/sub messages."""

    def _make_bridge(self, hmac_secret: str = "test-hmac-secret"):
        from src.tap.enforcement_bridge import EnforcementBridge

        config = {
            "security": {"pubsub_hmac_secret": hmac_secret},
            "tap_enforcement": {},
        }
        mock_redis = MagicMock()
        return EnforcementBridge(config, mock_redis)

    def _sign_message(self, secret: str, msg_type: str, value: str) -> str:
        data = f"{msg_type}:{value}".encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        envelope = {"type": msg_type, "value": value, "signature": sig}
        return json.dumps(envelope)

    def test_valid_hmac_accepted(self):
        bridge = self._make_bridge("my-secret")
        value = json.dumps({"ip": "1.2.3.4", "ttl": 3600, "reason": "test"})
        signed = self._sign_message("my-secret", "ja4proxy:bans", value)
        envelope = json.loads(signed)
        assert bridge._verify_hmac(envelope) is True

    def test_invalid_hmac_rejected(self):
        bridge = self._make_bridge("my-secret")
        envelope = {
            "type": "ja4proxy:bans",
            "value": '{"ip": "1.2.3.4"}',
            "signature": "deadbeef" * 8,
        }
        assert bridge._verify_hmac(envelope) is False

    def test_missing_signature_rejected(self):
        bridge = self._make_bridge("my-secret")
        envelope = {"type": "ja4proxy:bans", "value": '{"ip": "1.2.3.4"}'}
        assert bridge._verify_hmac(envelope) is False

    def test_no_hmac_configured_accepts_all(self):
        bridge = self._make_bridge("")
        envelope = {"ip": "1.2.3.4", "ttl": 3600}
        assert bridge._verify_hmac(envelope) is True

    @pytest.mark.asyncio
    async def test_handle_message_drops_unsigned_when_hmac_configured(self):
        bridge = self._make_bridge("my-secret")
        bridge._on_ban = AsyncMock()

        msg = {"data": json.dumps({"ip": "1.2.3.4", "ttl": 3600, "reason": "test"})}
        await bridge._handle_message(msg)

        bridge._on_ban.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_message_processes_signed_message(self):
        bridge = self._make_bridge("my-secret")
        bridge._on_ban = AsyncMock()

        value = json.dumps({"ip": "1.2.3.4", "ttl": 3600, "reason": "test"})
        signed = self._sign_message("my-secret", "ja4proxy:bans", value)
        msg = {"data": signed}
        await bridge._handle_message(msg)

        bridge._on_ban.assert_called_once_with("1.2.3.4", 3600, "test")


# ── M-5: Health server defaults to 127.0.0.1 ────────────────────────────────


class TestHealthServerBindDefault:
    """Health server must default to 127.0.0.1, not 0.0.0.0."""

    def test_health_server_default_host(self):
        from unittest.mock import MagicMock

        from src.security.health import HealthMonitor, HealthServer

        monitor = HealthMonitor(redis_client=MagicMock(), config={})
        server = HealthServer(monitor=monitor)
        assert server.host == "127.0.0.1"


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
