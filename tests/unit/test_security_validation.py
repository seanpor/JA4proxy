#!/usr/bin/env python3
"""
Dedicated unit tests for security/validation.py

Covers SecurityValidator, SecureHeadersManager, AuditLogger, MTLSManager,
and the exception hierarchy. These are contract/smoke tests that pin the
documented public API without mocking the module under test.
"""

import hashlib
import hmac
import time
from unittest.mock import patch

import pytest

from src.security.validation import (
    AuditLogger,
    ComplianceError,
    MTLSManager,
    SecureHeadersManager,
    SecurityError,
    SecurityValidator,
    ValidationError,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def validator():
    """SecurityValidator with a known CSRF secret and no GeoIP DB path."""
    return SecurityValidator(
        {
            "security": {
                "csrf_secret": "test-secret-for-unit-tests",
                "max_request_size": 1024 * 1024,
                "rate_limit_window": 60,
                "max_requests_per_minute": 100,
            }
        }
    )


@pytest.fixture()
def empty_validator():
    """SecurityValidator with an empty config (no GeoIP path specified)."""
    return SecurityValidator({})


# ---------------------------------------------------------------------------
# SecurityValidator — initialisation
# ---------------------------------------------------------------------------

class TestSecurityValidatorInit:
    """SecurityValidator must initialise cleanly when no GeoIP path is given."""

    def test_init_without_geoip_path(self):
        """No GeoIP path → geo_reader stays None, no exception raised."""
        v = SecurityValidator({})
        assert v.geo_reader is None

    def test_init_with_nonexistent_geoip_path(self):
        """Bad GeoIP path → warning logged, geo_reader stays None, no raise."""
        v = SecurityValidator({"security": {"geoip_database": "/nonexistent/path.mmdb"}})
        assert v.geo_reader is None

    def test_init_stores_config(self, validator):
        assert validator.config["security"]["csrf_secret"] == "test-secret-for-unit-tests"


# ---------------------------------------------------------------------------
# SecurityValidator — CSRF token roundtrip
# ---------------------------------------------------------------------------

class TestCSRFToken:
    """CSRF token generation and validation contract."""

    def test_generate_returns_string(self, validator):
        token = validator.generate_csrf_token("sess-abc")
        assert isinstance(token, str)

    def test_generate_token_has_timestamp_colon_mac(self, validator):
        token = validator.generate_csrf_token("sess-abc")
        parts = token.split(":", 1)
        assert len(parts) == 2
        assert parts[0].isdigit()
        assert len(parts[1]) == 64  # sha256 hex digest

    def test_roundtrip_passes_within_window(self, validator):
        """Token generated now should validate within default max_age (3600s)."""
        token = validator.generate_csrf_token("session-xyz")
        assert validator.validate_csrf_token(token, "session-xyz") is True

    def test_roundtrip_wrong_session_fails(self, validator):
        """Token for session A must not validate against session B."""
        token = validator.generate_csrf_token("session-A")
        assert validator.validate_csrf_token(token, "session-B") is False

    def test_expired_token_fails(self, validator):
        """Token whose embedded timestamp is older than max_age is rejected."""
        old_timestamp = int(time.time()) - 7200  # 2 hours ago
        secret = validator.config["security"]["csrf_secret"]
        message = f"session-exp:{old_timestamp}"
        mac = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
        expired_token = f"{old_timestamp}:{mac}"
        # max_age=3600, token is 7200s old → should fail
        assert validator.validate_csrf_token(expired_token, "session-exp", max_age=3600) is False

    def test_tampered_mac_fails(self, validator):
        """Flipping a single character in the MAC must fail validation."""
        token = validator.generate_csrf_token("sess-tamper")
        timestamp_str, mac = token.split(":", 1)
        # Flip the first character of the HMAC
        bad_char = "0" if mac[0] != "0" else "1"
        tampered = f"{timestamp_str}:{bad_char}{mac[1:]}"
        assert validator.validate_csrf_token(tampered, "sess-tamper") is False

    def test_tampered_timestamp_fails(self, validator):
        """Changing the timestamp makes the HMAC invalid."""
        token = validator.generate_csrf_token("sess-ts")
        timestamp_str, mac = token.split(":", 1)
        new_ts = str(int(timestamp_str) - 1)
        tampered = f"{new_ts}:{mac}"
        assert validator.validate_csrf_token(tampered, "sess-ts") is False

    def test_garbage_token_fails(self, validator):
        assert validator.validate_csrf_token("not-a-valid-token", "sess") is False

    def test_empty_token_fails(self, validator):
        assert validator.validate_csrf_token("", "sess") is False

    def test_none_token_fails(self, validator):
        assert validator.validate_csrf_token(None, "sess") is False  # type: ignore[arg-type]

    def test_different_sessions_produce_different_tokens(self, validator):
        t1 = validator.generate_csrf_token("sess-1")
        t2 = validator.generate_csrf_token("sess-2")
        assert t1 != t2

    def test_repeated_calls_produce_same_mac_within_same_second(self, validator):
        """Two tokens generated in the same second with the same session share the MAC."""
        # Freeze time so both calls return identical timestamps
        fixed_ts = int(time.time())
        with patch("src.security.validation.time") as mock_time:
            mock_time.time.return_value = float(fixed_ts)
            t1 = validator.generate_csrf_token("sess-same")
            t2 = validator.generate_csrf_token("sess-same")
        assert t1 == t2


# ---------------------------------------------------------------------------
# SecurityValidator — input validation (XSS / injection via JA4 endpoint)
# ---------------------------------------------------------------------------

class TestJA4FingerprintValidation:
    """validate_ja4_fingerprint rejects malicious input and allows valid format."""

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "';alert(1)//",
    ]

    INJECTION_PAYLOADS = [
        "'; DROP TABLE users; --",
        "| whoami",
        "$(uname -a)",
        '{"$ne": null}',
    ]

    VALID_FINGERPRINTS = [
        "t13d1516h2_8daaf6152771_02713d6af862",
        "t13d1516h2_acb858a92adb_1a2b3c4d5e6f",
        "q02d0000h0_aabbccddeeff_112233445566",
    ]

    def test_xss_payloads_rejected(self, validator):
        for payload in self.XSS_PAYLOADS:
            with pytest.raises(ValidationError, match="Invalid JA4 format|Fingerprint"):
                validator.validate_ja4_fingerprint(payload)

    def test_injection_payloads_rejected(self, validator):
        for payload in self.INJECTION_PAYLOADS:
            with pytest.raises(ValidationError):
                validator.validate_ja4_fingerprint(payload)

    def test_non_string_raises_validation_error(self, validator):
        with pytest.raises(ValidationError, match="must be string"):
            validator.validate_ja4_fingerprint(12345)  # type: ignore[arg-type]

    def test_oversized_string_raises_validation_error(self, validator):
        with pytest.raises(ValidationError):
            validator.validate_ja4_fingerprint("t" * 200)

    def test_empty_string_raises_validation_error(self, validator):
        with pytest.raises(ValidationError):
            validator.validate_ja4_fingerprint("")

    @pytest.mark.parametrize("fp", VALID_FINGERPRINTS)
    def test_valid_fingerprint_accepted(self, validator, fp):
        # validate_ja4_fingerprint returns True or False (False for anomalous patterns).
        # It must NOT raise for a well-formed fingerprint.
        result = validator.validate_ja4_fingerprint(fp)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# SecurityValidator — HTTP header sanitisation
# ---------------------------------------------------------------------------

class TestHTTPHeaderValidation:
    """validate_http_headers cleans malicious values and drops bad names."""

    def test_clean_headers_pass_through(self, validator):
        headers = {"X-Custom-Header": "safe value", "Content-Type": "application/json"}
        result = validator.validate_http_headers(headers)
        assert result["content-type"] == "application/json"

    def test_control_characters_stripped(self, validator):
        headers = {"X-Bad": "value\x00with\x1fnull"}
        result = validator.validate_http_headers(headers)
        assert "\x00" not in result["x-bad"]
        assert "\x1f" not in result["x-bad"]

    def test_header_names_lowercased(self, validator):
        headers = {"X-UPPERCASE": "val"}
        result = validator.validate_http_headers(headers)
        assert "x-uppercase" in result

    def test_invalid_header_name_dropped(self, validator):
        """Header names with special chars (space, colon, etc.) are dropped."""
        headers = {"bad header!": "value", "Good-Header": "ok"}
        result = validator.validate_http_headers(headers)
        assert "bad header!" not in result
        assert "good-header" in result

    def test_oversized_header_value_truncated(self, validator):
        long_value = "x" * 9000
        headers = {"X-Long": long_value}
        result = validator.validate_http_headers(headers)
        assert len(result["x-long"]) <= 8192

    def test_empty_headers_returns_empty_dict(self, validator):
        assert validator.validate_http_headers({}) == {}


# ---------------------------------------------------------------------------
# SecurityValidator — request size validation
# ---------------------------------------------------------------------------

class TestRequestSizeValidation:
    def test_size_within_limit_allowed(self, validator):
        assert validator.validate_request_size(1024) is True

    def test_size_at_limit_allowed(self, validator):
        max_size = 1024 * 1024
        assert validator.validate_request_size(max_size) is True

    def test_size_over_limit_raises(self, validator):
        with pytest.raises(SecurityError, match="too large"):
            validator.validate_request_size(1024 * 1024 + 1)

    def test_default_max_size_applied_when_not_configured(self, empty_validator):
        """Without config, default 1 MiB applies."""
        assert empty_validator.validate_request_size(512) is True
        with pytest.raises(SecurityError):
            empty_validator.validate_request_size(1024 * 1024 + 1)


# ---------------------------------------------------------------------------
# SecurityValidator — IP address validation
# ---------------------------------------------------------------------------

class TestIPAddressValidation:
    def test_valid_public_ipv4_accepted(self, validator):
        assert validator.validate_ip_address("8.8.8.8", check_reputation=False) is True

    def test_valid_public_ipv6_accepted(self, validator):
        assert validator.validate_ip_address("2001:db8::1", check_reputation=False) is True

    def test_invalid_ip_raises_validation_error(self, validator):
        with pytest.raises(ValidationError, match="Invalid IP"):
            validator.validate_ip_address("not-an-ip", check_reputation=False)

    def test_private_ip_blocked_when_configured(self):
        v = SecurityValidator({"security": {"block_private_ips": True}})
        with pytest.raises(SecurityError, match="Private"):
            v.validate_ip_address("192.168.1.1", check_reputation=False)

    def test_private_ip_allowed_when_not_configured(self, validator):
        """Default config does not set block_private_ips → private IPs pass."""
        result = validator.validate_ip_address("192.168.1.1", check_reputation=False)
        assert result is True


# ---------------------------------------------------------------------------
# SecurityValidator — geo blocking (no GeoIP reader → fail open)
# ---------------------------------------------------------------------------

class TestGeoBlocking:
    def test_no_geo_reader_returns_true(self, validator):
        """Without a GeoIP DB the check must fail open."""
        assert validator.geo_reader is None
        assert validator.check_geo_blocking("1.2.3.4") is True


# ---------------------------------------------------------------------------
# SecureHeadersManager
# ---------------------------------------------------------------------------

class TestSecureHeadersManager:
    @pytest.fixture()
    def manager(self):
        return SecureHeadersManager({})

    def test_returns_dict(self, manager):
        assert isinstance(manager.get_security_headers(), dict)

    def test_x_content_type_nosniff(self, manager):
        h = manager.get_security_headers()
        assert h.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options_deny(self, manager):
        h = manager.get_security_headers()
        assert h.get("X-Frame-Options") == "DENY"

    def test_hsts_present(self, manager):
        h = manager.get_security_headers()
        assert "Strict-Transport-Security" in h
        assert "max-age=31536000" in h["Strict-Transport-Security"]

    def test_csp_present_and_restrictive(self, manager):
        h = manager.get_security_headers()
        csp = h.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp

    def test_xss_protection_header(self, manager):
        h = manager.get_security_headers()
        assert "X-XSS-Protection" in h

    def test_referrer_policy_present(self, manager):
        h = manager.get_security_headers()
        assert "Referrer-Policy" in h


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

class TestAuditLogger:
    """AuditLogger checksum and event-logging contract."""

    @pytest.fixture()
    def audit(self, tmp_path):
        log_file = tmp_path / "audit.log"
        return AuditLogger({"logging": {"audit_log_path": str(log_file)}})

    def test_checksum_is_deterministic(self, audit):
        data = {"action": "login", "user": "alice"}
        c1 = audit._calculate_checksum(data)
        c2 = audit._calculate_checksum(data)
        assert c1 == c2

    def test_checksum_changes_on_data_mutation(self, audit):
        data = {"action": "login", "user": "alice"}
        c1 = audit._calculate_checksum(data)
        c2 = audit._calculate_checksum({"action": "logout", "user": "alice"})
        assert c1 != c2

    def test_checksum_is_sha256_hex(self, audit):
        checksum = audit._calculate_checksum({"k": "v"})
        assert len(checksum) == 64
        assert all(c in "0123456789abcdef" for c in checksum)

    def test_log_security_event_does_not_raise(self, audit):
        """log_security_event must not raise for a well-formed call."""
        audit.log_security_event(
            "test_event",
            {"ip": "1.2.3.4", "action": "block"},
            severity="WARNING",
        )

    def test_log_security_event_default_severity(self, audit):
        audit.log_security_event("default_sev", {"x": 1})  # severity defaults to 'INFO'


# ---------------------------------------------------------------------------
# MTLSManager
# ---------------------------------------------------------------------------

class TestMTLSManager:
    """MTLSManager SSL context creation contract."""

    @pytest.fixture()
    def mtls(self):
        return MTLSManager({"tls": {}})

    def test_create_server_context_no_raise(self, mtls):
        import ssl
        ctx = mtls.create_ssl_context(server_side=True)
        assert ctx is not None

    def test_server_context_min_tls_12(self, mtls):
        import ssl
        ctx = mtls.create_ssl_context(server_side=True)
        assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    def test_server_context_max_tls_13(self, mtls):
        import ssl
        ctx = mtls.create_ssl_context(server_side=True)
        assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3

    def test_create_client_context_no_raise(self, mtls):
        ctx = mtls.create_ssl_context(server_side=False)
        assert ctx is not None

    def test_validate_certificate_chain_garbage_returns_false(self, mtls):
        assert mtls.validate_certificate_chain(b"not a certificate") is False

    def test_validate_certificate_chain_empty_returns_false(self, mtls):
        assert mtls.validate_certificate_chain(b"") is False


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_validation_error_is_exception(self):
        with pytest.raises(ValidationError):
            raise ValidationError("bad input")

    def test_security_error_is_exception(self):
        with pytest.raises(SecurityError):
            raise SecurityError("policy violation")

    def test_compliance_error_is_exception(self):
        with pytest.raises(ComplianceError):
            raise ComplianceError("compliance failure")

    def test_all_are_distinct_types(self):
        assert ValidationError is not SecurityError
        assert SecurityError is not ComplianceError
        assert ValidationError is not ComplianceError
