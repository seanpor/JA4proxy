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
from unittest.mock import MagicMock, patch

from cryptography import x509

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


# ---------------------------------------------------------------------------
# Phase 104 — coverage gap closure
# ---------------------------------------------------------------------------


class TestFingerprintEdgeCases:
    """Cover lines 58, 62-63: length check before regex, anomaly logging."""

    def test_long_but_valid_format_raises(self, validator):
        """Line 58: fingerprint > 100 chars is rejected even if it starts valid."""
        # Build a string that exceeds 100 chars
        long_fp = "t13d1516h2_8daaf6152771_02713d6af862" + "x" * 100
        with pytest.raises(ValidationError, match="Invalid JA4 format"):
            validator.validate_ja4_fingerprint(long_fp)

    def test_anomalous_all_zeros_hash_returns_false(self, validator):
        """Lines 62-63: anomalous fingerprint (all-zero hashes) → returns False."""
        # This matches the all-zeros hash pattern in _detect_fingerprint_anomalies
        fp = "t13d1516h2_000000000000_000000000000"
        result = validator.validate_ja4_fingerprint(fp)
        assert result is False

    def test_anomalous_all_fs_hash_returns_false(self, validator):
        """Anomalous fingerprint (all-f hashes) → returns False."""
        fp = "t13d1516h2_ffffffffffff_ffffffffffff"
        result = validator.validate_ja4_fingerprint(fp)
        assert result is False

    def test_low_entropy_hash_returns_false(self, validator):
        """Lines 193-195: hash part with < 3 unique chars → anomalous."""
        fp = "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb"
        result = validator.validate_ja4_fingerprint(fp)
        assert result is False


class TestIPReputationCheck:
    """Cover line 83: check_reputation=True triggers _check_ip_reputation."""

    def test_reputation_flagged_raises_security_error(self, validator):
        """Line 83: _check_ip_reputation returns True → SecurityError."""
        with patch.object(validator, "_check_ip_reputation", return_value=True):
            with pytest.raises(SecurityError, match="flagged"):
                validator.validate_ip_address("1.2.3.4", check_reputation=True)

    def test_reputation_clean_passes(self, validator):
        """check_reputation=True but IP is clean → returns True."""
        result = validator.validate_ip_address("8.8.8.8", check_reputation=True)
        assert result is True

    def test_reputation_uses_cache(self, validator):
        """Lines 203-204: cached result is used on second call."""
        validator.threat_intel_cache["10.0.0.1"] = {"malicious": True, "timestamp": time.time()}
        with pytest.raises(SecurityError):
            validator.validate_ip_address("10.0.0.1", check_reputation=True)

    def test_loopback_blocked_when_configured(self):
        """Line 78-79: loopback is_loopback → SecurityError."""
        v = SecurityValidator({"security": {"block_private_ips": True}})
        with pytest.raises(SecurityError, match="Private"):
            v.validate_ip_address("127.0.0.1", check_reputation=False)

    def test_reserved_ip_blocked_when_configured(self):
        """is_reserved → SecurityError."""
        v = SecurityValidator({"security": {"block_private_ips": True}})
        with pytest.raises(SecurityError, match="Private"):
            v.validate_ip_address("240.0.0.1", check_reputation=False)


class TestRateLimitEdgeCases:
    """Cover lines 141-143: rate limit Redis error → fail open."""

    def test_redis_error_fails_open(self, validator):
        """Lines 141-143: Redis pipeline raises → returns True (fail open)."""
        mock_redis = MagicMock()
        mock_redis.pipeline.side_effect = Exception("connection refused")
        result = validator.check_rate_limit("1.2.3.4", mock_redis)
        assert result is True

    def test_rate_limit_exceeded(self, validator):
        """Lines 135-137: count > max → returns False."""
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        mock_pipe.execute.return_value = [200, True]  # 200 > 100 default
        result = validator.check_rate_limit("1.2.3.4", mock_redis)
        assert result is False

    def test_rate_limit_within_limit(self, validator):
        """Count <= max → returns True."""
        mock_redis = MagicMock()
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        mock_pipe.execute.return_value = [5, True]
        result = validator.check_rate_limit("1.2.3.4", mock_redis)
        assert result is True


class TestGeoBlockingPaths:
    """Cover lines 152-171: geo blocking allow/block country logic."""

    @pytest.fixture()
    def geo_validator(self):
        """Validator with a mocked geo_reader."""
        v = SecurityValidator({
            "security": {
                "allowed_countries": ["US", "GB"],
                "blocked_countries": ["RU"],
            }
        })
        v.geo_reader = MagicMock()
        return v

    def test_country_in_allowed_list_passes(self, geo_validator):
        """Lines 159: country in allowed_countries → True."""
        mock_resp = MagicMock()
        mock_resp.country.iso_code = "US"
        geo_validator.geo_reader.city.return_value = mock_resp
        assert geo_validator.check_geo_blocking("1.2.3.4") is True

    def test_country_not_in_allowed_list_blocked(self, geo_validator):
        """Lines 159-161: country not in allowed_countries → False."""
        mock_resp = MagicMock()
        mock_resp.country.iso_code = "CN"
        geo_validator.geo_reader.city.return_value = mock_resp
        assert geo_validator.check_geo_blocking("1.2.3.4") is False

    def test_country_in_blocked_list(self):
        """Lines 163-165: country in blocked_countries → False."""
        v = SecurityValidator({"security": {"blocked_countries": ["RU"]}})
        v.geo_reader = MagicMock()
        mock_resp = MagicMock()
        mock_resp.country.iso_code = "RU"
        v.geo_reader.city.return_value = mock_resp
        assert v.check_geo_blocking("1.2.3.4") is False

    def test_country_not_blocked_passes(self):
        """Country not in blocked list and no allowed list → True."""
        v = SecurityValidator({"security": {"blocked_countries": ["RU"]}})
        v.geo_reader = MagicMock()
        mock_resp = MagicMock()
        mock_resp.country.iso_code = "US"
        v.geo_reader.city.return_value = mock_resp
        assert v.check_geo_blocking("1.2.3.4") is True

    def test_geoip_lookup_exception_fails_open(self, geo_validator):
        """Lines 169-171: geo lookup raises → returns True (fail open)."""
        geo_validator.geo_reader.city.side_effect = Exception("GeoIP error")
        assert geo_validator.check_geo_blocking("1.2.3.4") is True


class TestCSRFEdgeCases:
    """Cover lines 249-250: exception in CSRF validation."""

    def test_token_with_non_integer_timestamp_fails(self, validator):
        """Lines 238: ValueError on int() → returns False."""
        assert validator.validate_csrf_token("notanumber:abc123", "sess") is False

    def test_token_none_attribute_error(self, validator):
        """Lines 238: AttributeError on None.split → returns False."""
        assert validator.validate_csrf_token(None, "sess") is False  # type: ignore

    def test_hmac_compare_exception_returns_false(self, validator):
        """Lines 249-250: exception during hmac compare → returns False."""
        token = validator.generate_csrf_token("sess-x")
        with patch("src.security.validation.hmac.compare_digest", side_effect=TypeError("bad")):
            assert validator.validate_csrf_token(token, "sess-x") is False


class TestMTLSManagerPaths:
    """Cover lines 362-415: cert/key loading, CA verification, certificate validation."""

    def test_cert_chain_loaded_when_configured(self):
        """Lines 362-363: cert_path + key_path → load_cert_chain called."""
        mgr = MTLSManager({"tls": {"cert_path": "/fake/cert.pem", "key_path": "/fake/key.pem"}})
        with patch("ssl.SSLContext") as MockCtx:
            mock_ctx = MagicMock()
            MockCtx.return_value = mock_ctx
            mgr.create_ssl_context(server_side=True)
            mock_ctx.load_cert_chain.assert_called_once_with("/fake/cert.pem", "/fake/key.pem")

    def test_ca_cert_loaded_and_verify_required(self):
        """Lines 365-367: ca_cert_path → load_verify_locations + CERT_REQUIRED."""
        import ssl
        mgr = MTLSManager({"tls": {"ca_cert_path": "/fake/ca.pem"}})
        with patch("ssl.SSLContext") as MockCtx:
            mock_ctx = MagicMock()
            MockCtx.return_value = mock_ctx
            mgr.create_ssl_context(server_side=True)
            mock_ctx.load_verify_locations.assert_called_once_with("/fake/ca.pem")
            assert mock_ctx.verify_mode == ssl.CERT_REQUIRED

    def test_validate_expired_cert_returns_false(self):
        """Lines 402-403: expired certificate → False."""
        from datetime import datetime, timezone, timedelta
        from unittest.mock import PropertyMock
        mgr = MTLSManager({"tls": {}})
        mock_cert = MagicMock()
        # not_valid_after in the past
        mock_cert.not_valid_after = datetime.now(timezone.utc) - timedelta(days=1)
        with patch("src.security.validation.x509.load_pem_x509_certificate", return_value=mock_cert):
            assert mgr.validate_certificate_chain(b"fake-pem") is False

    def test_validate_cert_missing_digital_signature_returns_false(self):
        """Lines 408-410: certificate without digital_signature usage → False."""
        from datetime import datetime, timezone, timedelta
        mgr = MTLSManager({"tls": {}})
        mock_cert = MagicMock()
        mock_cert.not_valid_after = datetime.now(timezone.utc) + timedelta(days=365)
        mock_key_usage = MagicMock()
        mock_key_usage.value.digital_signature = False
        mock_cert.extensions.get_extension_for_oid.return_value = mock_key_usage
        with patch("src.security.validation.x509.load_pem_x509_certificate", return_value=mock_cert):
            assert mgr.validate_certificate_chain(b"fake-pem") is False

    def test_validate_cert_no_key_usage_extension_passes(self):
        """Lines 412-413: ExtensionNotFound → passes (no key usage check)."""
        from datetime import datetime, timezone, timedelta
        mgr = MTLSManager({"tls": {}})
        mock_cert = MagicMock()
        mock_cert.not_valid_after = datetime.now(timezone.utc) + timedelta(days=365)
        mock_cert.extensions.get_extension_for_oid.side_effect = \
            x509.ExtensionNotFound("not found", MagicMock())
        with patch("src.security.validation.x509.load_pem_x509_certificate", return_value=mock_cert):
            assert mgr.validate_certificate_chain(b"fake-pem") is True

    def test_validate_cert_with_valid_digital_signature_passes(self):
        """Lines 409: digital_signature is True → passes."""
        from datetime import datetime, timezone, timedelta
        mgr = MTLSManager({"tls": {}})
        mock_cert = MagicMock()
        mock_cert.not_valid_after = datetime.now(timezone.utc) + timedelta(days=365)
        mock_key_usage = MagicMock()
        mock_key_usage.value.digital_signature = True
        mock_cert.extensions.get_extension_for_oid.return_value = mock_key_usage
        with patch("src.security.validation.x509.load_pem_x509_certificate", return_value=mock_cert):
            assert mgr.validate_certificate_chain(b"fake-pem") is True

    def test_validate_cert_load_exception_returns_false(self):
        """Lines 417-419: certificate load raises → False."""
        mgr = MTLSManager({"tls": {}})
        with patch("src.security.validation.x509.load_pem_x509_certificate",
                   side_effect=ValueError("bad cert")):
            assert mgr.validate_certificate_chain(b"bad-data") is False


class TestFingerprintAnomalyDetection:
    """Cover lines 185-195: _detect_fingerprint_anomalies internal paths."""

    def test_null_fingerprint_pattern_detected(self, validator):
        """Line 184: null fingerprint pattern matched."""
        fp = "t00d0000h0_000000000000_000000000000"
        assert validator._detect_fingerprint_anomalies(fp) is True

    def test_wrong_number_of_parts_detected(self, validator):
        """Lines 189-190: split doesn't produce 3 parts → anomaly."""
        assert validator._detect_fingerprint_anomalies("nounderscores") is True
        assert validator._detect_fingerprint_anomalies("one_two") is True

    @pytest.mark.parametrize("fp", [
        "t13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb",  # < 3 unique in each hash
        "t13d1516h2_111111111111_222222222222",
    ])
    def test_low_entropy_hashes_detected(self, validator, fp):
        """Lines 193-195: hash parts with < 3 unique chars → anomaly."""
        assert validator._detect_fingerprint_anomalies(fp) is True

    def test_normal_fingerprint_not_anomalous(self, validator):
        """Normal fingerprint with diverse hash chars → not anomalous."""
        fp = "t13d1516h2_8daaf6152771_02713d6af862"
        assert validator._detect_fingerprint_anomalies(fp) is False


class TestIPReputationCache:
    """Cover lines 203-214: _check_ip_reputation cache and lookup."""

    def test_uncached_ip_returns_false_and_caches(self, validator):
        """Lines 209-214: new IP → returns False, added to cache."""
        assert "99.99.99.99" not in validator.threat_intel_cache
        result = validator._check_ip_reputation("99.99.99.99")
        assert result is False
        assert "99.99.99.99" in validator.threat_intel_cache
        assert validator.threat_intel_cache["99.99.99.99"]["malicious"] is False

    def test_cached_malicious_ip_returns_true(self, validator):
        """Lines 203-204: cached as malicious → returns True."""
        validator.threat_intel_cache["bad.ip"] = {"malicious": True, "timestamp": time.time()}
        assert validator._check_ip_reputation("bad.ip") is True

    def test_cached_clean_ip_returns_false(self, validator):
        """Cached as not malicious → returns False."""
        validator.threat_intel_cache["good.ip"] = {"malicious": False, "timestamp": time.time()}
        assert validator._check_ip_reputation("good.ip") is False


class TestAuditLoggerSeverityLevels:
    """Cover audit logger severity mapping edge cases."""

    def test_invalid_severity_defaults_to_info(self, tmp_path):
        """Line 328: unknown severity string → getattr falls back to INFO."""
        import logging
        audit = AuditLogger({"logging": {"audit_log_path": str(tmp_path / "audit.log")}})
        # Should not raise for an unknown severity
        audit.log_security_event("test", {"k": "v"}, severity="NONEXISTENT")
