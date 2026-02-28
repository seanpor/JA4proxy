"""Unit tests for proxy.py pure-logic utilities.

Covers:
- classify_ja4()         — JA4 fingerprint human-readable decoder
- SensitiveDataFilter    — regex redaction of passwords/tokens/cards/emails
- SecureFormatter        — production stack-trace sanitisation
- ConfigManager          — validation methods and env-var expansion
- ProxyServer._parse_proxy_protocol     — PROXY protocol v1 + v2 parsing
- ProxyServer._extract_client_ip_from_http — X-Forwarded-For / X-Real-IP extraction

All tests call the actual code under test.  No test simply checks a default
or asserts True without going through real logic.
"""

import logging
import os
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from proxy import (
    classify_ja4,
    ConfigManager,
    ProxyServer,
    SensitiveDataFilter,
    SecureFormatter,
    ValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pp2_header(src_ip: str, *, family: int = 0x11, addr_len: int = 12) -> bytes:
    """Build a minimal PROXY protocol v2 header for an IPv4 or IPv6 address."""
    PP2_SIG = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
    ver_cmd = 0x21  # v2, PROXY command
    header = PP2_SIG + bytes([ver_cmd, family]) + struct.pack("!H", addr_len)
    if family == 0x11:  # AF_INET
        src_bytes = socket.inet_aton(src_ip)
        dst_bytes = socket.inet_aton("10.0.0.1")
        ports = struct.pack("!HH", 12345, 443)
        header += src_bytes + dst_bytes + ports  # 4+4+2+2 = 12 bytes
    elif family == 0x21:  # AF_INET6
        src_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_bytes = socket.inet_pton(socket.AF_INET6, "::1")
        ports = struct.pack("!HH", 12345, 443)
        header += src_bytes + dst_bytes + ports  # 16+16+2+2 = 36 bytes
    return header


def _proxy_server_stub() -> ProxyServer:
    """Return a ProxyServer with __init__ bypassed, only logger set."""
    server = object.__new__(ProxyServer)
    server.logger = logging.getLogger("proxy")
    server.config = {}
    return server


# ---------------------------------------------------------------------------
# classify_ja4()
# ---------------------------------------------------------------------------


class TestClassifyJa4:
    def test_h2_alpn_is_browser(self):
        # prefix ends in h2 → Browser
        ja4 = "t13d1516h2_8daaf6152771_02713d6af862"
        result = classify_ja4(ja4)
        assert "Browser" in result

    def test_tool_bot_00_alpn(self):
        # prefix ends in 00 → Tool/Bot
        ja4 = "t13d190900_9dc949149365_97f8aa674fd9"
        result = classify_ja4(ja4)
        assert "Tool" in result or "Bot" in result

    def test_unknown_short_string(self):
        assert classify_ja4("t13") == "Unknown"

    def test_unknown_for_empty(self):
        assert classify_ja4("") == "Unknown"

    def test_unknown_sentinel_values(self):
        assert classify_ja4("unknown") == "Unknown"
        assert classify_ja4("error") == "Unknown"

    def test_quic_protocol(self):
        # starts with 'q' → QUIC
        ja4 = "q13d190900_9dc949149365_97f8aa674fd9"
        result = classify_ja4(ja4)
        assert "QUIC" in result

    def test_config_label_takes_precedence(self):
        config = {"security": {"fingerprint_labels": {"t13d1516h2_8daaf6152771_02713d6af862": "MyBrowser"}}}
        result = classify_ja4("t13d1516h2_8daaf6152771_02713d6af862", config)
        assert result == "MyBrowser"

    def test_version_12_decoded(self):
        ja4 = "t12d190900_9dc949149365_97f8aa674fd9"
        result = classify_ja4(ja4)
        assert "1.2" in result

    def test_version_13_decoded(self):
        ja4 = "t13d190900_9dc949149365_97f8aa674fd9"
        result = classify_ja4(ja4)
        assert "1.3" in result

    def test_non_standard_alpn(self):
        # alpn that isn't h2 or 00 → 'Client'
        ja4 = "t13d1516h1_8daaf6152771_02713d6af862"
        result = classify_ja4(ja4)
        assert "Client" in result or "Browser" in result  # h1 is also browser-like


# ---------------------------------------------------------------------------
# SensitiveDataFilter
# ---------------------------------------------------------------------------


class TestSensitiveDataFilter:
    def setup_method(self):
        self.f = SensitiveDataFilter()

    def _make_record(self, msg: str) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=msg, args=(), exc_info=None
        )
        return record

    def test_password_redacted(self):
        record = self._make_record("connecting with password=supersecret123")
        self.f.filter(record)
        assert "supersecret123" not in record.msg
        assert "REDACTED" in record.msg

    def test_api_key_redacted(self):
        record = self._make_record("api_key=abcdef12345")
        self.f.filter(record)
        assert "abcdef12345" not in record.msg
        assert "REDACTED" in record.msg

    def test_token_redacted(self):
        record = self._make_record("token=mysecrettoken")
        self.f.filter(record)
        assert "mysecrettoken" not in record.msg

    def test_secret_redacted(self):
        record = self._make_record("secret=topsecret")
        self.f.filter(record)
        assert "topsecret" not in record.msg

    def test_bearer_token_redacted(self):
        record = self._make_record("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abc")
        self.f.filter(record)
        assert "eyJhbGciOiJSUzI1NiJ9" not in record.msg

    def test_credit_card_redacted(self):
        record = self._make_record("card=4111111111111111")
        self.f.filter(record)
        assert "4111111111111111" not in record.msg
        assert "CARD_REDACTED" in record.msg

    def test_email_redacted(self):
        record = self._make_record("user email: john.doe@example.com connected")
        self.f.filter(record)
        assert "john.doe@example.com" not in record.msg
        assert "EMAIL_REDACTED" in record.msg

    def test_innocuous_message_unchanged(self):
        record = self._make_record("Connection from 1.2.3.4 established")
        self.f.filter(record)
        assert "Connection from 1.2.3.4 established" in record.msg

    def test_filter_returns_true(self):
        """filter() must always return True (do not suppress the record)."""
        record = self._make_record("password=secret")
        assert self.f.filter(record) is True

    def test_args_filtered(self):
        """Sensitive data in record.args is also redacted."""
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="auth %s", args=("password=mysecret",), exc_info=None
        )
        self.f.filter(record)
        assert "mysecret" not in str(record.args)


# ---------------------------------------------------------------------------
# SecureFormatter
# ---------------------------------------------------------------------------


class TestSecureFormatter:
    def test_format_adds_event_type_attribute(self):
        fmt = SecureFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello", args=(), exc_info=None
        )
        fmt.format(record)
        assert hasattr(record, "event_type")
        assert record.event_type == "general"

    def test_production_exc_info_sanitised(self):
        """In production, full traceback must not appear — only exc type + value."""
        fmt = SecureFormatter("%(message)s")
        try:
            raise ValueError("sensitive internal detail")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="error", args=(), exc_info=exc_info
        )
        with patch.dict(os.environ, {"ENVIRONMENT": "production"}):
            fmt.format(record)

        # In production the exc_info should be cleared and exc_text set
        assert record.exc_info is None
        assert "ValueError" in record.exc_text

    def test_non_production_exc_info_preserved(self):
        """Outside production, exc_info passes through unmodified."""
        fmt = SecureFormatter("%(message)s")
        try:
            raise RuntimeError("debug info")
        except RuntimeError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="error", args=(), exc_info=exc_info
        )
        # Ensure ENVIRONMENT is not 'production'
        env = {k: v for k, v in os.environ.items() if k != "ENVIRONMENT"}
        with patch.dict(os.environ, env, clear=True):
            fmt.format(record)

        # exc_info should still be set (not cleared)
        assert record.exc_info is not None


# ---------------------------------------------------------------------------
# ConfigManager validation
# ---------------------------------------------------------------------------


class TestConfigManagerValidation:
    """Test ConfigManager._validate_*  and _expand_env_vars methods directly."""

    @pytest.fixture
    def mgr(self):
        """ConfigManager with real config/proxy.yml — good for testing methods."""
        return ConfigManager("config/proxy.yml")

    def test_validate_proxy_config_bad_port_raises(self, mgr):
        with pytest.raises(ValidationError, match="bind_port"):
            mgr._validate_proxy_config({"bind_port": 99999})

    def test_validate_proxy_config_bad_port_zero(self, mgr):
        with pytest.raises(ValidationError, match="bind_port"):
            mgr._validate_proxy_config({"bind_port": 0})

    def test_validate_proxy_config_non_int_port_raises(self, mgr):
        with pytest.raises(ValidationError, match="bind_port"):
            mgr._validate_proxy_config({"bind_port": "8080"})

    def test_validate_proxy_config_max_connections_too_large(self, mgr):
        with pytest.raises(ValidationError, match="max_connections"):
            mgr._validate_proxy_config({"max_connections": 999999})

    def test_validate_proxy_config_valid_passes(self, mgr):
        # Should not raise
        mgr._validate_proxy_config({"bind_port": 8080, "max_connections": 1000})

    def test_validate_redis_config_valid_passes(self, mgr):
        mgr._validate_redis_config({"host": "redis", "port": 6379, "password": "secret"})

    def test_validate_redis_config_bad_port_raises(self, mgr):
        with pytest.raises(ValidationError, match="Redis port"):
            mgr._validate_redis_config({"port": 99999})

    def test_validate_redis_config_host_too_long_raises(self, mgr):
        with pytest.raises(ValidationError, match="Redis host"):
            mgr._validate_redis_config({"host": "x" * 300})

    def test_validate_security_config_non_bool_flag_raises(self, mgr):
        with pytest.raises(ValidationError, match="must be boolean"):
            mgr._validate_security_config({"whitelist_enabled": "yes"})

    def test_validate_security_config_max_requests_too_large(self, mgr):
        with pytest.raises(ValidationError, match="max_requests_per_minute"):
            mgr._validate_security_config({"max_requests_per_minute": 2000000})

    def test_validate_security_config_valid_passes(self, mgr):
        mgr._validate_security_config({"whitelist_enabled": True, "max_requests_per_minute": 500})


class TestConfigManagerEnvVars:
    @pytest.fixture
    def mgr(self):
        return ConfigManager("config/proxy.yml")

    def test_var_with_value_substituted(self, mgr):
        with patch.dict(os.environ, {"MY_VAR": "hello"}):
            result = mgr._expand_env_vars({"key": "${MY_VAR}"})
        assert result["key"] == "hello"

    def test_var_with_default_used_when_unset(self, mgr):
        env = {k: v for k, v in os.environ.items() if k != "UNSET_VAR_XYZ"}
        with patch.dict(os.environ, env, clear=True):
            result = mgr._expand_env_vars({"key": "${UNSET_VAR_XYZ:-fallback}"})
        assert result["key"] == "fallback"

    def test_var_no_default_returns_empty_string(self, mgr, caplog):
        env = {k: v for k, v in os.environ.items() if k != "TOTALLY_MISSING"}
        with patch.dict(os.environ, env, clear=True):
            with caplog.at_level(logging.WARNING):
                result = mgr._expand_env_vars({"key": "${TOTALLY_MISSING}"})
        assert result["key"] == ""

    def test_nested_dict_expanded(self, mgr):
        with patch.dict(os.environ, {"REDIS_PW": "secret123"}):
            result = mgr._expand_env_vars({"redis": {"password": "${REDIS_PW}"}})
        assert result["redis"]["password"] == "secret123"

    def test_list_values_expanded(self, mgr):
        with patch.dict(os.environ, {"HOST1": "10.0.0.1"}):
            result = mgr._expand_env_vars({"hosts": ["${HOST1}", "static"]})
        assert result["hosts"][0] == "10.0.0.1"
        assert result["hosts"][1] == "static"

    def test_non_string_values_unchanged(self, mgr):
        result = mgr._expand_env_vars({"port": 6379, "enabled": True})
        assert result["port"] == 6379
        assert result["enabled"] is True


# ---------------------------------------------------------------------------
# ProxyServer._parse_proxy_protocol
# ---------------------------------------------------------------------------


class TestParseProxyProtocol:
    """Tests for the PROXY protocol v1 + v2 parser.

    Uses object.__new__ to create a ProxyServer without running __init__.
    Only self.logger is used inside _parse_proxy_protocol.
    """

    @pytest.fixture
    def server(self):
        return _proxy_server_stub()

    # ── PPv2 IPv4 ──────────────────────────────────────────────────────────

    def test_ppv2_ipv4_extracts_src_ip(self, server):
        header = _make_pp2_header("203.0.113.42", family=0x11, addr_len=12)
        payload = b"TLS data follows"
        ip, remaining = server._parse_proxy_protocol(header + payload, "0.0.0.0")
        assert ip == "203.0.113.42"
        assert remaining == payload

    def test_ppv2_strips_header_from_remaining(self, server):
        header = _make_pp2_header("10.1.2.3", family=0x11, addr_len=12)
        trailer = b"\x16\x03\x01"  # TLS record start
        ip, remaining = server._parse_proxy_protocol(header + trailer, "9.9.9.9")
        assert remaining == trailer

    # ── PPv2 IPv6 ──────────────────────────────────────────────────────────

    def test_ppv2_ipv6_extracts_src_ip(self, server):
        header = _make_pp2_header("2001:db8::1", family=0x21, addr_len=36)
        payload = b"data"
        ip, remaining = server._parse_proxy_protocol(header + payload, "::1")
        assert ip == "2001:db8::1"
        assert remaining == payload

    # ── PPv2 unknown family ────────────────────────────────────────────────

    def test_ppv2_unknown_family_uses_fallback(self, server):
        PP2_SIG = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
        # family=0x00 (UNSPEC) — unknown to our parser
        header = PP2_SIG + bytes([0x21, 0x00]) + struct.pack("!H", 4) + b"\x00" * 4
        payload = b"rest"
        ip, remaining = server._parse_proxy_protocol(header + payload, "1.2.3.4")
        assert ip == "1.2.3.4"  # fallback
        assert remaining == payload

    # ── PPv1 ───────────────────────────────────────────────────────────────

    def test_ppv1_tcp4_extracts_src_ip(self, server):
        header = b"PROXY TCP4 192.168.1.100 10.0.0.1 56789 443\r\n"
        payload = b"TLS bytes"
        ip, remaining = server._parse_proxy_protocol(header + payload, "0.0.0.0")
        assert ip == "192.168.1.100"
        assert remaining == payload

    def test_ppv1_tcp6_extracts_src_ip(self, server):
        header = b"PROXY TCP6 2001:db8::cafe ::1 12345 443\r\n"
        payload = b"more bytes"
        ip, remaining = server._parse_proxy_protocol(header + payload, "0.0.0.0")
        assert ip == "2001:db8::cafe"
        assert remaining == payload

    # ── No PROXY header ────────────────────────────────────────────────────

    def test_no_proxy_header_returns_fallback(self, server):
        data = b"\x16\x03\x01\x00\x80"  # TLS record — no PROXY header
        ip, remaining = server._parse_proxy_protocol(data, "5.6.7.8")
        assert ip == "5.6.7.8"
        assert remaining == data

    def test_empty_data_returns_fallback(self, server):
        ip, remaining = server._parse_proxy_protocol(b"", "9.9.9.9")
        assert ip == "9.9.9.9"
        assert remaining == b""


# ---------------------------------------------------------------------------
# ProxyServer._extract_client_ip_from_http
# ---------------------------------------------------------------------------


class TestExtractClientIpFromHttp:
    @pytest.fixture
    def server(self):
        return _proxy_server_stub()

    def test_x_forwarded_for_first_ip_extracted(self, server):
        data = b"GET / HTTP/1.1\r\nX-Forwarded-For: 203.0.113.5, 10.0.0.1\r\n\r\n"
        ip = server._extract_client_ip_from_http(data)
        assert ip == "203.0.113.5"

    def test_x_forwarded_for_single_ip(self, server):
        data = b"POST /api HTTP/1.1\r\nX-Forwarded-For: 198.51.100.99\r\n\r\n"
        ip = server._extract_client_ip_from_http(data)
        assert ip == "198.51.100.99"

    def test_x_real_ip_extracted(self, server):
        data = b"GET / HTTP/1.1\r\nX-Real-IP: 203.0.113.10\r\n\r\n"
        ip = server._extract_client_ip_from_http(data)
        assert ip == "203.0.113.10"

    def test_non_http_data_returns_empty(self, server):
        data = b"\x16\x03\x01\x00\x80\x01"  # TLS ClientHello start
        ip = server._extract_client_ip_from_http(data)
        assert ip == ""

    def test_invalid_ip_in_header_returns_empty(self, server):
        data = b"GET / HTTP/1.1\r\nX-Forwarded-For: not-an-ip\r\n\r\n"
        ip = server._extract_client_ip_from_http(data)
        assert ip == ""

    def test_missing_xff_returns_empty(self, server):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ip = server._extract_client_ip_from_http(data)
        assert ip == ""

    def test_put_method_recognised(self, server):
        data = b"PUT /resource HTTP/1.1\r\nX-Forwarded-For: 10.0.0.42\r\n\r\n"
        ip = server._extract_client_ip_from_http(data)
        assert ip == "10.0.0.42"

    def test_delete_method_recognised(self, server):
        data = b"DELETE /item HTTP/1.1\r\nX-Real-IP: 10.0.0.99\r\n\r\n"
        ip = server._extract_client_ip_from_http(data)
        assert ip == "10.0.0.99"

    def test_empty_data_returns_empty(self, server):
        ip = server._extract_client_ip_from_http(b"")
        assert ip == ""
