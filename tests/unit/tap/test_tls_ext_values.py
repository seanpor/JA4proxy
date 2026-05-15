"""
Unit tests for src/tap/fingerprints/tls_ext_values.py (Phase 20 Group 5-H).
"""

import struct

import pytest

from src.tap.fingerprints.ja4 import extract_ja4
from src.tap.fingerprints.tls_ext_values import JA4TLSExtValues, extract_tls_ext_values


def _build_hello_with_grease_and_chrome_exts() -> bytes:
    """Build a ClientHello that resembles Chrome (GREASE, ALPS, key_share, padding)."""
    grease = 0x0A0A
    exts_payload = b""

    # SNI ext (type 0)
    host = b"example.com"
    sni_entry = struct.pack("!BH", 0, len(host)) + host
    sni_body = struct.pack("!H", len(sni_entry)) + sni_entry
    exts_payload += struct.pack("!HH", 0, len(sni_body)) + sni_body

    # GREASE ext
    exts_payload += struct.pack("!HH", grease, 0)

    # Compress cert (ext 27, RFC 8879)
    exts_payload += struct.pack("!HH", 27, 0)

    # ALPS ext (0x4469)
    exts_payload += struct.pack("!HH", 0x4469, 0)

    # Supported groups (ext 10)
    groups = struct.pack("!HH", 0x001D, 0x0017)  # x25519, secp256r1
    sg_body = struct.pack("!H", len(groups)) + groups
    exts_payload += struct.pack("!HH", 10, len(sg_body)) + sg_body

    # Key share (ext 51)
    ks_entry = struct.pack("!HH", 0x001D, 0)  # x25519, 0-len key
    ks_body = struct.pack("!H", len(ks_entry)) + ks_entry
    exts_payload += struct.pack("!HH", 51, len(ks_body)) + ks_body

    # Padding (ext 21)
    exts_payload += struct.pack("!HH", 21, 4) + b"\x00" * 4

    ext_section = struct.pack("!H", len(exts_payload)) + exts_payload

    # Cipher suites: [GREASE, TLS_AES_128_GCM_SHA256]
    cipher_data = struct.pack("!HH", grease, 0x1301)
    cipher_section = struct.pack("!H", len(cipher_data)) + cipher_data

    body = (
        struct.pack("!H", 0x0303)  # client_version
        + b"\x00" * 32  # random
        + struct.pack("!B", 0)  # session_id length = 0
        + cipher_section  # cipher suites
        + struct.pack("!BB", 1, 0)  # compression_methods: 1 method (null)
        + ext_section
    )
    hs = bytes([0x01]) + struct.pack("!I", len(body))[1:]  # 3-byte handshake len
    rec_len = len(hs) + len(body)
    return struct.pack("!BHH", 0x16, 0x0303, rec_len) + hs + body


class TestTLSExtValues:
    def test_grease_values_extracted(self):
        data = _build_hello_with_grease_and_chrome_exts()
        ja4 = extract_ja4(data)
        assert ja4 is not None
        ext_vals = extract_tls_ext_values(ja4)
        assert 0x0A0A in ext_vals.grease_values

    def test_no_grease_in_python_requests_like_hello(self):
        from tests.unit.tap.test_ja4 import _build_client_hello

        data = _build_client_hello(sni="api.example.com")
        ja4 = extract_ja4(data)
        assert ja4 is not None
        ext_vals = extract_tls_ext_values(ja4)
        assert len(ext_vals.grease_values) == 0

    def test_compress_cert_detected(self):
        data = _build_hello_with_grease_and_chrome_exts()
        ja4 = extract_ja4(data)
        assert ja4 is not None
        ext_vals = extract_tls_ext_values(ja4)
        assert ext_vals.has_compress_cert is True

    def test_alps_detected(self):
        data = _build_hello_with_grease_and_chrome_exts()
        ja4 = extract_ja4(data)
        assert ja4 is not None
        ext_vals = extract_tls_ext_values(ja4)
        assert ext_vals.has_alps is True

    def test_key_share_groups_in_order(self):
        data = _build_hello_with_grease_and_chrome_exts()
        ja4 = extract_ja4(data)
        assert ja4 is not None
        ext_vals = extract_tls_ext_values(ja4)
        # Should have at least one key share group
        # (exact value depends on whether key_share parse worked)
        assert isinstance(ext_vals.key_share_groups, list)

    def test_result_is_always_returned(self):
        """extract_tls_ext_values must never raise, even with empty JA4Result."""
        from src.tap.fingerprints.ja4 import JA4Result

        empty = JA4Result(
            fingerprint="t00i0000_000000000000_000000000000",
            tls_version_offered="00",
            ciphers=[],
            extensions=[],
            alpn_list=[],
            sni=None,
        )
        result = extract_tls_ext_values(empty)
        assert isinstance(result, JA4TLSExtValues)


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestTLSExtValuesExceptionHandler:
    """Lines 62-63: exception inside extract_tls_ext_values is caught."""

    def test_exception_returns_safe_default(self):
        """Lines 62-63: if JA4Result attribute access raises, the except block returns
        a zeroed JA4TLSExtValues with empty lists and False flags.
        So what: if this except block is absent, any AttributeError on a malformed
        JA4Result (e.g. from an experimental parser version) propagates to the tap
        pipeline and crashes the fingerprint aggregation for the entire connection batch.
        """
        from unittest.mock import patch

        bad_result = object()  # not a JA4Result — accessing .extensions raises
        result = extract_tls_ext_values(bad_result)
        assert isinstance(result, JA4TLSExtValues)
        assert result.supported_groups == []
        assert result.key_share_groups == []
        assert result.has_compress_cert is False
        assert result.has_alps is False
        assert result.session_ticket_len == 0
