"""
Unit tests for src/tap/fingerprints/ja4s.py (Phase 20 Group 5-B).
"""
import struct

import pytest

from src.tap.fingerprints.ja4s import JA4SResult, extract_ja4s

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_server_hello(
    version: int = 0x0303,
    cipher: int = 0x1301,
    session_id: bytes = b"",
    extensions: list = None,
    alpn: str = None,
    supported_versions_ext: int = None,
) -> bytes:
    """Build a minimal TLS ServerHello record."""
    ext_blob = b""

    if alpn is not None:
        enc = alpn.encode()
        proto = struct.pack("!B", len(enc)) + enc
        proto_list = struct.pack("!H", len(proto)) + proto
        ext_blob += struct.pack("!HH", 16, len(proto_list)) + proto_list

    if supported_versions_ext is not None:
        sv_body = struct.pack("!H", supported_versions_ext)
        ext_blob += struct.pack("!HH", 43, len(sv_body)) + sv_body

    for ext_type in (extensions or []):
        ext_blob += struct.pack("!HH", ext_type, 0)

    ext_section = struct.pack("!H", len(ext_blob)) + ext_blob if ext_blob else b""

    sid_section = struct.pack("!B", len(session_id)) + session_id

    body = (
        struct.pack("!H", version)
        + b"\x00" * 32           # random
        + sid_section
        + struct.pack("!H", cipher)
        + struct.pack("!B", 0)  # compression = null
        + ext_section
    )

    hs_header = bytes([0x02]) + struct.pack("!I", len(body))[1:]
    rec = struct.pack("!BHH", 0x16, 0x0303, len(hs_header) + len(body))
    return rec + hs_header + body


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExtractJA4S:
    def test_extract_ja4s_returns_result_for_valid_hello(self):
        data = _build_server_hello()
        result = extract_ja4s(data)
        assert result is not None
        assert isinstance(result, JA4SResult)

    def test_fingerprint_starts_with_s(self):
        result = extract_ja4s(_build_server_hello())
        assert result is not None
        assert result.fingerprint[0] == "s"

    def test_cipher_hex_in_fingerprint(self):
        result = extract_ja4s(_build_server_hello(cipher=0x002F))
        assert result is not None
        parts = result.fingerprint.split("_")
        assert parts[1] == "002f"

    def test_alpn_chosen_extracted(self):
        result = extract_ja4s(_build_server_hello(alpn="h2"))
        assert result is not None
        assert result.alpn_chosen == "h2"

    def test_session_id_presence_detected(self):
        result = extract_ja4s(_build_server_hello(session_id=b"\xaa" * 32))
        assert result is not None
        assert result.session_id_present is True

    def test_session_id_absent(self):
        result = extract_ja4s(_build_server_hello(session_id=b""))
        assert result is not None
        assert result.session_id_present is False

    def test_tls13_via_supported_versions_ext(self):
        result = extract_ja4s(_build_server_hello(supported_versions_ext=0x0304))
        assert result is not None
        assert result.tls_version_negotiated == "13"

    def test_returns_none_on_truncated_server_hello(self):
        data = _build_server_hello()
        assert extract_ja4s(data[:8]) is None

    def test_returns_none_on_non_tls_bytes(self):
        assert extract_ja4s(b"\x00" * 50) is None

    def test_fingerprint_format_matches_spec(self):
        """Format: s{tls_ver}01{alpn}_{cipher_4hex}_{ext_hash}"""
        result = extract_ja4s(_build_server_hello(alpn="h2", cipher=0x1301))
        assert result is not None
        parts = result.fingerprint.split("_")
        assert len(parts) == 3
        assert parts[0].startswith("s")
        assert len(parts[1]) == 4  # 4-char cipher hex
        assert len(parts[2]) == 12  # 12-char ext hash

    def test_extract_ja4s_from_nginx_like_hello(self):
        """Nginx typically uses TLS 1.2 with no session ID (TLS 1.3 default)."""
        result = extract_ja4s(
            _build_server_hello(
                cipher=0x1302,  # AES-256-GCM-SHA384
                supported_versions_ext=0x0304,
                alpn="h2",
            )
        )
        assert result is not None
        assert result.cipher_chosen == 0x1302

    def test_extract_ja4s_from_openssl_like_hello(self):
        """OpenSSH/OpenSSL pattern without ALPN."""
        result = extract_ja4s(_build_server_hello(cipher=0x002F))
        assert result is not None
        assert result.alpn_chosen is None
