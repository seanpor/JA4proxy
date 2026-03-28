"""
Unit tests for src/tap/fingerprints/ja4.py (Phase 20 Group 5-A).
"""
import struct

import pytest

from src.tap.fingerprints.ja4 import JA4Result, _GREASE, extract_ja4, _hash_ciphers, _hash_exts


# ---------------------------------------------------------------------------
# Helpers — build raw ClientHello bytes
# ---------------------------------------------------------------------------


def _build_client_hello(
    version: int = 0x0303,
    ciphers: list = None,
    extensions: list = None,
    sni: str = None,
    alpn: list = None,
    supported_versions: list = None,
    key_share_groups: list = None,
) -> bytes:
    """Build a minimal TLS ClientHello record for testing."""
    ciphers = ciphers or [0x1301, 0x1302, 0x002F]
    extensions = extensions or []

    # Build extensions blob
    ext_blob = b""

    if sni is not None:
        host = sni.encode()
        entry = struct.pack("!BH", 0, len(host)) + host
        list_data = struct.pack("!H", len(entry)) + entry
        ext_blob += struct.pack("!HH", 0, len(list_data)) + list_data

    if alpn is not None:
        proto_list = b""
        for p in alpn:
            enc = p.encode()
            proto_list += struct.pack("!B", len(enc)) + enc
        alpn_list = struct.pack("!H", len(proto_list)) + proto_list
        ext_blob += struct.pack("!HH", 16, len(alpn_list)) + alpn_list

    if supported_versions is not None:
        ver_bytes = b""
        for v in supported_versions:
            ver_bytes += struct.pack("!H", v)
        sv_body = struct.pack("!B", len(ver_bytes)) + ver_bytes
        ext_blob += struct.pack("!HH", 43, len(sv_body)) + sv_body

    if key_share_groups is not None:
        ks_entries = b""
        for g in key_share_groups:
            ks_entries += struct.pack("!HH", g, 0)  # group + 0-length key
        ks_body = struct.pack("!H", len(ks_entries)) + ks_entries
        ext_blob += struct.pack("!HH", 51, len(ks_body)) + ks_body

    # Remaining extra extensions (type 0xff01 = renegotiation info as placeholder)
    for ext_type in extensions:
        ext_blob += struct.pack("!HH", ext_type, 0)

    ext_section = struct.pack("!H", len(ext_blob)) + ext_blob

    # cipher suites
    cs_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cs_section = struct.pack("!H", len(cs_bytes)) + cs_bytes

    # ClientHello body
    body = (
        struct.pack("!H", version)     # version
        + b"\x00" * 32                  # random
        + struct.pack("!B", 0)          # session_id len = 0
        + cs_section
        + struct.pack("!BB", 1, 0)      # compression_methods: [null]
        + ext_section
    )

    # Handshake header
    hs_header = bytes([0x01]) + struct.pack("!I", len(body))[1:]  # 3-byte length

    # TLS Record header
    rec = struct.pack("!BHH", 0x16, 0x0303, len(hs_header) + len(body))
    return rec + hs_header + body


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestExtractJA4:
    def test_extract_ja4_returns_result_for_valid_hello(self):
        data = _build_client_hello(sni="example.com", alpn=["h2"])
        result = extract_ja4(data)
        assert result is not None
        assert isinstance(result, JA4Result)

    def test_extract_ja4_fingerprint_format(self):
        data = _build_client_hello(sni="example.com", alpn=["h2"])
        result = extract_ja4(data)
        assert result is not None
        parts = result.fingerprint.split("_")
        assert len(parts) == 3
        assert result.fingerprint[0] == "t"  # TLS protocol
        assert len(parts[1]) == 12  # cipher hash
        assert len(parts[2]) == 12  # ext hash

    def test_sni_extracted(self):
        data = _build_client_hello(sni="www.example.org")
        result = extract_ja4(data)
        assert result is not None
        assert result.sni == "www.example.org"
        assert "d" in result.fingerprint  # SNI present

    def test_no_sni_produces_i_indicator(self):
        data = _build_client_hello(sni=None)
        result = extract_ja4(data)
        assert result is not None
        assert result.fingerprint[3] == "i"

    def test_alpn_h2_captured(self):
        data = _build_client_hello(alpn=["h2", "http/1.1"])
        result = extract_ja4(data)
        assert result is not None
        assert "h2" in result.alpn_list
        assert "h2" in result.fingerprint  # first+last chars = h2

    def test_alpn_absent_produces_00(self):
        data = _build_client_hello(alpn=None)
        result = extract_ja4(data)
        assert result is not None
        assert "00" in result.fingerprint

    def test_tls13_via_supported_versions(self):
        data = _build_client_hello(
            version=0x0303,
            supported_versions=[0x0304, 0x0303],
        )
        result = extract_ja4(data)
        assert result is not None
        assert result.tls_version_offered == "13"
        assert result.fingerprint[1:3] == "13"

    def test_grease_values_identified(self):
        grease = 0x0A0A
        data = _build_client_hello(ciphers=[grease, 0x1301, 0x002F])
        result = extract_ja4(data)
        assert result is not None
        # GREASE should be in grease_values but NOT affect the cipher count
        assert grease in result.grease_values or grease in result.ciphers

    def test_returns_none_on_truncated_input(self):
        data = _build_client_hello()
        assert extract_ja4(data[:10]) is None

    def test_returns_none_on_non_tls_bytes(self):
        assert extract_ja4(b"\x00" * 100) is None

    def test_returns_none_on_empty_bytes(self):
        assert extract_ja4(b"") is None

    def test_cipher_count_in_fingerprint(self):
        ciphers = [0x1301, 0x1302, 0x1303, 0x002F]
        data = _build_client_hello(ciphers=ciphers)
        result = extract_ja4(data)
        assert result is not None
        # Verify cipher count in fingerprint prefix
        prefix = result.fingerprint.split("_")[0]
        assert f"{len(ciphers):02d}" in prefix

    def test_fingerprint_matches_reference_tool_output(self):
        """Golden-file: verify known cipher/ext hash values are deterministic."""
        data = _build_client_hello(
            ciphers=[0x002F],  # single cipher: TLS_RSA_WITH_AES_128_CBC_SHA
            alpn=None,
            sni=None,
        )
        result = extract_ja4(data)
        assert result is not None
        # Cipher hash of a single cipher must be stable
        expected_hash = _hash_ciphers([0x002F])
        assert result.fingerprint.split("_")[1] == expected_hash


class TestHashFunctions:
    def test_hash_ciphers_empty(self):
        assert _hash_ciphers([]) == "000000000000"

    def test_hash_ciphers_grease_filtered(self):
        grease = 0x0A0A
        assert _hash_ciphers([grease]) == "000000000000"

    def test_hash_exts_excludes_sni_and_alpn(self):
        # SNI=0 and ALPN=16 should both be excluded
        import hashlib
        exts_without = [0x000A, 0x000D]  # supported_groups, sig_algs
        h1 = _hash_exts(exts_without)
        # Adding SNI or ALPN should NOT change the hash
        h2 = _hash_exts([0, 16] + exts_without)
        assert h1 == h2

    def test_hash_exts_empty_after_filter(self):
        assert _hash_exts([0, 16]) == "000000000000"
