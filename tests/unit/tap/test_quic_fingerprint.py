"""
Unit tests for src/tap/fingerprints/quic_fingerprint.py (Phase 20 Group 5-K).
"""
import struct

import pytest

from src.tap.fingerprints.quic_fingerprint import (
    QUICFingerprintResult,
    _QUIC_V1,
    extract_quic_fingerprint,
)


def _build_quic_initial(
    version: int = _QUIC_V1,
    dcid: bytes = b"\xaa" * 8,
    scid: bytes = b"\xbb" * 4,
    token: bytes = b"",
) -> bytes:
    """Build a minimal QUIC Initial long header packet."""
    # First byte: long header (0xC0) | Initial type (0x00) | reserved=0, pn_len=0 → 0xC3 for v1
    first_byte = 0xC3  # Long header, Initial packet type for QUIC v1
    data = bytes([first_byte])
    data += struct.pack("!I", version)
    data += bytes([len(dcid)]) + dcid
    data += bytes([len(scid)]) + scid
    # Token length (varint: 0 = single byte)
    data += bytes([len(token)])
    if token:
        data += token
    # Remaining length (varint) and payload (minimal)
    data += bytes([0])  # length = 0
    return data


class TestQUICFingerprint:
    def test_quic_v1_version_extracted(self):
        data = _build_quic_initial(version=_QUIC_V1)
        result = extract_quic_fingerprint(data)
        assert result is not None
        assert result.quic_version == _QUIC_V1
        assert "v1" in result.fingerprint

    def test_dcid_length_extracted(self):
        dcid = b"\xcc" * 12
        data = _build_quic_initial(dcid=dcid)
        result = extract_quic_fingerprint(data)
        assert result is not None
        assert result.dcid_len == 12

    def test_token_len_zero_when_no_token(self):
        data = _build_quic_initial(token=b"")
        result = extract_quic_fingerprint(data)
        assert result is not None
        assert result.token_len == 0

    def test_embedded_ja4_is_none(self):
        """Embedded JA4 requires QUIC crypto frame decryption — not implemented."""
        data = _build_quic_initial()
        result = extract_quic_fingerprint(data)
        assert result is not None
        assert result.embedded_ja4 is None

    def test_returns_none_on_short_udp_payload(self):
        assert extract_quic_fingerprint(b"\xc3") is None
        assert extract_quic_fingerprint(b"") is None

    def test_returns_none_on_non_quic_header(self):
        # First byte has top 2 bits as 00 → not a long-header QUIC packet
        data = bytes([0x00, 0x00, 0x00, 0x00, 0x01] + [0] * 20)
        result = extract_quic_fingerprint(data)
        assert result is None

    def test_fingerprint_format(self):
        data = _build_quic_initial()
        result = extract_quic_fingerprint(data)
        assert result is not None
        assert result.fingerprint.startswith("quic_")

    def test_unknown_version_in_fingerprint(self):
        custom_ver = 0xDEADBEEF
        data = _build_quic_initial(version=custom_ver)
        result = extract_quic_fingerprint(data)
        assert result is not None
        assert f"{custom_ver:08x}" in result.fingerprint
