"""
Unit tests for src/tap/fingerprints/quic_fingerprint.py (Phase 20 Group 5-K).
"""

import struct

import pytest

from src.tap.fingerprints.quic_fingerprint import (
    _QUIC_V1,
    QUICFingerprintResult,
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


# ── Missing-coverage tests ────────────────────────────────────────────────────


class TestQUICEdgeCases:
    """Cover parse-failure paths not reached by the happy-path tests."""

    def test_exception_in_parse_returns_none(self):
        """_parse() raising unexpectedly must be caught and return None.
        So what: a malformed internet packet must never crash the capture loop."""
        from unittest.mock import patch

        with patch(
            "src.tap.fingerprints.quic_fingerprint._parse",
            side_effect=RuntimeError("injected"),
        ):
            result = extract_quic_fingerprint(_build_quic_initial())
        assert result is None

    def test_version_field_truncated_returns_none(self):
        """Packet truncated after 4-byte version incomplete → None.
        So what: prevents struct.unpack_from IndexError on short network frames."""
        # first_byte (1) + 3 bytes version (needs 4)
        data = bytes([0xC3]) + b"\x00\x00\x01"
        assert extract_quic_fingerprint(data) is None

    def test_version_negotiation_packet_returns_none(self):
        """QUIC version 0 = Version Negotiation — not an Initial packet.
        So what: VN packets carry no fingerprint; skipping prevents garbage output."""
        data = bytes([0xC3]) + struct.pack("!I", 0x00000000) + bytes([0, 0, 0])
        assert extract_quic_fingerprint(data) is None

    def test_dcid_len_byte_missing_returns_none(self):
        """Truncated after version field, dcid_len byte absent → None."""
        data = bytes([0xC3]) + struct.pack("!I", _QUIC_V1)  # 5 bytes only
        assert extract_quic_fingerprint(data) is None

    def test_dcid_overruns_buffer_returns_none(self):
        """dcid_len=200 with no following bytes → None.
        So what: malformed DCID must not cause slice-beyond-buffer."""
        data = bytes([0xC3]) + struct.pack("!I", _QUIC_V1) + bytes([200])
        assert extract_quic_fingerprint(data) is None

    def test_scid_len_byte_missing_returns_none(self):
        """Truncated after DCID bytes, scid_len byte absent → None."""
        dcid = b"\xaa" * 4
        data = bytes([0xC3]) + struct.pack("!I", _QUIC_V1) + bytes([len(dcid)]) + dcid
        assert extract_quic_fingerprint(data) is None

    def test_scid_overruns_buffer_returns_none(self):
        """scid_len=200 with no following bytes → None."""
        dcid = b"\xaa" * 4
        data = (
            bytes([0xC3])
            + struct.pack("!I", _QUIC_V1)
            + bytes([len(dcid)])
            + dcid
            + bytes([200])
        )
        assert extract_quic_fingerprint(data) is None

    def test_token_varint_truncated_returns_none(self):
        """Incomplete 2-byte token-length varint → None.
        So what: token field size must be parseable to build a valid fingerprint."""
        dcid = b"\xaa" * 4
        scid = b"\xbb" * 4
        # 0x40 = length_type 1 (2-byte varint) but only 1 byte present
        data = (
            bytes([0xC3])
            + struct.pack("!I", _QUIC_V1)
            + bytes([len(dcid)])
            + dcid
            + bytes([len(scid)])
            + scid
            + bytes([0x40])
        )
        assert extract_quic_fingerprint(data) is None

    def test_quic_v2_produces_v2_in_fingerprint(self):
        """QUIC v2 (RFC 9369) must be identified as 'v2', not an unknown hex string.
        So what: v2 is the current IETF version; wrong label pollutes fingerprint DBs.
        """
        from src.tap.fingerprints.quic_fingerprint import _QUIC_V2

        data = _build_quic_initial(version=_QUIC_V2)
        result = extract_quic_fingerprint(data)
        assert result is not None
        assert result.fingerprint == "quic_v2_dcid8_tok0"


class TestQUICVarint:
    """Tests for _read_varint — all four QUIC VLI encodings (RFC 9000 §16)."""

    def setup_method(self):
        from src.tap.fingerprints.quic_fingerprint import _read_varint

        self._rv = _read_varint

    def test_empty_buffer_returns_none(self):
        """pos >= len(data) → (None, pos). So what: sentinel prevents crash on any short field."""
        val, pos = self._rv(b"", 0)
        assert val is None

    def test_1byte_encoding_max_value(self):
        """length_type 0 (00xxxxxx): 6-bit value, max 63."""
        val, new_pos = self._rv(bytes([0x3F]), 0)
        assert val == 63
        assert new_pos == 1

    def test_2byte_encoding(self):
        """length_type 1 (01xxxxxx): 14-bit value read from 2 bytes."""
        # 0x41 0x00 → (0x41 & 0x3F) << 8 | 0x00 = 0x0100 = 256
        val, new_pos = self._rv(bytes([0x41, 0x00]), 0)
        assert val == 256
        assert new_pos == 2

    def test_2byte_truncated_returns_none(self):
        """2-byte varint but only 1 byte available → (None, pos)."""
        val, _ = self._rv(bytes([0x41]), 0)
        assert val is None

    def test_4byte_encoding(self):
        """length_type 2 (10xxxxxx): 30-bit value read from 4 bytes."""
        # 0x80 0x00 0x00 0x01 → value = 1
        val, new_pos = self._rv(bytes([0x80, 0x00, 0x00, 0x01]), 0)
        assert val == 1
        assert new_pos == 4

    def test_4byte_truncated_returns_none(self):
        """4-byte varint with only 2 bytes available → (None, pos)."""
        val, _ = self._rv(bytes([0x80, 0x00]), 0)
        assert val is None

    def test_8byte_encoding(self):
        """length_type 3 (11xxxxxx): 62-bit value read from 8 bytes."""
        val, new_pos = self._rv(
            bytes([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]), 0
        )
        assert val == 1
        assert new_pos == 8

    def test_8byte_truncated_returns_none(self):
        """8-byte varint with only 4 bytes → (None, pos)."""
        val, _ = self._rv(bytes([0xC0, 0x00, 0x00, 0x00]), 0)
        assert val is None


class TestQUICSmallPacketTruncations:
    """
    Lines 82: dcid overrun with minimal valid packet length (>=7).

    Lines 60, 66, 76 are dead code — the `len(data) < 7` guard at line 51
    makes those specific bounds checks unreachable; they exist as defensive
    belt-and-suspenders assertions.  We document this here so future readers
    know why coverage shows them as uncoverable without source changes.
    """

    def test_dcid_overruns_remaining_bytes_returns_none(self):
        """dcid_len byte claims 2 bytes but only 1 byte follows (line 82).
        Input: 7 bytes (passes len<7 guard), dcid_len=2 but only 1 remaining.
        So what: a crafted DCID length must not cause slice-beyond-end in packet capture.
        """
        # Layout: [first_byte(1)] [version(4)] [dcid_len=2(1)] [one_byte(1)] — 7 bytes
        data = bytes([0xC3]) + struct.pack("!I", _QUIC_V1) + bytes([2, 0x00])
        assert extract_quic_fingerprint(data) is None
