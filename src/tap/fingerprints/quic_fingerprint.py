"""
QUIC Initial packet fingerprint extractor (Phase 20, Group 5-K).

Parses the first few bytes of a QUIC Initial packet (long header format)
to extract the QUIC version and connection ID lengths.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


# QUIC long-header first-byte bit pattern
_QUIC_LONG_HEADER_MASK = 0xC0  # top 2 bits must be 11
_QUIC_LONG_HEADER_VAL = 0xC0

# Known QUIC versions
_QUIC_V1 = 0x00000001
_QUIC_V2 = 0x6B3343CF  # RFC 9369
_VERSION_NEGOTIATION = 0x00000000


@dataclass
class QUICFingerprintResult:
    """QUIC Initial packet fingerprint."""

    quic_version: int
    dcid_len: int
    token_len: int
    embedded_ja4: Optional[str]
    fingerprint: str


def extract_quic_fingerprint(udp_payload: bytes) -> Optional[QUICFingerprintResult]:
    """Parse a QUIC Initial packet and return a fingerprint.

    Args:
        udp_payload: Raw UDP payload bytes starting at the QUIC packet.

    Returns:
        QUICFingerprintResult on success, None on non-QUIC or malformed input.
    """
    try:
        return _parse(udp_payload)
    except Exception:
        return None


def _parse(data: bytes) -> Optional[QUICFingerprintResult]:
    if len(data) < 7:
        return None

    first_byte = data[0]
    # QUIC long-header: top 2 bits must be 11
    if (first_byte & _QUIC_LONG_HEADER_MASK) != _QUIC_LONG_HEADER_VAL:
        return None
    # Long header bit (bit 6 from top) must be 1 for long header
    if not (first_byte & 0x80):
        return None

    pos = 1

    # QUIC Version (4 bytes)
    if pos + 4 > len(data):
        return None
    quic_version = struct.unpack_from("!I", data, pos)[0]
    pos += 4

    # Version Negotiation packet — not an Initial
    if quic_version == _VERSION_NEGOTIATION:
        return None

    # Destination Connection ID Length (1 byte)
    if pos + 1 > len(data):
        return None
    dcid_len = data[pos]
    pos += 1

    # Skip DCID
    if pos + dcid_len > len(data):
        return None
    pos += dcid_len

    # Source Connection ID Length (1 byte)
    if pos + 1 > len(data):
        return None
    scid_len = data[pos]
    pos += 1

    # Skip SCID
    if pos + scid_len > len(data):
        return None
    pos += scid_len

    # Token Length (variable-length integer)
    token_len, pos = _read_varint(data, pos)
    if token_len is None:
        return None

    # Build fingerprint string
    ver_str = _version_str(quic_version)
    fingerprint = f"quic_{ver_str}_dcid{dcid_len}_tok{token_len}"

    return QUICFingerprintResult(
        quic_version=quic_version,
        dcid_len=dcid_len,
        token_len=token_len,
        embedded_ja4=None,  # Would require decryption of crypto frame
        fingerprint=fingerprint,
    )


def _read_varint(data: bytes, pos: int) -> tuple[Optional[int], int]:
    """Read a QUIC variable-length integer. Returns (value, new_pos)."""
    if pos >= len(data):
        return None, pos
    first = data[pos]
    length_type = (first & 0xC0) >> 6
    if length_type == 0:
        return first & 0x3F, pos + 1
    if length_type == 1:
        if pos + 2 > len(data):
            return None, pos
        val = struct.unpack_from("!H", data, pos)[0] & 0x3FFF
        return val, pos + 2
    if length_type == 2:
        if pos + 4 > len(data):
            return None, pos
        val = struct.unpack_from("!I", data, pos)[0] & 0x3FFFFFFF
        return val, pos + 4
    if pos + 8 > len(data):
        return None, pos
    val = struct.unpack_from("!Q", data, pos)[0] & 0x3FFFFFFFFFFFFFFF
    return val, pos + 8


def _version_str(version: int) -> str:
    if version == _QUIC_V1:
        return "v1"
    if version == _QUIC_V2:
        return "v2"
    return f"0x{version:08x}"
