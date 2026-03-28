"""
JA4S — TLS server fingerprint extractor (Phase 20, Group 5-B).

Parses a raw TLS ServerHello byte buffer and returns a JA4SResult.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from src.tap.fingerprints.ja4 import _GREASE, _TLS_VERSIONS, _parse_alpn

_EXT_ALPN = 16
_EXT_SUPPORTED_VERSIONS = 43


@dataclass
class JA4SResult:
    """Parsed JA4S fingerprint from a TLS ServerHello."""

    fingerprint: str
    tls_version_negotiated: str
    cipher_chosen: int
    alpn_chosen: Optional[str]
    extensions: list[int]
    session_id_present: bool
    supported_versions_ext: list[int] = field(default_factory=list)


def extract_ja4s(server_hello: bytes) -> Optional[JA4SResult]:
    """Parse raw TLS ServerHello bytes and return JA4S fingerprint.

    Args:
        server_hello: Raw bytes starting at the TLS record header (0x16 0x03 ...).

    Returns:
        JA4SResult on success, None on invalid / incomplete input.
    """
    try:
        return _parse(server_hello)
    except Exception:
        return None


def _parse(data: bytes) -> Optional[JA4SResult]:
    pos = 0
    n = len(data)

    # TLS Record Header (5 bytes)
    if n < 5:
        return None
    if data[0] != 0x16:
        return None
    record_len = struct.unpack_from("!H", data, 3)[0]
    pos = 5
    if pos + record_len > n:
        return None

    # Handshake Header (4 bytes)
    if pos + 4 > n:
        return None
    msg_type = data[pos]
    if msg_type != 0x02:  # ServerHello
        return None
    hs_len = struct.unpack_from("!I", bytes([0]) + data[pos + 1:pos + 4])[0]
    pos += 4
    hs_end = pos + hs_len
    if hs_end > n:
        return None

    # server_version (2)
    if pos + 2 > hs_end:
        return None
    server_version = struct.unpack_from("!H", data, pos)[0]
    pos += 2

    # server_random (32)
    if pos + 32 > hs_end:
        return None
    pos += 32

    # session_id
    if pos + 1 > hs_end:
        return None
    sid_len = data[pos]
    session_id_present = sid_len > 0
    pos += 1 + sid_len
    if pos > hs_end:
        return None

    # cipher_suite (2)
    if pos + 2 > hs_end:
        return None
    cipher_chosen = struct.unpack_from("!H", data, pos)[0]
    pos += 2

    # compression_method (1)
    if pos + 1 > hs_end:
        return None
    pos += 1

    # Extensions
    extensions_raw: list[int] = []
    alpn_chosen: Optional[str] = None
    supported_versions: list[int] = []

    if pos + 2 <= hs_end:
        ext_total_len = struct.unpack_from("!H", data, pos)[0]
        pos += 2
        ext_end = pos + ext_total_len
        if ext_end <= hs_end:
            while pos + 4 <= ext_end:
                ext_type = struct.unpack_from("!H", data, pos)[0]
                ext_len = struct.unpack_from("!H", data, pos + 2)[0]
                ext_data_start = pos + 4
                ext_data_end = ext_data_start + ext_len
                pos = ext_data_end
                if ext_data_end > ext_end:
                    break
                ext_payload = data[ext_data_start:ext_data_end]
                extensions_raw.append(ext_type)

                if ext_type == _EXT_ALPN:
                    alpn_list: list[str] = []
                    _parse_alpn(ext_payload, alpn_list)
                    if alpn_list:
                        alpn_chosen = alpn_list[0]
                elif ext_type == _EXT_SUPPORTED_VERSIONS:
                    try:
                        if len(ext_payload) >= 2:
                            ver = struct.unpack_from("!H", ext_payload, 0)[0]
                            supported_versions.append(ver)
                    except Exception:
                        pass

    # Determine negotiated version
    if 0x0304 in supported_versions:
        tls_ver = "13"
    else:
        tls_ver = _TLS_VERSIONS.get(server_version, "00")

    # Compute JA4S
    proto = "s"  # server
    alpn_str = _alpn_chars(alpn_chosen)
    exts_filt = [e for e in extensions_raw if e not in _GREASE]
    ext_hash = _hash_exts(exts_filt)
    cipher_hex = f"{cipher_chosen:04x}"

    fingerprint = f"{proto}{tls_ver}01{alpn_str}_{cipher_hex}_{ext_hash}"

    return JA4SResult(
        fingerprint=fingerprint,
        tls_version_negotiated=tls_ver,
        cipher_chosen=cipher_chosen,
        alpn_chosen=alpn_chosen,
        extensions=extensions_raw,
        session_id_present=session_id_present,
        supported_versions_ext=supported_versions,
    )


def _alpn_chars(alpn: Optional[str]) -> str:
    if not alpn:
        return "00"
    if len(alpn) >= 2:
        return alpn[0] + alpn[-1]
    if len(alpn) == 1:
        return alpn[0] + "0"
    return "00"


def _hash_exts(exts: list) -> str:
    if not exts:
        return "000000000000"
    filtered = [e for e in exts if e not in _GREASE]
    if not filtered:
        return "000000000000"
    s = ",".join(f"{e:04x}" for e in sorted(filtered))
    return hashlib.sha256(s.encode()).hexdigest()[:12]
