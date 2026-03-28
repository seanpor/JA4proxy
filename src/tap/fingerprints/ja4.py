"""
JA4 — TLS client fingerprint extractor (Phase 20, Group 5-A).

Parses a raw TLS ClientHello byte buffer and returns a JA4Result.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional


# GREASE values (RFC 8701)
_GREASE = frozenset(
    [
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    ]
)

# TLS extension type codes
_EXT_SNI = 0
_EXT_SESSION_TICKET = 35
_EXT_SUPPORTED_GROUPS = 10
_EXT_SIG_ALGS = 13
_EXT_ALPN = 16
_EXT_SUPPORTED_VERSIONS = 43
_EXT_KEY_SHARE = 51
_EXT_PSK_MODES = 45
_EXT_PADDING = 21
_EXT_COMPRESS_CERT = 27  # RFC 8879

# TLS version mapping
_TLS_VERSIONS = {
    0x0301: "10",
    0x0302: "11",
    0x0303: "12",
    0x0304: "13",
}


@dataclass
class JA4Result:
    """Parsed JA4 fingerprint from a TLS ClientHello."""

    fingerprint: str
    tls_version_offered: str
    ciphers: list[int]
    extensions: list[int]
    alpn_list: list[str]
    sni: Optional[str]
    key_share_groups: list[int] = field(default_factory=list)
    psk_modes: list[int] = field(default_factory=list)
    supported_groups: list[int] = field(default_factory=list)
    signature_algorithms: list[int] = field(default_factory=list)
    session_ticket_present: bool = False
    session_ticket_len: int = 0
    grease_values: list[int] = field(default_factory=list)
    padding_ext_len: Optional[int] = None
    compress_cert_present: bool = False


def extract_ja4(client_hello: bytes) -> Optional[JA4Result]:
    """Parse raw TLS ClientHello bytes and return JA4 fingerprint.

    Args:
        client_hello: Raw bytes starting at the TLS record header (0x16 0x03 ...).

    Returns:
        JA4Result on success, None if the buffer is not a valid ClientHello
        or is incomplete.
    """
    try:
        return _parse(client_hello)
    except Exception:
        return None


def _parse(data: bytes) -> Optional[JA4Result]:
    """Internal parser — may raise; caller catches."""
    pos = 0
    n = len(data)

    # ── TLS Record Header (5 bytes) ──────────────────────────────────────
    if n < 5:
        return None
    rec_type = data[0]
    if rec_type != 0x16:  # TLS Handshake
        return None
    record_len = struct.unpack_from("!H", data, 3)[0]
    pos = 5
    if pos + record_len > n:
        return None  # Incomplete record

    # ── Handshake Header (4 bytes) ────────────────────────────────────────
    if pos + 4 > n:
        return None
    msg_type = data[pos]
    if msg_type != 0x01:  # ClientHello
        return None
    hs_len = struct.unpack_from("!I", bytes([0]) + data[pos + 1: pos + 4])[0]
    pos += 4
    hs_end = pos + hs_len
    if hs_end > n:
        return None

    # ── ClientHello Body ─────────────────────────────────────────────────
    # client_version (2 bytes)
    if pos + 2 > hs_end:
        return None
    client_version = struct.unpack_from("!H", data, pos)[0]
    pos += 2

    # random (32 bytes)
    if pos + 32 > hs_end:
        return None
    pos += 32  # skip random

    # session_id
    if pos + 1 > hs_end:
        return None
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos > hs_end:
        return None

    # cipher_suites
    if pos + 2 > hs_end:
        return None
    cs_len = struct.unpack_from("!H", data, pos)[0]
    pos += 2
    if pos + cs_len > hs_end or cs_len % 2 != 0:
        return None
    ciphers_raw = list(struct.unpack_from(f"!{cs_len // 2}H", data, pos))
    pos += cs_len

    # compression_methods
    if pos + 1 > hs_end:
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos > hs_end:
        return None

    # extensions (optional — some legacy hellos omit them)
    extensions_raw: list[int] = []
    alpn_list: list[str] = []
    sni: Optional[str] = None
    supported_versions: list[int] = []
    supported_groups: list[int] = []
    sig_algs: list[int] = []
    key_share_groups: list[int] = []
    psk_modes: list[int] = []
    session_ticket_present = False
    session_ticket_len = 0
    padding_ext_len: Optional[int] = None
    compress_cert_present = False
    grease_found: list[int] = []

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

                if ext_type in _GREASE:
                    grease_found.append(ext_type)
                    continue

                _parse_extension(
                    ext_type,
                    ext_payload,
                    alpn_list,
                    supported_versions,
                    supported_groups,
                    sig_algs,
                    key_share_groups,
                    psk_modes,
                    result_sni=sni,
                )
                # Handle fields that need direct assignment
                if ext_type == _EXT_SNI:
                    sni = _parse_sni(ext_payload)
                elif ext_type == _EXT_SESSION_TICKET:
                    session_ticket_present = True
                    session_ticket_len = ext_len
                elif ext_type == _EXT_PADDING:
                    padding_ext_len = ext_len
                elif ext_type == _EXT_COMPRESS_CERT:
                    compress_cert_present = True

    # ── Determine TLS version ─────────────────────────────────────────────
    # If supported_versions extension has 0x0304 (TLS 1.3), use "13"
    if 0x0304 in supported_versions:
        tls_ver = "13"
    else:
        tls_ver = _TLS_VERSIONS.get(client_version, "00")

    # ── Compute JA4 components ─────────────────────────────────────────────
    proto = "t"  # TCP/TLS (not QUIC/DTLS)
    sni_char = "d" if sni is not None else "i"

    # Filter GREASE from ciphers and extensions for fingerprint
    ciphers_filt = [c for c in ciphers_raw if c not in _GREASE]
    exts_filt = [e for e in extensions_raw if e not in _GREASE]

    cipher_count = len(ciphers_filt)
    ext_count = len(exts_filt)

    alpn_str = _alpn_chars(alpn_list)

    cipher_hash = _hash_ciphers(ciphers_filt)
    ext_hash = _hash_exts(exts_filt)

    fingerprint = (
        f"{proto}{tls_ver}{sni_char}{cipher_count:02d}{ext_count:02d}{alpn_str}"
        f"_{cipher_hash}_{ext_hash}"
    )

    return JA4Result(
        fingerprint=fingerprint,
        tls_version_offered=tls_ver,
        ciphers=ciphers_raw,
        extensions=extensions_raw,
        alpn_list=alpn_list,
        sni=sni,
        key_share_groups=key_share_groups,
        psk_modes=psk_modes,
        supported_groups=supported_groups,
        signature_algorithms=sig_algs,
        session_ticket_present=session_ticket_present,
        session_ticket_len=session_ticket_len,
        grease_values=grease_found,
        padding_ext_len=padding_ext_len,
        compress_cert_present=compress_cert_present,
    )


def _parse_extension(
    ext_type: int,
    payload: bytes,
    alpn_list: list,
    supported_versions: list,
    supported_groups: list,
    sig_algs: list,
    key_share_groups: list,
    psk_modes: list,
    result_sni,
) -> None:
    """Parse known extension types; fill the relevant lists in place."""
    try:
        if ext_type == _EXT_ALPN:
            _parse_alpn(payload, alpn_list)
        elif ext_type == _EXT_SUPPORTED_VERSIONS:
            _parse_supported_versions(payload, supported_versions)
        elif ext_type == _EXT_SUPPORTED_GROUPS:
            _parse_uint16_list_with_len(payload, supported_groups)
        elif ext_type == _EXT_SIG_ALGS:
            _parse_uint16_list_with_len(payload, sig_algs)
        elif ext_type == _EXT_KEY_SHARE:
            _parse_key_share_ext(payload, key_share_groups)
        elif ext_type == _EXT_PSK_MODES:
            if len(payload) >= 1:
                count = payload[0]
                for i in range(1, 1 + count):
                    if i < len(payload):
                        psk_modes.append(payload[i])
    except Exception:
        pass


def _parse_sni(payload: bytes) -> Optional[str]:
    """Parse SNI extension payload, return hostname string or None."""
    try:
        if len(payload) < 5:
            return None
        # server_name_list_length (2) + name_type (1) + name_length (2) + name
        list_len = struct.unpack_from("!H", payload, 0)[0]
        if list_len + 2 > len(payload):
            return None
        name_type = payload[2]
        if name_type != 0:  # 0 = host_name
            return None
        name_len = struct.unpack_from("!H", payload, 3)[0]
        if 5 + name_len > len(payload):
            return None
        return payload[5:5 + name_len].decode("ascii", errors="ignore")
    except Exception:
        return None


def _parse_alpn(payload: bytes, out: list) -> None:
    """Parse ALPN extension payload, append protocol strings to out."""
    try:
        if len(payload) < 2:
            return
        list_len = struct.unpack_from("!H", payload, 0)[0]
        pos = 2
        end = pos + list_len
        while pos + 1 <= end and pos + 1 <= len(payload):
            proto_len = payload[pos]
            pos += 1
            if pos + proto_len > len(payload):
                break
            proto = payload[pos:pos + proto_len].decode("ascii", errors="ignore")
            out.append(proto)
            pos += proto_len
    except Exception:
        pass


def _parse_supported_versions(payload: bytes, out: list) -> None:
    """Parse supported_versions extension, append version ints to out."""
    try:
        if len(payload) < 1:
            return
        list_len = payload[0]
        for i in range(1, 1 + list_len, 2):
            if i + 2 <= len(payload):
                ver = struct.unpack_from("!H", payload, i)[0]
                out.append(ver)
    except Exception:
        pass


def _parse_uint16_list_with_len(payload: bytes, out: list) -> None:
    """Parse a uint16-length-prefixed list of uint16 values."""
    try:
        if len(payload) < 2:
            return
        list_len = struct.unpack_from("!H", payload, 0)[0]
        for i in range(2, 2 + list_len, 2):
            if i + 2 <= len(payload):
                out.append(struct.unpack_from("!H", payload, i)[0])
    except Exception:
        pass


def _parse_key_share_ext(payload: bytes, out: list) -> None:
    """Parse key_share extension, append offered group IDs to out."""
    try:
        if len(payload) < 2:
            return
        list_len = struct.unpack_from("!H", payload, 0)[0]
        pos = 2
        end = pos + list_len
        while pos + 4 <= end and pos + 4 <= len(payload):
            group = struct.unpack_from("!H", payload, pos)[0]
            key_len = struct.unpack_from("!H", payload, pos + 2)[0]
            out.append(group)
            pos += 4 + key_len
    except Exception:
        pass


def _alpn_chars(alpn_list: list) -> str:
    """Return 2-char ALPN descriptor: first and last char of first protocol, or '00'."""
    if not alpn_list:
        return "00"
    first = str(alpn_list[0])
    if len(first) >= 2:
        return first[0] + first[-1]
    if len(first) == 1:
        return first[0] + "0"
    return "00"


def _hash_ciphers(ciphers: list) -> str:
    """SHA-256[:12] of sorted non-GREASE cipher suites as comma-joined hex."""
    filtered = [c for c in ciphers if c not in _GREASE]
    if not filtered:
        return "000000000000"
    s = ",".join(f"{c:04x}" for c in sorted(filtered))
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _hash_exts(exts: list) -> str:
    """SHA-256[:12] of sorted non-GREASE extension types, excluding SNI (0) and ALPN (16)."""
    filtered = [
        e for e in exts
        if e not in _GREASE and e != _EXT_SNI and e != _EXT_ALPN
    ]
    if not filtered:
        return "000000000000"
    s = ",".join(f"{e:04x}" for e in sorted(filtered))
    return hashlib.sha256(s.encode()).hexdigest()[:12]
