#!/usr/bin/env python3
"""
Generate synthetic TLS ClientHello fixture files with known JA4 fingerprints.

Saves binary files to tests/fixtures/clienthello/ and writes
tests/fixtures/clienthello/known_ja4.json mapping fixture name -> expected JA4.

These fixtures enable parity tests without requiring browser containers.
The JA4 values are computed purely from the binary structure using the same
algorithm as both the Go and Python implementations.

Fixtures generated:
  synthetic_tls13_basic.bin   -- TLS 1.3, AES-GCM ciphers, SNI, standard extensions
  synthetic_tls12_basic.bin   -- TLS 1.2, RSA+AES ciphers, SNI
  synthetic_tls13_no_sni.bin  -- TLS 1.3, no SNI extension
  synthetic_grease.bin        -- TLS 1.3 with GREASE values (must be filtered)
"""
import hashlib
import json
import pathlib
import struct
import sys

FIXTURES_DIR = pathlib.Path(__file__).parent.parent / "tests" / "fixtures" / "clienthello"

# GREASE values per RFC 8701
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}

# Well-known cipher suites
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
GREASE_0A0A = 0x0A0A

# Extension types
EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SESSION_TICKET = 0x0023
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_KEY_SHARE = 0x0033


# ── Low-level builders ────────────────────────────────────────────────────────

def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def _sni_ext(hostname: str) -> bytes:
    name = hostname.encode()
    entry = struct.pack(">BH", 0, len(name)) + name
    body = struct.pack(">H", len(entry)) + entry
    return _ext(EXT_SNI, body)


def _supported_versions_ext(versions: list) -> bytes:
    data = struct.pack(f">B{len(versions)}H", len(versions) * 2, *versions)
    return _ext(EXT_SUPPORTED_VERSIONS, data)


def _supported_groups_ext(groups: list) -> bytes:
    data = struct.pack(f">H{len(groups)}H", len(groups) * 2, *groups)
    return _ext(EXT_SUPPORTED_GROUPS, data)


def _signature_algorithms_ext(algs: list) -> bytes:
    data = struct.pack(f">H{len(algs)}H", len(algs) * 2, *algs)
    return _ext(EXT_SIGNATURE_ALGORITHMS, data)


def _session_ticket_ext() -> bytes:
    return _ext(EXT_SESSION_TICKET, b"")


def _ec_point_formats_ext() -> bytes:
    # uncompressed (0)
    return _ext(EXT_EC_POINT_FORMATS, struct.pack(">BB", 1, 0))


def _alpn_ext(protocols: list) -> bytes:
    proto_bytes = b"".join(struct.pack(">B", len(p)) + p.encode() for p in protocols)
    body = struct.pack(">H", len(proto_bytes)) + proto_bytes
    return _ext(EXT_ALPN, body)


def _build_record(ciphers: list, extensions_bytes: bytes) -> bytes:
    """Build a complete TLS ClientHello record."""
    cipher_bytes = struct.pack(f">{len(ciphers)}H", *ciphers)
    cipher_suites_field = struct.pack(">H", len(cipher_bytes)) + cipher_bytes

    random_bytes = b"\xAB" * 32
    session_id = b"\x00"  # empty
    compression = b"\x01\x00"  # 1 method: null

    extensions_field = struct.pack(">H", len(extensions_bytes)) + extensions_bytes

    # ClientHello body: legacy_version(0x0303) + random + session_id + ciphers + compression + extensions
    hello_body = (
        struct.pack(">H", 0x0303)
        + random_bytes
        + session_id
        + cipher_suites_field
        + compression
        + extensions_field
    )

    # Handshake: type=1 (ClientHello) + uint24 length
    hs_len = len(hello_body)
    handshake = (
        struct.pack(">B", 0x01)
        + struct.pack(">I", hs_len)[1:]  # uint24 big-endian
        + hello_body
    )

    # TLS record: content_type=22, version=0x0301, length
    record = struct.pack(">BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


# ── JA4 computation (pure Python, no Scapy) ────────────────────────────────

def _tls_version_str(v: int) -> str:
    return {0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}.get(v, "00")


def _alpn_str(protocols: list) -> str:
    if not protocols:
        return "00"
    first = protocols[0]
    if not first:
        return "00"
    return first[0] + (first[-1] if len(first) > 1 else "0")


def _hash12(values: list) -> str:
    if not values:
        return "000000000000"
    s = ",".join("%04x" % v for v in sorted(values))
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def compute_ja4(
    ciphers: list,
    extensions: list,
    supported_versions: list,
    alpn: list,
    sni_present: bool,
) -> str:
    proto = "t"

    # Version: use supported_versions if TLS 1.3 present
    legacy_ver = 0x0303  # always 0x0303 in our synthetic fixtures
    version = _tls_version_str(legacy_ver)
    if 0x0304 in supported_versions:
        version = "13"

    sni_char = "d" if sni_present else "i"

    # Filter GREASE
    filtered_ciphers = [c for c in ciphers if c not in GREASE_VALUES]
    filtered_exts = [e for e in extensions if e not in GREASE_VALUES]
    hashable_exts = [e for e in filtered_exts if e != EXT_SNI]

    cipher_count = len(filtered_ciphers)
    ext_count = len(filtered_exts)
    cipher_hash = _hash12(filtered_ciphers)
    ext_hash = _hash12(hashable_exts)
    alpn_str = _alpn_str(alpn)

    return f"{proto}{version}{sni_char}{cipher_count:02d}{ext_count:02d}{alpn_str}_{cipher_hash}_{ext_hash}"


# ── Fixture definitions ────────────────────────────────────────────────────────

def make_synthetic_tls13_basic():
    """TLS 1.3: AES-GCM ciphers, SNI, standard extensions."""
    ciphers = [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ]
    sni = "test.example.com"
    exts_bytes = (
        _sni_ext(sni)
        + _supported_versions_ext([0x0304, 0x0303])
        + _supported_groups_ext([0x001D, 0x0017, 0x0018])
        + _signature_algorithms_ext([0x0403, 0x0804, 0x0401, 0x0503])
        + _session_ticket_ext()
    )
    ext_types = [EXT_SNI, EXT_SUPPORTED_VERSIONS, EXT_SUPPORTED_GROUPS,
                 EXT_SIGNATURE_ALGORITHMS, EXT_SESSION_TICKET]
    record = _build_record(ciphers, exts_bytes)
    ja4 = compute_ja4(
        ciphers=ciphers,
        extensions=ext_types,
        supported_versions=[0x0304, 0x0303],
        alpn=[],
        sni_present=True,
    )
    return record, ja4


def make_synthetic_tls12_basic():
    """TLS 1.2: RSA+AES ciphers, SNI, no TLS 1.3 supported_versions."""
    ciphers = [
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        TLS_RSA_WITH_AES_128_CBC_SHA,
    ]
    sni = "test.example.com"
    exts_bytes = (
        _sni_ext(sni)
        + _supported_groups_ext([0x0017, 0x0018, 0x0019])
        + _ec_point_formats_ext()
        + _signature_algorithms_ext([0x0401, 0x0501, 0x0601, 0x0403])
        + _session_ticket_ext()
    )
    ext_types = [EXT_SNI, EXT_SUPPORTED_GROUPS, EXT_EC_POINT_FORMATS,
                 EXT_SIGNATURE_ALGORITHMS, EXT_SESSION_TICKET]
    record = _build_record(ciphers, exts_bytes)
    # No 0x0304 in supported_versions -> legacy_version 0x0303 -> version "12"
    ja4 = compute_ja4(
        ciphers=ciphers,
        extensions=ext_types,
        supported_versions=[],
        alpn=[],
        sni_present=True,
    )
    return record, ja4


def make_synthetic_tls13_no_sni():
    """TLS 1.3: no SNI extension."""
    ciphers = [
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
    ]
    exts_bytes = (
        _supported_versions_ext([0x0304, 0x0303])
        + _supported_groups_ext([0x001D, 0x0017])
        + _signature_algorithms_ext([0x0403, 0x0401])
    )
    ext_types = [EXT_SUPPORTED_VERSIONS, EXT_SUPPORTED_GROUPS, EXT_SIGNATURE_ALGORITHMS]
    record = _build_record(ciphers, exts_bytes)
    ja4 = compute_ja4(
        ciphers=ciphers,
        extensions=ext_types,
        supported_versions=[0x0304, 0x0303],
        alpn=[],
        sni_present=False,
    )
    return record, ja4


def make_synthetic_grease():
    """TLS 1.3 with GREASE cipher and GREASE extension — must be filtered."""
    # GREASE cipher is prepended; real ciphers follow
    ciphers = [
        GREASE_0A0A,
        TLS_AES_128_GCM_SHA256,
        TLS_AES_256_GCM_SHA384,
        TLS_CHACHA20_POLY1305_SHA256,
    ]
    sni = "grease.example.com"
    # GREASE extension type 0x0A0A included in extension list
    grease_ext = _ext(0x0A0A, b"\x00")
    exts_bytes = (
        _sni_ext(sni)
        + grease_ext
        + _supported_versions_ext([0x0304, 0x0303])
        + _supported_groups_ext([0x001D, 0x0017])
        + _signature_algorithms_ext([0x0403, 0x0401])
    )
    # Extension types as they appear (GREASE included for accurate count/hash computation)
    ext_types = [EXT_SNI, 0x0A0A, EXT_SUPPORTED_VERSIONS, EXT_SUPPORTED_GROUPS,
                 EXT_SIGNATURE_ALGORITHMS]
    record = _build_record(ciphers, exts_bytes)
    ja4 = compute_ja4(
        ciphers=ciphers,
        extensions=ext_types,
        supported_versions=[0x0304, 0x0303],
        alpn=[],
        sni_present=True,
    )
    return record, ja4


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    fixtures = {
        "synthetic_tls13_basic": make_synthetic_tls13_basic,
        "synthetic_tls12_basic": make_synthetic_tls12_basic,
        "synthetic_tls13_no_sni": make_synthetic_tls13_no_sni,
        "synthetic_grease": make_synthetic_grease,
    }

    known_ja4 = {}
    for name, builder in fixtures.items():
        record, ja4 = builder()
        out = FIXTURES_DIR / f"{name}.bin"
        out.write_bytes(record)
        known_ja4[name] = ja4
        print(f"  {out.name}  ({len(record)} bytes)  JA4={ja4}")

    # Write known_ja4.json
    json_path = FIXTURES_DIR / "known_ja4.json"
    json_path.write_text(json.dumps(known_ja4, indent=2) + "\n")
    print(f"\nWrote {json_path}")
    print(f"Generated {len(fixtures)} synthetic fixtures.")


if __name__ == "__main__":
    main()
