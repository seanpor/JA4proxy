#!/usr/bin/env python3
"""Compute JA4 fingerprint from a raw TLS ClientHello binary file.

Usage: python3 scripts/compute_ja4.py <file.bin>
Output: the JA4 fingerprint string, or 'ERROR: ...' on failure.

Used by JA4 parity tests to compare Go and Python implementations.

This script parses the raw binary ClientHello without Scapy (which expects
network-captured packets), using the same algorithm as proxy.py JA4Generator
but operating directly on the parsed byte fields.
"""
import hashlib
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# GREASE values per RFC 8701
GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
    0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _parse_raw_clienthello(data: bytes) -> dict:
    """Parse raw TLS ClientHello bytes into field dict matching JA4Generator input."""
    if len(data) < 5:
        raise ValueError("too short for TLS record header")

    # TLS Record layer
    if data[0] != 0x16:
        raise ValueError(f"not a TLS handshake record (type={data[0]:#x})")
    record_len = struct.unpack_from(">H", data, 3)[0]
    if len(data) < 5 + record_len:
        raise ValueError("truncated TLS record")

    body = data[5:5 + record_len]
    if len(body) < 4:
        raise ValueError("truncated handshake header")
    if body[0] != 0x01:
        raise ValueError(f"not a ClientHello (handshake type={body[0]:#x})")

    hello_len = (body[1] << 16) | (body[2] << 8) | body[3]
    if len(body) < 4 + hello_len:
        raise ValueError("truncated ClientHello body")

    hello = body[4:4 + hello_len]

    # legacy_version (2) + random (32) = 34 bytes minimum
    if len(hello) < 34:
        raise ValueError("ClientHello body too short")

    legacy_version = struct.unpack_from(">H", hello, 0)[0]
    pos = 34  # skip version + random

    # session_id
    if pos >= len(hello):
        raise ValueError("truncated at session_id length")
    sid_len = hello[pos]
    pos += 1 + sid_len

    # cipher suites
    if pos + 2 > len(hello):
        raise ValueError("truncated at cipher suites length")
    cs_len = struct.unpack_from(">H", hello, pos)[0]
    pos += 2
    if pos + cs_len > len(hello):
        raise ValueError("truncated cipher suites")
    cipher_suites = []
    for i in range(0, cs_len, 2):
        cs = struct.unpack_from(">H", hello, pos + i)[0]
        cipher_suites.append(cs)
    pos += cs_len

    # compression methods
    if pos >= len(hello):
        raise ValueError("truncated at compression methods")
    comp_len = hello[pos]
    pos += 1 + comp_len

    # extensions (optional)
    extensions = []
    supported_versions = []
    alpn = []
    sni = None

    if pos + 2 <= len(hello):
        ext_total = struct.unpack_from(">H", hello, pos)[0]
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end:
            ext_type = struct.unpack_from(">H", hello, pos)[0]
            ext_len = struct.unpack_from(">H", hello, pos + 2)[0]
            pos += 4
            ext_body = hello[pos:pos + ext_len]
            pos += ext_len

            extensions.append(ext_type)

            if ext_type == 0x0000:  # SNI
                if len(ext_body) >= 5:
                    list_len = struct.unpack_from(">H", ext_body, 0)[0]
                    if list_len >= 3 and 2 + list_len <= len(ext_body):
                        name_len = struct.unpack_from(">H", ext_body, 3)[0]
                        if 5 + name_len <= len(ext_body):
                            sni = ext_body[5:5 + name_len].decode("ascii", errors="ignore")

            elif ext_type == 0x0010:  # ALPN
                if len(ext_body) >= 2:
                    proto_list_len = struct.unpack_from(">H", ext_body, 0)[0]
                    ep = 2
                    end = min(2 + proto_list_len, len(ext_body))
                    while ep + 1 <= end:
                        plen = ext_body[ep]
                        ep += 1
                        if ep + plen > end:
                            break
                        alpn.append(ext_body[ep:ep + plen].decode("ascii", errors="ignore"))
                        ep += plen

            elif ext_type == 0x002b:  # supported_versions
                if len(ext_body) >= 1:
                    vlist_len = ext_body[0]
                    for vi in range(0, vlist_len, 2):
                        if 1 + vi + 2 <= len(ext_body):
                            v = struct.unpack_from(">H", ext_body, 1 + vi)[0]
                            supported_versions.append(v)

    return {
        "version": legacy_version,
        "cipher_suites": cipher_suites,
        "extensions": extensions,
        "supported_versions": supported_versions,
        "alpn": alpn,
        "sni": sni,
    }


def _tls_version_string(v: int) -> str:
    return {0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}.get(v, "00")


def _alpn_string(protocols: list) -> str:
    if not protocols:
        return "00"
    first = protocols[0]
    if not first:
        return "00"
    if len(first) == 1:
        return first[0] + "0"
    return first[0] + first[-1]


def _hash12(values: list, fmt: str = "%04x") -> str:
    """SHA-256 of sorted comma-joined hex values, first 12 chars."""
    if not values:
        return "000000000000"
    sorted_vals = sorted(values)
    s = ",".join(fmt % v for v in sorted_vals)
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def compute_ja4_from_file(path: str) -> str:
    data = pathlib.Path(path).read_bytes()
    try:
        fields = _parse_raw_clienthello(data)
    except Exception as e:
        return f"PARSE_FAILED: {e}"

    try:
        legacy_version = fields["version"]
        cipher_suites = fields["cipher_suites"]
        extensions = fields["extensions"]
        supported_versions = fields["supported_versions"]
        alpn = fields["alpn"]
        _sni = fields["sni"]

        # TLS version: prefer supported_versions extension for TLS 1.3
        version = _tls_version_string(legacy_version)
        if 0x0304 in supported_versions:
            version = "13"

        # SNI indicator
        sni_char = "d" if (0x0000 in extensions) else "i"

        # Cipher suites: filter GREASE, count, hash sorted
        filtered_ciphers = [c for c in cipher_suites if c not in GREASE_VALUES]
        cipher_count = len(filtered_ciphers)
        cipher_hash = _hash12(filtered_ciphers)

        # Extensions: filter GREASE; count includes SNI, hash excludes SNI (type 0)
        filtered_exts = [e for e in extensions if e not in GREASE_VALUES]
        ext_count = len(filtered_exts)
        hashable_exts = [e for e in filtered_exts if e != 0x0000]
        ext_hash = _hash12(hashable_exts)

        # ALPN
        alpn_str = _alpn_string(alpn)

        return f"t{version}{sni_char}{cipher_count:02d}{ext_count:02d}{alpn_str}_{cipher_hash}_{ext_hash}"

    except Exception as e:
        return f"ERROR: {e}"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: compute_ja4.py <file.bin>", file=sys.stderr)
        sys.exit(1)
    print(compute_ja4_from_file(sys.argv[1]))
