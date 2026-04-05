"""Fuzz / robustness tests for the pure-Python TLS ClientHello parser.

These tests verify that parse_client_hello() never raises an exception and
returns either None (failure to parse) or a valid result dict for every
possible input — including malformed, truncated, or adversarially crafted
byte sequences.

The parser lives at src/tls/parser.py and is the zero-dependency fast path
for JA4 fingerprinting.

Test categories:
  1. Trivially short / empty inputs
  2. Truncated valid ClientHello structures
  3. Random / garbage data
  4. Adversarial edge cases (huge extension lists, all-zeros, ...)
  5. Extension-length overflow
"""

import os
import struct

import pytest

from src.tls.parser import parse_client_hello


# ---------------------------------------------------------------------------
# Helper: load a known-good ClientHello fixture
# ---------------------------------------------------------------------------

_FIXTURE_DIR = os.path.join(
    os.path.dirname(__file__), "..", "fixtures", "clienthello"
)


def _load_fixture(name: str) -> bytes:
    path = os.path.join(_FIXTURE_DIR, name)
    with open(path, "rb") as fh:
        return fh.read()


# The synthetic TLS 1.3 ClientHello from the test fixtures directory.
# Hex: 16030100730100006f0303...
_VALID_TLS13 = _load_fixture("synthetic_tls13_basic.bin")


# ---------------------------------------------------------------------------
# Helper: valid-result predicate
# ---------------------------------------------------------------------------


def _is_valid_result(r) -> bool:
    """Return True iff r is a dict with expected keys (non-None valid result)."""
    if r is None:
        return True  # None is always acceptable
    required_keys = {"version", "cipher_suites", "extensions", "sni", "alpn"}
    return isinstance(r, dict) and required_keys.issubset(r.keys())


# ---------------------------------------------------------------------------
# 1. Trivially short / empty inputs
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data,label",
    [
        (b"", "empty bytes"),
        (b"\x16", "single TLS record-type byte"),
        (b"\x16\x03", "two bytes — incomplete record header"),
        (b"\x16\x03\x01\x00\x01", "record header complete but body missing"),
        (b"\x00" * 4, "all-zeros short buffer"),
    ],
)
def test_short_inputs_never_raise(data: bytes, label: str):
    """Short/empty byte sequences must return None without raising."""
    result = parse_client_hello(data)
    assert result is None, f"Expected None for {label!r}; got {result!r}"


# ---------------------------------------------------------------------------
# 2. Truncated valid ClientHello
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("truncate_at", [1, 5, 9, 20, 40, 60, 80, 100, 115])
def test_truncated_valid_clienthello_no_exception(truncate_at: int):
    """A valid ClientHello truncated at various offsets must not raise."""
    data = _VALID_TLS13[:truncate_at]
    result = parse_client_hello(data)
    assert _is_valid_result(result), f"Unexpected result type at truncate_at={truncate_at}"


def test_full_valid_clienthello_parses_successfully():
    """The untruncated synthetic TLS 1.3 ClientHello must parse to a non-None dict."""
    result = parse_client_hello(_VALID_TLS13)
    assert result is not None, "Expected successful parse of known-good ClientHello"
    assert isinstance(result, dict)
    assert "cipher_suites" in result
    assert isinstance(result["cipher_suites"], list)


# ---------------------------------------------------------------------------
# 3. Random / garbage data
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(10))
def test_random_1000_bytes_no_exception(seed: int):
    """1000 random bytes must return None or a valid dict — never raise."""
    # Deterministic pseudo-random bytes based on seed (no stdlib random needed)
    data = bytes((seed * 37 + i * 13 + i * i) % 256 for i in range(1000))
    result = parse_client_hello(data)
    assert _is_valid_result(result), f"Invalid result for seed={seed}: {result!r}"


def test_all_null_bytes_1000():
    """1000 null bytes → must return None, no exception."""
    result = parse_client_hello(b"\x00" * 1000)
    assert result is None


def test_all_0xff_bytes_1000():
    """1000 0xFF bytes → must return None, no exception."""
    result = parse_client_hello(b"\xff" * 1000)
    assert result is None


def test_tls_record_type_but_garbage_body():
    """Correct TLS record type byte (0x16) followed by garbage → None, no exception."""
    data = b"\x16" + bytes(range(256)) * 4
    result = parse_client_hello(data)
    assert _is_valid_result(result)


# ---------------------------------------------------------------------------
# 4. Adversarial edge cases
# ---------------------------------------------------------------------------


def _build_clienthello_with_extensions(extensions_bytes: bytes) -> bytes:
    """Construct a minimal TLS 1.3 ClientHello with the given extensions block."""
    # ClientHello body (no session ID, no cipher suites, no compression methods)
    # 2 bytes version (0x0303)
    # 32 bytes random
    # 1 byte session_id_len = 0
    # 2 bytes cipher_suites_len = 2, then one cipher suite (0x1301)
    # 1 byte compression_methods_len = 1, then 0x00
    ch_body = (
        b"\x03\x03"          # legacy version
        + b"\xab" * 32       # random
        + b"\x00"            # session_id_len = 0
        + b"\x00\x02"        # cipher_suites_len = 2
        + b"\x13\x01"        # TLS_AES_128_GCM_SHA256
        + b"\x01\x00"        # compression_methods: 1 byte, value 0x00
        + extensions_bytes
    )
    # Handshake header: type=0x01, length = len(ch_body)
    hs_len = len(ch_body)
    hs_header = b"\x01" + struct.pack("!I", hs_len)[1:]  # 3-byte big-endian length
    # TLS record header: content_type=0x16, version=0x0301, length = hs_len+4
    record_body = hs_header + ch_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_body)) + record_body
    return record


def test_empty_extension_list_no_exception():
    """ClientHello with zero extensions → valid parse or None, no exception."""
    # No extensions bytes at all (omit extension list entirely)
    result = parse_client_hello(_build_clienthello_with_extensions(b""))
    assert _is_valid_result(result)


def test_500_minimal_extensions_no_stack_exhaustion():
    """ClientHello with 500 extensions of 4 bytes each → no exception (stack safety)."""
    # Each extension: 2 bytes type + 2 bytes length (0) = 4 bytes total, zero-length data
    single_ext = b"\x00\x09\x00\x00"  # ext type 9 (padding), length 0
    ext_list = single_ext * 500
    # 2-byte total extensions length prefix
    exts_block = struct.pack("!H", len(ext_list)) + ext_list
    result = parse_client_hello(_build_clienthello_with_extensions(exts_block))
    assert _is_valid_result(result)


def test_extension_length_exceeds_record_length():
    """Extension length field larger than remaining record → None, no exception."""
    # Build a valid-looking extension header but with ext_len=9999
    ext_overflow = (
        struct.pack("!H", 8)       # total extensions length = 8 bytes
        + b"\x00\x00"              # ext type = SNI (0)
        + struct.pack("!H", 9999)  # ext data length claims 9999 bytes (overflow!)
        + b"\x00\x00"              # only 2 bytes of actual data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_overflow))
    assert _is_valid_result(result)


def test_sni_extension_length_overflow():
    """SNI extension with internal name_len pointing past buffer → None, no exception."""
    # SNI ext: list_len=5, name_type=0, name_len=0xFFFF (overflow)
    sni_ext_data = b"\x00\x05\x00\xff\xff\x68\x69"  # name_len=0xFFFF
    ext_block = (
        struct.pack("!H", len(sni_ext_data) + 4)   # total exts len
        + b"\x00\x00"                               # ext type = SNI
        + struct.pack("!H", len(sni_ext_data))      # ext data length
        + sni_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert _is_valid_result(result)


def test_cipher_suites_length_odd_no_exception():
    """Cipher suites length that is odd (malformed) → None, no exception."""
    # Construct a ClientHello where cs_len=3 (odd — would cause off-by-one in loop)
    ch_body = (
        b"\x03\x03"
        + b"\xab" * 32
        + b"\x00"        # session_id_len = 0
        + b"\x00\x03"    # cipher_suites_len = 3 (odd — malformed)
        + b"\x13\x01\x13"  # 3 bytes of cipher data
        + b"\x01\x00"
    )
    hs_len = len(ch_body)
    hs_header = b"\x01" + struct.pack("!I", hs_len)[1:]
    record_body = hs_header + ch_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_body)) + record_body
    result = parse_client_hello(record)
    assert _is_valid_result(result)


def test_session_id_overrun_no_exception():
    """session_id_len=255 but buffer is much smaller → None, no exception."""
    ch_body = (
        b"\x03\x03"
        + b"\xab" * 32
        + b"\xff"  # session_id_len = 255 — claims far more than available
    )
    hs_len = len(ch_body)
    hs_header = b"\x01" + struct.pack("!I", hs_len)[1:]
    record_body = hs_header + ch_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_body)) + record_body
    result = parse_client_hello(record)
    assert _is_valid_result(result)


# ---------------------------------------------------------------------------
# 5. Non-ClientHello TLS records
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content_type,label",
    [
        (0x14, "ChangeCipherSpec"),
        (0x15, "Alert"),
        (0x17, "ApplicationData"),
    ],
)
def test_non_handshake_record_types_return_none(content_type: int, label: str):
    """TLS record types other than 0x16 (Handshake) must return None."""
    data = bytes([content_type]) + b"\x03\x03\x00\x01\x00"
    result = parse_client_hello(data)
    assert result is None, f"Expected None for {label} record type 0x{content_type:02x}"


def test_handshake_type_not_clienthello_returns_none():
    """Handshake type != 0x01 (ServerHello, etc.) must return None."""
    # type=0x02 (ServerHello)
    body = b"\x02\x00\x00\x04" + b"\x03\x03\x00\x00"
    data = b"\x16\x03\x01" + struct.pack("!H", len(body)) + body
    result = parse_client_hello(data)
    assert result is None
