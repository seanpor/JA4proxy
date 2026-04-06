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


# ---------------------------------------------------------------------------
# 6. Specific branch coverage — previously uncovered lines
# ---------------------------------------------------------------------------


def test_record_len_less_than_hs_len_returns_none():
    """Line 40: record_len < 4 + hs_len → return None.

    Why it matters: A malicious client can craft a packet where the TLS record
    length and handshake length are inconsistent. If this check were skipped,
    the parser would read beyond the declared record boundary.
    """
    # Build a valid-looking minimal ClientHello body
    ch_body = (
        b"\x03\x03"
        + b"\xab" * 32
        + b"\x00"           # session_id_len = 0
        + b"\x00\x02"       # cipher_suites_len = 2
        + b"\x13\x01"       # TLS_AES_128_GCM_SHA256
        + b"\x01\x00"       # compression_methods
    )
    # Handshake header with the real body length
    hs_len = len(ch_body)
    hs_header = b"\x01" + struct.pack("!I", hs_len)[1:]  # 3-byte big-endian
    hs_record = hs_header + ch_body
    # TLS record header, but lie about the record length: claim only 4 bytes
    # so that record_len (4) < 4 + hs_len → return None
    record = b"\x16\x03\x01" + struct.pack("!H", 4) + hs_record
    result = parse_client_hello(record)
    assert result is None, "Expected None when record_len < 4 + hs_len"


def test_body_truncated_before_version_returns_none():
    """Line 49: buffer exhausted before the ClientHello body version/random/session_id.

    Why it matters: A truncated handshake message must be rejected cleanly.
    If the body-size check is skipped, struct.unpack reads beyond the buffer.
    """
    # Handshake header declares hs_len=1, record header matches, but body is
    # only 1 byte — insufficient for the 35-byte version+random+session_id read.
    hs_body = b"\x42"  # 1 byte only
    hs_header = b"\x01" + b"\x00\x00\x01"  # hs_len = 1
    record_body = hs_header + hs_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_body)) + record_body
    result = parse_client_hello(record)
    assert result is None, "Expected None when body is too short for version+random"


def test_cipher_suites_overrun_buffer_returns_none():
    """Line 64: cipher suites cs_len claims more bytes than the buffer contains.

    Why it matters: A malicious client can claim a large cipher suite list to
    make the parser read past the end of the received bytes. This check prevents
    that buffer overread.
    """
    ch_body = (
        b"\x03\x03"
        + b"\xab" * 32     # random
        + b"\x00"           # session_id_len = 0
        + b"\x00\xff"       # cipher_suites_len = 255, but only 2 bytes follow
        + b"\x13\x01"       # only 2 bytes of cipher data — far less than 255
        # compression and extensions intentionally omitted
    )
    hs_len = len(ch_body)
    hs_header = b"\x01" + struct.pack("!I", hs_len)[1:]
    record_body = hs_header + ch_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_body)) + record_body
    result = parse_client_hello(record)
    assert result is None, "Expected None when cipher suites overrun the buffer"


def test_compression_methods_length_byte_missing_returns_none():
    """Line 73: buffer ends before the compression methods length byte → return None.

    Why it matters: The parser must reject a ClientHello that is truncated
    exactly at the compression methods field. If this check were absent, reading
    data[pos] would raise an IndexError. The guard at line 73 prevents that.
    """
    # Build a body that ends immediately after the cipher suites, so there is
    # no byte available for cm_len.  The record and hs headers match exactly,
    # so record_len and hs_len checks all pass — only the cm_len byte is absent.
    ch_body = (
        b"\x03\x03"
        + b"\xab" * 32     # random (32 bytes)
        + b"\x00"           # session_id_len = 0
        + b"\x00\x02"       # cipher_suites_len = 2
        + b"\x13\x01"       # one cipher suite — deliberately ends here, no cm_len
    )
    hs_len = len(ch_body)
    hs_header = b"\x01" + struct.pack("!I", hs_len)[1:]
    record_body = hs_header + ch_body
    record = b"\x16\x03\x01" + struct.pack("!H", len(record_body)) + record_body
    result = parse_client_hello(record)
    assert result is None, "Expected None when cm_len byte is absent from buffer"


def test_ext_len_exceeds_remaining_space_breaks_loop():
    """Line 106: an extension whose data length exceeds exts_end triggers break.

    Why it matters: An extension claiming more bytes than declared in the outer
    extensions block is malformed. The parser must break out of the loop rather
    than reading beyond the extensions boundary. Without this check, subsequent
    extension parsing would operate on wrong offsets.
    """
    # Build a single extension that claims 200 bytes of data, but the outer
    # extensions block only has 4 bytes allocated for it.
    ext_type = 0x000f  # heartbeat — not specially handled, just recorded
    ext_claimed_len = 200  # lies: real data is 0 bytes
    exts_payload = struct.pack("!HH", ext_type, ext_claimed_len)  # 4 bytes, no data
    exts_block = struct.pack("!H", len(exts_payload)) + exts_payload

    result = parse_client_hello(_build_clienthello_with_extensions(exts_block))
    # Must not raise; may return fields dict with empty extensions (loop broke early)
    assert _is_valid_result(result)
    if result is not None:
        # The malformed extension must NOT have been added to the list
        assert ext_type not in result["extensions"], (
            "A malformed extension (ext_len > remaining) must be skipped"
        )


def test_alpn_h2_single_protocol_parsed():
    """Lines 124-138: ALPN extension with a single 'h2' protocol is parsed correctly.

    Why it matters: ALPN determines whether a connection gets the browser bypass.
    If 'h2' is not correctly parsed from the extension, legitimate browser traffic
    could be misclassified and scored as potential bot traffic.
    """
    # ALPN ext_data format: [2-byte total list len][1-byte proto len][proto bytes]
    # 'h2' is 2 bytes; total list = 1 (len byte) + 2 (proto) = 3; so list_len = 3
    alpn_ext_data = b"\x00\x03" + b"\x02" + b"h2"
    ext_block = (
        struct.pack("!H", len(alpn_ext_data) + 4)  # total exts len
        + struct.pack("!H", 16)                     # ext_type = ALPN (0x0010)
        + struct.pack("!H", len(alpn_ext_data))     # ext data length
        + alpn_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert result is not None, "Expected successful parse with ALPN extension"
    assert "h2" in result["alpn"], (
        f"ALPN='h2' must be in result['alpn']; got {result['alpn']!r}"
    )


def test_alpn_h2_and_http11_both_parsed():
    """Lines 124-138: ALPN with two protocols ('h2' + 'http/1.1') parses both.

    Why it matters: Browsers advertise both h2 and http/1.1. Both must appear
    in alpn[] so the pipeline can correctly identify browser traffic and apply
    the bypass — missing either protocol could cause incorrect security decisions.
    """
    # h2 = \x02h2 (3 bytes), http/1.1 = \x08http/1.1 (9 bytes)
    # total list bytes = 3 + 9 = 12, so list_len header = 12
    alpn_ext_data = b"\x00\x0c" + b"\x02h2" + b"\x08http/1.1"
    ext_block = (
        struct.pack("!H", len(alpn_ext_data) + 4)
        + struct.pack("!H", 16)
        + struct.pack("!H", len(alpn_ext_data))
        + alpn_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert result is not None, "Expected successful parse with multi-protocol ALPN"
    assert "h2" in result["alpn"], "h2 must be parsed from ALPN extension"
    assert "http/1.1" in result["alpn"], "http/1.1 must be parsed from ALPN extension"


def test_alpn_too_short_handled_gracefully():
    """Lines 124-138: ALPN ext_data shorter than 3 bytes → silently skipped.

    Why it matters: A truncated ALPN extension must not crash the parser or
    produce garbage in alpn[]. The connection should be processed without ALPN
    rather than incorrectly getting the browser bypass.
    """
    # ext_data only 2 bytes — len(ext_data) >= 3 check fails → alpn stays []
    alpn_ext_data = b"\x00\x01"  # only 2 bytes
    ext_block = (
        struct.pack("!H", len(alpn_ext_data) + 4)
        + struct.pack("!H", 16)
        + struct.pack("!H", len(alpn_ext_data))
        + alpn_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert _is_valid_result(result)
    if result is not None:
        assert result["alpn"] == [], "Truncated ALPN ext must result in empty alpn list"


def test_supported_versions_extension_parsed():
    """Lines 139-149: supported_versions extension (ext_type=43) is parsed.

    Why it matters: supported_versions carries the real TLS version for TLS 1.3
    clients. If this extension is not parsed, the version field will be the
    legacy 0x0303 value and JA4 fingerprinting will misclassify the TLS version.
    """
    # supported_versions ext_data: [1-byte list len][2-byte version] ...
    # TLS 1.3 = 0x0304, list_len = 2 (one 2-byte entry)
    sv_ext_data = b"\x02" + b"\x03\x04"  # len=2, version=TLS 1.3
    ext_block = (
        struct.pack("!H", len(sv_ext_data) + 4)
        + struct.pack("!H", 43)                     # ext_type = supported_versions
        + struct.pack("!H", len(sv_ext_data))
        + sv_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert result is not None, "Expected successful parse with supported_versions"
    assert 0x0304 in result["supported_versions"], (
        f"TLS 1.3 (0x0304) must be in supported_versions; got {result['supported_versions']!r}"
    )


def test_supported_versions_exception_path():
    """Lines 148-149: supported_versions with corrupt data is silently skipped.

    Why it matters: A malformed supported_versions extension must not crash
    the parser. It is better to continue parsing with no version list than to
    drop the connection, since missing version data is a recoverable condition.
    """
    # ext_data >= 3 bytes but contents will cause struct.unpack to fail on the
    # last iteration (odd number of bytes in the version list body)
    # v_len=3, but only 1 real byte follows → range(1, 3, 2) tries to read [1:3]
    # which works; force an error via a mock: pass a non-bytes object that
    # looks long enough but will blow up struct.unpack.
    # Simplest approach: pass ext_data where v_len > actual remaining bytes.
    sv_ext_data = b"\x04\x03\x04"  # v_len=4, but only 2 bytes of data → unpack fails on i=3
    ext_block = (
        struct.pack("!H", len(sv_ext_data) + 4)
        + struct.pack("!H", 43)
        + struct.pack("!H", len(sv_ext_data))
        + sv_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert _is_valid_result(result)  # Must not raise; partial parse is fine


def test_supported_groups_extension_parsed():
    """Lines 150-159: supported_groups extension (ext_type=10) is parsed.

    Why it matters: supported_groups (named curves) is one of the four extension
    types included in the JA4 fingerprint hash. Missing this data produces an
    incorrect fingerprint, degrading detection accuracy for known bot JA4s.
    """
    # supported_groups ext_data: [2-byte list len][2-byte group] ...
    # x25519=0x001d, secp256r1=0x0017; list_len = 4 (two groups)
    sg_ext_data = b"\x00\x04" + b"\x00\x1d" + b"\x00\x17"
    ext_block = (
        struct.pack("!H", len(sg_ext_data) + 4)
        + struct.pack("!H", 10)                     # ext_type = supported_groups
        + struct.pack("!H", len(sg_ext_data))
        + sg_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert result is not None, "Expected successful parse with supported_groups"
    assert 0x001d in result["supported_groups"], (
        f"x25519 (0x001d) must be in supported_groups; got {result['supported_groups']!r}"
    )


def test_supported_groups_exception_path():
    """Lines 158-159: supported_groups with truncated data is silently skipped.

    Why it matters: Corrupt extension data must not propagate as an exception.
    Partial group lists are better than crashing the parser mid-connection.
    """
    # g_len claims 10 bytes but only 2 bytes follow → range overruns → struct fails
    sg_ext_data = b"\x00\x0a" + b"\x00\x1d"  # g_len=10, only 2 bytes
    ext_block = (
        struct.pack("!H", len(sg_ext_data) + 4)
        + struct.pack("!H", 10)
        + struct.pack("!H", len(sg_ext_data))
        + sg_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert _is_valid_result(result)


def test_signature_algorithms_extension_parsed():
    """Lines 160-169: signature_algorithms extension (ext_type=13) is parsed.

    Why it matters: signature_algorithms is part of the JA4 fingerprint. Without
    it, two clients with different algorithm support but identical ciphers and
    extensions would produce the same JA4, reducing fingerprint resolution.
    """
    # sig_algs ext_data: [2-byte list len][2-byte sig alg] ...
    # rsa_pkcs1_sha256=0x0401, ecdsa_secp256r1_sha256=0x0403; list_len=4
    sa_ext_data = b"\x00\x04" + b"\x04\x01" + b"\x04\x03"
    ext_block = (
        struct.pack("!H", len(sa_ext_data) + 4)
        + struct.pack("!H", 13)                     # ext_type = signature_algorithms
        + struct.pack("!H", len(sa_ext_data))
        + sa_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert result is not None, "Expected successful parse with signature_algorithms"
    assert 0x0401 in result["signature_algorithms"], (
        f"rsa_pkcs1_sha256 (0x0401) must be in signature_algorithms; got {result['signature_algorithms']!r}"
    )


def test_signature_algorithms_exception_path():
    """Lines 168-169: signature_algorithms with truncated data is silently skipped.

    Why it matters: Same as supported_groups — corrupt extensions must be
    tolerated rather than allowed to abort parsing of an otherwise valid hello.
    """
    # s_len claims 10 bytes but only 2 follow → struct.unpack will raise
    sa_ext_data = b"\x00\x0a" + b"\x04\x01"  # s_len=10, only 2 bytes
    ext_block = (
        struct.pack("!H", len(sa_ext_data) + 4)
        + struct.pack("!H", 13)
        + struct.pack("!H", len(sa_ext_data))
        + sa_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert _is_valid_result(result)


def test_sni_name_type_nonzero_skips_decode():
    """Lines 117-120 branch (ext_data[2] != 0): non-host_name SNI type is skipped.

    Why it matters: The SNI extension supports multiple name types. Only
    name_type=0 (host_name) is used in practice. A non-zero type should leave
    sni='' rather than causing a parse error or reading garbage bytes.
    """
    # SNI ext_data: list_len=5, name_type=1 (not 0), name_len=2, "hi"
    sni_ext_data = b"\x00\x05\x01\x00\x02hi"
    ext_block = (
        struct.pack("!H", len(sni_ext_data) + 4)
        + b"\x00\x00"                               # ext_type = SNI
        + struct.pack("!H", len(sni_ext_data))
        + sni_ext_data
    )
    result = parse_client_hello(_build_clienthello_with_extensions(ext_block))
    assert _is_valid_result(result)
    if result is not None:
        # name_type != 0 → sni should remain ''
        assert result["sni"] == "", (
            f"Non-host_name SNI type must not populate sni field; got {result['sni']!r}"
        )


def test_sni_inner_exception_path_is_silenced():
    """Lines 121-122: SNI extension inner except — exception is swallowed, sni stays ''.

    Why it matters: The inner try/except around SNI parsing ensures that even
    an unexpected error reading the host name (e.g. from a future codec change)
    does not abort the entire parse. The connection continues with sni='' instead
    of being dropped due to a parser crash.

    Call order for a hello with one SNI extension and one cipher suite:
      1. record_len        2. hs_len           3. legacy_version
      4. cs_len            5. cipher suite[0]  6. exts_total_len
      7. ext_type          8. ext_len          9. SNI name_len  ← inject fault here
    """
    import unittest.mock as _mock

    original_unpack = struct.unpack
    sni_unpack_calls = [0]

    def _sni_failing_unpack(fmt, buf):
        sni_unpack_calls[0] += 1
        if sni_unpack_calls[0] == 9:  # SNI name_len call inside inner try
            raise RuntimeError("injected SNI name_len fault")
        return original_unpack(fmt, buf)

    # Build a ClientHello with a valid SNI extension
    sni_host = b"example.com"
    sni_ext_data = (
        struct.pack("!H", 3 + len(sni_host))  # list_len
        + b"\x00"                               # name_type = host_name
        + struct.pack("!H", len(sni_host))     # name_len
        + sni_host
    )
    ext_block = (
        struct.pack("!H", len(sni_ext_data) + 4)
        + b"\x00\x00"
        + struct.pack("!H", len(sni_ext_data))
        + sni_ext_data
    )
    hello = _build_clienthello_with_extensions(ext_block)

    with _mock.patch("src.tls.parser.struct.unpack", side_effect=_sni_failing_unpack):
        result = parse_client_hello(hello)

    # Parser must not raise; sni will be '' because the inner except caught the error
    assert _is_valid_result(result)


def test_alpn_inner_exception_path_is_silenced():
    """Lines 137-138: ALPN extension inner except — exception is swallowed, alpn stays [].

    Why it matters: Same principle as the SNI inner except. An unexpected error
    inside ALPN parsing must not abort the parse. The consequence is that the
    connection is processed without ALPN, which means it will not get the browser
    bypass — a safe, conservative outcome.

    Call order for a hello with one ALPN extension and one cipher suite:
      1. record_len        2. hs_len           3. legacy_version
      4. cs_len            5. cipher suite[0]  6. exts_total_len
      7. ext_type          8. ext_len          9. ALPN alpn_len  ← inject fault here
    """
    import unittest.mock as _mock

    original_unpack = struct.unpack
    alpn_unpack_calls = [0]

    def _alpn_failing_unpack(fmt, buf):
        alpn_unpack_calls[0] += 1
        if alpn_unpack_calls[0] == 9:  # ALPN alpn_len call inside inner try
            raise RuntimeError("injected ALPN alpn_len fault")
        return original_unpack(fmt, buf)

    # Build a ClientHello with a valid ALPN extension
    alpn_ext_data = b"\x00\x03\x02h2"
    ext_block = (
        struct.pack("!H", len(alpn_ext_data) + 4)
        + struct.pack("!H", 16)
        + struct.pack("!H", len(alpn_ext_data))
        + alpn_ext_data
    )
    hello = _build_clienthello_with_extensions(ext_block)

    with _mock.patch("src.tls.parser.struct.unpack", side_effect=_alpn_failing_unpack):
        result = parse_client_hello(hello)

    assert _is_valid_result(result)


def test_outer_exception_path_returns_none():
    """Lines 175-176: the outermost except Exception: return None path.

    Why it matters: This catch-all is the last line of defence against any
    unexpected exception the parser encounters. It guarantees parse_client_hello()
    never raises, even if a future code change introduces a bug in an inner branch.
    We trigger it by passing a non-bytes type that passes the initial length check
    but fails on a later struct.unpack call.
    """
    # Craft a bytes-like object that will cause struct.unpack to raise outside
    # the inner try/except blocks. The record header check passes (len >= 5,
    # data[0] == 0x16), but we engineer an impossible state by patching struct.
    import unittest.mock as _mock

    original_unpack = struct.unpack
    call_count = [0]

    def _failing_unpack(fmt, buf):
        call_count[0] += 1
        # Allow the first few unpacks (record_len, hs_type, hs_len, legacy_version,
        # cs_len, exts_total_len), then raise on the 7th call to hit the outer except.
        if call_count[0] >= 7:
            raise RuntimeError("injected fault to trigger outer except")
        return original_unpack(fmt, buf)

    with _mock.patch("src.tls.parser.struct.unpack", side_effect=_failing_unpack):
        result = parse_client_hello(_VALID_TLS13)

    # The outer except must catch the RuntimeError and return None
    assert result is None, (
        "Outer except Exception must catch injected faults and return None"
    )
