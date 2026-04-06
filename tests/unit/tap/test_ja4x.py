"""
Unit tests for src/tap/fingerprints/ja4x.py (Phase 20 Group 5-F).
"""
import hashlib

import pytest

from src.tap.fingerprints.ja4x import JA4XResult, extract_ja4x

# Try to import cryptography to check availability
try:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    _CRYPTO = True
except ImportError:
    _CRYPTO = False


def _gen_rsa_cert(
    subject_cn: str = "test.example.com",
    issuer_cn: str = None,
    san_dns: list = None,
    san_ips: list = None,
    key_size: int = 2048,
) -> bytes:
    """Generate a self-signed RSA DER certificate for testing."""
    import datetime as _dt
    import ipaddress

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.x509.oid import NameOID as _OID

    key = _rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    issuer_cn = issuer_cn or subject_cn

    subject = issuer = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, subject_cn)])
    if issuer_cn != subject_cn:
        issuer = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, issuer_cn)])

    builder = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(_dt.datetime(2024, 1, 1, tzinfo=_dt.timezone.utc))
        .not_valid_after(_dt.datetime(2025, 1, 1, tzinfo=_dt.timezone.utc))
    )

    san_names = []
    for d in (san_dns or []):
        san_names.append(_x509.DNSName(d))
    for ip in (san_ips or []):
        san_names.append(_x509.IPAddress(ipaddress.ip_address(ip)))
    if san_names:
        builder = builder.add_extension(
            _x509.SubjectAlternativeName(san_names), critical=False
        )

    cert = builder.sign(key, _hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _gen_ec_cert(curve_name: str = "secp256r1") -> bytes:
    import datetime as _dt

    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.x509.oid import NameOID as _OID

    curve_map = {"secp256r1": _ec.SECP256R1(), "secp384r1": _ec.SECP384R1()}
    curve = curve_map.get(curve_name, _ec.SECP256R1())
    key = _ec.generate_private_key(curve)

    subject = issuer = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, "ec.example.com")])
    cert = (
        _x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_x509.random_serial_number())
        .not_valid_before(_dt.datetime(2024, 1, 1, tzinfo=_dt.timezone.utc))
        .not_valid_after(_dt.datetime(2025, 1, 1, tzinfo=_dt.timezone.utc))
        .sign(key, _hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


pytestmark = pytest.mark.skipif(
    not _CRYPTO, reason="cryptography package not installed"
)


class TestJA4X:
    def test_rsa2048_cert_key_type_identified(self):
        der = _gen_rsa_cert(key_size=2048)
        result = extract_ja4x(der)
        assert result is not None
        assert "RSA2048" in result.key_type

    def test_ec256_cert_key_type_identified(self):
        der = _gen_ec_cert("secp256r1")
        result = extract_ja4x(der)
        assert result is not None
        assert "EC256" in result.key_type

    def test_self_signed_cert_detected(self):
        der = _gen_rsa_cert(subject_cn="self.example.com", issuer_cn="self.example.com")
        result = extract_ja4x(der)
        assert result is not None
        assert result.self_signed is True

    def test_not_self_signed_when_different_issuer(self):
        der = _gen_rsa_cert(
            subject_cn="leaf.example.com",
            issuer_cn="issuing-ca.example.com",
        )
        result = extract_ja4x(der)
        assert result is not None
        assert result.self_signed is False

    def test_san_domains_and_ips_extracted(self):
        der = _gen_rsa_cert(
            san_dns=["www.example.com", "example.com"],
            san_ips=["1.2.3.4"],
        )
        result = extract_ja4x(der)
        assert result is not None
        assert "www.example.com" in result.san_domains
        assert "example.com" in result.san_domains
        assert "1.2.3.4" in result.san_ips

    def test_fingerprint_matches_manual_openssl_calculation(self):
        """JA4X issuer_hash must be SHA-256[:12] of the RFC 4514 issuer DN."""
        der = _gen_rsa_cert(issuer_cn="Test CA")
        result = extract_ja4x(der)
        assert result is not None
        # Verify issuer hash
        expected = hashlib.sha256(result.issuer_dn.encode()).hexdigest()[:12]
        assert result.fingerprint.split("_")[0] == expected

    def test_returns_none_on_truncated_certificate_message(self):
        assert extract_ja4x(b"\x30\x82\x01") is None

    def test_returns_none_on_garbage(self):
        assert extract_ja4x(b"\x00" * 20) is None

    def test_expired_cert_not_before_after_correct(self):
        der = _gen_rsa_cert()
        result = extract_ja4x(der)
        assert result is not None
        assert result.not_before is not None
        assert result.not_after is not None
        assert result.not_after > result.not_before

    def test_sha256_fingerprint_present(self):
        der = _gen_rsa_cert()
        result = extract_ja4x(der)
        assert result is not None
        assert len(result.sha256) == 64  # 32-byte hash as 64 hex chars
        assert result.sha256 == hashlib.sha256(der).hexdigest()

    def test_fingerprint_format_three_parts(self):
        der = _gen_rsa_cert()
        result = extract_ja4x(der)
        assert result is not None
        parts = result.fingerprint.split("_")
        assert len(parts) == 3
        for p in parts:
            assert len(p) == 12


# ── Missing-coverage tests ────────────────────────────────────────────────────

class TestJA4XCryptoUnavailable:
    def test_returns_none_when_crypto_unavailable(self):
        """_CRYPTO_AVAILABLE=False → extract_ja4x returns None immediately.
        So what: if cryptography is absent at deploy time the proxy must not crash;
        JA4X fingerprinting simply produces no output."""
        import src.tap.fingerprints.ja4x as _mod
        from unittest.mock import patch
        with patch.object(_mod, "_CRYPTO_AVAILABLE", False):
            result = _mod.extract_ja4x(b"\x30\x00")
        assert result is None


@pytest.mark.skipif(not _CRYPTO, reason="cryptography package not installed")
class TestJA4XExtractFirstCert:
    """Cover _extract_first_cert() edge cases (lines 74, 83-99)."""

    def test_empty_bytes_returns_none(self):
        """Empty input → None (line 74).
        So what: empty TLS cert buffer from network must not crash fingerprinting."""
        assert extract_ja4x(b"") is None

    def test_short_non_der_data_returns_none(self):
        """Non-DER (first byte != 0x30), len < 10 → None (line 83).
        So what: too-short handshake record must not cause an unpack error."""
        assert extract_ja4x(bytes([0x0B, 0x00, 0x00, 0x05, 0x00])) is None

    def test_wrong_handshake_type_returns_none(self):
        """First byte 0x02 (ServerHello) rather than 0x0B (Certificate) → None.
        So what: wrong message type arriving in cert slot must not be misinterpreted."""
        data = bytes([0x02]) + b"\x00" * 15
        assert extract_ja4x(data) is None

    def test_hs_len_exceeds_buffer_returns_none(self):
        """hs_len claims 255 bytes but buffer is only 10 bytes → None (lines 88-89).
        So what: attacker-crafted oversized length field must not cause overread."""
        data = bytes([0x0B, 0x00, 0x00, 0xFF]) + b"\x00" * 6
        assert extract_ja4x(data) is None

    def test_cert_list_len_exceeds_buffer_returns_none(self):
        """cert_list_len larger than remaining bytes → None (lines 92-93)."""
        data = bytes([0x0B, 0x00, 0x00, 0x06, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00])
        assert extract_ja4x(data) is None

    def test_first_cert_len_exceeds_buffer_returns_none(self):
        """first_cert_len overruns buffer → None (lines 96-97)."""
        data = bytes([0x0B, 0x00, 0x00, 0x06, 0x00, 0x00, 0x03, 0x00, 0x00, 0xFF])
        assert extract_ja4x(data) is None

    def test_tls_certificate_message_with_valid_der(self):
        """Valid TLS Certificate message wrapping a real DER cert → parsed (line 99).
        So what: if TLS-wrapped cert messages aren't parsed, server certs arriving in
        Certificate handshake format produce no JA4X fingerprint."""
        import struct as _struct
        der = _gen_rsa_cert()
        # Construct TLS Certificate message
        first_cert_len_bytes = _struct.pack("!I", len(der))[1:]  # 3 bytes
        cert_list = first_cert_len_bytes + der
        cert_list_len_bytes = _struct.pack("!I", len(cert_list))[1:]  # 3 bytes
        hs_body = cert_list_len_bytes + cert_list
        hs_len_bytes = _struct.pack("!I", len(hs_body))[1:]  # 3 bytes
        msg = bytes([0x0B]) + hs_len_bytes + hs_body
        result = extract_ja4x(msg)
        assert result is not None
        assert result.key_type.startswith("RSA")


@pytest.mark.skipif(not _CRYPTO, reason="cryptography package not installed")
class TestJA4XAlternativeKeyTypes:
    """Lines 173-180: DSA, Ed25519, Ed448, UNKNOWN key type identification."""

    def _gen_ed25519_cert(self) -> bytes:
        import datetime as _dt
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.x509.oid import NameOID as _OID
        key = Ed25519PrivateKey.generate()
        subj = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, "ed25519.example.com")])
        cert = (
            _x509.CertificateBuilder()
            .subject_name(subj).issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(_dt.datetime(2024, 1, 1, tzinfo=_dt.timezone.utc))
            .not_valid_after(_dt.datetime(2025, 1, 1, tzinfo=_dt.timezone.utc))
            .sign(key, None)
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def _gen_ed448_cert(self) -> bytes:
        import datetime as _dt
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
        from cryptography.x509.oid import NameOID as _OID
        key = Ed448PrivateKey.generate()
        subj = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, "ed448.example.com")])
        cert = (
            _x509.CertificateBuilder()
            .subject_name(subj).issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(_dt.datetime(2024, 1, 1, tzinfo=_dt.timezone.utc))
            .not_valid_after(_dt.datetime(2025, 1, 1, tzinfo=_dt.timezone.utc))
            .sign(key, None)
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_ed25519_key_type(self):
        """Ed25519 cert → key_type == 'ED25519'.
        So what: wrong key label corrupts the JA4X fingerprint, breaking blocklist lookups."""
        result = extract_ja4x(self._gen_ed25519_cert())
        assert result is not None
        assert result.key_type == "ED25519"

    def test_ed448_key_type(self):
        """Ed448 cert → key_type == 'ED448'."""
        result = extract_ja4x(self._gen_ed448_cert())
        assert result is not None
        assert result.key_type == "ED448"

    def _gen_dsa_cert(self) -> bytes:
        import datetime as _dt
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.x509.oid import NameOID as _OID
        params = dsa.generate_parameters(key_size=1024)
        key = params.generate_private_key()
        subj = _x509.Name([_x509.NameAttribute(_OID.COMMON_NAME, "dsa.example.com")])
        cert = (
            _x509.CertificateBuilder()
            .subject_name(subj).issuer_name(subj)
            .public_key(key.public_key())
            .serial_number(_x509.random_serial_number())
            .not_valid_before(_dt.datetime(2024, 1, 1, tzinfo=_dt.timezone.utc))
            .not_valid_after(_dt.datetime(2025, 1, 1, tzinfo=_dt.timezone.utc))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def test_dsa_key_type(self):
        """Lines 174-175: DSA cert → key_type starts with 'DSA' followed by key size.
        So what: if this branch is missing, any DSA-keyed certificate gets 'UNKNOWN' as
        key_type, causing a mismatch in the JA4X fingerprint and silently breaking
        blocklist lookups against known-malicious DSA-cert patterns."""
        result = extract_ja4x(self._gen_dsa_cert())
        assert result is not None
        assert result.key_type.startswith("DSA")

    def test_unknown_key_type_returns_unknown(self):
        """Public key not matching any known type → 'UNKNOWN' (line 180).
        So what: unknown key must not crash fingerprinting — must produce a safe sentinel."""
        from src.tap.fingerprints.ja4x import _key_type
        from unittest.mock import MagicMock

        class _WeirdKey:
            pass

        result = _key_type(_WeirdKey())
        assert result == "UNKNOWN"


@pytest.mark.skipif(not _CRYPTO, reason="cryptography package not installed")
class TestJA4XSANExceptionSwallowed:
    """Lines 125-126: generic exception in SAN parsing is swallowed."""

    def test_san_generic_exception_does_not_propagate(self):
        """A non-ExtensionNotFound exception from SAN parsing must be swallowed.
        So what: a crafted cert with a corrupted SAN extension must not crash
        fingerprinting and must not bypass the JA4X blacklist check."""
        from unittest.mock import MagicMock, patch
        import src.tap.fingerprints.ja4x as _mod

        # Patch x509.SubjectAlternativeName so extensions.get_extension_for_class raises
        # a generic Exception (not ExtensionNotFound), hitting lines 125-126.
        der = _gen_rsa_cert()
        with patch.object(
            _mod.x509.extensions.Extensions,
            "get_extension_for_class",
            side_effect=ValueError("malformed SAN"),
        ):
            result = _mod.extract_ja4x(der)
        # Must return a result (not None) with empty SANs — fail-open
        assert result is not None
        assert result.san_domains == []
        assert result.san_ips == []
