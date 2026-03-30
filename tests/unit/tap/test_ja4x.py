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
