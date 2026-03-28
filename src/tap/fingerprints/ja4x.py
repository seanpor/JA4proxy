"""
JA4X — X.509 certificate fingerprint extractor (Phase 20, Group 5-F).

Parses the TLS Certificate message from the server's `server_data` stream
and extracts the first leaf certificate to compute the JA4X fingerprint.

JA4X format: {issuer_hash}_{subject_hash}_{san_hash}
Each hash is SHA-256[:12] of the respective DER-encoded field.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTO_AVAILABLE = False


@dataclass
class JA4XResult:
    """X.509 certificate fingerprint."""

    fingerprint: str
    issuer_dn: str
    subject_dn: str
    key_type: str
    not_before: Optional[datetime]
    not_after: Optional[datetime]
    san_domains: list[str] = field(default_factory=list)
    san_ips: list[str] = field(default_factory=list)
    self_signed: bool = False
    serial: str = ""
    sha256: str = ""


def extract_ja4x(certificate_message: bytes) -> Optional[JA4XResult]:
    """Parse a TLS Certificate message and return JA4X fingerprint.

    Args:
        certificate_message: Raw bytes of the TLS Certificate handshake message,
            starting at the Handshake header (type 0x0b), **or** a raw DER-encoded
            X.509 certificate (detected by first byte 0x30).

    Returns:
        JA4XResult on success, None on malformed / incomplete input.
    """
    if not _CRYPTO_AVAILABLE:
        return None
    try:
        cert_der = _extract_first_cert(certificate_message)
        if cert_der is None:
            return None
        return _parse_cert(cert_der)
    except Exception:
        return None


def _extract_first_cert(data: bytes) -> Optional[bytes]:
    """Extract the first DER certificate from a TLS Certificate message.

    Handles both:
    - Raw DER cert (starts with 0x30)
    - TLS handshake Certificate message (type 0x0b)
    """
    if not data:
        return None

    # If it looks like a raw DER cert, use it directly
    if data[0] == 0x30:
        return data

    # Otherwise expect a TLS handshake message:
    # msg_type (1) + length (3) + cert_list_length (3) + first_cert_length (3) + cert_der
    if len(data) < 10:
        return None
    if data[0] != 0x0B:  # Certificate handshake type
        return None

    hs_len = struct.unpack_from("!I", bytes([0]) + data[1:4])[0]
    if hs_len + 4 > len(data):
        return None

    cert_list_len = struct.unpack_from("!I", bytes([0]) + data[4:7])[0]
    if cert_list_len + 7 > len(data):
        return None

    first_cert_len = struct.unpack_from("!I", bytes([0]) + data[7:10])[0]
    if 10 + first_cert_len > len(data):
        return None

    return data[10:10 + first_cert_len]


def _parse_cert(der: bytes) -> Optional[JA4XResult]:
    """Parse DER-encoded certificate and compute JA4X."""
    cert = x509.load_der_x509_certificate(der)

    issuer_dn = cert.issuer.rfc4514_string()
    subject_dn = cert.subject.rfc4514_string()
    self_signed = issuer_dn == subject_dn

    # Key type
    pub_key = cert.public_key()
    key_type = _key_type(pub_key)

    # SAN
    san_domains: list[str] = []
    san_ips: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        # get_values_for_type returns plain Python values (str for DNSName,
        # ipaddress.IPv4/IPv6Address for IPAddress) — not wrapper objects.
        san_domains = list(san_ext.value.get_values_for_type(x509.DNSName))
        san_ips = [
            str(ip)
            for ip in san_ext.value.get_values_for_type(x509.IPAddress)
        ]
    except x509.extensions.ExtensionNotFound:
        pass
    except Exception:
        pass

    serial = str(cert.serial_number)
    sha256_fp = hashlib.sha256(der).hexdigest()

    # JA4X hashes
    issuer_hash = hashlib.sha256(issuer_dn.encode()).hexdigest()[:12]
    subject_hash = hashlib.sha256(subject_dn.encode()).hexdigest()[:12]
    san_str = ",".join(sorted(san_domains + san_ips))
    san_hash = hashlib.sha256(san_str.encode()).hexdigest()[:12] if san_str else "000000000000"

    fingerprint = f"{issuer_hash}_{subject_hash}_{san_hash}"

    return JA4XResult(
        fingerprint=fingerprint,
        issuer_dn=issuer_dn,
        subject_dn=subject_dn,
        key_type=key_type,
        not_before=cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before,
        not_after=cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after,
        san_domains=san_domains,
        san_ips=san_ips,
        self_signed=self_signed,
        serial=serial,
        sha256=sha256_fp,
    )


def _key_type(pub_key) -> str:
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

    if isinstance(pub_key, rsa.RSAPublicKey):
        bits = pub_key.key_size
        return f"RSA{bits}"
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        bits = pub_key.key_size
        return f"EC{bits}"
    if isinstance(pub_key, dsa.DSAPublicKey):
        bits = pub_key.key_size
        return f"DSA{bits}"
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "ED25519"
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return "ED448"
    return "UNKNOWN"
