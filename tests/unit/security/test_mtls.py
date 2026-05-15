import os
import unittest
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from src.security.models import ConnectionContext
from src.security.mtls import MTLSHandler


def generate_self_signed_ca():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.utcnow())
        .not_valid_after(
            __import__("datetime").datetime.utcnow()
            + __import__("datetime").timedelta(days=1)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert, private_key


def generate_signed_cert(ca_cert, ca_key):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Client")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(__import__("datetime").datetime.utcnow())
        .not_valid_after(
            __import__("datetime").datetime.utcnow()
            + __import__("datetime").timedelta(days=1)
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert, private_key


class TestMTLSHandler(unittest.TestCase):

    def setUp(self):
        self.ca_cert, self.ca_key = generate_self_signed_ca()
        self.client_cert, self.client_key = generate_signed_cert(
            self.ca_cert, self.ca_key
        )

        self.ca_cert_path = "test_ca.pem"
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        self.config = {
            "mtls": {
                "enabled": True,
                "ca_cert_path": self.ca_cert_path,
                "require_client_cert": False,
                "cert_cn_allowlist": ["Test Client"],
            }
        }
        self.mtls_handler = MTLSHandler(self.config)

    def tearDown(self):
        if os.path.exists(self.ca_cert_path):
            os.remove(self.ca_cert_path)

    def test_valid_cert_bypass(self):
        client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM)
        ctx = ConnectionContext(client_ip="1.2.3.4", client_certificate=client_cert_pem)
        self.assertTrue(self.mtls_handler.verify_client_cert(ctx))

    def test_invalid_cert_rejected(self):
        # Create a cert signed by a different CA
        other_ca_cert, other_ca_key = generate_self_signed_ca()
        invalid_client_cert, _ = generate_signed_cert(other_ca_cert, other_ca_key)
        invalid_client_cert_pem = invalid_client_cert.public_bytes(
            serialization.Encoding.PEM
        )

        ctx = ConnectionContext(
            client_ip="1.2.3.4", client_certificate=invalid_client_cert_pem
        )
        self.assertFalse(self.mtls_handler.verify_client_cert(ctx))

    def test_cn_allowlist_enforcement(self):
        self.config["mtls"]["cert_cn_allowlist"] = ["Another Client"]
        self.mtls_handler = MTLSHandler(self.config)
        client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM)
        ctx = ConnectionContext(client_ip="1.2.3.4", client_certificate=client_cert_pem)
        self.assertFalse(self.mtls_handler.verify_client_cert(ctx))


if __name__ == "__main__":
    unittest.main()


# ── Missing-coverage tests (pytest-style) ─────────────────────────────────────

from unittest.mock import patch

import pytest


class TestMTLSMissingPaths:
    """Cover error-handling paths not reached by the happy-path unittest tests."""

    def _make_handler_with_ca(self):
        ca_cert, ca_key = generate_self_signed_ca()
        client_cert, _ = generate_signed_cert(ca_cert, ca_key)
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            path = f.name
        try:
            handler = MTLSHandler({"mtls": {"enabled": True, "ca_cert_path": path}})
        finally:
            os.unlink(path)
        return handler, ca_cert, ca_key, client_cert

    def test_ca_cert_none_with_client_certificate_returns_false(self):
        """has_valid_client_cert=False, client_certificate present, but _ca_cert=None.
        Triggers lines 46-48: logs error and returns False.
        So what: if the CA cert failed to load, a presented client cert must be rejected,
        not silently accepted — prevents privilege escalation."""
        handler = MTLSHandler(
            {"mtls": {"enabled": True, "ca_cert_path": "/nonexistent/ca.pem"}}
        )
        assert handler._ca_cert is None  # confirm load failed
        ctx = MagicMock()
        ctx.has_valid_client_cert = False
        ctx.client_certificate = (
            b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
        )
        assert handler.verify_client_cert(ctx) is False

    def test_malformed_pem_raises_value_error_caught(self):
        """Garbage PEM bytes → ValueError from load_pem_x509_certificate.
        Triggers lines 90-92: except (ValueError, TypeError, OSError).
        So what: attacker-supplied malformed cert must not crash the proxy."""
        _, ca_cert, ca_key, _ = self._make_handler_with_ca()
        # Make a new temp CA file
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            path = f.name
        try:
            handler = MTLSHandler({"mtls": {"enabled": True, "ca_cert_path": path}})
        finally:
            os.unlink(path)
        ctx = MagicMock()
        ctx.has_valid_client_cert = False
        ctx.client_certificate = b"not-a-valid-pem-cert-at-all"
        result = handler.verify_client_cert(ctx)
        assert result is False  # caught, not raised

    def test_load_ca_cert_file_not_found_returns_none(self):
        """CA cert path does not exist → FileNotFoundError logged (lines 103-106).
        So what: a missing CA cert file at startup must not crash the proxy,
        just disable mTLS."""
        handler = MTLSHandler(
            {"mtls": {"enabled": True, "ca_cert_path": "/no/such/file.pem"}}
        )
        assert handler._ca_cert is None

    def test_load_ca_cert_os_error_returns_none(self):
        """CA cert path is a directory → OSError logged (lines 107-108).
        So what: misconfigured path must fail gracefully, not crash."""
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            handler = MTLSHandler({"mtls": {"enabled": True, "ca_cert_path": d}})
        assert handler._ca_cert is None


# ── Missing-coverage additions ────────────────────────────────────────────────


class TestMTLSCoverageGaps:
    """Cover lines 56, 59-60 in verify_client_cert()."""

    def test_no_client_cert_returns_false(self):
        """Line 56: ctx has no client_certificate and has_valid_client_cert=False
        → verify_client_cert returns False immediately.
        So what: if this guard is missing, the function proceeds to try parsing
        None as a certificate, raising an uncaught AttributeError or crashing the
        proxy instead of a clean False."""
        handler = MTLSHandler(
            {"mtls": {"enabled": True, "ca_cert_path": "/nonexistent/ca.pem"}}
        )
        ctx = MagicMock(spec=[])  # no attributes at all
        ctx.has_valid_client_cert = False
        # Ensure client_certificate attr does not exist
        assert not hasattr(ctx, "client_certificate")
        result = handler.verify_client_cert(ctx)
        assert result is False

    def test_client_cert_present_but_ca_cert_not_loaded_returns_false(self):
        """Lines 59-60: has_cert=True but _ca_cert is None → logs error and returns False.
        So what: if this guard is missing, the code continues to ca_cert.verify(...)
        on a None object — AttributeError crashes the connection handling coroutine
        rather than cleanly rejecting the unverifiable client certificate."""
        handler = MTLSHandler(
            {"mtls": {"enabled": True, "ca_cert_path": "/nonexistent/ca.pem"}}
        )
        assert handler._ca_cert is None
        ctx = MagicMock()
        ctx.has_valid_client_cert = False
        ctx.client_certificate = (
            b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"
        )
        result = handler.verify_client_cert(ctx)
        assert result is False


class TestMTLSCoverageGaps2:
    """Lines 35, 39-40: disabled handler; has_valid_client_cert bypass."""

    def test_disabled_handler_returns_false(self):
        """Line 35: mTLS disabled → verify_client_cert returns False immediately.
        So what: without this guard, disabling mTLS via config would still attempt
        certificate parsing, potentially blocking connections that should be allowed."""
        handler = MTLSHandler({"mtls": {"enabled": False}})
        from unittest.mock import MagicMock

        ctx = MagicMock()
        assert handler.verify_client_cert(ctx) is False

    def test_has_valid_client_cert_flag_returns_true(self):
        """Lines 39-40: ctx.has_valid_client_cert=True → verified counter inc + return True.
        So what: without this shortcut, valid TLS-layer-verified client certs would
        go through full x509 parsing on the hot path, adding latency and potential crashes.
        """
        handler = MTLSHandler(
            {"mtls": {"enabled": True, "ca_cert_path": "/nonexistent/ca.pem"}}
        )
        from unittest.mock import MagicMock

        ctx = MagicMock()
        ctx.has_valid_client_cert = True
        assert handler.verify_client_cert(ctx) is True
