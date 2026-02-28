import unittest
import os
from unittest.mock import MagicMock
from src.security.mtls import MTLSHandler
from src.security.models import ConnectionContext
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_self_signed_ca():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test CA")])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        __import__('datetime').datetime.utcnow()
    ).not_valid_after(
        __import__('datetime').datetime.utcnow() + __import__('datetime').timedelta(days=1)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(private_key, hashes.SHA256())
    return cert, private_key

def generate_signed_cert(ca_cert, ca_key):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Test Client")])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        __import__('datetime').datetime.utcnow()
    ).not_valid_after(
        __import__('datetime').datetime.utcnow() + __import__('datetime').timedelta(days=1)
    ).sign(ca_key, hashes.SHA256())
    return cert, private_key

class TestMTLSHandler(unittest.TestCase):

    def setUp(self):
        self.ca_cert, self.ca_key = generate_self_signed_ca()
        self.client_cert, self.client_key = generate_signed_cert(self.ca_cert, self.ca_key)

        self.ca_cert_path = "test_ca.pem"
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        self.config = {
            "mtls": {
                "enabled": True,
                "ca_cert_path": self.ca_cert_path,
                "require_client_cert": False,
                "cert_cn_allowlist": ["Test Client"]
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
        invalid_client_cert_pem = invalid_client_cert.public_bytes(serialization.Encoding.PEM)
        
        ctx = ConnectionContext(client_ip="1.2.3.4", client_certificate=invalid_client_cert_pem)
        self.assertFalse(self.mtls_handler.verify_client_cert(ctx))

    def test_cn_allowlist_enforcement(self):
        self.config["mtls"]["cert_cn_allowlist"] = ["Another Client"]
        self.mtls_handler = MTLSHandler(self.config)
        client_cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM)
        ctx = ConnectionContext(client_ip="1.2.3.4", client_certificate=client_cert_pem)
        self.assertFalse(self.mtls_handler.verify_client_cert(ctx))

if __name__ == '__main__':
    unittest.main()
