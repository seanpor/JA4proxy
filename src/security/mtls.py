import logging
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from src.security.models import ConnectionContext


class MTLSHandler:
    def __init__(self, config: dict):
        """
        Initializes the MTLSHandler with configuration.
        """
        self._config = config.get("mtls", {})
        self._enabled = self._config.get("enabled", False)
        self._ca_cert_path = self._config.get("ca_cert_path")
        self._require_client_cert = self._config.get("require_client_cert", False)
        self._cert_cn_allowlist = set(self._config.get("cert_cn_allowlist", []))
        self._ca_cert = self._load_ca_cert() if self._enabled else None
        self.logger = logging.getLogger(__name__)

    def verify_client_cert(self, ctx: ConnectionContext) -> bool:
        """
        Verifies the client certificate. Returns True if the client cert is valid
        and should bypass scoring.
        """
        if not self._enabled:
            return False

        # If has_valid_client_cert is set (TLS layer validated it), trust it
        if ctx.has_valid_client_cert:
            return True

        # Otherwise check for actual client certificate
        if not hasattr(ctx, "client_certificate") or not ctx.client_certificate:
            return False

        if not self._ca_cert:
            self.logger.error("mTLS is enabled, but CA certificate is not loaded.")
            return False

        # Check if we have either a client certificate or the flag set
        has_cert = (
            hasattr(ctx, "client_certificate") and ctx.client_certificate
        ) or ctx.has_valid_client_cert

        if not has_cert:
            return False

        if not self._ca_cert:
            self.logger.error("mTLS is enabled, but CA certificate is not loaded.")
            return False

        try:
            client_cert = x509.load_pem_x509_certificate(ctx.client_certificate)

            # Verify the certificate's signature
            self._ca_cert.public_key().verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                client_cert.signature_hash_algorithm,
            )

            # Check CN against allowlist if specified
            if self._cert_cn_allowlist:
                common_name = client_cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value
                if common_name not in self._cert_cn_allowlist:
                    self.logger.warning(
                        f"mTLS verification failed: CN '{common_name}' not in allowlist."
                    )
                    return False

            return True
        except InvalidSignature:
            self.logger.warning("mTLS verification failed: Invalid signature.")
            return False
        except Exception as e:
            self.logger.error(f"Error during mTLS verification: {e}")
            return False

    def _load_ca_cert(self):
        """
        Loads the CA certificate from the path specified in the config.
        """
        if self._ca_cert_path:
            try:
                with open(self._ca_cert_path, "rb") as f:
                    ca_cert_data = f.read()
                return x509.load_pem_x509_certificate(ca_cert_data)
            except FileNotFoundError:
                self.logger.error(
                    f"mTLS CA certificate not found at: {self._ca_cert_path}"
                )
            except Exception as e:
                self.logger.error(f"Error loading mTLS CA certificate: {e}")
        return None
