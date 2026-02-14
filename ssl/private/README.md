# SSL Private Keys Directory
#
# SECURITY REQUIREMENTS:
# - Directory permissions MUST be 700 (drwx------)
# - Private key files MUST be 600 (-rw-------)
# - Never commit private keys to version control
# - Use proper certificate management and rotation
# - Monitor for certificate expiration
#
# This directory stores:
# - TLS/SSL private keys
# - Certificate signing requests (CSRs)
# - Client certificates for mTLS
#
# Access restricted to proxy service user only.
