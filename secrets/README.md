# Security Notice
# This directory contains sensitive secrets and credentials.
# 
# SECURITY REQUIREMENTS:
# - Directory permissions MUST be 700 (drwx------)
# - Files MUST be 600 (-rw-------)
# - Never commit actual secrets to version control
# - Use environment variables or secret management systems
# - Rotate secrets regularly (recommended: every 90 days)
#
# Stored secrets may include:
# - Redis passwords
# - API keys
# - Encryption keys
# - Database credentials
#
# Access is restricted to the proxy service user only.
