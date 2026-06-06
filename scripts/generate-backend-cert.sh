#!/usr/bin/env bash
# Generate a self-signed TLS cert for the mock backend (deploy/docker/Dockerfile.mockbackend
# COPYs these). They are gitignored dev/test artifacts, so they are absent on a
# fresh clone and in CI — this script creates them on demand. Idempotent: a no-op
# if the cert already exists. The mock backend is a test fixture; a self-signed
# cert with SANs for backend/localhost is sufficient.
set -euo pipefail

cd "$(dirname "$0")/.."

CRT="deploy/ssl/certs/backend.crt"
KEY="deploy/ssl/private/backend.key"

if [ -f "$CRT" ] && [ -f "$KEY" ]; then
	echo "✓ backend cert already present ($CRT)"
	exit 0
fi

mkdir -p deploy/ssl/certs deploy/ssl/private
openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$KEY" -out "$CRT" \
	-days 825 -subj "/CN=backend" \
	-addext "subjectAltName=DNS:backend,DNS:localhost,IP:127.0.0.1"
chmod 644 "$CRT" "$KEY"
echo "✓ generated self-signed backend cert: $CRT / $KEY"
