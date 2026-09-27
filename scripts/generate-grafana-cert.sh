#!/usr/bin/env bash
# Generate a self-signed TLS cert for Grafana (deploy/docker/docker-compose.monitoring.yml mounts this).
# Gitignored dev/test artifact — absent on fresh clone and in CI.
# Idempotent: a no-op if the cert already exists.
set -euo pipefail

cd "$(dirname "$0")/.."

CERT_DIR="deploy/docker/certs/grafana"
CRT="${CERT_DIR}/grafana.crt"
KEY="${CERT_DIR}/grafana.key"

if [ -f "$CRT" ] && [ -f "$KEY" ]; then
	echo "✓ grafana cert already present ($CRT)"
	exit 0
fi

mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "$KEY" -out "$CRT" \
	-days 3650 -subj "/CN=grafana.internal" \
	-addext "subjectAltName=DNS:grafana.internal,DNS:localhost,IP:127.0.0.1"
chmod 644 "$CRT" "$KEY"
echo "✓ generated self-signed grafana cert: $CRT / $KEY"
