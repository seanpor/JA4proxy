#!/usr/bin/env bash
# phase-201: generate a self-signed TLS cert for the Redis-TLS compose overlay.
#
# Usage:
#   ./deploy/docker/redis-tls/generate-certs.sh [OUT_DIR]
#
# Produces:
#   OUT_DIR/redis.key (2048-bit RSA, mode 0600)
#   OUT_DIR/redis.crt (self-signed, 30-day validity,
#                      CN=localhost, SAN DNS:redis,DNS:localhost,IP:127.0.0.1)
#
# Defaults OUT_DIR to the directory containing this script. The compose
# overlay mounts OUT_DIR at /tls inside the redis container.
#
# Private keys are NEVER committed; .gitignore already excludes *.key and
# *.pem globally.

set -euo pipefail

OUT_DIR="${1:-$(cd "$(dirname "$0")" && pwd)}"
mkdir -p "$OUT_DIR"

KEY="$OUT_DIR/redis.key"
CRT="$OUT_DIR/redis.crt"

if [[ -f "$KEY" && -f "$CRT" ]]; then
  echo "certs already present in $OUT_DIR — remove to regenerate" >&2
  exit 0
fi

CONF="$(mktemp)"
trap 'rm -f "$CONF"' EXIT

cat > "$CONF" <<'EOF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt]
DNS.1 = redis
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$KEY" \
  -out    "$CRT" \
  -days 30 \
  -config "$CONF" \
  -extensions v3_req >/dev/null 2>&1

chmod 0600 "$KEY"
chmod 0644 "$CRT"

echo "generated $CRT (30-day) and $KEY" >&2
