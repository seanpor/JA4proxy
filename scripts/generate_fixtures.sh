#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES="$REPO/tests/fixtures/clienthello"

cd "$REPO"

# Build ja4check
echo "Building ja4check..."
GOROOT=/snap/go/current go build -o bin/ja4check ./cmd/ja4check

# Start capture server
echo "Starting capture server..."
python3 scripts/capture_server.py \
  --names curl_tls13,curl_tls12,openssl_tls13,python_tls13 \
  --timeout 30 &
CAPTURE_PID=$!
sleep 1

# Capture curl TLS 1.3
echo "Capturing curl TLS 1.3..."
curl --tlsv1.3 -sk https://127.0.0.1:9443/ 2>/dev/null || true

# Capture curl TLS 1.2
echo "Capturing curl TLS 1.2..."
curl --tlsv1.2 --tls-max 1.2 -sk https://127.0.0.1:9444/ 2>/dev/null || true

# Capture openssl TLS 1.3
echo "Capturing openssl s_client TLS 1.3..."
echo "Q" | timeout 2 openssl s_client -connect 127.0.0.1:9445 -tls1_3 -no_ticket 2>/dev/null || true

# Capture Python ssl TLS 1.3
echo "Capturing Python ssl TLS 1.3..."
python3 -c "
import ssl, socket
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    with socket.create_connection(('127.0.0.1', 9446), timeout=2) as s:
        with ctx.wrap_socket(s, server_hostname='test.example.com') as ss:
            pass
except Exception:
    pass
" 2>/dev/null || true

wait $CAPTURE_PID 2>/dev/null || true

# Also generate synthetic fixtures
echo "Generating synthetic fixtures..."
python3 scripts/generate_synthetic_fixtures.py

# Report
echo ""
echo "Fixtures in $FIXTURES:"
ls -la "$FIXTURES"/*.bin 2>/dev/null || echo "  (none captured -- clients may have timed out)"
echo ""
echo "To verify parity:"
echo "  for f in tests/fixtures/clienthello/*.bin; do"
echo "    echo -n \"\$f: Go=\"; bin/ja4check \"\$f\"; "
echo "    echo -n \"       Py=\"; python3 scripts/compute_ja4.py \"\$f\"; "
echo "  done"
