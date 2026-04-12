#!/bin/bash
# quick-start.sh — JA4proxy quick-start helper
# Builds the Go proxy binary and starts the proxy with default config.
# Suitable for local development and CI smoke testing.
#
# Usage: bash scripts/quick-start.sh [config-file]
#   config-file  Path to proxy config YAML (default: config/proxy.yml)

set -euo pipefail

CONFIG=${1:-config/proxy.yml}
BIN=bin/proxy

echo "=== JA4proxy Quick Start ==="
echo "Config: ${CONFIG}"
echo ""

# Build if binary is missing or source is newer
if [ ! -f "${BIN}" ] || [ -n "$(find cmd/proxy internal -name '*.go' -newer "${BIN}" 2>/dev/null)" ]; then
    echo "[1/2] Building Go proxy..."
    make build-go
else
    echo "[1/2] Binary is up to date, skipping build."
fi

echo "[2/2] Starting proxy..."
exec "${BIN}" --config "${CONFIG}"
