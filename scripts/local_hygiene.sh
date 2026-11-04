#!/usr/bin/env bash
# scripts/local_hygiene.sh — Fast on-demand local pre-check for CVEs and drift.
# Container-strict: delegates Python checks to $(TOOLS_RUN).
set -euo pipefail

echo "=== JA4proxy Local Hygiene Check ==="

echo "1. Checking documentation & Docker image reference synchronization..."
python3 scripts/sync_reference_docs.py --check
python3 scripts/lint-phases.py

echo "2. Checking Python dependency resolution and fixture parity..."
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools python3 scripts/check_deps_resolution.py

echo "3. Running containerized Python CVE audit (pip-audit)..."
docker run --rm -v "$PWD":/src -w /src ja4proxy-tools bash scripts/pip-audit-resilient.sh \
    -r requirements.txt \
    -r requirements-test.txt \
    -r requirements-analytics.txt \
    -r management/requirements.txt \
    $(grep -v '^[[:space:]]*#' .pip-audit-ignores)

echo "4. Checking Go toolchain & dependencies..."
if command -v go >/dev/null 2>&1; then
    go vet ./...
elif docker image inspect golang:1.26-alpine >/dev/null 2>&1; then
    docker run --rm -v "$PWD":/src -w /src golang:1.26-alpine go vet ./...
fi

echo "✓ Local hygiene check complete: all pins resolve cleanly, docs in sync, zero un-waived CVEs."
