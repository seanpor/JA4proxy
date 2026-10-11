#!/usr/bin/env bash
# scripts/run-concurrency-stress.sh
# Multi-core concurrent preemption stress harness for JA4proxy pipeline (Phase 842)
set -euo pipefail

echo "=========================================================="
echo " Starting JA4proxy High-Preemption Concurrency Stress Test"
echo "=========================================================="

export GOROOT=${GOROOT:-/snap/go/current}
GO_BIN="${GOROOT}/bin/go"

if [ ! -x "${GO_BIN}" ]; then
    echo "Using host 'go' binary"
    GO_BIN="go"
fi

# Run with -race and GOMAXPROCS set to high concurrency (e.g. 16 or 32)
# to force thread preemption and uncover scheduling races.
GOMAXPROCS=16 "${GO_BIN}" test -v -race -run="Stress" -timeout=120s ./internal/security/...

echo "=========================================================="
echo " ✓ Concurrency Stress Test Passed Cleanly (0 Data Races)"
echo "=========================================================="
