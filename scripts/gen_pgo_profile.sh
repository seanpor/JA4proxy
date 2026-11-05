#!/usr/bin/env bash
# scripts/gen_pgo_profile.sh — Regenerate cmd/ja4pd/default.pgo from representative load run (Phase 863)
# Usage: ./scripts/gen_pgo_profile.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "=== Generating Go PGO Profile for ja4pd ==="
TMP_PROF="$(mktemp /tmp/ja4pd_pipeline_XXXXXX.pprof)"
trap 'rm -f "${TMP_PROF}"' EXIT

# Run pipeline benchmark with CPU profiling inside Docker toolchain
docker run --rm -v "${REPO_ROOT}":/src -w /src golang:1.27.3-alpine sh -c "
  go test -run '^$' -bench 'BenchmarkPipeline' -benchtime 5s \
    -cpuprofile /tmp/bench.pprof ./cmd/ja4pd
  cat /tmp/bench.pprof
" > "${TMP_PROF}"

if [ ! -s "${TMP_PROF}" ]; then
  echo "Error: profiling output was empty" >&2
  exit 1
fi

# Move raw pprof CPU profile to cmd/ja4pd/default.pgo (do not run preprofile manually)
cp "${TMP_PROF}" cmd/ja4pd/default.pgo
echo "✓ Successfully generated cmd/ja4pd/default.pgo ($(wc -c < cmd/ja4pd/default.pgo) bytes)"
