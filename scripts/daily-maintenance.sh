#!/usr/bin/env bash
# scripts/daily-maintenance.sh — Automated daily dependency update and preflight runner.
#
# Usage:
#   scripts/daily-maintenance.sh --dry-run
#   scripts/daily-maintenance.sh --apply [--skip-preflight]
#
# Modes:
#   --dry-run         Read-only check across Docker, Go, Python, and Node (no files modified)
#   --apply           Apply updates across all 4 ecosystems and run `make preflight` (default)
#   --skip-preflight  Skip `make preflight` during --apply (for fast local validation)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="apply"
RUN_PREFLIGHT=1

for arg in "$@"; do
  case "$arg" in
    --dry-run)
      MODE="dry-run"
      ;;
    --apply)
      MODE="apply"
      ;;
    --skip-preflight)
      RUN_PREFLIGHT=0
      ;;
    -h|--help)
      sed -n '2,12p' "$0"
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

START_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "================================================================"
echo " JA4proxy Daily Maintenance"
echo " Timestamp : ${START_TS}"
echo " Mode      : ${MODE}"
echo " Repo      : ${REPO_ROOT}"
echo "================================================================"

if [[ "$MODE" == "dry-run" ]]; then
  echo "[1/5] Checking Go module updates (dry-run)..."
  GOROOT="${GOROOT:-/snap/go/current}" python3 scripts/apply_updates_go_node.py --go --dry-run

  echo "[2/5] Checking Node / sql.js updates (dry-run)..."
  docker build -q -t ja4proxy-update-checker -f deploy/docker/update-checker/Dockerfile . >/dev/null
  docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/tmp/npm-cache \
    -v "${REPO_ROOT}:/app" --entrypoint python3 ja4proxy-update-checker \
    scripts/apply_updates_go_node.py --node --dry-run

  echo "[3/5] Checking Python requirements parity updates (dry-run)..."
  docker run --rm -v "${REPO_ROOT}:/src" -w /src ja4proxy-tools \
    python3 scripts/apply_updates_python.py --dry-run

  echo "[4/5] Checking Docker multi-arch digests (dry-run)..."
  docker run --rm -v "${REPO_ROOT}:/src" -w /src ja4proxy-tools \
    python3 scripts/apply_updates_docker.py --dry-run

  echo "[5/5] Summary"
  echo "  Status    : DRY-RUN COMPLETE (no files modified)"
  echo "  Completed : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  exit 0
fi

echo "[1/5] Applying Go module updates..."
make update-go

echo "[2/5] Applying Python multi-environment updates..."
make update-python

echo "[3/5] Applying Node / sql.js updates + retire.js scan..."
make update-node

echo "[4/5] Resolving Docker multi-arch digests..."
make update-docker

if [[ "$RUN_PREFLIGHT" -eq 1 ]]; then
  echo "[5/5] Running make preflight (lint + scan + test)..."
  make preflight
else
  echo "[5/5] Skipping make preflight (--skip-preflight)"
fi

END_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
CHANGED_COUNT="$(git status --porcelain | wc -l | tr -d ' ')"

echo "================================================================"
echo " JA4proxy Daily Maintenance Summary"
echo " Status        : SUCCESS"
echo " Changed files : ${CHANGED_COUNT}"
echo " Started       : ${START_TS}"
echo " Completed     : ${END_TS}"
echo "================================================================"
if [[ "$CHANGED_COUNT" -gt 0 ]]; then
  git status -s
fi
