#!/usr/bin/env bash
# ensure-poc-secrets.sh — create any missing deploy/secrets/*.txt the PoC
# compose stack declares, so targets that bring the stack up work from a clean
# checkout (phase-800).
#
# WHY THIS EXISTS
#   `make bench-all` aborted at `perf-test` with a bare Docker error:
#
#     invalid mount config for type "bind": bind source path does not exist:
#     .../deploy/secrets/analytics_redis_password.txt
#
#   docker-compose.poc.yml declares five `secrets:` entries as bind-mounted
#   files. Nothing in the repo created four of them:
#   scripts/setup-redis-security.sh generates redis_password.txt plus three
#   others the PoC stack does not use, and scripts/start-pentest-range.sh
#   deliberately writes to its own directory and refuses to touch
#   deploy/secrets/. So any target that raises the PoC stack failed on a
#   machine that had not been hand-primed — and failed with a Docker bind-mount
#   error that says nothing about how to fix it.
#
#   The names are read FROM THE COMPOSE FILE rather than hardcoded here. A
#   hand-maintained list is exactly what drifted before: start-poc.sh carries a
#   comment about its .env list drifting out of sync with the same services'
#   requirements, and start-pentest-range.sh hardcodes the five names today.
#   Deriving them means adding a secret to the compose file cannot silently
#   break this again.
#
# SECURITY
#   - Never overwrites an existing file: re-running cannot rotate a credential
#     out from under a running stack.
#   - Generated values go straight to a 0600 file; nothing is echoed
#     (JA4PROXY-2026-0040 forbids printing credentials).
#   - deploy/secrets/* is gitignored, so these are local dev credentials only.
#     They are NOT suitable for production, where secrets should come from a
#     real secret manager.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${1:-${REPO_ROOT}/deploy/docker/docker-compose.poc.yml}"
SECRETS_DIR="${REPO_ROOT}/deploy/secrets"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "✗ compose file not found: $COMPOSE_FILE" >&2
    exit 1
fi

# Emit "<name> <relative-path>" per declared file-backed secret.
mapfile -t entries < <(python3 - "$COMPOSE_FILE" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1])) or {}
for name, spec in (doc.get("secrets") or {}).items():
    if isinstance(spec, dict) and spec.get("file"):
        print(f"{name}\t{spec['file']}")
PY
)

if [ "${#entries[@]}" -eq 0 ]; then
    echo "  no file-backed secrets declared in $(basename "$COMPOSE_FILE") — nothing to do"
    exit 0
fi

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

created=0
kept=0
for entry in "${entries[@]}"; do
    rel="${entry#*$'\t'}"
    # Paths in the compose file are relative to the compose file's directory.
    target="$(cd "$(dirname "$COMPOSE_FILE")" && printf '%s/%s' "$PWD" "$rel")"

    if [ -s "$target" ]; then
        kept=$((kept + 1))
        continue
    fi

    mkdir -p "$(dirname "$target")"
    # 40 chars of base64-derived entropy, matching start-pentest-range.sh.
    ( umask 077; openssl rand -base64 48 | tr -d '\n/+=' | head -c 40 > "$target" )
    chmod 600 "$target"
    created=$((created + 1))
    echo "  generated $(basename "$target")"
done

echo "  ✓ PoC secrets ready (${created} generated, ${kept} already present)"
