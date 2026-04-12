#!/usr/bin/env bash
# close-phase.sh — mechanical pre-merge gate for phase close-out.
#
# Runs every local check that CI will run. Exits non-zero on the first
# failure so agents can iterate until green. Designed to be called by
# the /close-phase Claude Code command, but also runnable standalone.
#
# Usage:  bash scripts/close-phase.sh
#
# Exit codes:
#   0  All checks passed — safe to create PR and merge.
#   1  One or more checks failed — fix and re-run.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

pass() { echo -e "${GREEN}✓ $1${RESET}"; }
fail() { echo -e "${RED}✗ $1${RESET}"; echo -e "${RED}  Fix the above and re-run scripts/close-phase.sh${RESET}"; exit 1; }

echo -e "${BOLD}=== Phase Close-Out Gate ===${RESET}"
echo ""

# 1. Python lint (ruff) — fastest check, catches most common CI breaker
echo -e "${BOLD}[1/6] ruff check .${RESET}"
if command -v ruff &>/dev/null; then
    ruff check . || fail "ruff found lint errors"
    pass "ruff"
else
    pip install -q ruff==0.15.9
    ruff check . || fail "ruff found lint errors"
    pass "ruff"
fi

# 2. Go formatting — second most common CI breaker
echo -e "${BOLD}[2/6] gofmt${RESET}"
if command -v gofmt &>/dev/null; then
    out="$(gofmt -l . | grep -vE '^\.claude/|^\.qwen/|^vendor/' || true)"
    if [ -n "$out" ]; then
        echo "Unformatted files:"
        echo "$out"
        fail "gofmt found unformatted files (run: gofmt -w <file>)"
    fi
    pass "gofmt"
else
    echo "  (gofmt not found, skipping — Go not installed)"
fi

# 3. Go vet
echo -e "${BOLD}[3/6] go vet${RESET}"
if command -v go &>/dev/null; then
    go vet $(go list ./... | grep -vE '/\.claude/|/\.qwen/|/vendor/') || fail "go vet found issues"
    pass "go vet"
else
    echo "  (go not found, skipping — Go not installed)"
fi

# 4. Go tests
echo -e "${BOLD}[4/6] go test${RESET}"
if command -v go &>/dev/null; then
    GOFLAGS="-count=1" go test ./... || fail "Go tests failed"
    pass "go test"
else
    echo "  (go not found, skipping)"
fi

# 5. make test (Python: mypy + bandit + ruff + pip-audit + pytest)
echo -e "${BOLD}[5/6] make test${RESET}"
make test || fail "make test failed"
pass "make test"

# 6. Phase doc sync
echo -e "${BOLD}[6/6] sync roadmap${RESET}"
python3 scripts/sync-roadmap.py || fail "sync-roadmap.py failed"
if ! git diff --quiet docs/phases/TODO.md docs/PROJECT_STATUS.md 2>/dev/null; then
    echo "  WARNING: TODO.md or PROJECT_STATUS.md changed after sync."
    echo "  Stage and commit these files before merging."
fi
pass "sync"

echo ""
echo -e "${GREEN}${BOLD}All checks passed. Safe to create PR and merge.${RESET}"
