#!/usr/bin/env bash
# close-phase.sh — mechanical pre-merge gate for phase close-out.
#
# Runs every local check that CI will run. Exits non-zero on the first
# failure so agents can iterate until green. Designed to be called by
# the /close-phase command, but also runnable standalone.
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

# --- Environment setup ---

# Snap Go knows its own GOROOT (/snap/go/NNNN).  If the user's profile
# sets GOROOT to the old apt-installed Go (/usr/share/go), `go vet` and
# `go build` break because the stdlib paths don't match.  Unset GOROOT
# when snap Go is detected so it can use its built-in value.
if command -v go &>/dev/null && [[ "$(command -v go)" == /snap/* ]]; then
    unset GOROOT
fi

GO_AVAILABLE=false
if command -v go &>/dev/null; then
    GO_AVAILABLE=true
fi

# Detect if this phase touches signal scores (any changed file under
# src/security/, internal/security/, or config/signal_scores.yml).
SCORES_TOUCHED=false
if git diff --cached --name-only 2>/dev/null | grep -qE '(src/security/|internal/security/|config/signal_scores\.yml)'; then
    SCORES_TOUCHED=true
fi

# Detect if this phase touches scoring pipeline (risk_scorer, action_decider,
# pipeline, signal_scores.yml).
PIPELINE_TOUCHED=false
if git diff --cached --name-only 2>/dev/null | grep -qE '(risk_scorer|action_decider|pipeline\.py|signal_scores\.yml|internal/security/scorer|internal/security/pipeline)'; then
    PIPELINE_TOUCHED=true
fi

echo -e "${BOLD}=== Phase Close-Out Gate ===${RESET}"
if [ -n "${GOROOT:-}" ]; then
    echo -e "  GOROOT=${GOROOT}"
fi
echo -e "  Go available: $GO_AVAILABLE"
echo -e "  Signal scores touched: $SCORES_TOUCHED"
echo -e "  Pipeline touched: $PIPELINE_TOUCHED"
echo ""

# 1. Python lint (ruff) — fastest check, catches most common CI breaker
echo -e "${BOLD}[1/8] ruff check .${RESET}"
if command -v ruff &>/dev/null; then
    ruff check . || fail "ruff found lint errors"
    pass "ruff"
else
    pip install -q ruff==0.15.9
    ruff check . || fail "ruff found lint errors"
    pass "ruff"
fi

# 2. Go formatting — second most common CI breaker
echo -e "${BOLD}[2/8] gofmt${RESET}"
if $GO_AVAILABLE; then
    out="$(gofmt -l . | grep -vE '^\.claude/|^\.qwen/|^vendor/' || true)"
    if [ -n "$out" ]; then
        echo "Unformatted files:"
        echo "$out"
        fail "gofmt found unformatted files (run: gofmt -w <file>)"
    fi
    pass "gofmt"
else
    echo "  (go not found, skipping)"
fi

# 3. Go vet
echo -e "${BOLD}[3/8] go vet${RESET}"
if $GO_AVAILABLE; then
    go vet $(go list ./... | grep -vE '/\.claude/|/\.qwen/|/vendor/') || fail "go vet found issues"
    pass "go vet"
else
    echo "  (go not found, skipping)"
fi

# 4. Go tests
echo -e "${BOLD}[4/8] go test${RESET}"
if $GO_AVAILABLE; then
    GOFLAGS="-count=1" go test ./... || fail "Go tests failed"
    pass "go test"
else
    echo "  (go not found, skipping)"
fi

# 5. make test (Python: mypy + bandit + ruff + pip-audit + pytest)
echo -e "${BOLD}[5/8] make test${RESET}"
make test || fail "make test failed"
pass "make test"

# 6. Phase doc lint
echo -e "${BOLD}[6/8] make lint-phases${RESET}"
make lint-phases || fail "make lint-phases failed"
pass "lint-phases"

# 7. Signal score parity (conditional)
echo -e "${BOLD}[7/8] make check-scores${RESET}"
if $SCORES_TOUCHED; then
    make check-scores || fail "make check-scores failed — signal scores don't match config/signal_scores.yml"
    pass "check-scores"
else
    echo "  (no signal score changes, skipping)"
fi

# 8. Phase doc sync
echo -e "${BOLD}[8/8] sync roadmap${RESET}"
make sync || fail "make sync (containerized sync-roadmap.py) failed"
if ! git diff --quiet docs/phases/TODO.md docs/PROJECT_STATUS.md 2>/dev/null; then
    echo "  WARNING: TODO.md or PROJECT_STATUS.md changed after sync."
    echo "  Stage and commit these files before merging."
fi
pass "sync"

echo ""
if $PIPELINE_TOUCHED; then
    echo -e "${BOLD}⚠ Pipeline/scoring changes detected.${RESET}"
    echo -e "  Run 'make parity-check' with both proxies running before merging."
    echo -e "  (This check is not automated here — requires live services.)"
    echo ""
fi

echo -e "${GREEN}${BOLD}All checks passed. Safe to create PR and merge.${RESET}"
