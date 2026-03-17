#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  JA4proxy — local test runner
#  Called by:  make test
#  Results:    test-results/run-YYYYMMDD-HHMMSS.log   (full output)
#              test-results/latest.log                 (symlink to most recent)
#              test-results/junit-YYYYMMDD-HHMMSS.xml  (JUnit XML for CI)
#              test-results/latest-junit.xml           (symlink to most recent)
#
#  Extra pytest args can be passed through, e.g.:
#    make test ARGS="-k test_beaconing -v"
#    ./scripts/run-local-tests.sh -k test_abuseipdb --tb=long
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PYTHON=${PYTHON:-python3}
RESULTS_DIR="test-results"
TS=$(date +"%Y%m%d-%H%M%S")
LOG="$RESULTS_DIR/run-$TS.log"
JUNIT="$RESULTS_DIR/junit-$TS.xml"

# ── Worker count ──────────────────────────────────────────────────────────────
if [ ! -f ".local/machine.mk" ]; then
    echo "First run: calibrating machine speed..."
    echo ""
    "$PYTHON" scripts/detect_workers.py
    echo ""
fi

WORKERS=$(grep -E '^WORKERS\s*:?=' .local/machine.mk 2>/dev/null \
          | awk -F'=' '{print $2}' | tr -d ' \t' || echo "auto")
WORKERS=${WORKERS:-auto}

# ── Setup ─────────────────────────────────────────────────────────────────────
mkdir -p "$RESULTS_DIR"

# ── Banner ────────────────────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  JA4proxy Test Suite  │  $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Workers: $WORKERS  │  Timeout: 60s/test  │  dist: loadfile"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Static Analysis (Phase 16) ──────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Static Analysis (Phase 16)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Type checking with mypy
if ! command -v mypy &> /dev/null; then
    echo "  ✗ mypy not installed (pip install mypy)"
else
    echo "  ✓ Running mypy type checking..."
    mypy src/ proxy.py --ignore-missing-imports --no-strict-optional || true
fi

# Security scanning with bandit
if ! command -v bandit &> /dev/null; then
    echo "  ✗ bandit not installed (pip install bandit)"
else
    echo "  ✓ Running bandit security scan..."
    bandit -r src/ proxy.py -ll || true
fi

# Dependency vulnerability check with safety
if ! command -v safety &> /dev/null; then
    echo "  ✗ safety not installed (pip install safety)"
else
    echo "  ✓ Running safety dependency check..."
    safety check --full-report || true
fi

echo ""

# ── Run ───────────────────────────────────────────────────────────────────────
set +e
"$PYTHON" -m pytest tests/ \
    --ignore=tests/integration/test_docker_stack.py \
    -n "$WORKERS" \
    --dist=loadfile \
    --timeout=60 \
    --junitxml="$JUNIT" \
    "$@" \
    2>&1 | tee "$LOG"
EXIT=${PIPESTATUS[0]}
set -e

# ── Symlinks to latest ────────────────────────────────────────────────────────
(cd "$RESULTS_DIR" && ln -sf "run-$TS.log" latest.log)
(cd "$RESULTS_DIR" && ln -sf "junit-$TS.xml" latest-junit.xml)

# ── File summary ──────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Results written to:"
echo "    Log:   $LOG"
echo "    JUnit: $JUNIT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

exit $EXIT
