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

# Type checking with mypy (Phase 16f — enabled; uses mypy.ini baseline)
if ! command -v mypy &> /dev/null; then
    echo "  ✗ mypy not installed (pip install mypy)"
else
    echo "  ✓ Running mypy type checking..."
    python3 -m mypy src/ proxy.py && echo "  ✓ mypy: OK" || echo "  ✗ mypy: type errors found (see above)"
fi

# Security scanning with bandit (Phase 16f — medium/high only; B104 suppressed in source)
if ! command -v bandit &> /dev/null; then
    echo "  ✗ bandit not installed (pip install bandit)"
else
    echo "  ✓ Running bandit security scan..."
    python3 -m bandit -r src/ proxy.py -ll -q && echo "  ✓ bandit: OK" || echo "  ✗ bandit: findings above"
fi

# Ruff linting (Phase 16f — replaces flake8/isort for new code)
if command -v ruff &> /dev/null || python3 -m ruff --version &> /dev/null 2>&1; then
    echo "  ✓ Running ruff linter..."
    python3 -m ruff check src/ proxy.py tests/ && echo "  ✓ ruff: OK" || echo "  ⚠️  ruff: style issues found"
else
    echo "  ✗ ruff not installed (pip install ruff)"
fi

# Dependency vulnerability check with pip-audit (Phase 16f — replaces safety 3.x which requires auth)
if command -v pip-audit &> /dev/null; then
    echo "  ✓ Running pip-audit CVE scan..."
    pip-audit -r requirements.txt \
      --ignore-vuln CVE-2025-50181 \
      --ignore-vuln CVE-2025-66418 \
      --ignore-vuln CVE-2025-66471 \
      --ignore-vuln CVE-2026-21441 \
      && echo "  ✓ pip-audit: OK (urllib3 CVEs acknowledged — transitive dep)" \
      || echo "  ✗ pip-audit: new vulnerabilities found — update requirements.txt"
else
    echo "  ✗ pip-audit not installed (pip install pip-audit)"
fi

echo ""

# ── Coverage (Phase 16) ──────────────────────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Running tests with coverage (Phase 16)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── Run ───────────────────────────────────────────────────────────────────────
set +e
"$PYTHON" -m pytest tests/ \
    --ignore=tests/integration/test_docker_stack.py \
    -n "$WORKERS" \
    --dist=loadfile \
    --timeout=60 \
    --cov=src \
    --cov=proxy \
    --cov-fail-under=80 \
    --cov-report=term-missing \
    --cov-report=html:.local/coverage \
    --junitxml="$JUNIT" \
    -m "${PYTEST_MARKS:-not live_services}" \
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
