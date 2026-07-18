#!/usr/bin/env bash
# phase-800-code-health.sh — deterministic gate-runner + reporter (Phase 800).
#
# Detects and reports. It NEVER fixes anything and NEVER runs git add/commit.
# Fixing is the /code-health skill's job (.claude/skills/code-health/SKILL.md):
# read the logs, fix with judgment, re-run the failed gate here to verify, and
# commit explicitly named files. Design rationale: docs/phases/PHASE_800.md.
#
# Usage:
#   scripts/phase-800-code-health.sh              # all gates, full tier (CI-equivalent)
#   scripts/phase-800-code-health.sh --fast       # all gates, fast tier (host-light subset)
#   scripts/phase-800-code-health.sh --gate lint  # one gate only (mid-loop verification)
#
#   Gate -> make target:   full tier              fast tier
#     lint                 make lint              make lint-static
#     scan                 make scan              make scan-js
#     test                 make test              make test-unit
#
# Guards:
#   - refuses to run on main/master (exit 64) — create a work branch first
#   - an all-gates run refuses a dirty tree (exit 64) so the report describes a
#     committed, reproducible state; --gate subset runs allow a dirty tree (that
#     is how in-flight fixes are verified before being committed)
#
# Exit codes:
#   0   CLEAN    — every requested gate ran and passed
#   1   RESIDUAL — at least one gate failed; failure fingerprint differs from
#                  the previous all-gates run (progress is possible/being made)
#   2   STUCK    — all-gates run failed with the same failure fingerprint as the
#                  previous all-gates run (no progress since last run)
#   64  REFUSED  — on main, dirty tree on an all-gates run, or bad usage
#
# Report: <=33 lines x <=170 chars, enforced by construction in render_report().
# The report goes to stdout and to the run directory; progress goes to stderr.
# Full logs: .local/code-health/run-<timestamp>-<pid>/   (gitignored)
# Stuck-state: .local/code-health/last-full.fingerprint  (all-gates runs only)

set -euo pipefail

usage_error() {
  echo "REFUSED: $1" >&2
  echo "Usage: $0 [--fast] [--gate lint|scan|test]... (see header comment)" >&2
  exit 64
}

# ---------------------------------------------------------------- arguments --
TIER="full"
GATES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --fast) TIER="fast" ;;
    --gate)
      shift
      case "${1:-}" in
        lint|scan|test) GATES+=("$1") ;;
        *) usage_error "--gate needs lint, scan or test (got '${1:-}')" ;;
      esac
      ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) usage_error "unknown argument '$1'" ;;
  esac
  shift
done
if [ "${#GATES[@]}" -eq 0 ]; then
  GATES=(lint scan test)
fi
UNIQUE_GATES=$(printf '%s\n' "${GATES[@]}" | sort -u | tr '\n' ' ')
if [ "$UNIQUE_GATES" = "lint scan test " ]; then
  ALL_GATES=1
else
  ALL_GATES=0
fi

# ------------------------------------------------------------------- guards --
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) \
  || usage_error "not inside a git repository"
cd "$REPO_ROOT"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" = "main" ] || [ "$BRANCH" = "master" ]; then
  usage_error "refusing to run on '$BRANCH' — create a work branch first (git checkout -b phase-XXX-...)"
fi

DIRTY_COUNT=$(git status --porcelain | wc -l)
if [ "$ALL_GATES" -eq 1 ] && [ "$DIRTY_COUNT" -gt 0 ]; then
  echo "REFUSED: dirty working tree ($DIRTY_COUNT files) on an all-gates run." >&2
  echo "Commit (or stash) first so the report describes a reproducible commit." >&2
  echo "Mid-fix verification of a single gate is allowed dirty: --gate lint|scan|test" >&2
  git status --porcelain | head -10 >&2
  exit 64
fi

# --------------------------------------------------------------- run gates --
STATE_DIR=".local/code-health"
RUN_DIR="$STATE_DIR/run-$(date +%Y%m%d-%H%M%S)-$$"   # PID suffix: no same-second or concurrent-run collisions
STATE_FILE="$STATE_DIR/last-full.fingerprint"
mkdir -p "$RUN_DIR"

gate_target() {
  case "$1-$TIER" in
    lint-full) echo "lint" ;;      lint-fast) echo "lint-static" ;;
    scan-full) echo "scan" ;;      scan-fast) echo "scan-js" ;;
    test-full) echo "test" ;;      test-fast) echo "test-unit" ;;
  esac
}

# Salient failure lines from a gate log: ANSI stripped, durations normalised so
# the fingerprint is stable across runs. Heuristic — the full log is the truth.
salient() {
  sed -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$1" \
    | grep -E '(ERROR|Error:|error:|error\[|FAILED|FAIL:|failed|Found [0-9]+ (error|known)|PYSEC-[0-9]|GHSA-|CVE-[0-9]{4}|undefined name|panic:|No rule to make target|Traceback|vulnerabilit)' \
    | sed -E 's/ in [0-9]+\.[0-9]+s//g; s/[0-9]+\.[0-9]+s//g' \
    | head -40 || true
}

declare -A GATE_STATUS GATE_SECS
OVERALL_FAIL=0
for g in "${GATES[@]}"; do
  target=$(gate_target "$g")
  echo "[code-health] gate '$g': make $target (log: $RUN_DIR/$g.log)" >&2
  start=$SECONDS
  if make "$target" >"$RUN_DIR/$g.log" 2>&1; then
    GATE_STATUS[$g]="PASS"
  else
    GATE_STATUS[$g]="FAIL"
    OVERALL_FAIL=1
  fi
  GATE_SECS[$g]=$((SECONDS - start))
  echo "[code-health] gate '$g': ${GATE_STATUS[$g]} (${GATE_SECS[$g]}s)" >&2
done

# ------------------------------------------- status, fingerprint, exit code --
FINGERPRINT=""
if [ "$OVERALL_FAIL" -eq 1 ]; then
  FP_INPUT=""
  for g in "${GATES[@]}"; do
    if [ "${GATE_STATUS[$g]}" = "FAIL" ]; then
      FP_INPUT+="$g:$(salient "$RUN_DIR/$g.log")"$'\n'
    fi
  done
  FINGERPRINT=$(printf '%s' "$FP_INPUT" | sha256sum | cut -d' ' -f1)
fi

if [ "$OVERALL_FAIL" -eq 0 ]; then
  STATUS="CLEAN"; EXIT_CODE=0
  if [ "$ALL_GATES" -eq 1 ]; then rm -f "$STATE_FILE"; fi
elif [ "$ALL_GATES" -eq 1 ] && [ -f "$STATE_FILE" ] \
    && [ "$(cat "$STATE_FILE")" = "$FINGERPRINT" ]; then
  STATUS="STUCK"; EXIT_CODE=2
else
  STATUS="RESIDUAL"; EXIT_CODE=1
  if [ "$ALL_GATES" -eq 1 ]; then printf '%s\n' "$FINGERPRINT" > "$STATE_FILE"; fi
fi

# ------------------------------------------------------------------ report --
# Contract: <=33 lines, <=170 chars/line — enforced here, not merely hoped for.
# Header+footer are fixed; the REMAINING ISSUES section gets whatever line
# budget is left and elides the rest with a pointer at the full logs.
render_report() {
  local -a head foot issues
  local g m total shown
  head+=("=== CODE HEALTH REPORT (phase 800) ============================================")
  head+=("Status: $STATUS | tier: $TIER | branch: $BRANCH @ $(git rev-parse --short HEAD) | dirty files: $DIRTY_COUNT | $(date -u +%Y-%m-%dT%H:%M:%SZ)")
  head+=("GATE   RESULT  SECS  TARGET")
  for g in "${GATES[@]}"; do
    head+=("$(printf '%-6s %-6s %5s  make %s' "$g" "${GATE_STATUS[$g]}" "${GATE_SECS[$g]}" "$(gate_target "$g")")")
  done
  foot+=("Full logs: $RUN_DIR/  | fingerprint: ${FINGERPRINT:0:12}")
  foot+=("Exit $EXIT_CODE (0=CLEAN 1=RESIDUAL 2=STUCK-no-change-since-last-run 64=REFUSED)")
  foot+=("=== END =======================================================================")

  if [ "$OVERALL_FAIL" -eq 1 ]; then
    for g in "${GATES[@]}"; do
      if [ "${GATE_STATUS[$g]}" = "FAIL" ]; then
        while IFS= read -r m; do
          [ -n "$m" ] && issues+=("[$g] $m")
        done < <(salient "$RUN_DIR/$g.log")
      fi
    done
    total=${#issues[@]}
    # 33 minus head, foot and the section-header line
    local budget=$((33 - ${#head[@]} - ${#foot[@]} - 1))
    shown=$total
    if [ "$total" -gt "$budget" ]; then
      shown=$((budget - 1))
      issues=("${issues[@]:0:$shown}" "(+$((total - shown)) more - see full logs)")
    fi
    head+=("REMAINING ISSUES (showing $shown of $total salient lines):")
  fi

  # tr: tabs count as up to 8 columns in wc -L — flatten them so the 170-byte
  # cut really is a 170-column bound; also drop CRs from containerised logs.
  printf '%s\n' "${head[@]}" "${issues[@]:-}" "${foot[@]}" \
    | tr '\t' ' ' | tr -d '\r' | sed -e 's/[[:space:]]*$//' \
    | cut -c1-170 | grep -v '^$' || true
}

REPORT_FILE="$RUN_DIR/report.txt"
render_report | tee "$REPORT_FILE"

# Belt-and-braces: assert the contract we just enforced by construction.
LINES=$(wc -l < "$REPORT_FILE")
WIDTH=$(wc -L < "$REPORT_FILE")
if [ "$LINES" -gt 33 ] || [ "$WIDTH" -gt 170 ]; then
  echo "[code-health] BUG: report violates 33x170 contract (${LINES}L x ${WIDTH}C)" >&2
fi

exit "$EXIT_CODE"
