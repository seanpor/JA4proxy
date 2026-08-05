#!/usr/bin/env bash
#
# verify_revert.sh — machine-check the two-state proof (Phase 814a).
#
# PROGRAMME.md §10.3: a verification test must be demonstrated to FAIL against
# the pre-fix build and PASS against the post-fix build. A test that passes in
# both states proves nothing, and that is the single most common way regression
# tests become decoration.
#
# Humans assert "verified to fail on revert" all the time. This script is the
# difference between asserting it and having checked it:
#
#   1. Resolve the commit that fixed the finding, and its parent.
#   2. Check the PARENT out into a throwaway git worktree (never touching the
#      working tree — a pentest tool that dirties your checkout is a hazard).
#   3. Copy the verification test INTO that worktree, because the test does not
#      exist at the parent commit — it was written alongside the fix.
#   4. Run it there and require FAILURE.
#   5. Run it on the current tree and require SUCCESS.
#
# Step 3 is the subtle one. Checking out the parent alone would run the OLD
# tests against OLD code, which proves nothing about this finding. The test
# must be new-test-against-old-code.
#
# Usage:
#   scripts/verify_revert.sh JA4PROXY-2026-0042
#   scripts/verify_revert.sh JA4PROXY-2026-0042 --fix-commit <sha>
#
# Exit 0 = two-state proof holds. Exit 1 = it does not (and says which half).
#
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

die()  { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }
ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
info() { echo -e "${BLUE}▶ $*${NC}"; }
warn() { echo -e "${YELLOW}  ! $*${NC}"; }

FINDING_ID=""
FIX_COMMIT=""
WORKTREE=""

cleanup() {
    if [ -n "$WORKTREE" ] && [ -d "$WORKTREE" ]; then
        git worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

usage() {
    cat <<'USAGE'
Usage: scripts/verify_revert.sh <FINDING-ID> [--fix-commit <sha>]

  <FINDING-ID>        Canonical ID, e.g. JA4PROXY-2026-0042
  --fix-commit <sha>  Commit that fixed it. Defaults to the register's
                      closed_commit field.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --fix-commit) FIX_COMMIT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) FINDING_ID="$1"; shift ;;
    esac
done

[ -n "$FINDING_ID" ] || { usage; exit 1; }

# ── Look the finding up in the register ──────────────────────────────────────
read_register_field() {
    python3 - "$FINDING_ID" "$1" <<'PY'
import sys, yaml, pathlib
fid, field = sys.argv[1], sys.argv[2]
data = yaml.safe_load(pathlib.Path("docs/security/findings.yaml").read_text())
for finding in data.get("findings", []):
    if finding.get("id") == fid:
        print(finding.get(field) or "")
        break
else:
    print("__NOT_FOUND__")
PY
}

REGRESSION_TEST="$(read_register_field regression_test)"
[ "$REGRESSION_TEST" != "__NOT_FOUND__" ] || die "${FINDING_ID} is not in docs/security/findings.yaml"
[ -n "$REGRESSION_TEST" ] || die "${FINDING_ID} has no regression_test recorded — required once status >= FIXED"

if [ -z "$FIX_COMMIT" ]; then
    FIX_COMMIT="$(read_register_field closed_commit)"
fi
[ -n "$FIX_COMMIT" ] || die "no fix commit: pass --fix-commit, or set closed_commit on ${FINDING_ID}"

git cat-file -e "${FIX_COMMIT}^{commit}" 2>/dev/null \
    || die "fix commit ${FIX_COMMIT} not found in this repository"

PARENT="$(git rev-parse "${FIX_COMMIT}^" 2>/dev/null)" \
    || die "cannot resolve parent of ${FIX_COMMIT} (is it a root commit?)"

echo "════════════════════════════════════════════════════════════════"
echo " Two-state proof: ${FINDING_ID}"
echo "════════════════════════════════════════════════════════════════"
echo "  regression test : ${REGRESSION_TEST}"
echo "  fix commit      : ${FIX_COMMIT}"
echo "  parent (pre-fix): ${PARENT}"
echo ""

# ── Which runner? ────────────────────────────────────────────────────────────
# Go test paths look like ./pkg/... or contain _test.go; everything else is
# treated as a pytest node id.
run_test() {
    local dir="$1" nodeid="$2"
    if [[ "$nodeid" == *"_test.go"* || "$nodeid" == ./* ]]; then
        ( cd "$dir" && go test "$(dirname "${nodeid#./}")/..." 2>&1 )
    else
        # Container-strict per AGENTS.md: Python runs in the pinned tools image.
        docker run --rm -v "${dir}:/src" -w /src ja4proxy-tools pytest "$nodeid" -q 2>&1
    fi
}

# ── State 1: the test must FAIL against pre-fix code ─────────────────────────
info "State 1/2 — running the CURRENT test against PRE-FIX code (must fail)"
WORKTREE="$(mktemp -d -t ja4proxy-revert-XXXXXX)"
git worktree add --detach "$WORKTREE" "$PARENT" >/dev/null 2>&1 \
    || die "could not create worktree at ${PARENT}"

# The test does not exist at the parent commit — it was written with the fix.
# Copy it in, so this is new-test-against-old-code rather than old-vs-old.
TEST_FILE="${REGRESSION_TEST%%::*}"
TEST_FILE="${TEST_FILE#./}"
if [ -f "$TEST_FILE" ]; then
    mkdir -p "${WORKTREE}/$(dirname "$TEST_FILE")"
    cp "$TEST_FILE" "${WORKTREE}/${TEST_FILE}"
    ok "copied ${TEST_FILE} into the pre-fix worktree"
else
    warn "test file ${TEST_FILE} not found on the current tree — running whatever exists at the parent"
fi

PRE_OUTPUT=""
PRE_STATUS=0
PRE_OUTPUT="$(run_test "$WORKTREE" "$REGRESSION_TEST")" || PRE_STATUS=$?

if [ "$PRE_STATUS" -eq 0 ]; then
    echo "$PRE_OUTPUT" | tail -20
    echo ""
    die "TWO-STATE PROOF FAILED: the test PASSES against pre-fix code.
     It therefore does not test this finding — it is decoration, not a
     regression test. Either the test asserts the wrong thing, or the bug
     was never present at ${PARENT}.
     See PROGRAMME.md §10.3."
fi
ok "test fails against pre-fix code (exit ${PRE_STATUS}) — it detects the bug"

# ── State 2: the test must PASS against the fix ──────────────────────────────
info "State 2/2 — running the same test against the CURRENT tree (must pass)"
POST_STATUS=0
POST_OUTPUT="$(run_test "$REPO_ROOT" "$REGRESSION_TEST")" || POST_STATUS=$?

if [ "$POST_STATUS" -ne 0 ]; then
    echo "$POST_OUTPUT" | tail -20
    echo ""
    die "TWO-STATE PROOF FAILED: the test does not pass on the current tree.
     Either the fix has regressed, or the test is broken. Both are findings."
fi
ok "test passes on the current tree — the fix holds"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN} TWO-STATE PROOF HOLDS for ${FINDING_ID}${NC}"
echo -e "${GREEN}   pre-fix  (${PARENT:0:12}): FAIL${NC}"
echo -e "${GREEN}   post-fix (current tree):   PASS${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Paste both results into the finding's §9. This does NOT promote the"
echo "finding to VERIFIED — that needs the independent fix-audit (PROGRAMME.md §11),"
echo "which re-runs the ORIGINAL attack rather than this test."
