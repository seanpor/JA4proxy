#!/usr/bin/env bash
# pip-audit-resilient.sh — run pip-audit but don't let a transient outage of a
# vulnerability service turn the *required* CI lint gate red (phase-311), and
# only soft-pass when BOTH PyPI and OSV are unreachable (phase-312).
#
# The problem: pip-audit (default `pypi` service) queries PyPI's per-package JSON
# API; a transient 5xx/timeout there raises ServiceError and exits non-zero,
# failing the gate and emailing maintainers — even though no vulnerability was
# found. That has flaked the Full Lint gate repeatedly.
#
# Behaviour:
#   - clean run                          -> exit 0
#   - REAL vulnerability found            -> exit 1  (authoritative; no fallback)
#   - unknown non-zero (bad args, parse)  -> exit <rc> (fail safe)
#   - PyPI service unreachable (retries)  -> fall back to OSV.dev (-s osv):
#         OSV clean        -> exit 0  (note: verified via OSV fallback)
#         OSV real vuln    -> exit 1
#         OSV unknown      -> exit <rc>
#         OSV unreachable  -> CI warning + exit 0  (rare DOUBLE outage only)
#
# The soft-pass is bounded and *loud*: it triggers ONLY when BOTH services are
# unreachable, never when a vuln is found. Persistent gaps are still caught by
# the weekly scheduled CI audit, the standalone dependency-audit-python job, and
# Dependabot. All args are passed through to pip-audit; the OSV fallback adds
# `-s osv --aliases on` so the PyPI-format `--ignore-vuln` CVE IDs still match
# their OSV/GHSA aliases (the 5 acknowledged transitive CVEs stay suppressed).
set -uo pipefail

RETRIES="${PIP_AUDIT_RETRIES:-4}"
BACKOFF="${PIP_AUDIT_BACKOFF:-5}"   # seconds, grows linearly per attempt
TIMEOUT="${PIP_AUDIT_TIMEOUT:-30}"

# Output that means "the vulnerability service was unreachable", not "a vuln exists".
TRANSIENT='ServiceError|HTTP Error 5[0-9][0-9]|5[0-9][0-9] (Server Error|Service)|Backend is unhealthy|timed out|TimeoutError|Read timed out|Connection (refused|reset|error|aborted)|Max retries exceeded|Temporary failure in name resolution|Name or service not known|HTTP Error 429|429 |rate.?limit'
# Output that means "a real finding" — must always fail even amid noise.
FINDINGS='Found [0-9]+ known vulnerabilit|^Name +Version +ID|vulnerabilit(y|ies) (found|present)'

BASE_ARGS=("$@")

# run_audit [extra pip-audit args...]
# Sets AUDIT_RESULT to one of: clean | vuln | unreachable | other.
# Sets AUDIT_RC to the real pip-audit exit code (for fail-safe propagation).
run_audit() {
  local attempt=1 out
  while :; do
    out="$(pip-audit --timeout "$TIMEOUT" "${BASE_ARGS[@]}" "$@" 2>&1)"; AUDIT_RC=$?
    printf '%s\n' "$out"
    if [ "$AUDIT_RC" -eq 0 ]; then AUDIT_RESULT=clean; return; fi
    if grep -qiE "$FINDINGS" <<<"$out"; then AUDIT_RESULT=vuln; return; fi
    if grep -qiE "$TRANSIENT" <<<"$out"; then
      if [ "$attempt" -ge "$RETRIES" ]; then AUDIT_RESULT=unreachable; return; fi
      echo "pip-audit-resilient: transient service error (attempt ${attempt}/${RETRIES}); retrying in $((BACKOFF*attempt))s..." >&2
      sleep "$((BACKOFF*attempt))"; attempt=$((attempt+1)); continue
    fi
    AUDIT_RESULT=other; return
  done
}

soft_pass() {
  local msg="pip-audit: BOTH PyPI and OSV vulnerability services were unreachable (double outage); not blocking CI. Coverage remains via the weekly scheduled audit, the standalone dependency-audit job, and Dependabot."
  [ -n "${GITHUB_ACTIONS:-}" ] && echo "::warning title=pip-audit soft-pass::${msg}" || echo "WARNING: ${msg}" >&2
  exit 0
}

# --- primary: PyPI (pip-audit default) ---------------------------------------
run_audit
case "$AUDIT_RESULT" in
  clean) exit 0 ;;
  vuln)  echo "pip-audit-resilient: real vulnerabilities reported — failing." >&2; exit 1 ;;
  other) echo "pip-audit-resilient: non-zero exit (${AUDIT_RC}) with no transient marker — failing safe." >&2; exit "$AUDIT_RC" ;;
  unreachable)
    echo "pip-audit-resilient: PyPI service unreachable after ${RETRIES} attempts — trying the OSV fallback..." >&2
    # --- fallback: OSV.dev -----------------------------------------------------
    run_audit -s osv --aliases on
    case "$AUDIT_RESULT" in
      clean)
        msg="pip-audit verified via the OSV fallback (PyPI was unreachable)."
        [ -n "${GITHUB_ACTIONS:-}" ] && echo "::notice title=pip-audit OSV fallback::${msg}" || echo "NOTE: ${msg}" >&2
        exit 0 ;;
      vuln)  echo "pip-audit-resilient: OSV fallback reported real vulnerabilities — failing." >&2; exit 1 ;;
      other) echo "pip-audit-resilient: OSV fallback non-zero exit (${AUDIT_RC}) — failing safe." >&2; exit "$AUDIT_RC" ;;
      unreachable) soft_pass ;;
    esac ;;
esac
