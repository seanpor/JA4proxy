#!/usr/bin/env bash
# pip-audit-resilient.sh — run pip-audit but don't let a transient PyPI/OSV
# outage turn the *required* CI lint gate red (phase-311).
#
# The problem: pip-audit (default `pypi` service) queries PyPI's per-package JSON
# API; a transient 5xx/timeout there raises ServiceError and exits non-zero,
# failing the gate and emailing maintainers — even though no vulnerability was
# found. That has flaked the Full Lint gate repeatedly.
#
# Behaviour:
#   - clean run                        -> exit 0
#   - REAL vulnerabilities found       -> exit 1  (always blocks — the point)
#   - vulnerability service unreachable-> retry with backoff; if still down,
#                                         emit a CI warning and exit 0 (do NOT
#                                         block on an upstream outage)
#   - any other non-zero (e.g. bad args, parse error) -> exit 1 (fail safe)
#
# The soft-pass is bounded and safe: it triggers ONLY when the service itself is
# unreachable, never when a vuln is found. Persistent gaps are still caught by
# the weekly scheduled CI audit, the standalone dependency-audit-python job, and
# Dependabot. All args are passed through to pip-audit.
set -uo pipefail

RETRIES="${PIP_AUDIT_RETRIES:-4}"
BACKOFF="${PIP_AUDIT_BACKOFF:-5}"   # seconds, grows linearly per attempt
TIMEOUT="${PIP_AUDIT_TIMEOUT:-30}"

# Output that means "the vulnerability service was unreachable", not "a vuln exists".
TRANSIENT='ServiceError|HTTP Error 5[0-9][0-9]|5[0-9][0-9] (Server Error|Service)|Backend is unhealthy|timed out|TimeoutError|Read timed out|Connection (refused|reset|error|aborted)|Max retries exceeded|Temporary failure in name resolution|Name or service not known|HTTP Error 429|429 |rate.?limit'
# Output that means "a real finding" — must always fail even amid noise.
FINDINGS='Found [0-9]+ known vulnerabilit|^Name +Version +ID|vulnerabilit(y|ies) (found|present)'

attempt=1
while :; do
  out="$(pip-audit --timeout "$TIMEOUT" "$@" 2>&1)"; rc=$?
  printf '%s\n' "$out"
  if [ "$rc" -eq 0 ]; then
    exit 0
  fi
  if grep -qiE "$FINDINGS" <<<"$out"; then
    echo "pip-audit-resilient: real vulnerabilities reported — failing." >&2
    exit 1
  fi
  if grep -qiE "$TRANSIENT" <<<"$out"; then
    if [ "$attempt" -ge "$RETRIES" ]; then
      msg="pip-audit: vulnerability service unreachable after ${RETRIES} attempts (PyPI/OSV outage); not blocking CI. Coverage remains via the weekly scheduled audit, the standalone dependency-audit job, and Dependabot."
      # GitHub Actions annotation if running in CI; plain warning otherwise.
      [ -n "${GITHUB_ACTIONS:-}" ] && echo "::warning title=pip-audit soft-pass::${msg}" || echo "WARNING: ${msg}" >&2
      exit 0
    fi
    echo "pip-audit-resilient: transient service error (attempt ${attempt}/${RETRIES}); retrying in $((BACKOFF*attempt))s..." >&2
    sleep "$((BACKOFF*attempt))"
    attempt=$((attempt+1))
    continue
  fi
  echo "pip-audit-resilient: non-zero exit (${rc}) with no recognised transient marker — failing safe." >&2
  exit "$rc"
done
