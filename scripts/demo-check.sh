#!/usr/bin/env bash
# demo-check.sh — refuse to start a demo on a stack that is quietly broken.
#
# phase-826. Every failure this checks for has actually happened, and every one
# of them was invisible: containers up, health checks green, pages returning
# 200, and nothing working. Run it before anyone is watching.
set -uo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$(dirname "$(readlink -f "$0")")")"
# shellcheck disable=SC1091
[ -f .env ] && . ./.env

PASS=0; FAIL=0
ok()   { printf '  \033[0;32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[0;31m✗\033[0m %s\n' "$1"; printf '      %s\n' "${2:-}"; FAIL=$((FAIL+1)); }
# Non-fatal: worth saying, but must not fail the pre-flight. A handful of
# rejected events with traffic flowing is not a reason to abandon a demo.
warn() { printf '  \033[1;33m!\033[0m %s\n' "$1"; printf '      %s\n' "${2:-}"; PASS=$((PASS+1)); }

P="${COMPOSE_PROJECT_NAME:-ja4proxy-lane0}"
PROXY=$(docker ps --format '{{.Names}}' | grep -E "^${P}-proxy-[0-9]+$"     | head -1)
ANALYTICS=$(docker ps --format '{{.Names}}' | grep -E "^${P}-analytics-[0-9]+$" | head -1)
REDIS=$(docker ps --format '{{.Names}}' | grep -E "^${P}-redis-[0-9]+$"     | head -1)

echo "Demo pre-flight — project ${P}"
echo

# --- containers ---------------------------------------------------------------
for c in "$PROXY" "$ANALYTICS" "$REDIS"; do
  [ -n "$c" ] && ok "container up: $c" || bad "a required container is not running" \
    "run: scripts/start-poc.sh"
done
[ -n "$PROXY" ] && [ -n "$ANALYTICS" ] && [ -n "$REDIS" ] || { echo; echo "ABORT"; exit 1; }

rcli() { docker exec "$REDIS" redis-cli --user management --pass "${MANAGEMENT_REDIS_PASSWORD:-}" --no-auth-warning "$@" 2>/dev/null; }

# --- the analytics pipeline ---------------------------------------------------
# This is the one that was broken for the entire life of the project: the
# consumer could not read the stream at all, so the Intelligence panel was
# permanently empty while every other signal looked healthy.
ERRS=$(docker logs "$ANALYTICS" 2>&1 | grep -c "Stream consumer error" || true)
[ "$ERRS" -eq 0 ] && ok "analytics stream consumer has no read errors" \
  || bad "analytics cannot read the event stream ($ERRS errors)" \
         "check socket_timeout vs the XREADGROUP block window"

# One fetch, reused: two docker-exec scrapes could disagree, and the reason
# label below has to come from the same sample as the count it explains.
METRICS=$(docker exec "$ANALYTICS" wget -qO- http://127.0.0.1:8080/metrics 2>/dev/null || true)
REJ=$(printf '%s\n' "$METRICS" | awk '/^ja4proxy_analytics_events_rejected_total\{/{s+=$2} END{print s+0}')
ING=$(printf '%s\n' "$METRICS" | awk '/^ja4proxy_analytics_events_ingested_total /{print $2+0}')
ING=${ING:-0}; REJ=${REJ:-0}
if [ "${ING%.*}" -gt 0 ]; then ok "analytics has ingested events (${ING%.*})"
else bad "analytics has ingested 0 events" "generate traffic, then re-run"; fi
if [ "${REJ%.*}" -eq 0 ]; then ok "no events rejected"
else
  # Report the reason label rather than guessing. "usually an HMAC mismatch" was
  # wrong the first time it fired in anger: the label said reason="invalid"
  # (schema), and a real mismatch rejects 100% of events, not a handful. Sending
  # someone to rotate secrets over three malformed events wastes the one thing
  # they are short of during a demo.
  REASONS=$(printf '%s' "$METRICS" | awk -F'reason="' '/^ja4proxy_analytics_events_rejected_total\{/ {split($2,a,"\""); printf "%s ", a[1]}')
  if printf '%s' "$REASONS" | grep -q hmac; then
    bad "analytics is REJECTING events (${REJ%.*}, reason: ${REASONS% })" \
        "HMAC secret mismatch — see docs/runbooks/analytics_ingest_silent_failure.md"
  elif [ "${ING%.*}" -gt 0 ]; then
    warn "analytics rejected ${REJ%.*} event(s) (reason: ${REASONS% }) but is ingesting ${ING%.*}" \
         "not a secret mismatch; usually connections that carried no ClientHello"
  else
    bad "analytics is REJECTING events (${REJ%.*}, reason: ${REASONS% })" \
        "nothing is being ingested — see docs/runbooks/analytics_ingest_silent_failure.md"
  fi
fi

# --- enforcement path ---------------------------------------------------------
BL=$(docker logs "$PROXY" 2>&1 | grep -o 'blacklist=[0-9]*' | tail -1 | cut -d= -f2)
[ -n "$BL" ] && ok "proxy loaded security lists (blacklist=$BL)" \
  || bad "proxy never logged 'security lists loaded'" "it cannot enforce the JA4 blacklist"

# --- console ------------------------------------------------------------------
MP="${HOST_PORT_MANAGEMENT:-8090}"
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${MP}/login" || echo 000)
[ "$CODE" = "200" ] && ok "console reachable on :${MP}" \
  || bad "console not reachable on :${MP} (HTTP $CODE)" "docker compose up -d management"

# --- findings -----------------------------------------------------------------
F=$(rcli ZCARD analytics:findings:index | tr -d '\r')
F=${F:-0}
if [ "$F" -gt 0 ]; then ok "Intelligence panel has $F finding(s) to show"
else bad "no Intelligence findings" \
  "blacklist a tool fingerprint, SIGHUP the proxy, then run the bulk traffic"; fi

echo
if [ "$FAIL" -eq 0 ]; then
  printf '\033[0;32mReady to demo — %d checks passed.\033[0m\n' "$PASS"; exit 0
fi
printf '\033[0;31mNOT ready — %d of %d checks failed.\033[0m\n' "$FAIL" "$((PASS+FAIL))"
echo "See docs/DEMO_RUNBOOK.md."
exit 1
