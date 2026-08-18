#!/usr/bin/env bash
# Journey J2 — "can an operator actually use the console?"  (Phase 824)
#
# WHY THIS EXISTS
#
# The suite has ~1900 unit tests and 751 management tests. On 2026-08-17 an
# operator opened the console for a client demo and hit, in order:
#
#   1. the console was not running at all — start-poc.sh never started it
#   2. login was impossible — "Rate limiter unavailable"; management
#      authenticated to Redis as the disabled `default` ACL user
#   3. a permanent red "certificate not found" banner for optional HAProxy
#   4. most of the UI unstyled — the purged Tailwind build was 2 months stale,
#      83% of template classes missing
#   5. in Firefox the dial rendered as an unstyled OS slider (webkit-only CSS)
#   6. the dial presets silently did nothing — a client-side ±10 guard meant
#      the request never left the browser
#   7. the metrics curl command the tooling printed returned 401 (unquoted -H)
#   8. `ja4-admin.sh dial 50` died with a bash syntax error (Redis NOAUTH text
#      flowing into arithmetic)
#
# EVERY ONE passed the unit suite. Not one of them was a unit-level defect:
# they were startup, wiring, auth, build-freshness and browser-compat failures.
# Static tests cannot see them, and the point-fix guards added alongside each
# catch that specific regression, not the class.
#
# This asserts the JOURNEY. It needs a running stack, so it is not a unit test.
#   make start   &&   tests/integration/journeys/check_console_journey.sh

set -uo pipefail

BIND="${AGENT_BIND_IP:-127.0.0.1}"
PORT="${HOST_PORT_MANAGEMENT:-8090}"
BASE="http://${BIND}:${PORT}"
FAIL=0

ok()   { echo "  OK    $*"; }
bad()  { echo "  FAIL  $*"; FAIL=1; }

echo "=== J2: console usable at ${BASE} ==="

# 1. It is running at all. (Bug 1: nothing started it.)
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "${BASE}/login" || echo 000)
[ "$code" = "200" ] && ok "console is up (/login 200)" \
                    || { bad "console not reachable (/login -> $code)"; echo "  Is it started? scripts/start-poc.sh must include 'management'."; exit 1; }

# 2. Auth is enforced, not merely present.
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "${BASE}/")
[ "$code" = "401" ] && ok "unauthenticated dashboard is refused (401)" \
                    || bad "dashboard returned $code unauthenticated (expected 401)"

# 3. Redis actually works. (Bug 2: login was impossible because it did not.)
health=$(curl -s --max-time 8 "${BASE}/api/v1/health")
echo "$health" | grep -q '"redis":"ok"' \
  && ok "management can reach Redis" \
  || bad "health reports Redis not ok — login will fail closed: $health"

# 4. Every dashboard partial answers. A 5xx means it crashed before auth.
for p in situation infrastructure threat-posture triage-queue health-cards \
         dial bans audit intelligence intelligence-review attack-top \
         attack-fingerprint-table attack-mode-indicator; do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "${BASE}/api/v1/partials/${p}")
  case "$c" in
    401) ;;                                   # expected unauthenticated
    5*)  bad "partial ${p} crashed (${c})" ;;
    *)   bad "partial ${p} returned ${c} (expected 401)" ;;
  esac
done
ok "all dashboard partials respond without crashing"

# 5. The stylesheet is not stale. (Bug 4: 83% of classes missing.)
css=$(curl -s --max-time 8 "${BASE}/static/vendor/tailwind.css")
css_bytes=$(printf '%s' "$css" | wc -c)
[ "$css_bytes" -gt 30000 ] \
  && ok "tailwind build looks current (${css_bytes} bytes)" \
  || bad "tailwind.css is only ${css_bytes} bytes — likely a stale purged build; rebuild per management/static/VENDOR.md"

# 6. Firefox-critical CSS is present. (Bug 5: the dial was unstyled.)
custom=$(curl -s --max-time 8 "${BASE}/static/custom.css")
echo "$custom" | grep -q -- "-moz-range-thumb" \
  && ok "range slider has Firefox styling" \
  || bad "custom.css has no ::-moz-range-thumb — the dial renders unstyled in Firefox"
echo "$custom" | grep -q "scrollbar-color" \
  && ok "scrollbars have Firefox styling" \
  || bad "custom.css has no scrollbar-color — Firefox falls back to OS scrollbars"

# 7. The dial widget can actually reach the API. (Bug 6: it never sent.)
widget_src="management/templates/partials/dial_widget.html"
if [ -f "$widget_src" ]; then
  grep -q "steps.push" "$widget_src" \
    && ok "dial applies changes in steps (presets are reachable)" \
    || bad "dial widget does not step — presets >10 away will silently do nothing"
fi

# 8. The admin CLI can talk to Redis. (Bug 8: NOAUTH into arithmetic.)
if [ -x scripts/ja4-admin.sh ]; then
  out=$(./scripts/ja4-admin.sh dial 5 2>&1 || true)
  case "$out" in
    *"syntax error"*|*NOAUTH*) bad "ja4-admin cannot authenticate to Redis: $out" ;;
    *)                         ok  "ja4-admin reaches Redis" ;;
  esac
fi

echo
[ "$FAIL" -eq 0 ] && { echo "=== J2 PASSED — the console is usable ==="; exit 0; }
echo "=== J2 FAILED — an operator could not use the console ==="
exit 1
