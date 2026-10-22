#!/usr/bin/env bash
# Console journey — live-stack check for unauthenticated partial routes.
# Phase 824c: the list below is now complete for every registered
# /api/v1/partials/* route (authoritative map: management/tests/test_template_route_targets.py).
# It asserts real 401 behaviour (and no 5xx) against a running stack; a static
# gate cannot prove that.
#
# Usage: ./tests/integration/journeys/check_console_journey.sh [BASE_URL]
# Defaults: BASE_URL=http://localhost:8000
set -euo pipefail

BASE="${1:-http://localhost:8000}"

PARTIALS=(
  alerts-bar
  attack-fingerprint-table
  attack-top
  audit
  bans
  dial
  health-cards
  infrastructure
  intelligence
  intelligence-review
  list-table
  panel1-harm
  panel2-decisions
  panel3-liveness
  panel4-reliability
  panel5-changes
  situation
  threat-posture
  triage-queue
)

fail=0
for p in "${PARTIALS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/v1/partials/$p" || echo 000)
  if [ "$code" = "401" ]; then
    echo "OK   /api/v1/partials/$p -> $code"
  elif [ "$code" = "200" ]; then
    echo "FAIL /api/v1/partials/$p -> $code (expected 401 unauthenticated)"
    fail=1
  else
    echo "FAIL /api/v1/partials/$p -> $code (expected 401, got $code)"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "Console journey check failed"
  exit 1
fi

echo "All partial routes correctly require authentication"
