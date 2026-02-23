#!/usr/bin/env bash
# geoip-monitor.sh — Auto-block countries that are actively attacking
#
# Queries Prometheus for per-country blocked request rates.
# If a country exceeds the threshold AND is not in geoip:safe_countries,
# it is added to geoip:dynamic_blacklist (Redis) and takes effect immediately
# in the proxy (no restart needed).
#
# Usage:
#   ./scripts/geoip-monitor.sh              # Run once, print report
#   ./scripts/geoip-monitor.sh --watch      # Loop every 60s
#   ./scripts/geoip-monitor.sh --dry-run    # Show what would be blocked, don't act
#
# Cron example (every 5 minutes):
#   */5 * * * * /path/to/scripts/geoip-monitor.sh >> /var/log/geoip-monitor.log 2>&1
#
# Tuning (override via environment):
#   BLOCK_THRESHOLD=50     — blocked connections per 5-min window to trigger auto-block
#   BLOCK_PCT_THRESHOLD=80 — AND that country must have >80% of its connections blocked
#   WINDOW=5m              — Prometheus lookback window
#   PROMETHEUS_URL=...     — Prometheus base URL

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ENV_FILE="${ENV_FILE:-.env}"
REDIS_CONTAINER="${REDIS_CONTAINER:-ja4proxy-redis}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9091}"
BLOCK_THRESHOLD="${BLOCK_THRESHOLD:-50}"      # min blocked connections in window
BLOCK_PCT_THRESHOLD="${BLOCK_PCT_THRESHOLD:-70}" # min % of that country's traffic that is blocked
WINDOW="${WINDOW:-5m}"
DRY_RUN=false
WATCH=false

# ── Args ───────────────────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --watch)   WATCH=true ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────────────────
die()  { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }
info() { echo -e "${BLUE}▶ $*${NC}"; }
ok()   { echo -e "${GREEN}✓ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠ $*${NC}"; }

load_env() {
    [ -f "$ENV_FILE" ] || die ".env not found."
    REDIS_PASS=$(grep '^REDIS_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 || true)
    [ -n "$REDIS_PASS" ] || die "No REDIS_PASSWORD in .env"
}

redis_cmd() {
    docker exec "$REDIS_CONTAINER" redis-cli -a "$REDIS_PASS" --no-auth-warning "$@" 2>/dev/null
}

prom_query() {
    local query="$1"
    curl -sf --max-time 10 \
        "${PROMETHEUS_URL}/api/v1/query" \
        --data-urlencode "query=${query}" \
        2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for r in d.get('data',{}).get('result',[]):
        cc = r.get('metric',{}).get('source_country','')
        val = float(r.get('value',[0,0])[1])
        if cc:
            print(f'{cc}\t{val:.0f}')
except Exception:
    pass
" || true
}

# ── Core logic ─────────────────────────────────────────────────────────────────
run_once() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo ""
    echo -e "${BOLD}${CYAN}══ GeoIP Monitor — $timestamp ══${NC}"
    [ "$DRY_RUN" = true ] && echo -e "${YELLOW}  DRY-RUN MODE — no changes will be made${NC}"
    echo ""

    # Check Prometheus is available
    if ! curl -sf --max-time 5 "${PROMETHEUS_URL}/-/healthy" > /dev/null 2>&1; then
        warn "Prometheus not reachable at ${PROMETHEUS_URL}"
        return
    fi

    # Query 1: blocked connections per country in the last WINDOW
    info "Querying blocked traffic by country (last ${WINDOW})..."
    local blocked_by_cc
    blocked_by_cc=$(prom_query \
        "sum by (source_country) (increase(ja4_blocked_requests_total{source_country!=\"\"}[${WINDOW}]))")

    # Query 2: total connections per country in the last WINDOW
    local total_by_cc
    total_by_cc=$(prom_query \
        "sum by (source_country) (increase(ja4_requests_total{source_country!=\"\"}[${WINDOW}]))")

    if [ -z "$blocked_by_cc" ]; then
        ok "No blocked traffic by country in last ${WINDOW} — nothing to do."
        return
    fi

    echo ""
    printf "  ${BOLD}%-6s %-10s %-10s %-8s %-14s %s${NC}\n" \
        "CC" "Blocked" "Total" "Block%" "Status" "Action"
    echo "  ─────────────────────────────────────────────────────────────────"

    local auto_blocked=0
    local already_blocked=0
    local safe_skipped=0

    while IFS=$'\t' read -r cc blocked_count; do
        [[ -z "$cc" || "$cc" == "N/A" ]] && continue

        # Get total for this country
        local total_count=0
        total_count=$(echo "$total_by_cc" | awk -v cc="$cc" '$1==cc {print $2}' | head -1)
        total_count="${total_count:-0}"

        # Compute block percentage
        local block_pct=0
        if [ "${total_count%.*}" -gt 0 ] 2>/dev/null; then
            block_pct=$(echo "$total_count $blocked_count" | \
                awk '{printf "%.0f", ($1>0)?$2*100/$1:0}')
        fi

        # Check current status
        local in_static_bl in_dynamic_bl is_safe
        in_static_bl=$(redis_cmd SISMEMBER "ja4:static_blacklist_cc" "$cc" 2>/dev/null || echo 0)
        in_dynamic_bl=$(redis_cmd SISMEMBER "geoip:dynamic_blacklist" "$cc" 2>/dev/null || echo 0)
        is_safe=$(redis_cmd SISMEMBER "geoip:safe_countries" "$cc" 2>/dev/null || echo 0)

        local status action color
        if [ "$in_dynamic_bl" = "1" ]; then
            status="BLOCKED"; action="already blocked"; color="$RED"
            already_blocked=$((already_blocked + 1))
        elif [ "$is_safe" = "1" ]; then
            status="SAFE"; action="protected"; color="$GREEN"
            safe_skipped=$((safe_skipped + 1))
        elif [ "${blocked_count%.*}" -ge "$BLOCK_THRESHOLD" ] && \
             [ "${block_pct%.*}" -ge "$BLOCK_PCT_THRESHOLD" ]; then
            status="ATTACK"; color="$RED"
            if [ "$DRY_RUN" = true ]; then
                action="would auto-block"
            else
                action="AUTO-BLOCKED"
                # Add to dynamic blacklist with reason metadata
                local reason="auto:${blocked_count%.*}/${total_count%.*} blocked in ${WINDOW} (${block_pct}%)"
                redis_cmd HSET "geoip:block_reasons" "$cc" "$reason" > /dev/null
                redis_cmd SADD "geoip:dynamic_blacklist" "$cc" > /dev/null
                auto_blocked=$((auto_blocked + 1))
            fi
        else
            status="OK"; action="-"; color="$NC"
        fi

        printf "  ${color}%-6s %-10s %-10s %-8s %-14s %s${NC}\n" \
            "$cc" "${blocked_count%.*}" "${total_count%.*}" "${block_pct}%" "$status" "$action"

    done <<< "$blocked_by_cc"

    echo ""
    if [ "$DRY_RUN" = false ]; then
        [ "$auto_blocked" -gt 0 ] && \
            echo -e "  ${RED}Auto-blocked ${auto_blocked} country/countries.${NC}"
        [ "$already_blocked" -gt 0 ] && \
            echo -e "  ${YELLOW}${already_blocked} already blocked.${NC}"
        [ "$safe_skipped" -gt 0 ] && \
            echo -e "  ${GREEN}${safe_skipped} safe country/countries protected from auto-block.${NC}"
        [ "$auto_blocked" -gt 0 ] && \
            echo -e "  ${CYAN}→ Review with: ./scripts/ja4-admin.sh list-countries${NC}"
        [ "$auto_blocked" -gt 0 ] && \
            echo -e "  ${CYAN}→ Unblock with: ./scripts/ja4-admin.sh unblock-country <CC>${NC}"
    fi
    echo ""
}

# ── Main ───────────────────────────────────────────────────────────────────────
load_env

if [ "$WATCH" = true ]; then
    echo -e "${CYAN}Watching — checking every 60s. Ctrl-C to stop.${NC}"
    while true; do
        run_once
        sleep 60
    done
else
    run_once
fi
