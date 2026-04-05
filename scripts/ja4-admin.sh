#!/usr/bin/env bash
# ja4-admin — JA4proxy incident response CLI
#
# Wraps Redis and Prometheus operations into human-friendly commands.
# All changes take effect immediately — no proxy restart needed.
#
# Usage: ./scripts/ja4-admin.sh <command> [args]

set -euo pipefail

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

METRICS_URL="${METRICS_URL:-http://localhost:9090/metrics}"
ENV_FILE="${ENV_FILE:-.env}"

# ── Multi-agent support ────────────────────────────────────────────────────────
# Resolve which agent to target using this priority order:
#   1. Explicit --agent <name> flag (must be first two args)
#   2. .current-agent file (written by: make agent-up NAME=<agent>)
#   3. Default single-instance mode (uses .env)
#
# Example usage:
#   ./scripts/ja4-admin.sh status                  # uses .current-agent or default
#   ./scripts/ja4-admin.sh --agent claude status   # explicit override

COMPOSE_PROJECT_NAME=""
COMPOSE_FILE="docker-compose.poc.yml"

if [[ "${1:-}" == "--agent" ]]; then
    AGENT_NAME="${2:?--agent requires a name (gemini|claude|ollama|mistral)}"
    shift 2
    ENV_FILE=".env.${AGENT_NAME}"
    [ -f "$ENV_FILE" ] || { echo -e "${RED}✗ No $ENV_FILE found — run: ./scripts/agent-env.sh ${AGENT_NAME}${NC}" >&2; exit 1; }
    AGENT_BIND_IP=$(grep '^AGENT_BIND_IP=' "$ENV_FILE" | cut -d= -f2)
    [ -n "$AGENT_BIND_IP" ] || { echo -e "${RED}✗ AGENT_BIND_IP not set in $ENV_FILE${NC}" >&2; exit 1; }
    COMPOSE_PROJECT_NAME="ja4_${AGENT_NAME}"
    METRICS_URL="http://${AGENT_BIND_IP}:9090/metrics"
elif [[ -f ".current-agent" ]]; then
    AGENT_NAME="$(cat .current-agent)"
    ENV_FILE=".env.${AGENT_NAME}"
    if [[ -f "$ENV_FILE" ]]; then
        AGENT_BIND_IP=$(grep '^AGENT_BIND_IP=' "$ENV_FILE" | cut -d= -f2)
        COMPOSE_PROJECT_NAME="ja4_${AGENT_NAME}"
        METRICS_URL="http://${AGENT_BIND_IP}:9090/metrics"
    fi
fi

# If no project name from agent, let docker compose decide (usually folder name)
COMPOSE_CMD="docker compose -f ${COMPOSE_FILE}"
if [ -n "$COMPOSE_PROJECT_NAME" ]; then
    COMPOSE_CMD="${COMPOSE_CMD} --project-name ${COMPOSE_PROJECT_NAME}"
fi

# ── Helpers ────────────────────────────────────────────────────────────────────
die() { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

load_redis_pass() {
    [ -f "$ENV_FILE" ] || die ".env not found — run ./scripts/start-poc.sh first."
    REDIS_PASS=$(grep '^REDIS_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2)
    [ -n "$REDIS_PASS" ] || die "No REDIS_PASSWORD in .env"
}

redis_cmd() {
    $COMPOSE_CMD exec -T redis redis-cli -a "$REDIS_PASS" --no-auth-warning "$@" 2>/dev/null
}

redis_count() {
    # Atomically count keys matching a pattern
    redis_cmd EVAL "return #redis.call('keys',ARGV[1])" 0 "$1" 2>/dev/null || echo 0
}

validate_ja4() {
    local fp="$1"
    [[ "$fp" =~ ^[a-z0-9_]+$ ]] || die "Invalid fingerprint format — expected lowercase alphanumeric + underscores. Got: $fp"
}

validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "Invalid IP address: $ip"
}

# ── Commands ───────────────────────────────────────────────────────────────────

usage() {
    echo -e "${BOLD}ja4-admin — JA4proxy incident response CLI${NC}"
    echo ""
    echo "Usage: $0 <command> [args]"
    echo ""
    echo -e "${CYAN}Monitoring & Reporting${NC}"
    echo "  status                      Quick attack snapshot"
    echo "  top [N]                     Top N fingerprints by traffic (default: 10)"
    echo "  blocked                     List all active blocks/bans with remaining TTL"
    echo "  report                      Full blocking report (countries, CIDRs, fingerprints)"
    echo ""
    echo -e "${CYAN}JA4 Fingerprint Management${NC}  (no restart needed)"
    echo "  list-ja4                    Show current blacklist and whitelist"
    echo "  block-ja4   <FP>            Blacklist fingerprint → instant TCP RST, permanent"
    echo "  unblock-ja4 <FP>            Remove fingerprint from blacklist"
    echo "  whitelist-ja4   <FP>        Add to whitelist → bypass all rate limiting"
    echo "  unwhitelist-ja4 <FP>        Remove from whitelist"
    echo ""
    echo -e "${CYAN}ja4db.com Feed${NC}"
    echo "  fetch-db                    Fetch new malicious fingerprints from ja4db.com / FoxIO GitHub"
    echo "  list-pending                Show fingerprints awaiting approval"
    echo "  approve    <FP>             Approve fingerprint → move to blacklist"
    echo "  reject     <FP>             Reject fingerprint → discard"
    echo "  approve-all                 Approve ALL pending fingerprints (asks confirmation)"
    echo ""
    echo -e "${CYAN}Country Management${NC}  (no restart needed)"
    echo "  list-countries              Show dynamic blacklist, safe list, and Prometheus stats"
    echo "  block-country   <CC>        Add country to dynamic blacklist (CC = ISO code e.g. CN)"
    echo "  unblock-country <CC>        Remove country from dynamic blacklist"
    echo "  safe-country    <CC>        Protect country from auto-blocking by geoip-monitor"
    echo "  unsafe-country  <CC>        Remove country from safe list"
    echo ""
    echo -e "${CYAN}CIDR / Subnet Management${NC}  (no restart needed, 30s cache)"
    echo "  list-cidrs                  Show all active CIDR blocks"
    echo "  block-cidr   <CIDR>         Block a subnet (e.g. 203.0.113.0/24)"
    echo "  unblock-cidr <CIDR>         Remove a CIDR block"
    echo ""
    echo -e "${CYAN}IP Management${NC}  (no restart needed)"
    echo "  block-ip   <IP> [secs]      Hard-block an IP (default: 3600s)"
    echo "  unblock-ip <IP>             Remove all blocks/bans for an IP"
    echo ""
    echo -e "${CYAN}State Management${NC}"
    echo "  flush                       Clear transient state (keep whitelist/blacklist)"
    echo ""
    echo -e "${CYAN}Examples${NC}"
    echo "  $0 status"
    echo "  $0 fetch-db && $0 list-pending"
    echo "  $0 block-country CN"
    echo "  $0 block-cidr 203.0.113.0/24"
    echo "  $0 block-ja4  t13d190900_9dc949149365_97f8aa674fd9"
    echo "  $0 block-ip   203.0.113.42 7200"
    echo "  $0 report"
}

cmd_status() {
    echo -e "${BOLD}${CYAN}══ JA4proxy Security Snapshot ══${NC}"
    echo ""

    BANS_TEMP=$(redis_count "banned:temporary:*")
    BANS_PERM=$(redis_count "banned:permanent:*")
    BLOCKS_T=$(redis_count "blocked:tarpit:*")
    BLOCKS_B=$(redis_count "blocked:block:*")
    BLACKLIST=$(redis_cmd SCARD "ja4:blacklist" 2>/dev/null || echo 0)
    WHITELIST=$(redis_cmd SCARD "ja4:whitelist" 2>/dev/null || echo 0)

    echo -e "${BOLD}Active state (Redis):${NC}"
    printf "  Temporary bans:     ${YELLOW}%s${NC}\n" "$BANS_TEMP"
    printf "  Permanent bans:     ${RED}%s${NC}\n"    "$BANS_PERM"
    printf "  Tarpit blocks:      ${YELLOW}%s${NC}\n" "$BLOCKS_T"
    printf "  Hard blocks:        ${RED}%s${NC}\n"    "$BLOCKS_B"
    printf "  Blacklisted FPs:    ${RED}%s${NC}  (instant TCP RST)\n"      "$BLACKLIST"
    printf "  Whitelisted FPs:    ${GREEN}%s${NC}  (bypass rate limiting)\n" "$WHITELIST"
    echo ""

    # Prometheus totals
    if curl -sf "$METRICS_URL" > /tmp/ja4_admin_snap.txt 2>/dev/null; then
        TOTAL=$(awk '/^ja4_requests_total\{/ {val=$NF; gsub(/^[^0-9.]+/,"",val); s+=val} END{printf "%.0f",s}' /tmp/ja4_admin_snap.txt)
        ALLOWED=$(awk '/^ja4_requests_total\{.*action="allowed"/ {val=$NF; gsub(/^[^0-9.]+/,"",val); s+=val} END{printf "%.0f",s}' /tmp/ja4_admin_snap.txt)
        BLOCKED=$(awk '/^ja4_blocked_requests_total\{/ {val=$NF; gsub(/^[^0-9.]+/,"",val); s+=val} END{printf "%.0f",s}' /tmp/ja4_admin_snap.txt)
        rm -f /tmp/ja4_admin_snap.txt

        if [ "${TOTAL:-0}" -gt 0 ] 2>/dev/null; then
            BLOCK_PCT=$(echo "$TOTAL $BLOCKED" | awk '{printf "%.1f", ($1>0)?$2*100/$1:0}')
            echo -e "${BOLD}Cumulative (since last restart):${NC}"
            printf "  Total connections:  %s\n" "$TOTAL"
            printf "  Allowed:            ${GREEN}%s${NC}\n"         "$ALLOWED"
            printf "  Blocked:            ${RED}%s${NC}  (%s%%)\n"  "$BLOCKED" "$BLOCK_PCT"
        fi
    else
        echo -e "  ${YELLOW}(Prometheus not reachable — is the proxy running? http://localhost:9090)${NC}"
    fi

    echo ""
    echo -e "  ${CYAN}→ $0 top        — fingerprint breakdown${NC}"
    echo -e "  ${CYAN}→ $0 blocked    — active bans with TTL${NC}"
}

cmd_top() {
    local N="${1:-10}"
    echo -e "${BOLD}${CYAN}══ Top ${N} Fingerprints ══${NC}"
    echo ""

    if ! curl -sf "$METRICS_URL" > /tmp/ja4_admin_top.txt 2>/dev/null; then
        echo -e "${YELLOW}  Metrics not available. Proxy may not be running.${NC}"
        echo -e "  Falling back to Redis rate keys..."
        echo ""
        redis_cmd KEYS "rate:ja4:*" 2>/dev/null | head -"$N" | while IFS= read -r key; do
            FP="${key#rate:ja4:}"
            echo "  $FP"
        done
        return
    fi

    printf "  ${BOLD}%-32s %-12s %-15s %s${NC}\n" "Name" "Action" "Count" "Fingerprint"
    echo "  ───────────────────────────────────────────────────────────────────────────"

    grep "^ja4_requests_total{" /tmp/ja4_admin_top.txt 2>/dev/null \
    | awk -F'"' '
        {
            fp=""; name=""; action=""; val=$NF
            gsub(/^[^0-9.]+/,"",val)
            for(i=2;i<=NF;i+=2){
                prev=$(i-1)
                if (prev ~ /fingerprint=/ && prev !~ /fingerprint_name=/) fp=$i
                if (prev ~ /fingerprint_name=/) name=$i
                if (prev ~ /action=/) action=$i
            }
            key = fp SUBSEP name SUBSEP action
            total[key] += val
        }
        END {
            for (k in total) {
                n = split(k, p, SUBSEP)
                printf "%s\t%s\t%s\t%.0f\n", p[2], p[3], p[1], total[k]
            }
        }
    ' \
    | sort -t$'\t' -k4 -rn \
    | head -"$N" \
    | while IFS=$'\t' read -r name action fp count; do
        if [[ "$action" == "blocked" ]] || [[ "$action" == "banned" ]]; then
            printf "  ${RED}%-32s %-12s %-15s %s${NC}\n" "$name" "$action" "$count" "$fp"
        elif [[ "$action" == "allowed" ]]; then
            printf "  ${GREEN}%-32s %-12s %-15s %s${NC}\n" "$name" "$action" "$count" "$fp"
        else
            printf "  ${YELLOW}%-32s %-12s %-15s %s${NC}\n" "$name" "$action" "$count" "$fp"
        fi
      done

    rm -f /tmp/ja4_admin_top.txt
    echo ""
    echo -e "  ${CYAN}→ Copy a fingerprint above and run: $0 block-ja4 <FP>${NC}"
}

cmd_blocked() {
    echo -e "${BOLD}${CYAN}══ Active Blocks & Bans ══${NC}"
    echo ""
    local found=0

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        found=1
        TTL=$(redis_cmd TTL "$key"); ENTITY="${key#blocked:block:}"
        printf "  ${RED}HARD-BLOCK${NC}  %-40s  expires in %ss\n" "$ENTITY" "$TTL"
    done < <(redis_cmd KEYS "blocked:block:*" 2>/dev/null)

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        found=1
        TTL=$(redis_cmd TTL "$key"); ENTITY="${key#blocked:tarpit:}"
        printf "  ${YELLOW}TARPIT${NC}      %-40s  expires in %ss\n" "$ENTITY" "$TTL"
    done < <(redis_cmd KEYS "blocked:tarpit:*" 2>/dev/null)

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        found=1
        TTL=$(redis_cmd TTL "$key"); ENTITY="${key#banned:temporary:}"
        printf "  ${RED}BAN${NC}         %-40s  expires in %ss\n" "$ENTITY" "$TTL"
    done < <(redis_cmd KEYS "banned:temporary:*" 2>/dev/null)

    while IFS= read -r key; do
        [[ -z "$key" ]] && continue
        found=1
        ENTITY="${key#banned:permanent:}"
        printf "  ${BOLD}${RED}PERMANENT${NC}   %-40s  no expiry\n" "$ENTITY"
    done < <(redis_cmd KEYS "banned:permanent:*" 2>/dev/null)

    if [[ "$found" -eq 0 ]]; then
        echo -e "  ${GREEN}No active blocks or bans.${NC}"
    fi
    echo ""
}

cmd_block_ja4() {
    local FP="${1:-}"
    [[ -n "$FP" ]] || die "Usage: $0 block-ja4 <fingerprint>"
    validate_ja4 "$FP"
    redis_cmd SADD "ja4:blacklist" "$FP" > /dev/null
    echo -e "${RED}✓ Blacklisted: ${FP}${NC}"
    echo -e "  Connections with this fingerprint now receive instant TCP RST."
    echo -e "  Effect is immediate — no restart needed."
    echo -e "  Persists until removed with: $0 unblock-ja4 ${FP}"
    echo -e "  Add permanently to config/proxy.yml blacklist section."
}

cmd_unblock_ja4() {
    local FP="${1:-}"
    [[ -n "$FP" ]] || die "Usage: $0 unblock-ja4 <fingerprint>"
    local REMOVED
    REMOVED=$(redis_cmd SREM "ja4:blacklist" "$FP")
    if [[ "$REMOVED" == "1" ]]; then
        echo -e "${GREEN}✓ Removed from blacklist: ${FP}${NC}"
    else
        echo -e "${YELLOW}Not in blacklist: ${FP}${NC}"
    fi
}

cmd_whitelist_ja4() {
    local FP="${1:-}"
    [[ -n "$FP" ]] || die "Usage: $0 whitelist-ja4 <fingerprint>"
    validate_ja4 "$FP"
    redis_cmd SADD "ja4:whitelist" "$FP" > /dev/null
    echo -e "${GREEN}✓ Whitelisted: ${FP}${NC}"
    echo -e "  Connections with this fingerprint bypass all rate limiting."
}

cmd_unwhitelist_ja4() {
    local FP="${1:-}"
    [[ -n "$FP" ]] || die "Usage: $0 unwhitelist-ja4 <fingerprint>"
    local REMOVED
    REMOVED=$(redis_cmd SREM "ja4:whitelist" "$FP")
    if [[ "$REMOVED" == "1" ]]; then
        echo -e "${GREEN}✓ Removed from whitelist: ${FP}${NC}"
    else
        echo -e "${YELLOW}Not in whitelist: ${FP}${NC}"
    fi
}

cmd_list_ja4() {
    echo -e "${BOLD}${CYAN}══ JA4 Fingerprint Lists ══${NC}"
    echo ""
    echo -e "${RED}${BOLD}Blacklist (instant TCP RST):${NC}"
    local bl
    bl=$(redis_cmd SMEMBERS "ja4:blacklist" 2>/dev/null)
    if [[ -z "$bl" ]]; then echo "  (empty)"; else echo "$bl" | sed 's/^/  /'; fi
    echo ""
    echo -e "${GREEN}${BOLD}Whitelist (bypass rate limiting):${NC}"
    local wl
    wl=$(redis_cmd SMEMBERS "ja4:whitelist" 2>/dev/null)
    if [[ -z "$wl" ]]; then echo "  (empty)"; else echo "$wl" | sed 's/^/  /'; fi
    echo ""
    echo -e "  ${CYAN}Lookup fingerprints at: https://ja4db.com/${NC}"
}

cmd_block_ip() {
    local IP="${1:-}" SECS="${2:-3600}"
    [[ -n "$IP" ]] || die "Usage: $0 block-ip <ip> [seconds]"
    validate_ip "$IP"
    [[ "$SECS" =~ ^[0-9]+$ ]] || die "Duration must be a positive integer"
    redis_cmd SETEX "blocked:block:${IP}" "$SECS" "admin-manual-block" > /dev/null
    echo -e "${RED}✓ Hard-blocked IP: ${IP} for ${SECS}s${NC}"
    echo -e "  Connections from this IP will be dropped immediately."
    echo -e "  To remove early: $0 unblock-ip ${IP}"
}

cmd_unblock_ip() {
    local IP="${1:-}"
    [[ -n "$IP" ]] || die "Usage: $0 unblock-ip <ip>"
    validate_ip "$IP"
    local removed=0
    for KEY in "blocked:block:${IP}" "blocked:tarpit:${IP}" "banned:temporary:${IP}" "banned:permanent:${IP}"; do
        if [[ "$(redis_cmd DEL "$KEY")" == "1" ]]; then
            removed=$((removed + 1))
            TYPE="${KEY%%:$IP}"
            echo -e "${GREEN}✓ Removed ${TYPE} for ${IP}${NC}"
        fi
    done
    [[ "$removed" -eq 0 ]] && echo -e "${YELLOW}No active blocks found for IP: ${IP}${NC}"
}

# ── ja4db feed commands ────────────────────────────────────────────────────────

cmd_fetch_db() {
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    local fetch_script="${script_dir}/fetch-ja4db.sh"
    [[ -x "$fetch_script" ]] || die "fetch-ja4db.sh not found or not executable: $fetch_script"
    exec "$fetch_script"
}

cmd_list_pending() {
    echo -e "${BOLD}${CYAN}══ Pending Fingerprints (awaiting approval) ══${NC}"
    echo ""
    local raw
    raw=$(redis_cmd HGETALL "ja4:pending" 2>/dev/null)
    if [[ -z "$raw" ]]; then
        echo -e "  ${GREEN}No pending fingerprints.${NC}"
        echo -e "  Run '$0 fetch-db' to fetch new fingerprints from ja4db."
        echo ""; return
    fi
    printf "  ${BOLD}%-44s %-22s %-12s %s${NC}\n" "Fingerprint" "Name" "Category" "Source"
    echo "  ──────────────────────────────────────────────────────────────────────────────────────────────"
    # HGETALL returns alternating field/value lines
    local fp=""
    while IFS= read -r line; do
        if [[ -z "$fp" ]]; then
            fp="$line"
        else
            local name category source
            name=$(echo "$line"     | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('name','?'))" 2>/dev/null || echo "?")
            category=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('category','?'))" 2>/dev/null || echo "?")
            source=$(echo "$line"   | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('source','?'))" 2>/dev/null || echo "?")
            printf "  ${RED}%-44s${NC} %-22s %-12s %s\n" "$fp" "${name:0:20}" "${category:0:12}" "$source"
            fp=""
        fi
    done <<< "$raw"
    echo ""
    echo -e "  ${CYAN}→ $0 approve <fingerprint>   or   $0 approve-all${NC}"
    echo ""
}

cmd_approve() {
    local FP="${1:-}"
    [[ -n "$FP" ]] || die "Usage: $0 approve <fingerprint>"
    validate_ja4 "$FP"
    local meta
    meta=$(redis_cmd HGET "ja4:pending" "$FP" 2>/dev/null)
    [[ -n "$meta" ]] || die "Fingerprint not in pending queue: $FP"
    redis_cmd SADD "ja4:blacklist" "$FP" > /dev/null
    redis_cmd HDEL "ja4:pending" "$FP" > /dev/null
    local name
    name=$(echo "$meta" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('name','?'))" 2>/dev/null || echo "?")
    echo -e "${RED}✓ Approved and blacklisted: ${FP}${NC}  (${name})"
    echo -e "  Add to config/proxy.yml blacklist section to survive container restart."
}

cmd_reject() {
    local FP="${1:-}"
    [[ -n "$FP" ]] || die "Usage: $0 reject <fingerprint>"
    local removed
    removed=$(redis_cmd HDEL "ja4:pending" "$FP")
    if [[ "$removed" == "1" ]]; then
        echo -e "${GREEN}✓ Rejected and discarded: ${FP}${NC}"
    else
        echo -e "${YELLOW}Fingerprint not in pending queue: ${FP}${NC}"
    fi
}

cmd_approve_all() {
    local count
    count=$(redis_cmd HLEN "ja4:pending" 2>/dev/null || echo 0)
    [[ "${count:-0}" -gt 0 ]] || { echo -e "${GREEN}No pending fingerprints.${NC}"; return; }

    echo -e "${YELLOW}${BOLD}About to approve ALL ${count} pending fingerprints into the blacklist.${NC}"
    echo -e "${YELLOW}Review them first with: $0 list-pending${NC}"
    echo ""
    read -r -p "Type YES to confirm: " confirm
    [[ "$confirm" == "YES" ]] || { echo "Cancelled."; return; }

    local approved=0
    # Process HGETALL pairs
    local fp=""
    while IFS= read -r line; do
        if [[ -z "$fp" ]]; then
            fp="$line"
        else
            redis_cmd SADD "ja4:blacklist" "$fp" > /dev/null
            redis_cmd HDEL "ja4:pending" "$fp" > /dev/null
            echo -e "  ${RED}✓${NC} $fp"
            approved=$((approved + 1))
            fp=""
        fi
    done < <(redis_cmd HGETALL "ja4:pending" 2>/dev/null)

    echo ""
    echo -e "${RED}✓ Approved ${approved} fingerprints.${NC}"
    echo -e "  Add them to config/proxy.yml blacklist to survive container restart."
}

# ── Country management ─────────────────────────────────────────────────────────

validate_cc() {
    local cc="${1:-}"
    [[ "$cc" =~ ^[A-Z]{2}$ ]] || die "Invalid country code (expected 2-letter ISO e.g. CN). Got: $cc"
}

cmd_list_countries() {
    echo -e "${BOLD}${CYAN}══ Country Blocking Status ══${NC}"
    echo ""

    echo -e "${RED}${BOLD}Dynamic blacklist (auto-blocked or admin-added):${NC}"
    local dbl
    dbl=$(redis_cmd SMEMBERS "geoip:dynamic_blacklist" 2>/dev/null)
    if [[ -z "$dbl" ]]; then echo "  (empty)"; else
        while IFS= read -r cc; do
            local reason
            reason=$(redis_cmd HGET "geoip:block_reasons" "$cc" 2>/dev/null || echo "-")
            printf "  ${RED}%-6s${NC}  %s\n" "$cc" "$reason"
        done <<< "$dbl"
    fi
    echo ""

    echo -e "${GREEN}${BOLD}Safe countries (never auto-blocked):${NC}"
    local safe
    safe=$(redis_cmd SMEMBERS "geoip:safe_countries" 2>/dev/null)
    if [[ -z "$safe" ]]; then echo "  (empty)"; else
        echo "$safe" | tr ' ' '\n' | sort | xargs printf "  %s\n"
    fi
    echo ""

    # Prometheus country breakdown if available
    if curl -sf "${METRICS_URL}" > /tmp/ja4_cc_snap.txt 2>/dev/null; then
        echo -e "${BOLD}Traffic by country (last run):${NC}"
        printf "  %-6s %-10s %-10s %s\n" "CC" "Allowed" "Blocked" "Block%"
        echo "  ──────────────────────────────────────────"
        awk '/^ja4_requests_total\{/ {
            match($0, /source_country="([^"]*)"/, cc)
            match($0, /action="([^"]*)"/, ac)
            val=$NF; gsub(/^[^0-9.]+/,"",val)
            c=cc[1]; a=ac[1]
            if(c!="") { total[c]+=val; if(a=="blocked"||a=="banned") blocked[c]+=val }
        }
        END { for(c in total) printf "%s\t%.0f\t%.0f\n", c, total[c]-blocked[c], blocked[c] }
        ' /tmp/ja4_cc_snap.txt \
        | sort -t$'\t' -k3 -rn \
        | head -15 \
        | while IFS=$'\t' read -r cc allowed blk; do
            local tot=$((allowed + blk))
            local pct=0
            [[ "$tot" -gt 0 ]] && pct=$((blk * 100 / tot))
            local col="$NC"
            [[ "$pct" -ge 80 ]] && col="$RED"
            [[ "$pct" -ge 50 && "$pct" -lt 80 ]] && col="$YELLOW"
            printf "  ${col}%-6s %-10s %-10s %s%%${NC}\n" "$cc" "$allowed" "$blk" "$pct"
          done
        rm -f /tmp/ja4_cc_snap.txt
    fi
    echo ""
}

cmd_block_country() {
    local CC="${1:-}"
    [[ -n "$CC" ]] || die "Usage: $0 block-country <CC>"
    CC="${CC^^}"  # uppercase
    validate_cc "$CC"
    # Refuse if in safe countries
    local is_safe
    is_safe=$(redis_cmd SISMEMBER "geoip:safe_countries" "$CC" 2>/dev/null || echo 0)
    [[ "$is_safe" == "1" ]] && die "${CC} is in the safe countries list — remove it first with: $0 unsafe-country ${CC}"
    redis_cmd SADD "geoip:dynamic_blacklist" "$CC" > /dev/null
    redis_cmd HSET "geoip:block_reasons" "$CC" "admin-manual $(date '+%Y-%m-%d %H:%M')" > /dev/null
    echo -e "${RED}✓ Country blocked: ${CC}${NC}"
    echo -e "  All connections from ${CC} will be dropped (takes effect immediately)."
    echo -e "  To reverse: $0 unblock-country ${CC}"
}

cmd_unblock_country() {
    local CC="${1:-}"
    [[ -n "$CC" ]] || die "Usage: $0 unblock-country <CC>"
    CC="${CC^^}"
    validate_cc "$CC"
    local removed
    removed=$(redis_cmd SREM "geoip:dynamic_blacklist" "$CC")
    redis_cmd HDEL "geoip:block_reasons" "$CC" > /dev/null
    if [[ "$removed" == "1" ]]; then
        echo -e "${GREEN}✓ Unblocked country: ${CC}${NC}"
    else
        echo -e "${YELLOW}Country was not in dynamic blacklist: ${CC}${NC}"
    fi
}

cmd_safe_country() {
    local CC="${1:-}"
    [[ -n "$CC" ]] || die "Usage: $0 safe-country <CC>"
    CC="${CC^^}"
    validate_cc "$CC"
    redis_cmd SADD "geoip:safe_countries" "$CC" > /dev/null
    echo -e "${GREEN}✓ Protected from auto-blocking: ${CC}${NC}"
}

cmd_unsafe_country() {
    local CC="${1:-}"
    [[ -n "$CC" ]] || die "Usage: $0 unsafe-country <CC>"
    CC="${CC^^}"
    validate_cc "$CC"
    local removed
    removed=$(redis_cmd SREM "geoip:safe_countries" "$CC")
    if [[ "$removed" == "1" ]]; then
        echo -e "${YELLOW}✓ Removed ${CC} from safe list — it can now be auto-blocked${NC}"
    else
        echo -e "${YELLOW}Country was not in safe list: ${CC}${NC}"
    fi
}

# ── CIDR management ────────────────────────────────────────────────────────────

validate_cidr() {
    local cidr="${1:-}"
    python3 -c "import ipaddress; ipaddress.ip_network('${cidr}', strict=False)" 2>/dev/null \
        || die "Invalid CIDR: ${cidr}  (example: 203.0.113.0/24)"
}

cmd_list_cidrs() {
    echo -e "${BOLD}${CYAN}══ Active CIDR Blocks ══${NC}"
    echo ""
    local cidrs
    cidrs=$(redis_cmd SMEMBERS "geoip:blocked_cidrs" 2>/dev/null)
    if [[ -z "$cidrs" ]]; then
        echo -e "  ${GREEN}No CIDR blocks active.${NC}"
    else
        printf "  ${BOLD}%-20s  %s${NC}\n" "CIDR" "Reason"
        echo "  ─────────────────────────────────────────"
        while IFS= read -r cidr; do
            local reason
            reason=$(redis_cmd HGET "geoip:cidr_reasons" "$cidr" 2>/dev/null || echo "-")
            printf "  ${RED}%-20s${NC}  %s\n" "$cidr" "$reason"
        done <<< "$cidrs"
    fi
    echo ""
}

cmd_block_cidr() {
    local CIDR="${1:-}"
    [[ -n "$CIDR" ]] || die "Usage: $0 block-cidr <CIDR>  (e.g. 203.0.113.0/24)"
    validate_cidr "$CIDR"
    redis_cmd SADD "geoip:blocked_cidrs" "$CIDR" > /dev/null
    redis_cmd HSET "geoip:cidr_reasons" "$CIDR" "admin-manual $(date '+%Y-%m-%d %H:%M')" > /dev/null
    echo -e "${RED}✓ CIDR blocked: ${CIDR}${NC}"
    echo -e "  Proxy picks up the change within 30 seconds (CIDR cache TTL)."
    echo -e "  To remove: $0 unblock-cidr ${CIDR}"
}

cmd_unblock_cidr() {
    local CIDR="${1:-}"
    [[ -n "$CIDR" ]] || die "Usage: $0 unblock-cidr <CIDR>"
    local removed
    removed=$(redis_cmd SREM "geoip:blocked_cidrs" "$CIDR")
    redis_cmd HDEL "geoip:cidr_reasons" "$CIDR" > /dev/null
    if [[ "$removed" == "1" ]]; then
        echo -e "${GREEN}✓ Removed CIDR block: ${CIDR}${NC}"
        echo -e "  Proxy picks up the change within 30 seconds."
    else
        echo -e "${YELLOW}CIDR was not blocked: ${CIDR}${NC}"
    fi
}

# ── Comprehensive report ───────────────────────────────────────────────────────

cmd_report() {
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  JA4proxy Security Report — ${ts}${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
    echo ""

    # ── Fingerprint stats ──
    echo -e "${BOLD}JA4 Fingerprints:${NC}"
    printf "  Blacklisted (instant RST):   %s\n" "$(redis_cmd SCARD 'ja4:blacklist' 2>/dev/null || echo '?')"
    printf "  Whitelisted (bypass rate):   %s\n" "$(redis_cmd SCARD 'ja4:whitelist' 2>/dev/null || echo '?')"
    printf "  Pending review:              %s\n" "$(redis_cmd HLEN  'ja4:pending'   2>/dev/null || echo '?')"
    echo ""

    # ── Country stats ──
    echo -e "${BOLD}Country Blocks:${NC}"
    local dbl_count safe_count
    dbl_count=$(redis_cmd SCARD "geoip:dynamic_blacklist" 2>/dev/null || echo 0)
    safe_count=$(redis_cmd SCARD "geoip:safe_countries"   2>/dev/null || echo 0)
    printf "  Dynamic blacklist:           %s countries\n" "$dbl_count"
    printf "  Safe (never auto-blocked):   %s countries\n" "$safe_count"
    if [[ "${dbl_count:-0}" -gt 0 ]]; then
        echo -e "  ${RED}Blocked countries:${NC}"
        while IFS= read -r cc; do
            local reason
            reason=$(redis_cmd HGET "geoip:block_reasons" "$cc" 2>/dev/null || echo "-")
            printf "    ${RED}%-6s${NC}  %s\n" "$cc" "$reason"
        done < <(redis_cmd SMEMBERS "geoip:dynamic_blacklist" 2>/dev/null)
    fi
    echo ""

    # ── CIDR stats ──
    echo -e "${BOLD}CIDR Blocks:${NC}"
    local cidr_count
    cidr_count=$(redis_cmd SCARD "geoip:blocked_cidrs" 2>/dev/null || echo 0)
    printf "  Active CIDR blocks:          %s\n" "$cidr_count"
    if [[ "${cidr_count:-0}" -gt 0 ]]; then
        while IFS= read -r cidr; do
            local reason
            reason=$(redis_cmd HGET "geoip:cidr_reasons" "$cidr" 2>/dev/null || echo "-")
            printf "    ${RED}%-22s${NC}  %s\n" "$cidr" "$reason"
        done < <(redis_cmd SMEMBERS "geoip:blocked_cidrs" 2>/dev/null)
    fi
    echo ""

    # ── Rate-limit enforcement ──
    echo -e "${BOLD}Rate-Limit Enforcement (active):${NC}"
    printf "  Temporary bans:  %s\n" "$(redis_count 'banned:temporary:*')"
    printf "  Permanent bans:  %s\n" "$(redis_count 'banned:permanent:*')"
    printf "  Tarpit blocks:   %s\n" "$(redis_count 'blocked:tarpit:*')"
    printf "  Hard blocks:     %s\n" "$(redis_count 'blocked:block:*')"
    printf "  Repeat offenders tracked: %s\n" "$(redis_count 'repeat_block:*')"
    echo ""

    # ── Prometheus summary ──
    if curl -sf "${METRICS_URL}" > /tmp/ja4_report_snap.txt 2>/dev/null; then
        echo -e "${BOLD}Traffic Summary (cumulative):${NC}"
        TOTAL=$(awk '/^ja4_requests_total\{/ {val=$NF; gsub(/^[^0-9.]+/,"",val); s+=val} END{printf "%.0f",s}' /tmp/ja4_report_snap.txt)
        ALLOWED=$(awk '/^ja4_requests_total\{.*action="allowed"/ {val=$NF; gsub(/^[^0-9.]+/,"",val); s+=val} END{printf "%.0f",s}' /tmp/ja4_report_snap.txt)
        BLOCKED=$(awk '/^ja4_blocked_requests_total\{/ {val=$NF; gsub(/^[^0-9.]+/,"",val); s+=val} END{printf "%.0f",s}' /tmp/ja4_report_snap.txt)
        printf "  Total:    %s\n  Allowed:  %s\n  Blocked:  %s\n" "$TOTAL" "$ALLOWED" "$BLOCKED"
        echo ""
        echo -e "${BOLD}Blocked by mechanism:${NC}"
        awk '/^ja4_blocked_requests_total\{/ {
            match($0, /reason="([^"]*)"/, r)
            val=$NF; gsub(/^[^0-9.]+/,"",val)
            total[r[1]]+=val
        } END { for(k in total) printf "  %-30s %.0f\n", k, total[k] }
        ' /tmp/ja4_report_snap.txt | sort -k2 -rn
        echo ""
        echo -e "${BOLD}Top blocked countries:${NC}"
        awk '/^ja4_blocked_requests_total\{/ {
            match($0, /source_country="([^"]*)"/, cc)
            val=$NF; gsub(/^[^0-9.]+/,"",val)
            if(cc[1]!="") total[cc[1]]+=val
        } END { for(k in total) printf "  %-6s %.0f\n", k, total[k] }
        ' /tmp/ja4_report_snap.txt | sort -k2 -rn | head -10
        rm -f /tmp/ja4_report_snap.txt
    fi
    echo ""
}

cmd_flush() {
    echo -e "${YELLOW}Flushing all transient security state...${NC}"
    COUNT=$(redis_cmd EVAL \
        "local n=0; for _,p in ipairs({'rate:*','banned:*','blocked:*','suspicious:*','enforcement:*','audit:*','repeat_block:*'}) do for _,k in ipairs(redis.call('keys',p)) do redis.call('del',k); n=n+1 end end; return n" \
        0 2>/dev/null || echo "?")
    echo -e "${GREEN}✓ Cleared ${COUNT} keys (whitelist/blacklist preserved)${NC}"
}

# ── Main dispatch ──────────────────────────────────────────────────────────────
load_redis_pass

COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
    status)             cmd_status ;;
    top)                cmd_top "${1:-10}" ;;
    blocked)            cmd_blocked ;;
    report)             cmd_report ;;
    list-ja4)           cmd_list_ja4 ;;
    block-ja4)          cmd_block_ja4 "${1:-}" ;;
    unblock-ja4)        cmd_unblock_ja4 "${1:-}" ;;
    whitelist-ja4)      cmd_whitelist_ja4 "${1:-}" ;;
    unwhitelist-ja4)    cmd_unwhitelist_ja4 "${1:-}" ;;
    fetch-db)           cmd_fetch_db ;;
    list-pending)       cmd_list_pending ;;
    approve)            cmd_approve "${1:-}" ;;
    reject)             cmd_reject "${1:-}" ;;
    approve-all)        cmd_approve_all ;;
    list-countries)     cmd_list_countries ;;
    block-country)      cmd_block_country "${1:-}" ;;
    unblock-country)    cmd_unblock_country "${1:-}" ;;
    safe-country)       cmd_safe_country "${1:-}" ;;
    unsafe-country)     cmd_unsafe_country "${1:-}" ;;
    list-cidrs)         cmd_list_cidrs ;;
    block-cidr)         cmd_block_cidr "${1:-}" ;;
    unblock-cidr)       cmd_unblock_cidr "${1:-}" ;;
    block-ip)           cmd_block_ip "${1:-}" "${2:-3600}" ;;
    unblock-ip)         cmd_unblock_ip "${1:-}" ;;
    flush)              cmd_flush ;;
    help|--help|-h)     usage ;;
    *)
        echo -e "${RED}Unknown command: ${COMMAND}${NC}" >&2
        echo ""
        usage
        exit 1
        ;;
esac
