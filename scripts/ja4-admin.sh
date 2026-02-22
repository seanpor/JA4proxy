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

REDIS_CONTAINER="${REDIS_CONTAINER:-ja4proxy-redis}"
METRICS_URL="${METRICS_URL:-http://localhost:9090/metrics}"
ENV_FILE="${ENV_FILE:-.env}"

# ── Helpers ────────────────────────────────────────────────────────────────────
die() { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

load_redis_pass() {
    [ -f "$ENV_FILE" ] || die ".env not found — run ./start-poc.sh first."
    REDIS_PASS=$(grep '^REDIS_PASSWORD=' "$ENV_FILE" 2>/dev/null | cut -d= -f2)
    [ -n "$REDIS_PASS" ] || die "No REDIS_PASSWORD in .env"
}

redis_cmd() {
    docker exec "$REDIS_CONTAINER" redis-cli -a "$REDIS_PASS" --no-auth-warning "$@" 2>/dev/null
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
    echo -e "${CYAN}Monitoring${NC}"
    echo "  status                      Quick attack snapshot"
    echo "  top [N]                     Top N fingerprints by traffic (default: 10)"
    echo "  blocked                     List all active blocks/bans with remaining TTL"
    echo "  list-ja4                    Show current blacklist and whitelist"
    echo ""
    echo -e "${CYAN}JA4 Fingerprint Management${NC}  (no restart needed)"
    echo "  block-ja4   <FP>            Blacklist fingerprint → instant TCP RST, permanent"
    echo "  unblock-ja4 <FP>            Remove fingerprint from blacklist"
    echo "  whitelist-ja4   <FP>        Add to whitelist → bypass all rate limiting"
    echo "  unwhitelist-ja4 <FP>        Remove from whitelist"
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
    echo "  $0 top 5"
    echo "  $0 block-ja4  t13d190900_9dc949149365_97f8aa674fd9"
    echo "  $0 block-ip   203.0.113.42 7200"
    echo "  $0 unblock-ip 203.0.113.42"
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
    status)           cmd_status ;;
    top)              cmd_top "${1:-10}" ;;
    blocked)          cmd_blocked ;;
    block-ja4)        cmd_block_ja4 "${1:-}" ;;
    unblock-ja4)      cmd_unblock_ja4 "${1:-}" ;;
    whitelist-ja4)    cmd_whitelist_ja4 "${1:-}" ;;
    unwhitelist-ja4)  cmd_unwhitelist_ja4 "${1:-}" ;;
    list-ja4)         cmd_list_ja4 ;;
    block-ip)         cmd_block_ip "${1:-}" "${2:-3600}" ;;
    unblock-ip)       cmd_unblock_ip "${1:-}" ;;
    flush)            cmd_flush ;;
    help|--help|-h)   usage ;;
    *)
        echo -e "${RED}Unknown command: ${COMMAND}${NC}" >&2
        echo ""
        usage
        exit 1
        ;;
esac
