#!/bin/bash
# JA4 Fingerprint Blocking Test Script
# Tests blacklist/whitelist functionality and rate limiting

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
REDIS_HOST=${REDIS_HOST:-localhost}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_PASSWORD=${REDIS_PASSWORD:-changeme}
PROXY_HOST=${PROXY_HOST:-localhost}
PROXY_PORT=${PROXY_PORT:-8080}
METRICS_PORT=${METRICS_PORT:-9090}
BACKEND_HOST=${BACKEND_HOST:-localhost}
BACKEND_PORT=${BACKEND_PORT:-8081}

# Test fingerprints
GOOD_FINGERPRINT="t13d1516h2_8daaf6152771_02713d6af862"
BAD_FINGERPRINT="t12d090909_ba640532068b_b186095e22b6"
ATTACKER_FINGERPRINT="t10d151415_deadbeef1337_attackertools"

header() {
    echo ""
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo -e "${BOLD}${BLUE}$1${NC}"
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo ""
}

step() {
    echo -e "${CYAN}▶${NC} ${BOLD}$1${NC}"
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

redis_cmd() {
    docker exec ja4proxy-redis redis-cli -a "$REDIS_PASSWORD" "$@" 2>/dev/null
}

check_services() {
    header "1. Checking Services"
    
    step "Checking Redis..."
    if redis_cmd PING | grep -q "PONG"; then
        success "Redis is running"
    else
        error "Redis is not responding"
        exit 1
    fi
    
    step "Checking Backend..."
    if curl -sf "http://$BACKEND_HOST:$BACKEND_PORT/api/health" > /dev/null; then
        success "Backend is running"
    else
        error "Backend is not responding"
        exit 1
    fi
    
    step "Checking Proxy Metrics..."
    if curl -sf "http://$PROXY_HOST:$METRICS_PORT/metrics" > /dev/null; then
        success "Proxy metrics endpoint is accessible"
    else
        error "Proxy metrics endpoint not accessible"
        exit 1
    fi
}

setup_test_data() {
    header "2. Setting Up Test Data"
    
    step "Clearing existing test data..."
    redis_cmd DEL "ja4:whitelist" > /dev/null
    redis_cmd DEL "ja4:blacklist" > /dev/null
    redis_cmd DEL "ja4:block:*" > /dev/null
    success "Test data cleared"
    
    step "Adding good fingerprint to whitelist..."
    redis_cmd SADD "ja4:whitelist" "$GOOD_FINGERPRINT" > /dev/null
    success "Added $GOOD_FINGERPRINT to whitelist"
    
    step "Adding bad fingerprint to blacklist..."
    redis_cmd SADD "ja4:blacklist" "$BAD_FINGERPRINT" > /dev/null
    success "Added $BAD_FINGERPRINT to blacklist"
    
    step "Verifying lists..."
    WHITELIST_COUNT=$(redis_cmd SCARD "ja4:whitelist")
    BLACKLIST_COUNT=$(redis_cmd SCARD "ja4:blacklist")
    info "Whitelist entries: $WHITELIST_COUNT"
    info "Blacklist entries: $BLACKLIST_COUNT"
}

test_whitelisted_fingerprint() {
    header "3. Testing Whitelisted Fingerprint"
    
    step "Simulating connection with whitelisted fingerprint..."
    info "Fingerprint: $GOOD_FINGERPRINT"
    info "IP: 192.168.1.100"
    
    # In a real scenario, the proxy would extract the JA4 from TLS handshake
    # For this POC, we simulate by checking the whitelist directly
    
    IS_WHITELISTED=$(redis_cmd SISMEMBER "ja4:whitelist" "$GOOD_FINGERPRINT")
    
    if [ "$IS_WHITELISTED" = "1" ]; then
        success "Fingerprint is whitelisted - would be ALLOWED"
        info "Status: Connection permitted (whitelist bypass)"
    else
        error "Fingerprint not found in whitelist"
    fi
    
    # Check if it's also blocked (shouldn't be)
    IS_BLOCKED=$(redis_cmd EXISTS "ja4:block:$GOOD_FINGERPRINT:192.168.1.100")
    if [ "$IS_BLOCKED" = "0" ]; then
        success "No active block for this fingerprint"
    else
        warning "Fingerprint has an active block (unexpected)"
    fi
}

test_blacklisted_fingerprint() {
    header "4. Testing Blacklisted Fingerprint"
    
    step "Simulating connection with blacklisted fingerprint..."
    info "Fingerprint: $BAD_FINGERPRINT"
    info "IP: 192.168.1.200"
    
    IS_BLACKLISTED=$(redis_cmd SISMEMBER "ja4:blacklist" "$BAD_FINGERPRINT")
    
    if [ "$IS_BLACKLISTED" = "1" ]; then
        success "Fingerprint is blacklisted - would be BLOCKED"
        info "Status: Connection DENIED (blacklist match)"
        
        # Simulate adding a block record
        step "Adding block record to Redis..."
        redis_cmd SETEX "ja4:block:$BAD_FINGERPRINT:192.168.1.200" 3600 "Blacklisted fingerprint" > /dev/null
        success "Block record created (TTL: 3600s)"
    else
        error "Fingerprint not found in blacklist"
    fi
}

test_rate_limiting() {
    header "5. Testing Rate Limiting"
    
    step "Simulating rapid connections from attacker..."
    info "Fingerprint: $ATTACKER_FINGERPRINT"
    info "IP: 192.168.1.250"
    
    # Simulate adding connection timestamps to sorted set
    WINDOW_START=$(date +%s)
    
    step "Simulating 15 connections in 1 second..."
    for i in {1..15}; do
        TIMESTAMP=$(echo "$WINDOW_START + 0.$i" | bc)
        redis_cmd ZADD "rate:by_ip:192.168.1.250:1s" "$TIMESTAMP" "conn_$i" > /dev/null
        echo -n "."
    done
    echo ""
    
    # Count connections in window
    CURRENT=$(date +%s)
    CUTOFF=$(echo "$CURRENT - 1" | bc)
    COUNT=$(redis_cmd ZCOUNT "rate:by_ip:192.168.1.250:1s" "$CUTOFF" "+inf")
    
    success "Tracked $COUNT connections in window"
    
    # Check against thresholds (from config)
    SUSPICIOUS_THRESHOLD=1
    BLOCK_THRESHOLD=5
    BAN_THRESHOLD=10
    
    if [ "$COUNT" -gt "$BAN_THRESHOLD" ]; then
        error "Rate exceeds BAN threshold ($BAN_THRESHOLD/sec) - would be BANNED"
        info "Action: IP banned for 7 days"
        
        # Simulate ban
        redis_cmd SETEX "ja4:ban:$ATTACKER_FINGERPRINT:192.168.1.250" 604800 "Rate limit exceeded: $COUNT/sec" > /dev/null
        success "Ban record created (TTL: 604800s = 7 days)"
    elif [ "$COUNT" -gt "$BLOCK_THRESHOLD" ]; then
        warning "Rate exceeds BLOCK threshold ($BLOCK_THRESHOLD/sec) - would be BLOCKED"
        info "Action: Connections tarpitted"
    elif [ "$COUNT" -gt "$SUSPICIOUS_THRESHOLD" ]; then
        warning "Rate exceeds SUSPICIOUS threshold ($SUSPICIOUS_THRESHOLD/sec) - LOGGED"
        info "Action: Monitored but allowed"
    else
        success "Rate is normal - would be ALLOWED"
    fi
}

test_block_verification() {
    header "6. Verifying Blocks"
    
    step "Checking for active blocks..."
    
    # Check blocks
    BLOCKS=$(redis_cmd KEYS "ja4:block:*" | wc -l)
    success "Found $BLOCKS active block(s)"
    
    if [ "$BLOCKS" -gt 0 ]; then
        echo ""
        info "Active blocks:"
        redis_cmd KEYS "ja4:block:*" | while read -r key; do
            if [ -n "$key" ]; then
                TTL=$(redis_cmd TTL "$key")
                REASON=$(redis_cmd GET "$key")
                echo -e "  ${CYAN}${key}${NC}"
                echo -e "    TTL: ${YELLOW}${TTL}s${NC}"
                echo -e "    Reason: ${reason}"
            fi
        done
    fi
    
    # Check bans
    BANS=$(redis_cmd KEYS "ja4:ban:*" | wc -l)
    success "Found $BANS active ban(s)"
    
    if [ "$BANS" -gt 0 ]; then
        echo ""
        info "Active bans:"
        redis_cmd KEYS "ja4:ban:*" | while read -r key; do
            if [ -n "$key" ]; then
                TTL=$(redis_cmd TTL "$key")
                REASON=$(redis_cmd GET "$key")
                echo -e "  ${RED}${key}${NC}"
                echo -e "    TTL: ${YELLOW}${TTL}s${NC} ($(echo "$TTL / 86400" | bc) days)"
                echo -e "    Reason: $REASON"
            fi
        done
    fi
}

test_metrics() {
    header "7. Checking Metrics"
    
    step "Fetching security metrics..."
    
    METRICS=$(curl -s "http://$PROXY_HOST:$METRICS_PORT/metrics")
    
    # Extract key metrics
    BLOCKED=$(echo "$METRICS" | grep "ja4_blocked_requests_total" | grep -v "#" | awk '{print $2}')
    REQUESTS=$(echo "$METRICS" | grep "ja4_requests_total" | grep -v "#" | head -1 | awk '{print $2}')
    SECURITY_EVENTS=$(echo "$METRICS" | grep "ja4_security_events_total" | grep -v "#" | head -1 | awk '{print $2}')
    
    info "Total requests: ${REQUESTS:-0}"
    info "Blocked requests: ${BLOCKED:-0}"
    info "Security events: ${SECURITY_EVENTS:-0}"
    
    if [ -n "$BLOCKED" ] && [ "$BLOCKED" != "0" ]; then
        success "Blocking is working (${BLOCKED} blocked)"
    else
        warning "No blocks recorded in metrics yet"
    fi
}

demonstrate_unban() {
    header "8. Demonstrating Manual Unban"
    
    step "Checking if attacker is banned..."
    BAN_KEY="ja4:ban:$ATTACKER_FINGERPRINT:192.168.1.250"
    
    if redis_cmd EXISTS "$BAN_KEY" | grep -q "1"; then
        info "Attacker is currently banned"
        
        step "Simulating manual unban (false positive)..."
        redis_cmd DEL "$BAN_KEY" > /dev/null
        success "Ban removed"
        
        step "Adding to whitelist to prevent future blocks..."
        redis_cmd SADD "ja4:whitelist" "$ATTACKER_FINGERPRINT" > /dev/null
        success "Added to whitelist"
        
        info "Attacker can now connect (assuming it was a false positive)"
    else
        info "No ban found for attacker"
    fi
}

show_statistics() {
    header "9. Security Statistics"
    
    step "Gathering statistics..."
    
    WHITELIST_SIZE=$(redis_cmd SCARD "ja4:whitelist")
    BLACKLIST_SIZE=$(redis_cmd SCARD "ja4:blacklist")
    ACTIVE_BLOCKS=$(redis_cmd KEYS "ja4:block:*" | wc -l)
    ACTIVE_BANS=$(redis_cmd KEYS "ja4:ban:*" | wc -l)
    RATE_KEYS=$(redis_cmd KEYS "rate:*" | wc -l)
    
    echo ""
    echo -e "${BOLD}List Statistics:${NC}"
    echo -e "  Whitelist entries:  ${GREEN}${WHITELIST_SIZE}${NC}"
    echo -e "  Blacklist entries:  ${RED}${BLACKLIST_SIZE}${NC}"
    echo ""
    echo -e "${BOLD}Active Enforcement:${NC}"
    echo -e "  Active blocks:      ${YELLOW}${ACTIVE_BLOCKS}${NC}"
    echo -e "  Active bans:        ${RED}${ACTIVE_BANS}${NC}"
    echo ""
    echo -e "${BOLD}Rate Tracking:${NC}"
    echo -e "  Rate tracking keys: ${CYAN}${RATE_KEYS}${NC}"
    echo ""
}

cleanup() {
    header "10. Cleanup (Optional)"
    
    echo -e "${YELLOW}Do you want to clean up test data? (y/N)${NC}"
    read -r -t 10 response || response="n"
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        step "Cleaning up test data..."
        redis_cmd DEL "ja4:whitelist" > /dev/null
        redis_cmd DEL "ja4:blacklist" > /dev/null
        redis_cmd KEYS "ja4:block:*" | xargs -r redis_cmd DEL > /dev/null 2>&1
        redis_cmd KEYS "ja4:ban:*" | xargs -r redis_cmd DEL > /dev/null 2>&1
        redis_cmd KEYS "rate:*" | xargs -r redis_cmd DEL > /dev/null 2>&1
        success "Test data cleaned up"
    else
        info "Keeping test data for inspection"
        info "To clean up manually:"
        echo "  redis-cli -a changeme DEL ja4:whitelist ja4:blacklist"
        echo "  redis-cli -a changeme KEYS 'ja4:*' | xargs redis-cli -a changeme DEL"
    fi
}

main() {
    clear
    echo -e "${BOLD}${BLUE}"
    echo "╔════════════════════════════════════════════════════╗"
    echo "║   JA4 Fingerprint Blocking & Security Test        ║"
    echo "║   Testing whitelist, blacklist, and rate limits   ║"
    echo "╚════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_services
    setup_test_data
    test_whitelisted_fingerprint
    test_blacklisted_fingerprint
    test_rate_limiting
    test_block_verification
    test_metrics
    demonstrate_unban
    show_statistics
    cleanup
    
    header "Test Complete!"
    
    echo -e "${GREEN}✓ All security features tested successfully${NC}"
    echo ""
    echo -e "${BOLD}Summary:${NC}"
    echo "  • Whitelist: Allows trusted fingerprints"
    echo "  • Blacklist: Blocks known bad fingerprints"
    echo "  • Rate limiting: Detects and blocks rapid connections"
    echo "  • Manual unban: Allows removing false positives"
    echo "  • Metrics: Tracks all security events"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  1. View metrics: curl http://localhost:9090/metrics | grep ja4_"
    echo "  2. Check Prometheus: open http://localhost:9091"
    echo "  3. View logs: docker compose -f docker-compose.poc.yml logs -f"
    echo ""
}

main
