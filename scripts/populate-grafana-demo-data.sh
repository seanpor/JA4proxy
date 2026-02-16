#!/bin/bash
# Populate Grafana with realistic demo data by simulating security events
# This script directly updates metrics and Redis to show dashboard functionality

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REDIS_HOST="localhost"
REDIS_PORT="6379"
REDIS_PASS="changeme"

echo "========================================="
echo "Populating Grafana with Demo Data"
echo "========================================="
echo ""

# Helper function for Redis commands
redis_cmd() {
    docker exec ja4proxy-redis redis-cli -a "$REDIS_PASS" "$@" 2>/dev/null
}

echo -e "${CYAN}▶${NC} Clearing existing data..."
redis_cmd FLUSHDB > /dev/null
echo -e "${GREEN}✓${NC} Cleared"

echo ""
echo "========================================="
echo "Creating Security Events"
echo "========================================="
echo ""

# Simulate whitelisted clients
echo -e "${CYAN}▶${NC} Adding trusted fingerprints (whitelist)..."
redis_cmd SADD ja4:whitelist "t13d1516h2_8daaf6152771_02713d6af862" > /dev/null
redis_cmd SADD ja4:whitelist "t13d1517h2_9ebbf7263882_13824e7bg973" > /dev/null
redis_cmd SADD ja4:whitelist "t13d1516h2_chrome_latest_v120" > /dev/null
echo -e "${GREEN}✓${NC} Added 3 trusted clients"

# Simulate known bad fingerprints
echo -e "${CYAN}▶${NC} Adding malicious fingerprints (blacklist)..."
redis_cmd SADD ja4:blacklist "t12d090909_ba640532068b_b186095e22b6" > /dev/null
redis_cmd SADD ja4:blacklist "t10d151415_deadbeef1337_attackertools" > /dev/null
redis_cmd SADD ja4:blacklist "t11d131313_malware_botnet_v2" > /dev/null
redis_cmd SADD ja4:blacklist "t10d121212_exploit_kit_2024" > /dev/null
echo -e "${GREEN}✓${NC} Added 4 malicious fingerprints"

# Simulate active blocks
echo -e "${CYAN}▶${NC} Creating active blocks..."
NOW=$(date +%s)

# Block 1: SQL injection attempt
redis_cmd SETEX "ja4:block:t12d090909_ba640532068b_b186095e22b6:45.142.212.61" 3600 "SQL injection attempt detected" > /dev/null

# Block 2: DDoS bot
redis_cmd SETEX "ja4:block:t10d151415_deadbeef1337_attackertools:195.123.456.789" 7200 "DDoS botnet fingerprint" > /dev/null

# Block 3: Malware C2
redis_cmd SETEX "ja4:block:t11d131313_malware_botnet_v2:103.45.67.89" 86400 "Malware C2 communication blocked" > /dev/null

echo -e "${GREEN}✓${NC} Created 3 active blocks"

# Simulate bans (long-term blocks)
echo -e "${CYAN}▶${NC} Creating bans..."

# Ban 1: Persistent attacker
redis_cmd SETEX "ja4:ban:t10d121212_exploit_kit_2024:198.51.100.42" 604800 "Exploit kit - banned for 7 days" > /dev/null

# Ban 2: Credential stuffing
redis_cmd SETEX "ja4:ban:by_ip:203.0.113.99" 259200 "Credential stuffing attack - 3 day ban" > /dev/null

echo -e "${GREEN}✓${NC} Created 2 bans"

# Simulate rate limiting data
echo -e "${CYAN}▶${NC} Simulating rate limit tracking..."

# Create rate tracking windows for various IPs
for i in {1..5}; do
    IP="192.168.1.$((100 + i))"
    FP="t13d1516h2_8daaf6152771_0271$i"
    
    # Add connection timestamps (last 10 seconds)
    for j in {1..10}; do
        TIMESTAMP=$(echo "$NOW - $j" | bc)
        redis_cmd ZADD "ja4:rate:by_ip:$IP" "$TIMESTAMP" "$TIMESTAMP-$j" > /dev/null
    done
    
    redis_cmd EXPIRE "ja4:rate:by_ip:$IP" 60 > /dev/null
done

echo -e "${GREEN}✓${NC} Created rate tracking for 5 clients"

# Add some statistics
echo -e "${CYAN}▶${NC} Recording statistics..."

# Total requests counter (simulated history)
redis_cmd SET "ja4:stats:total_requests" "15847" > /dev/null
redis_cmd SET "ja4:stats:total_blocks" "127" > /dev/null
redis_cmd SET "ja4:stats:total_bans" "23" > /dev/null
redis_cmd SET "ja4:stats:unique_fingerprints" "1543" > /dev/null

# Strategy-specific stats
redis_cmd HINCRBY "ja4:stats:by_strategy" "by_ip" 89 > /dev/null
redis_cmd HINCRBY "ja4:stats:by_strategy" "by_ja4" 156 > /dev/null
redis_cmd HINCRBY "ja4:stats:by_strategy" "by_ip_ja4_pair" 234 > /dev/null

# Tier-specific blocks
redis_cmd HINCRBY "ja4:stats:by_tier" "SUSPICIOUS" 45 > /dev/null
redis_cmd HINCRBY "ja4:stats:by_tier" "BLOCK" 67 > /dev/null
redis_cmd HINCRBY "ja4:stats:by_tier" "TARPIT" 89 > /dev/null
redis_cmd HINCRBY "ja4:stats:by_tier" "BANNED" 23 > /dev/null

echo -e "${GREEN}✓${NC} Statistics recorded"

echo ""
echo "========================================="
echo "Current State Summary"
echo "========================================="
echo ""

WHITELIST_COUNT=$(redis_cmd SCARD ja4:whitelist)
BLACKLIST_COUNT=$(redis_cmd SCARD ja4:blacklist)
BLOCK_COUNT=$(redis_cmd KEYS 'ja4:block:*' | wc -l)
BAN_COUNT=$(redis_cmd KEYS 'ja4:ban:*' | wc -l)
RATE_COUNT=$(redis_cmd KEYS 'ja4:rate:*' | wc -l)

echo "Whitelist entries:    $WHITELIST_COUNT"
echo "Blacklist entries:    $BLACKLIST_COUNT"
echo "Active blocks:        $BLOCK_COUNT"
echo "Active bans:          $BAN_COUNT"
echo "Rate tracking keys:   $RATE_COUNT"

echo ""
echo "========================================="
echo "Demo Data Ready!"
echo "========================================="
echo ""
echo -e "${GREEN}✓${NC} Grafana dashboard should now show data"
echo ""
echo "View at: http://localhost:3001"
echo "  Username: admin"
echo "  Password: admin"
echo ""
echo "Note: Since the proxy handles TLS fingerprinting and we're using"
echo "plain HTTP for testing, some metrics will remain at zero until"
echo "real TLS traffic flows through the proxy."
echo ""
echo "The Redis-based security data (blocks, bans, lists) is now"
echo "populated and should be visible in dashboard panels that"
echo "query Redis metrics."
echo ""
