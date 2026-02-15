# JA4 Security Testing Guide

This guide demonstrates how to test JA4 fingerprint blocking, rate limiting, and security features.

## Quick Start

```bash
# Run the automated security test
./test-ja4-blocking.sh
```

This script tests:
- ✅ Whitelist functionality (allowed fingerprints)
- ✅ Blacklist functionality (blocked fingerprints)
- ✅ Rate limiting (automatic bans)
- ✅ Block verification
- ✅ Manual unban procedures
- ✅ Security metrics

---

## Manual Testing

### 1. Add Fingerprint to Blacklist

```bash
# Add a bad fingerprint
docker exec ja4proxy-redis redis-cli -a changeme \
  SADD ja4:blacklist "t12d090909_ba640532068b_b186095e22b6"

# Verify it was added
docker exec ja4proxy-redis redis-cli -a changeme \
  SISMEMBER ja4:blacklist "t12d090909_ba640532068b_b186095e22b6"
# Returns: 1 (true)

# List all blacklisted fingerprints
docker exec ja4proxy-redis redis-cli -a changeme \
  SMEMBERS ja4:blacklist
```

### 2. Add Fingerprint to Whitelist

```bash
# Add a trusted fingerprint
docker exec ja4proxy-redis redis-cli -a changeme \
  SADD ja4:whitelist "t13d1516h2_8daaf6152771_02713d6af862"

# Verify
docker exec ja4proxy-redis redis-cli -a changeme \
  SMEMBERS ja4:whitelist
```

### 3. Block an IP/Fingerprint Combination

```bash
# Block for 1 hour (3600 seconds)
docker exec ja4proxy-redis redis-cli -a changeme \
  SETEX "ja4:block:FINGERPRINT:IP_ADDRESS" 3600 "Suspicious activity"

# Example:
docker exec ja4proxy-redis redis-cli -a changeme \
  SETEX "ja4:block:t12d090909_ba640532068b_b186095e22b6:192.168.1.100" 3600 "Blacklisted"

# Check if blocked
docker exec ja4proxy-redis redis-cli -a changeme \
  EXISTS "ja4:block:t12d090909_ba640532068b_b186095e22b6:192.168.1.100"
# Returns: 1 if blocked
```

### 4. Ban an IP (Long-term Block)

```bash
# Ban for 7 days (604800 seconds)
docker exec ja4proxy-redis redis-cli -a changeme \
  SETEX "ja4:ban:FINGERPRINT:IP_ADDRESS" 604800 "Rate limit exceeded"

# Example:
docker exec ja4proxy-redis redis-cli -a changeme \
  SETEX "ja4:ban:t10d151415_deadbeef1337_attackertools:192.168.1.250" 604800 "Attack detected"

# Check ban status
docker exec ja4proxy-redis redis-cli -a changeme \
  GET "ja4:ban:t10d151415_deadbeef1337_attackertools:192.168.1.250"
```

### 5. Check Active Blocks

```bash
# List all blocks
docker exec ja4proxy-redis redis-cli -a changeme \
  KEYS "ja4:block:*"

# List all bans
docker exec ja4proxy-redis redis-cli -a changeme \
  KEYS "ja4:ban:*"

# Check TTL (time remaining)
docker exec ja4proxy-redis redis-cli -a changeme \
  TTL "ja4:block:FINGERPRINT:IP"
```

### 6. Manual Unban

```bash
# Remove a ban
docker exec ja4proxy-redis redis-cli -a changeme \
  DEL "ja4:ban:FINGERPRINT:IP"

# Remove a block
docker exec ja4proxy-redis redis-cli -a changeme \
  DEL "ja4:block:FINGERPRINT:IP"

# Optionally add to whitelist to prevent future blocks
docker exec ja4proxy-redis redis-cli -a changeme \
  SADD ja4:whitelist "FINGERPRINT"
```

### 7. View Security Metrics

```bash
# Get all JA4-related metrics
curl -s http://localhost:9090/metrics | grep ja4_

# Specific metrics
curl -s http://localhost:9090/metrics | grep ja4_blocked_requests_total
curl -s http://localhost:9090/metrics | grep ja4_security_events_total
curl -s http://localhost:9090/metrics | grep ja4_active_connections
```

---

## Test Scenarios

### Scenario 1: Legitimate User (Whitelist)

```bash
# Setup
FINGERPRINT="t13d1516h2_8daaf6152771_02713d6af862"
IP="192.168.1.100"

# Add to whitelist
docker exec ja4proxy-redis redis-cli -a changeme \
  SADD ja4:whitelist "$FINGERPRINT"

# Verify whitelisted
docker exec ja4proxy-redis redis-cli -a changeme \
  SISMEMBER ja4:whitelist "$FINGERPRINT"

# Expected: Connection allowed, bypasses rate limits
```

### Scenario 2: Known Attacker (Blacklist)

```bash
# Setup
FINGERPRINT="t12d090909_ba640532068b_b186095e22b6"
IP="192.168.1.200"

# Add to blacklist
docker exec ja4proxy-redis redis-cli -a changeme \
  SADD ja4:blacklist "$FINGERPRINT"

# Create block
docker exec ja4proxy-redis redis-cli -a changeme \
  SETEX "ja4:block:$FINGERPRINT:$IP" 3600 "Blacklisted fingerprint"

# Expected: Connection immediately blocked
```

### Scenario 3: Rate Limit Violation

```bash
# Simulate rapid connections (15 in 1 second)
FINGERPRINT="t10d151415_deadbeef1337_attackertools"
IP="192.168.1.250"
WINDOW_START=$(date +%s)

# Add connections to rate tracking
for i in {1..15}; do
  TIMESTAMP=$(echo "$WINDOW_START + 0.$i" | bc)
  docker exec ja4proxy-redis redis-cli -a changeme \
    ZADD "rate:by_ip:$IP:1s" "$TIMESTAMP" "conn_$i"
done

# Count connections in window
CURRENT=$(date +%s)
CUTOFF=$(echo "$CURRENT - 1" | bc)
docker exec ja4proxy-redis redis-cli -a changeme \
  ZCOUNT "rate:by_ip:$IP:1s" "$CUTOFF" "+inf"

# If > 10/sec, should trigger BAN
docker exec ja4proxy-redis redis-cli -a changeme \
  SETEX "ja4:ban:$FINGERPRINT:$IP" 604800 "Rate limit: 15/sec"

# Expected: IP banned for 7 days
```

### Scenario 4: False Positive Unban

```bash
# Scenario: Legitimate user was mistakenly banned

FINGERPRINT="t13d1516h2_good_user_fingerprint"
IP="192.168.1.150"

# Remove ban
docker exec ja4proxy-redis redis-cli -a changeme \
  DEL "ja4:ban:$FINGERPRINT:$IP"

# Add to whitelist to prevent future false positives
docker exec ja4proxy-redis redis-cli -a changeme \
  SADD ja4:whitelist "$FINGERPRINT"

# Log the unban action
echo "$(date): Unbanned $FINGERPRINT:$IP (false positive)" >> unban_log.txt

# Expected: User can now connect, won't be blocked again
```

---

## Rate Limit Thresholds

From `config/proxy.yml`:

| Tier | Threshold | Action | Duration |
|------|-----------|--------|----------|
| **SUSPICIOUS** | > 1/sec | Log only | - |
| **BLOCK** | > 5/sec | Tarpit connections | 5 minutes |
| **BANNED** | > 10/sec | Full ban | 7 days |

### Testing Each Tier

**SUSPICIOUS (> 1/sec):**
```bash
# Make 2 connections in 1 second
for i in {1..2}; do
  # Connection would be logged but allowed
  echo "Connection $i - SUSPICIOUS but ALLOWED"
done
```

**BLOCK (> 5/sec):**
```bash
# Make 6 connections in 1 second
for i in {1..6}; do
  # Connections would be tarpitted
  echo "Connection $i"
done
# Result: BLOCKED/TARPITTED
```

**BANNED (> 10/sec):**
```bash
# Make 15 connections in 1 second
for i in {1..15}; do
  # Triggers immediate ban
  echo "Connection $i"
done
# Result: BANNED for 7 days
```

---

## Security Event Types

### 1. Whitelist Hit
```bash
# Key pattern: ja4:whitelist
# Action: Allow immediately
# Metrics: ja4_whitelist_hits_total
```

### 2. Blacklist Hit
```bash
# Key pattern: ja4:blacklist
# Action: Block immediately
# Metrics: ja4_blacklist_hits_total
```

### 3. Rate Limit Exceeded
```bash
# Key pattern: rate:by_ip:*, rate:by_ja4:*, rate:by_ip_ja4_pair:*
# Action: Block/Ban based on tier
# Metrics: ja4_rate_limit_exceeded_total
```

### 4. Active Block
```bash
# Key pattern: ja4:block:FINGERPRINT:IP
# Duration: Configurable (default 300s for BLOCK tier)
# Action: Drop connection
```

### 5. Active Ban
```bash
# Key pattern: ja4:ban:FINGERPRINT:IP
# Duration: 7 days (604800s)
# Action: Drop connection, log event
```

---

## Monitoring Commands

### Real-time Monitoring

```bash
# Watch security events
watch -n 1 'curl -s http://localhost:9090/metrics | grep ja4_security'

# Monitor blocks
watch -n 1 'docker exec ja4proxy-redis redis-cli -a changeme KEYS "ja4:block:*" | wc -l'

# Monitor bans
watch -n 1 'docker exec ja4proxy-redis redis-cli -a changeme KEYS "ja4:ban:*" | wc -l'
```

### Security Dashboard Commands

```bash
# Get statistics
echo "=== Security Statistics ==="
echo "Whitelist: $(docker exec ja4proxy-redis redis-cli -a changeme SCARD ja4:whitelist)"
echo "Blacklist: $(docker exec ja4proxy-redis redis-cli -a changeme SCARD ja4:blacklist)"
echo "Active Blocks: $(docker exec ja4proxy-redis redis-cli -a changeme KEYS 'ja4:block:*' | wc -l)"
echo "Active Bans: $(docker exec ja4proxy-redis redis-cli -a changeme KEYS 'ja4:ban:*' | wc -l)"
```

---

## Cleanup

### Clear Test Data

```bash
# Clear whitelist/blacklist
docker exec ja4proxy-redis redis-cli -a changeme DEL ja4:whitelist
docker exec ja4proxy-redis redis-cli -a changeme DEL ja4:blacklist

# Clear all blocks
docker exec ja4proxy-redis redis-cli -a changeme KEYS "ja4:block:*" | \
  xargs -r docker exec ja4proxy-redis redis-cli -a changeme DEL

# Clear all bans
docker exec ja4proxy-redis redis-cli -a changeme KEYS "ja4:ban:*" | \
  xargs -r docker exec ja4proxy-redis redis-cli -a changeme DEL

# Clear rate tracking
docker exec ja4proxy-redis redis-cli -a changeme KEYS "rate:*" | \
  xargs -r docker exec ja4proxy-redis redis-cli -a changeme DEL
```

### Reset Everything

```bash
# Nuclear option: flush all Redis data
docker exec ja4proxy-redis redis-cli -a changeme FLUSHALL

# Restart services
docker compose -f docker-compose.poc.yml restart
```

---

## Integration with SIEM

### Export Security Events

```bash
# Export current blocks to JSON
docker exec ja4proxy-redis redis-cli -a changeme KEYS "ja4:block:*" | \
while read key; do
  if [ -n "$key" ]; then
    TTL=$(docker exec ja4proxy-redis redis-cli -a changeme TTL "$key")
    REASON=$(docker exec ja4proxy-redis redis-cli -a changeme GET "$key")
    echo "{\"key\":\"$key\",\"ttl\":$TTL,\"reason\":\"$REASON\"}"
  fi
done > blocks_export.json
```

### Syslog Integration

```bash
# Log security events to syslog
docker compose -f docker-compose.poc.yml logs -f proxy | \
  grep -E "(BLOCK|BAN|SECURITY)" | \
  logger -t ja4proxy
```

---

## Troubleshooting

### Block Not Working?

```bash
# Check if fingerprint is in blacklist
docker exec ja4proxy-redis redis-cli -a changeme \
  SISMEMBER ja4:blacklist "YOUR_FINGERPRINT"

# Check if block key exists
docker exec ja4proxy-redis redis-cli -a changeme \
  EXISTS "ja4:block:FINGERPRINT:IP"

# Check Redis logs
docker logs ja4proxy-redis --tail 50
```

### Ban Not Persisting?

```bash
# Check TTL
docker exec ja4proxy-redis redis-cli -a changeme \
  TTL "ja4:ban:FINGERPRINT:IP"

# If TTL is -1, key has no expiry
# If TTL is -2, key doesn't exist
# Otherwise shows seconds remaining
```

### Rate Limiting Not Triggering?

```bash
# Check rate tracking keys
docker exec ja4proxy-redis redis-cli -a changeme \
  KEYS "rate:*"

# Check configuration
cat config/proxy.yml | grep -A 10 thresholds
```

---

## Best Practices

1. **Whitelist Carefully**
   - Only add known-good fingerprints
   - Review whitelist regularly
   - Document why each entry was added

2. **Blacklist Maintenance**
   - Keep blacklist updated with threat intelligence
   - Remove outdated entries
   - Document sources

3. **Monitor Regularly**
   - Check metrics daily
   - Review blocks/bans weekly
   - Investigate patterns

4. **Handle False Positives**
   - Have an unban procedure
   - Log all manual interventions
   - Adjust thresholds if needed

5. **Audit Trail**
   - Log all whitelist/blacklist changes
   - Track who made changes
   - Keep records for compliance

---

## Advanced Testing

### Distributed Attack Simulation

```bash
# Simulate attack from multiple IPs with same JA4
FINGERPRINT="t10d151415_botnet_fingerprint"

for ip in {100..110}; do
  IP="192.168.1.$ip"
  for conn in {1..5}; do
    TIMESTAMP=$(date +%s).$conn
    docker exec ja4proxy-redis redis-cli -a changeme \
      ZADD "rate:by_ja4:$FINGERPRINT:1s" "$TIMESTAMP" "$IP:$conn"
  done
done

# Check total rate for this JA4
docker exec ja4proxy-redis redis-cli -a changeme \
  ZCARD "rate:by_ja4:$FINGERPRINT:1s"
```

### Performance Testing Under Load

```bash
# Use locust for load testing
pip install locust

# Create locustfile.py with JA4 header simulation
# Run: locust -f locustfile.py --host=http://localhost:8080
```

---

## See Also

- [POC_SECURITY_SCAN.md](../POC_SECURITY_SCAN.md) - Security vulnerability analysis
- [ENTERPRISE_REVIEW.md](../ENTERPRISE_REVIEW.md) - Production security requirements
- [config/proxy.yml](../config/proxy.yml) - Configuration reference
- [Prometheus Dashboard](http://localhost:9091) - Live metrics
