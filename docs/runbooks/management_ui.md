# Management UI Runbook

## Quick Start

### Run locally (development)

```bash
# 1. Set a key (required — server refuses to start without one)
export UI_API_KEY="$(openssl rand -base64 32)"
echo "Your API key: $UI_API_KEY"   # save this somewhere

# 2. Point at your Redis instance
export REDIS_URL="redis://localhost:6379"   # default; adjust if needed

# 3. Start the server
python3 -m management.server
# or equivalently:
# uvicorn management.server:create_app --factory --host 127.0.0.1 --port 8090
```

### Access

| What | URL |
|------|-----|
| React SPA (management UI) | `http://localhost:8090/` |
| Interactive API docs (Swagger) | `http://localhost:8090/api/docs` |
| OpenAPI schema (JSON) | `http://localhost:8090/api/openapi.json` |
| Health check (unauthenticated) | `http://localhost:8090/health` |
| Prometheus metrics | `http://localhost:8090/metrics` |

### Authenticate

Every API endpoint (except `/health`, `/ready`, `/metrics`) requires a Bearer token:

```bash
# In the UI: enter the API key in the login screen

# With curl:
curl -H "Authorization: Bearer $UI_API_KEY" http://localhost:8090/api/v1/bans

# Or via query parameter:
curl "http://localhost:8090/api/v1/bans?key=$UI_API_KEY"
```

### Run with Docker Compose (POC stack)

```bash
# From the project root:
export UI_API_KEY="$(openssl rand -base64 32)"
docker compose -f docker-compose.poc.yml up -d

# Management UI is bound to 127.0.0.1:8001 on the host
# Access: http://localhost:8001/
```

---

## Access Setup

### Prerequisites
- Management UI API key (generated via `openssl rand -base64 32`)
- Redis server running and accessible
- FastAPI management server configured

### Installation

1. **Set environment variables:**
   ```bash
   export UI_API_KEY="$(openssl rand -base64 32)"
   export REDIS_URL="redis://localhost:6379"
   export MANAGEMENT_ALLOWED_CIDR="10.0.0.0/8"  # Optional: restrict access
   export MAX_SSE_SUBSCRIBERS=50
   export MAX_DIAL_CHANGES_PER_HOUR=10
   ```

2. **Start management server:**
   ```bash
   python3 -m management.server
   ```

3. **Access the UI:**
   - Development: `http://localhost:8090/`
   - API docs: `http://localhost:8090/api/docs`
   - Production: `https://mgmt.ja4proxy.internal` (behind nginx reverse proxy)

## Key Rotation

### Rotating the UI API Key

1. **Generate new key:**
   ```bash
   NEW_KEY=$(openssl rand -base64 32)
   ```

2. **Update environment:**
   ```bash
   export UI_API_KEY="$NEW_KEY"
   ```

3. **Restart management server:**
   ```bash
   # Graceful restart to pick up new key
   kill -HUP $(pidof uvicorn) || systemctl restart ja4proxy-management
   ```

4. **Distribute new key:**
   - Update key in secrets management system
   - Notify authorized operators
   - Old key is immediately invalid

## Standard Operating Procedures (SOPs)

### Raising the Dial

**⚠️ WARNING:** Increasing the dial above 0 will cause active blocking of connections.

1. **Navigate to Dial page** in Management UI
2. **Review current dial** (should be 0 for safe state)
3. **If slider is disabled:**
   - Click "Acknowledge Blocking Risk"
   - Read the warning carefully
   - Confirm acknowledgment
4. **Move slider gradually:**
   - Start with small increments (5-10)
   - Monitor live feed for unexpected blocks
5. **Check counterfactual impact:**
   - Note the "At this dial level, N% of recent traffic would be blocked"
   - Ensure this aligns with expectations
6. **Monitor for false positives:**
   - Watch live feed for legitimate traffic being blocked
   - If false positives appear, immediately set dial back to 0

### Emergency Dial Downgrade

1. **Set dial to 0 immediately:**
   ```bash
   curl -X PUT "http://localhost:8090/api/v1/dial" \
     -H "Authorization: Bearer $UI_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"dial": 0, "reason": "Emergency: false positives detected"}'
   ```

2. **Investigate root cause:**
   - Review recent blocks in audit log
   - Check if thresholds need adjustment
   - Verify no configuration errors

### Banning an IP

**Method 1: Manual Ban**
1. Navigate to **Bans Page**
2. Click "Add Ban"
3. Enter IP address (IPv4 or IPv6)
4. Select reason from dropdown or enter custom
5. Set TTL (1h/4h/24h/permanent)
6. Click "Confirm"

**Method 2: From Live Feed**
1. Monitor **Dashboard Page** live feed
2. Click on suspicious connection row
3. Click "Ban this IP?"
4. Confirm ban

**Both methods:**
- Write `ban:{ip}` to Redis with TTL
- Publish `ban_added` event to `ja4proxy:invalidate` stream
- Log to `management:audit_log`

### Releasing a Ban

1. Navigate to **Bans Page**
2. Find the IP in the ban list
3. Click "Release" button
4. Confirm release
5. Verify ban is removed from list

### Approving a JA4 Fingerprint Candidate

1. Navigate to **Fingerprints Page** → **Candidates** tab
2. Review candidates sorted by observation count (highest first)
3. Click "Approve" on malicious fingerprint
4. Confirm action
5. Fingerprint moves to blacklist and takes effect immediately

**Impact:**
- Adds to `ja4:blacklist` set
- Publishes `ja4_blacklist_add` to invalidate stream
- Proxy instances reload configuration within seconds

### Disabling a Security Bypass

1. Navigate to **Policy Page**
2. Review all 8 bypasses and their descriptions
3. Find the bypass to disable (e.g., `spamhaus_bypass`)
4. Toggle switch to disabled position
5. **⚠️ Read confirmation dialog carefully**
6. Understand the risk implications
7. Confirm disable

**Impact:**
- Writes to `policy:bypass:{name}`
- Publishes `policy_change` to invalidate stream
- Shows warning banner at top of Policy page
- **Increases blocking aggressiveness**

## Debugging

### "Redis unavailable" in UI

**Symptoms:** All API calls return 503 errors

**Debugging steps:**

1. **Check Redis process:**
   ```bash
   redis-cli ping
   # Should return "PONG"
   ```

2. **Check Redis logs:**
   ```bash
   journalctl -u redis --no-pager -n 50
   ```

3. **Check management server logs:**
   ```bash
   journalctl -u ja4proxy-management --no-pager -n 50
   ```

4. **Test direct connection:**
   ```bash
   redis-cli -h localhost -p 6379 INFO
   ```

5. **Check network connectivity:**
   ```bash
   telnet localhost 6379
   nc -zv localhost 6379
   ```

### SSE Feed Not Receiving Events

**Symptoms:** Live feed shows "Connecting..." or no updates

**Debugging steps:**

1. **Verify proxy is writing to stream:**
   ```bash
   redis-cli XLEN ja4proxy:events
   # Should show increasing count
   ```

2. **Check subscriber count:**
   ```bash
   curl -s http://localhost:8090/metrics | grep sse_subscribers
   ```

3. **Verify stream key name:**
   - Check proxy configuration matches management UI expectation
   - Both should use `ja4proxy:events` (not `analytics:events`)

4. **Test with curl:**
   ```bash
   curl -N -H "Authorization: Bearer $UI_API_KEY" \
     http://localhost:8090/api/v1/events
   ```

### Authentication Failures

**Symptoms:** 401 errors on all authenticated endpoints

**Debugging steps:**

1. **Verify API key is set:**
   ```bash
   echo $UI_API_KEY
   # Should show 44-character base64 string
   ```

2. **Test with correct key:**
   ```bash
   curl -H "Authorization: Bearer $UI_API_KEY" \
     http://localhost:8090/api/v1/health/detail
   ```

3. **Check rate limiting:**
   ```bash
   redis-cli GET mgmt:ratelimit:$(curl ifconfig.me)
   ```

4. **Restart management server:**
   ```bash
   systemctl restart ja4proxy-management
   ```

### CIDR Access Denied

**Symptoms:** 403 errors with "Access denied: IP not in allowed CIDR"

**Debugging steps:**

1. **Check your IP:**
   ```bash
   curl ifconfig.me
   ```

2. **Verify CIDR configuration:**
   ```bash
   echo $MANAGEMENT_ALLOWED_CIDR
   ```

3. **Test IP in CIDR:**
   ```bash
   python3 -c "
   import ipaddress
   network = ipaddress.ip_network('$MANAGEMENT_ALLOWED_CIDR')
   addr = ipaddress.ip_address('$(curl -s ifconfig.me)')
   print('Allowed:' if addr in network else 'Denied')
   "
   ```

4. **Temporarily disable CIDR restriction:**
   ```bash
   unset MANAGEMENT_ALLOWED_CIDR
   systemctl restart ja4proxy-management
   ```

## Monitoring and Alerts

### Critical Metrics to Monitor

```promql
# SSE Subscribers
ja4proxy_mgmt_sse_subscribers_active

# Redis Errors
rate(ja4proxy_mgmt_redis_errors_total[5m])

# Authentication Failures
rate(ja4proxy_mgmt_auth_failures_total[5m])

# API Request Rate
rate(ja4proxy_mgmt_requests_total[1m])

# API Latency (p99)
histogram_quantile(0.99, rate(ja4proxy_mgmt_request_duration_ms_bucket[5m]))
```

### Alert Rules

**High Auth Failure Rate:**
```yaml
groups:
  - name: management_ui
    rules:
      - alert: ManagementUIHighAuthFailures
        expr: rate(ja4proxy_mgmt_auth_failures_total[5m]) > 2
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Management UI: high authentication failure rate"
          description: "Auth failure rate {{ $value | humanize }}/s over 5 minutes. Possible brute-force."
```

**SSE Subscriber Cap Approaching:**
```yaml
      - alert: ManagementUISSESubscribersCapped
        expr: ja4proxy_mgmt_sse_subscribers_active >= 45
        for: 1m
        labels:
          severity: info
        annotations:
          summary: "Management UI: SSE subscriber cap approaching"
          description: "{{ $value }} active SSE subscribers (cap: 50)."
```

## Security Checklist

### Deployment Security

- [ ] Management UI runs on separate port (8090)
- [ ] Access restricted to internal network only
- [ ] TLS terminated at reverse proxy
- [ ] API key stored in secrets management (not in code)
- [ ] CIDR restriction configured for management access
- [ ] Rate limiting enabled (100 requests per IP)
- [ ] All endpoints require authentication except `/health` and `/ready`

### Operational Security

- [ ] API key rotated every 90 days
- [ ] Audit logs retained for 30 days
- [ ] All admin actions logged with IP and timestamp
- [ ] Redis password rotated separately
- [ ] Management UI access logged and monitored

### Incident Response

**Compromised API Key:**
1. Immediately rotate the key
2. Review audit logs for unauthorized access
3. Check all configuration changes during compromise window
4. Restore from known-good configuration if needed

**Unauthorized Configuration Change:**
1. Identify the change from audit logs
2. Revert to previous known-good state
3. Rotate all API keys
4. Investigate how access was obtained

## Performance Tuning

### SSE Performance

- **Max subscribers:** 50 (configurable via `MAX_SSE_SUBSCRIBERS`)
- **Heartbeat interval:** 15 seconds
- **Event batch size:** 100 events per read
- **Block timeout:** 1000ms between reads

### Rate Limiting

- **Auth failures:** 100 per IP before 429
- **Dial changes:** 10 per hour (UTC hour window)
- **API requests:** General rate limiting at 100 req/IP

### Redis Optimization

```conf
# In redis.conf
maxmemory 512mb
maxmemory-policy allkeys-lru
tcp-keepalive 60
client-output-buffer-limit pubsub 256mb 60 60
```

## Backup and Recovery

### Configuration Backup

```bash
# Backup Redis management keys
redis-cli --scan --pattern "mgmt:*" | xargs redis-cli DUMP > mgmt_backup.rdb
redis-cli --scan --pattern "policy:*" | xargs redis-cli DUMP >> mgmt_backup.rdb
redis-cli --scan --pattern "dial:*" | xargs redis-cli DUMP >> mgmt_backup.rdb
redis-cli --scan --pattern "config:*" | xargs redis-cli DUMP >> mgmt_backup.rdb

# Restore
cat mgmt_backup.rdb | redis-cli --pipe
```

### Audit Log Export

```bash
# Export audit log
redis-cli LRANGE management:audit_log 0 -1 > audit_log.jsonl

# Import (careful - this will overwrite)
cat audit_log.jsonl | while read line; do
  redis-cli LPUSH management:audit_log "$line"
done
redis-cli LTRIM management:audit_log 0 999
```

## Troubleshooting Matrix

| Symptom | Likely Cause | Solution |
|----------|--------------|----------|
| 503 errors on all endpoints | Redis unavailable | Check Redis process and connectivity |
| 401 errors | Invalid/missing API key | Verify UI_API_KEY environment variable |
| 403 errors | IP not in allowed CIDR | Check MANAGEMENT_ALLOWED_CIDR or disable temporarily |
| SSE not connecting | Stream key mismatch | Verify both proxy and UI use same stream key |
| Slow UI response | Redis latency | Check Redis performance metrics |
| Configuration not saving | Redis permission issue | Check Redis ACLs and user permissions |
| Audit log empty | Logging disabled | Verify LPUSH calls in Redis monitor |

## Contact and Escalation

**Primary:** `#ja4proxy-support` Slack channel
**Secondary:** `security@ja4proxy.internal` (for security incidents)
**Escalation:** `soc@company.com` (24/7 Security Operations Center)

**Response Time SLA:**
- P1 (Production outage): 15 minutes
- P2 (Degraded performance): 1 hour
- P3 (Configuration issue): 4 hours
- P4 (Documentation request): 24 hours