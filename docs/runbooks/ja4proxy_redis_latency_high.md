# Runbook: ja4proxy_redis_latency_high

## Severity
WARNING (>20ms P99) → CRITICAL (>50ms P99)

## What is happening
Redis PING latency has exceeded thresholds. This slows the entire
security pipeline since every connection waits on Redis for ban checks,
rate limits, beaconing state, and signal enrichment.

## Impact
- **High (CRITICAL):** Pipeline latency exceeds budget. Connections queue
  up, throughput drops, and the proxy may start failing open under load.
- **Low (WARNING):** Marginal latency increase. No immediate impact but
  trending toward critical.

## Diagnosis
1. Check current Redis latency from health endpoint:
   ```bash
   curl -sf http://<node>:8090/api/v1/health/deep | python3 -c "import sys,json; print(json.load(sys.stdin)['redis_latency_ms'])"
   ```
2. Check Redis INFO for latency and client stats:
   ```bash
   redis-cli -h <redis-host> INFO stats | grep -E "latency|connected_clients"
   ```
3. Check for memory pressure:
   ```bash
   redis-cli -h <redis-host> INFO memory | grep -E "used_memory|maxmemory"
   ```
4. Check slow log for expensive operations:
   ```bash
   redis-cli -h <redis-host> SLOWLOG GET 10
   ```
5. Check network latency between proxy and Redis:
   ```bash
   docker compose -f docker/docker-compose.poc.yml exec proxy ping -c 5 <redis-host>
   ```

## Resolution
**If memory pressure:**
1. Check for key explosion (e.g., ban list growth):
   ```bash
   redis-cli -h <redis-host> DBSIZE
   redis-cli -h <redis-host> KEYS 'ja4proxy:ban:*' | wc -l
   ```
2. If ban count is abnormally high, consider flushing stale bans:
   ```bash
   redis-cli -h <redis-host> --scan --pattern 'ja4proxy:ban:*' | head -1000 | xargs -r redis-cli -h <redis-host> DEL
   ```

**If network latency:**
1. Check for network congestion on the proxy-Redis path.
2. In cloud environments, check if Redis and proxy are in the same AZ.

**If slow queries:**
1. Identify the slow command from SLOWLOG.
2. If KEYS commands are the culprit, replace with SCAN-based operations
   (this is a code fix, not a runbook action).

## Escalation
Page Platform Engineering if Redis cluster needs scaling.
Page Network Engineering if cross-AZ latency is the root cause.
