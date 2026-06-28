<!--
title: Redis_Operations
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Runbook: Redis Operations

## Scope

This runbook covers day-to-day Redis operations for the JA4proxy deployment. Redis is
the shared state layer for all proxy instances. During a Redis outage, the proxy
continues to operate in fail-open mode using its local in-process cache — no proxy
restart is needed.

---

## Health Checks

### Basic connectivity

```bash
redis-cli -h <host> -p 6379 PING
# Expected: PONG
```

### Memory usage overview

```bash
redis-cli INFO memory
# Key fields:
#   used_memory_human       — current RSS
#   maxmemory_human         — configured limit (0 = no limit)
#   maxmemory_policy        — eviction policy (should be: allkeys-lru or volatile-lru)
#   mem_fragmentation_ratio — healthy range: 1.0–1.5; >2 indicates fragmentation
```

### Key-space statistics

```bash
redis-cli INFO keyspace
# Shows db0 key count, expires count, avg TTL
```

### Memory usage for a specific key

```bash
redis-cli MEMORY USAGE <key>
# Returns bytes. Use to audit unexpectedly large keys.
```

### Server info summary

```bash
redis-cli INFO server | grep -E 'redis_version|uptime_in_seconds|tcp_port|config_file'
```

---

## RDB Snapshot (Backup)

### Trigger a background save

```bash
redis-cli BGSAVE
# Returns: Background saving started
```

### Verify the snapshot completed

```bash
redis-cli LASTSAVE
# Returns Unix timestamp of last successful save.
# Compare against expected save interval in redis.conf (save 3600 1 etc.)
```

### Find the RDB file

```bash
redis-cli CONFIG GET dir
redis-cli CONFIG GET dbfilename
# Combine: <dir>/<dbfilename> is the RDB path.
```

Snapshot the file to a safe location before any destructive operation:

```bash
cp /data/dump.rdb /backup/dump-$(date +%Y%m%dT%H%M%S).rdb
```

---

## Replication Lag

```bash
redis-cli INFO replication
# Key fields:
#   role                   — master / slave
#   connected_slaves       — number of replicas (master)
#   master_repl_offset     — master write position
#   slave_repl_offset      — replica position (on replica)
#   master_last_io_seconds_ago — seconds since last communication
```

Lag in bytes = `master_repl_offset` − `slave_repl_offset`.

Alert if `master_last_io_seconds_ago > 30` — indicates network partition or replica
overload.

---

## Flush Procedure (DEVELOPMENT ONLY)

> **WARNING:** `FLUSHDB` permanently deletes all data in the selected database.
> Never run this in staging or production. Proxy instances will lose all shared state
> including bans, rate-limit windows, and analytics findings.

```bash
# Confirm you are on the correct host and database
redis-cli INFO server | grep tcp_port
redis-cli DBSIZE

# Only then flush
redis-cli FLUSHDB ASYNC
```

After flushing in development, restart the proxy so it reinitialises its Redis keys
(dial setting, policy structures, etc.):

```bash
docker compose restart proxy
```

---

## Key Inspection

### Scan for ja4proxy keys without blocking

```bash
# SCAN iterates without blocking — safe on live instances
redis-cli SCAN 0 MATCH 'ban:*' COUNT 100
redis-cli SCAN 0 MATCH 'ratelimit:*' COUNT 100
redis-cli SCAN 0 MATCH 'analytics:*' COUNT 100
redis-cli SCAN 0 MATCH 'rdap:*' COUNT 100
redis-cli SCAN 0 MATCH 'blocklist:*' COUNT 100
```

Full scan with cursor continuation (bash loop):

```bash
cursor=0
while true; do
  result=$(redis-cli SCAN $cursor MATCH '*' COUNT 200)
  cursor=$(echo "$result" | head -1)
  echo "$result" | tail -n +2
  [ "$cursor" = "0" ] && break
done
```

### Inspect key type and TTL

```bash
redis-cli TYPE ban:192.0.2.1
# Possible values: string, list, set, zset, hash, stream

redis-cli TTL ban:192.0.2.1
# -1 = no expiry, -2 = key does not exist, N = seconds remaining
```

### Common ja4proxy key patterns

| Key pattern | Type | Purpose |
|-------------|------|---------|
| `ban:{ip}` | string | Active IP ban (TTL = ban duration) |
| `ban_cidr:{cidr}` | string | CIDR-level ban from RDAP expansion |
| `config:dial` | string | Current dial value (0–100) |
| `ratelimit:{ip}:{window}` | zset | Sliding window rate limiting |
| `beacon:{ip}:{ja4}` | zset | Beaconing timestamps |
| `beacon:suspects` | zset | Beaconing leaderboard (score = count) |
| `abuseipdb:cache:{ip}` | string | Cached AbuseIPDB score + TTL |
| `rdap:ip:{ip}` | string | Cached RDAP enrichment data |
| `rdap:org:{org_hash}` | string | Cached org reputation |
| `blocklist:cidrs:{feed}` | string | JSON CIDR list per feed |
| `blocklist:etag:{feed}` | string | ETag for feed HTTP cache |
| `analytics:ja4:candidates` | zset | JA4 block candidates by score |
| `ja4proxy:events` | stream | Cross-instance analytics stream |
| `management:policy_audit` | list | Policy change audit trail |
| `dns:enrichment:queue` | list | Pending DNS enrichment jobs |
| `return_visitor:{ip}` | hash | Return visitor tracking |
| `concurrent:{ip}` | string | Current concurrent connection count |

---

## Redis Restart Procedure

### Docker Compose restart

```bash
docker compose restart redis
# Redis will reload the RDB snapshot automatically.
# Expect a brief unavailability window (usually < 5 seconds).
```

### What the proxy does during outage

The proxy uses a two-tier cache: Redis (shared, durable) and an in-process LRU cache.

During a Redis outage:
- All new ALLOW/BLOCK decisions fall back to local cache entries if present.
- If neither cache has an entry, the proxy **fails open** (allows the connection).
- No errors are surfaced to clients — connections are handled normally.
- Prometheus counter `ja4proxy_redis_operations_total{result="error"}` increments for each failed call.
- When Redis recovers, the proxy reconnects automatically (go-redis pool auto-reconnect).
- No proxy restart is needed.

This behaviour is governed by the core asymmetry principle: a missed bad request is
recoverable; a blocked legitimate user is not.

---

## Common Errors and Fixes

### MISCONF — appendonly on read-only filesystem

```
MISCONF Redis is configured to save RDB snapshots, but is currently not able to persist
on disk. Commands that may modify the data set are disabled...
```

Cause: Redis container cannot write to the persistence volume.

Fix:
```bash
# Check volume permissions
docker compose exec redis ls -la /data

# Fix ownership
docker compose exec --user root redis chown redis:redis /data

# Restart
docker compose restart redis
```

If appendonly is not needed (dev/test):
```bash
redis-cli CONFIG SET appendonly no
redis-cli CONFIG SET save ""
```

### NOAUTH — authentication required

```
NOAUTH Authentication required.
```

Fix: Pass the password configured in `config/proxy.yml` under `redis.password`:
```bash
redis-cli -a <password> PING
```

Or set `REDISCLI_AUTH` environment variable:
```bash
export REDISCLI_AUTH=<password>
redis-cli PING
```

### OOM — max memory eviction

```
OOM command not allowed when used memory > 'maxmemory'.
```

Cause: Redis has hit its memory limit.

Immediate mitigation:
```bash
# Check what is consuming memory
redis-cli MEMORY DOCTOR
redis-cli MEMORY STATS

# Scan for unexpectedly large keys
redis-cli --bigkeys

# Raise limit temporarily (bytes)
redis-cli CONFIG SET maxmemory 2gb
```

Long-term fix: review `maxmemory-policy` in `redis.conf`; for JA4proxy, `allkeys-lru`
is appropriate so that analytics data is evicted before operational keys.

### Slow log analysis

```bash
redis-cli SLOWLOG GET 10
# Returns last 10 slow commands with execution time in microseconds.
# Threshold is set by slowlog-log-slower-than in redis.conf (default: 10000 µs)
```

---

## When to Escalate

Escalate to the on-call infrastructure team if:

- Redis is unavailable for more than 60 seconds (proxy is now fail-open for all traffic)
- `mem_fragmentation_ratio > 3` after a restart (may indicate memory corruption)
- `LASTSAVE` timestamp is more than 2× the configured save interval (backups failing)
- Replication lag exceeds 1 MB sustained for more than 5 minutes
- `SLOWLOG GET` shows commands taking > 100ms (indicates blocking command or I/O issue)
- Any `MISCONF` error in production that cannot be resolved within 15 minutes

---

## Related

- `docs/runbooks/analytics_lag.md` — Stream consumer lag procedures
- `docs/reference/REDIS_SCHEMA.md` — Full key reference
- `docs/runbooks/security_policy.md` — Dial and ban management
