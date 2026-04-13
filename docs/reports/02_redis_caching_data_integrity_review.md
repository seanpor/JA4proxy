# Redis, Caching & Data Integrity Security Review

**Date:** 2026-04-08 (recalibrated 2026-04-08 v2)  
**Scope:** Redis client code (Python + Go), caching layers, backup system, rate limiting, Lua scripts, pub/sub  
**Severity scale:** CRITICAL → HIGH → MEDIUM → LOW · **[Go-PROD]** = production gap · **[Python-deprecated]** = maintenance debt

> **Production context:** Go (`internal/redis/`, `internal/cache/`) is production. Python (`src/cache/`, `src/backup/`) is deprecated. Go-only gaps are production issues. Shared infrastructure (Redis config, backup, Helm, compose) applies equally.

## Findings Summary

| # | Severity | Area | One-Line Description | Scope |
|---|----------|------|---------------------|-------|
| 1 | **CRITICAL** | Go Redis Client | TLS/SSL config field exists but is never applied to connection | **[Go-PROD]** |
| 2 | MEDIUM | Go Redis Client | No username support for ACL-based auth | **[Go-PROD]** |
| 3 | MEDIUM | Management API | Redis URL builder has no TLS (`rediss://`) support | [Infra] |
| 4 | LOW | Analytics | Uses deprecated `aioredis` package instead of `redis.asyncio` | [Python-deprecated] |
| 5 | MEDIUM | Analytics Rate Limiter | Non-atomic ZCARD+ZADD+EXPIRE — TOCTOU race condition | [Python-deprecated] |
| 6 | LOW | BloomFilter | Fallback SET TTL only set on first `add()` call | [Both] |
| 7 | INFO | Lua Script | Float timestamp + counter design is correct, no fix needed | [Both] |
| 8 | LOW | Go Rate Limiter | No input validation on IP/JA4 before Redis key construction | **[Go-PROD]** |
| 9 | LOW | Backup | Creates new Redis connection per backup run (connection churn) | [Python-deprecated] |
| 10 | MEDIUM | Backup Lock | 10-minute lock TTL with no extension mechanism — long backups can overlap | [Infra] |
| 11 | **HIGH** | Backup Restore | `FLUSHDB` wipes entire Redis DB, not just JA4proxy keys | [Infra] |
| 12 | LOW | Backup Encryption | PBKDF2 iterations (100K) below OWASP 2023 recommendation (600K) | [Python-deprecated] |
| 13 | MEDIUM | Redis Config | `allkeys-lru` eviction policy can evict security-critical keys | [Infra] |
| 14 | LOW | Rate Tracker Pipeline | Pipeline errors not checked per-strategy — partial failure silent | [Python-deprecated] |
| 15 | LOW | Pub/Sub | `whitelist_remove`/`ban_release` messages not HMAC-signed | [Both] |
| 16 | MEDIUM | Go Rate Limiter | IP/JA4 interpolated into Redis keys without length/character validation | **[Go-PROD]** |
| 17 | LOW | Management API | `whitelist_remove` publish not HMAC-signed | [Infra] |
| 18 | LOW | Deployment | POC exposes password via `docker inspect` (documented, accepted) | [Infra] |
| 19 | INFO | LocalCache | 30s `block_decisions` TTL is intentional and correct | [Both] |
| 20 | LOW | LocalCache | Whitelist allow can persist 30min after blacklist add (cache stale) | [Python-deprecated] |
| 21 | MEDIUM | Go Redis | `ZAdd`/`ZRemRangeByScore` swallow errors silently | **[Go-PROD]** |
| 22 | LOW | Backup | SCAN `count=100` is slow for large Redis instances | [Python-deprecated] |
| 23 | LOW | Go Redis | No health check / script reload after Redis outage | **[Go-PROD]** |
| 24 | INFO | Lua Script | Counter key TTL reset on every call is correct | [Both] |
| 25 | MEDIUM | Redis Stream | No `maxlen` on connection event stream (unbounded growth) | [Infra] |

---

## Critical Findings

### Finding 1 — CRITICAL (Go-PROD): Go Redis Client Omits TLS Despite Config Having SSL Field

**File:** `internal/redis/client.go`, lines 36-44

```go
opts := &goredis.Options{
    Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
    Password:     cfg.Password,
    DB:           cfg.DB,
    DialTimeout:  cfg.Timeout,
    ReadTimeout:  cfg.Timeout,
    WriteTimeout: cfg.Timeout,
}
```

The `Config` struct has an `SSL bool` field (`internal/config/loader.go:345`), and the config loader reads `redis.ssl: true/false` from YAML. However, the Go Redis client constructor never sets `TLSConfig` on the options. The Python proxy properly applies `ssl=ssl_enabled` and `ssl_cert_reqs` (`proxy.py:1679-1681`).

**Impact:** In any deployment where both proxies share the same Redis, the Go proxy connects in plaintext while the Python proxy uses TLS — credentials and data exposed on the wire.

**Remediation:**
```go
if cfg.SSL {
    opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
}
```
Also add `Username` to the Go Config struct for ACL parity.

### Finding 11 — HIGH: Backup Restore Wipes All Redis Data with FLUSHDB

**File:** `src/backup/restorer.py`, line 350

```python
def _wipe_redis_data(self, redis_client: redis.Redis) -> None:
    redis_client.flushdb()
```

In destructive restore mode, `FLUSHDB` wipes ALL keys in the database, not just JA4proxy-owned keys. If the Redis instance is shared with other applications (session stores, other microservices), those are destroyed.

**Remediation:** Delete only JA4proxy-owned keys by pattern using SCAN with known key prefixes. Add confirmation prompt and dry-run mode.

---

## Medium Findings

### Finding 2 — Go Redis Client Has No Username Support for ACLs

**File:** `internal/redis/client.go`, lines 21-27

The Python proxy supports `username` from config (`proxy.py:1657`) and the project ships a Redis ACL setup script (`scripts/redis-acl-setup.sh`). The Go client has no Username field, so it authenticates as the default user.

### Finding 3 — Management API Redis URL Built Without TLS Support

**File:** `management/api/redis_client.py`, lines 28-44

Fallback URL always uses `redis://` (plaintext). No `REDIS_SSL` env var or `rediss://` path.

### Finding 5 — Analytics Rate Limiter Uses Non-Atomic Operations

**File:** `src/analytics/security_hardening.py`, lines 70-95

Classic TOCTOU race: `ZCARD` and `ZADD` are two separate commands. Under concurrent load, multiple requests can read the same count, all pass, and all write — exceeding the limit. Additionally, `EXPIRE` is separate from `ZADD` — if ZADD succeeds but EXPIRE fails, the key never expires.

### Finding 10 — Backup Lock Has No Extension Mechanism

**File:** `src/backup/worker.py`, lines 215-216

Lock TTL is 600s (10 minutes). If a backup takes longer, the lock expires while still running, allowing concurrent backups to start.

### Finding 13 — Redis `allkeys-lru` Eviction Can Evict Security-Critical Keys

**File:** `deploy/docker/docker-compose.prod.yml`, line 111

If Redis reaches 512MB, it can evict `config:dial`, `ja4:whitelist`, `ban:{ip}`, etc. Use `volatile-lru` or `volatile-ttl` instead.

### Finding 16 — Go Rate Limiter Lacks Input Validation on Redis Key Construction

**File:** `internal/security/rate_limiter.go`, lines 65-80

IP and JA4 strings are interpolated directly into Redis key names. Python validates `len(ip) > 45` and `len(ja4) > 256`. Go has no equivalent check.

### Finding 25 — Redis Stream Has No MaxLen Enforcement

**File:** `internal/redis/client.go`, lines 247-254

Go proxy XADDs without `MaxLen` or `Approx`. The stream grows unbounded. REDIS_SCHEMA documents `maxlen=100,000` but no code enforces it.

---

## Low Findings

### Finding 4 — Analytics Uses Deprecated `aioredis` Package

**File:** `src/analytics/stream_consumer.py`, lines 10, 74

The rest of the codebase uses `redis.asyncio`. Two different Redis client libraries with potentially different connection behaviors.

### Finding 8 — Go Rate Limiter Key Construction Without Validation

Malformed IP with colons could create unexpected Redis key structures.

### Finding 9 — Backup Creates New Redis Connection Per Run

Connection churn under frequent scheduled backups.

### Finding 12 — PBKDF2 Iterations Below OWASP Recommendation

100K iterations vs OWASP's 600K recommendation for PBKDF2-HMAC-SHA256.

### Finding 14 — Rate Tracker Pipeline Swallows Individual Script Errors

Pipeline returns error for failed position but continues executing other scripts. Code reads results without checking for Exception instances.

### Finding 15, 17 — Pub/Sub Messages Not HMAC-Signed

`whitelist_remove` and `ban_release` messages are unsigned. A compromised service could publish cache invalidation messages.

### Finding 18 — POC Redis Password Visible via `docker inspect`

Documented and accepted risk. Production compose uses Docker secrets.

### Finding 20 — Whitelist Decisions Cache Can Stale for 30 Minutes

`ja4_blacklist_add` pub/sub invalidates the in-process blacklist set but not the `whitelist_decisions` LRUCache.

### Finding 21 — Go Redis ZAdd/ZRemRangeByScore Swallow Errors

Both methods discard the error return value entirely.

### Finding 22 — Backup SCAN Count=100 Is Slow for Large Instances

SCAN with low count hint takes many seconds on large Redis instances.

### Finding 23 — No Redis Health Monitoring in Go Proxy

If Redis goes down and comes back, `slidingWinSHA` remains empty forever. Rate limiter returns 0 permanently until restart.

---

## Informational

### Finding 7 — Lua Script Counter Design Is Correct

Uses INCR counter to generate unique IDs within the same timestamp. No fix needed.

### Finding 19 — Block Decisions 30s TTL Is Intentional

Short TTL is by design: "a stale block hurts real users." Correct.

### Finding 24 — Lua Script Counter Key TTL Reset Is Correct

EXPIRE called on every invocation ensures counter key survives as long as sorted set. Correct.
