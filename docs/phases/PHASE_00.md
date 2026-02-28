# Phase 0 — Redis Foundations, Caching & Infrastructure

## Goal

Establish the correct Redis data structures, in-process caching layer, IPv6 handling,
CDN/upstream proxy IP trust, and hot config reload that every subsequent phase depends
on. Getting these right first avoids costly retrofits later.

This phase has no user-visible security effect — it is pure infrastructure. But every
subsequent phase's correctness and performance depends on it.

## 0a. Upgrade to Redis Stack

Replace `redis:alpine` with `redis/redis-stack:latest` in all Docker Compose files.
Redis Stack is a drop-in replacement that adds RedisBloom (Bloom filters) and
RedisJSON natively. HyperLogLog and Sorted Sets are built into standard Redis already.

```yaml
# docker-compose.poc.yml, docker-compose.prod.yml, docker-compose.monitoring.yml:
redis:
  image: redis/redis-stack:latest    # was: redis:alpine
  # Everything else unchanged — fully backwards compatible
```

Existing tests must pass unchanged after this swap.

Redis config (set in container):
```
maxmemory 512mb
maxmemory-policy allkeys-lru    # Hot keys survive eviction naturally
hz 20                           # More frequent key expiry (default 10)
tcp-keepalive 60
```

---

## 0b. Upstream Proxy / CDN IP Trust

**Problem:** If the proxy ever sits behind Cloudflare, Fastly, an AWS ALB, or any other
upstream proxy, the source IP visible to the proxy is the upstream proxy's IP — not the
real client's. All scoring signals would apply to Cloudflare's IP range, which defeats
the purpose entirely.

HAProxy already passes the real client IP via PROXY protocol v2. The proxy must be
configured to trust specific upstream CIDRs and extract the real client IP from the
PROXY protocol header when the connection comes from a trusted upstream.

```yaml
upstream_trust:
  enabled: false                  # Default: false. Enable only when proxy sits behind a CDN or upstream load balancer.
  trusted_cidrs:                  # IPs from which PROXY protocol headers are trusted
    - "173.245.48.0/20"           # Cloudflare
    - "103.21.244.0/22"           # Cloudflare
    - "10.0.0.0/8"                # Internal HAProxy instances
  # If source IP is NOT in trusted_cidrs, use source IP directly.
  # If source IP IS in trusted_cidrs, use the client IP from PROXY protocol header.
  # NEVER trust X-Forwarded-For from untrusted sources — only PROXY protocol v2.
```

**Security note:** never accept `X-Forwarded-For` headers as a source of real client IP
unless the connection comes from a trusted upstream CIDR. An attacker can set
`X-Forwarded-For: 1.1.1.1` to spoof a clean IP. PROXY protocol v2 is a TCP-level
mechanism that cannot be forged by the application layer.

---

## 0c. IPv6 Handling

Every part of the proxy must handle both IPv4 and IPv6 from this phase onwards.
See the cross-cutting IPv6 requirements in `CLAUDE.md`. Key implementation notes:

**IP normalisation on ingress** — normalise all IPs to canonical form on the way in:
```python
from ipaddress import ip_address
canonical_ip = str(ip_address(raw_ip).compressed)
# "::1" stays "::1", "::ffff:192.0.2.1" becomes "192.0.2.1" (IPv4-mapped → IPv4)
# "2001:0db8:0000:0000::1" becomes "2001:db8::1"
```

**Subnet extraction for analytics:**
```python
from ipaddress import ip_network, ip_address

def get_analysis_subnet(ip: str) -> str:
    addr = ip_address(ip)
    if addr.version == 4:
        return str(ip_network(f"{ip}/24", strict=False))   # /24 for IPv4
    else:
        return str(ip_network(f"{ip}/48", strict=False))   # /48 for IPv6
```

**Rate limiting keys:** `ratelimit:{ip}` — full canonical IP string, works for both.
No special handling needed beyond normalisation.

**CIDR trie:** `pytricia` handles both IPv4 and IPv6 natively. For Go: `net/netip`.

---

## 0d. The Right Redis Data Structure for Each Use Case

### JA4 blacklist / whitelist → Redis SET + in-process Python set

```python
# Redis SET for persistence and cross-instance sync
await redis.sadd("ja4:blacklist", fingerprint)
await redis.sismember("ja4:blacklist", fingerprint)   # O(1)

# In-process Python set — authoritative for hot path (zero Redis RTT)
self._blacklist: set[str] = set()   # Loaded from Redis on startup
self._whitelist: set[str] = set()   # Updated via pub/sub on changes
```

### IP bans → String keys with TTL (keep existing pattern)

Bans need per-key TTL. Redis Sets do not support per-member TTL. Keep `ban:{ip}`.

### Sliding window rate limiting → Sorted Sets + Lua

The existing fixed-window INCR overcounts at window boundaries. Replace with a true
sliding window:

```lua
-- scripts/sliding_window.lua (loaded via SCRIPT LOAD on startup)
local key   = KEYS[1]
local now   = tonumber(ARGV[1])
local win   = tonumber(ARGV[2])
local uid   = ARGV[3]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - win)
redis.call('ZADD', key, now, uid)
redis.call('EXPIRE', key, win + 1)
return redis.call('ZCARD', key)
```

### Beaconing timestamps → Sorted Sets (Phase 9 will use this)

Plan ahead: `beacon:{ip}:{ja4}` → Sorted Set, score=unix_timestamp_float.
`ZRANGEBYSCORE` for window queries, `ZREMRANGEBYSCORE` for eviction. Much cleaner
than LIST + LTRIM.

### Unique IP per CIDR → HyperLogLog (Phase 12 will use this)

```python
await redis.pfadd(f"hll:subnet:{subnet}", canonical_ip)
count = await redis.pfcount(f"hll:subnet:{subnet}")
# O(1), 12KB per key regardless of cardinality, ~0.81% error — fine for analytics
```

### Enrichment dedup → Bloom filter

```python
# Create on startup (idempotent):
await redis.bf().reserve("bloom:rdap_enriched",      error_rate=0.01, capacity=1_000_000)
await redis.bf().reserve("bloom:abuseipdb_enriched", error_rate=0.01, capacity=1_000_000)

# Per enrichment connection:
is_new = await redis.bf().add("bloom:rdap_enriched", ip)  # 1=new, 0=probably seen
```

Fallback if RedisBloom unavailable: `SADD`/`SISMEMBER` on a Set with 24h TTL.
The Bloom filter is an optimisation; the fallback is correct.

---

## 0e. In-Process Cache Layer

```python
# src/cache/local_cache.py

class LocalCache:
    whitelist_decisions: LRUCache   # TTL: 1800s (30m)s (30 min) — long; wrong = blocks real user
    block_decisions:     LRUCache   # TTL: 30s   — short; stale release > stale block
    abuseipdb_scores:    LRUCache   # TTL: 14400s (4h)
    rdap_data:           LRUCache   # TTL: 3600s (1h)s (1h)
    geoip_country:       LRUCache   # TTL: 3600s (1h)s (1h)
    asn_class:           LRUCache   # TTL: 3600s (1h)s (1h)
    dial:                int        # Current dial value (no TTL — updated via pub/sub)
    # Rate limit counters: NO local cache — must be accurate across all instances
```

**Critical rule:** Redis says "block" + local cache says "allow" → **local cache wins.**

---

## 0f. Redis Pipelining on the Hot Path

Batch all hot-path Redis reads into a single round trip per connection:

```python
async def pipeline_lookup(ip: str, ja4: str) -> PipelineResult:
    async with redis.pipeline(transaction=False) as pipe:
        pipe.get(f"ban:{ip}")
        pipe.sismember("ja4:blacklist", ja4)
        pipe.sismember("ja4:whitelist", ja4)
        pipe.get(f"abuseipdb:score:{ip}")
        pipe.get(f"analytics:agg:ip:{ip}")    # Phase 12 input
        results = await pipe.execute()
    return PipelineResult(*results)
```

Add new pipeline reads here as subsequent phases introduce new Redis keys.

---

## 0g. Lua Scripts

Load all Lua scripts on startup via `SCRIPT LOAD`, call via `EVALSHA`.
Never embed Lua inline in code paths that run per-connection.

```python
# On startup:
scripts = {}
for name, script in LUA_SCRIPTS.items():
    scripts[name] = await redis.script_load(script)

# Per call:
result = await redis.evalsha(scripts["sliding_window"], 1, key, now, window, uid)
```

---

## 0h. Pub/Sub for Cross-Instance State

```
Channel: ja4proxy:invalidate

Message types:
  {"type": "whitelist_remove",  "value": "t13d..."}  # Remove JA4 from whitelist
  {"type": "ban_release",       "value": "1.2.3.4"}  # Release a ban immediately
  {"type": "ja4_blacklist_add", "value": "t13d..."}  # Add to blacklist
  {"type": "dial_change",       "value": 35}          # Phase 2: dial updated
  {"type": "config_reload"}                           # Phase 0h: reload proxy.yml
```

Each proxy instance subscribes on startup. Cache eviction happens on message receipt.
Do NOT use Pub/Sub for new ban additions, CIDR blocks, or enrichment results — those
propagate via TTL + next-lookup. Only **removals, releases, and secops admin actions**
need immediate propagation.

---

## 0i. Hot Config Reload

Config changes must not require a proxy restart.

**Trigger mechanisms:**
1. `SIGHUP` signal → proxy reloads `config/proxy.yml`
2. Redis pub/sub message `{"type": "config_reload"}` → same effect
3. Management UI (Phase 13) sends pub/sub message

**What can be hot-reloaded:**
- All security thresholds and feature flags
- GeoIP country lists
- JA4 whitelist/blacklist additions (also via `ja4_blacklist_add` pub/sub)
- Rate limiting thresholds
- Dial setting (Phase 2)

**What requires restart (document these in code comments):**
- Listen port
- Redis connection URL
- TLS certificate paths
- Worker count

```python
class ConfigLoader:
    async def reload(self) -> None:
        """Reload config/proxy.yml and apply changes without restart."""
        new_config = yaml.safe_load(open("config/proxy.yml"))
        self._validate(new_config)          # Validate before applying
        self._apply(new_config)             # Apply atomically
        logger.info("Config reloaded", changed_keys=self._diff(new_config))
```

---

## 0j. Static IP Allowlist

**Problem:** JA4 whitelist and mTLS handle trusted *client types*. But the secops admin also
need "always allow this specific IP regardless of anything" — for monitoring agents
with rotating JA4, partner IPs, the secops admin's own office, or legacy clients that
can't present a cert.

This is distinct from the scoring system. A static-allowlisted IP bypasses the
entire pipeline — no scorer, no dial, no rate limiting. It is a hard ALLOW like
h2/h1 ALPN, not a score reduction.

```yaml
static_allowlist:
  enabled: true
  ips:
    - ip: "203.0.113.10"
      comment: "Monitoring agent — uptime checks"
      added_by: "ops-team"
      added_at: "2025-01-15"
    - ip: "198.51.100.0/28"
      comment: "Partner API consumer — fixed office CIDR"
      added_by: "platform-team"
      added_at: "2025-02-01"
  # Both individual IPs and CIDRs supported
  # IPv4 and IPv6 supported
```

**Redis persistence:** allowlist entries added via the Management UI (Phase 13) are
written to Redis (`static:allowlist` SET) and propagated via pub/sub so all instances
update immediately. Entries in `config/proxy.yml` are loaded on startup/reload and
are authoritative — a Redis entry not in the config file is still honoured but logged
with a warning ("allowlist entry in Redis not found in config — may be stale").

**Security note:** entries in this list are logged at every connection:
`BYPASS   | 203.0.113.10  | score=N/A | dial=N/A | bypass=static_allowlist | comment=Monitoring agent`
This makes it visible in Grafana and auditable. The allowlist should be kept short.

**Acceptance criteria additions:**
- [ ] Static allowlist entries bypass entire pipeline (no score, no dial check)
- [ ] Both individual IPs and CIDRs supported; IPv4 and IPv6
- [ ] Config-file entries loaded on startup and hot-reload
- [ ] UI-added entries written to Redis and propagated via pub/sub immediately
- [ ] Every allowlisted connection logged with IP, comment, and `static_allowlist` label
- [ ] Prometheus counter: `ja4proxy_static_allowlist_hits_total` — connections matched by static IP allowlist
- [ ] Tests: allowlisted IP bypasses all checks including JA4 blacklist match
- [ ] 
  CIDR allowlist match, IPv6 allowlist entry, pub/sub propagation on UI add/remove

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `config:dial` | String (integer) | none (no expiry) | Management UI, secops admin CLI | Current dial value 0–100 |
| `config:reload` | Pub/Sub channel | N/A | Any instance | Triggers hot config reload on all instances |
| `whitelist:{ja4}` | String | none (no expiry) | Management UI | JA4 whitelist entries |
| `blacklist:{ja4}` | String | none (no expiry) | Management UI | JA4 blacklist entries |
| `ban:{ip}` | String (expiry timestamp) | ban_duration_seconds | Proxy | Active IP bans |
| `block:cidr:{cidr}` | String | none (no expiry) | Management UI, RDAP | Manual or expanded CIDR blocks |
| `session:ip:{ip}:ja4:{ja4}` | Hash `{total, resumed}` | 3600s (1h) | Proxy | TLS session resumption tracking |
| `lifespan:{ip}` | Sorted Set of durations | 1800s (30m) | Proxy | Connection lifespan samples |
| `concurrent:{ip}` | Integer (INCR/DECR) | 60s | Proxy | Concurrent connection count per IP |
| `visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Proxy | Return visitor tracking |
| `management:audit_log` | List (last 1000) | none (no expiry) | Management UI | All secops admin actions |
| `management:policy_audit` | List (last 1000) | none (no expiry) | Management UI, config reload | Security policy bypass changes |
| `static:allowlist` | Set of IP/CIDR strings | none (no expiry) | Management UI | Static IP allowlist entries (UI-added) |

## Config

```yaml
# Upstream trust — enable only when proxy sits behind a CDN or load balancer.
upstream_trust:
  enabled: false          # Default: false. Enable only when sitting behind a trusted upstream.
                          # CAUTION: enabling without setting trusted_cidrs trusts spoofed client IPs.
  trusted_cidrs:
    - "10.0.0.0/8"        # Adjust to your network. HAProxy or CDN egress CIDRs.

# In-process LRU cache sizes and per-type TTLs.
local_cache:
  whitelist_decisions:
    max_size: 50000         # Default: 50000.
    ttl_seconds: 1800       # Default: 1800s (30 minutes). Long — a wrong whitelist decision lets bad traffic through.
  block_decisions:
    max_size: 100000        # Default: 100000.
    ttl_seconds: 30         # Default: 30s. Short — a stale block is worse than a stale allow.
  abuseipdb_scores:
    max_size: 50000
    ttl_seconds: 14400      # Default: 14400s (4 hours). Scores change slowly.
  asn_class:
    max_size: 100000
    ttl_seconds: 3600       # Default: 3600s (1 hour).

# Config reload behaviour.
config:
  hot_reload_enabled: true  # Default: true. SIGHUP and pub/sub message both trigger reload.
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Redis: connection refused on startup | Proxy starts; all pipeline decisions fail open; `ERROR redis event=connection_failed` logged once |
| Redis: connection refused mid-traffic | In-process cache used; decisions fail open; WARN logged once per minute; error counter incremented |
| Redis: `allkeys-lru` OOM eviction active | Hot keys (whitelist, dial) survive; cold enrichment keys evicted first; no crash |
| Bloom filter key evicted by LRU | Falls back to SET-based dedup path; no crash; dedup still functions |
| SIGHUP during high traffic | Config reloads cleanly; no connections dropped; new values apply to next connection |
| `blocking_acknowledged: false` at startup | Dial reset to 0; WARN logged; proxy starts and allows all traffic |

## Acceptance Criteria

### Functional
- [ ] All Docker Compose files use `redis/redis-stack:latest`; existing tests pass unchanged
- [ ] `upstream_trust` enabled: real client IP extracted from PROXY protocol header
- [ ] `upstream_trust` disabled or source not in `trusted_cidrs`: source IP used directly
- [ ] `get_analysis_subnet()`: returns /24 for IPv4, /48 for IPv6
- [ ] All IPs normalised to canonical form on ingress (Phase 0 normaliser)
- [ ] Rate-limiting keys, ban keys, and beaconing keys all use full canonical IP string
- [ ] JA4 blacklist and whitelist backed by Redis SET + in-process Python `frozenset`
- [ ] Sliding window rate limiter uses Sorted Set + Lua via EVALSHA; no inline Lua in production
- [ ] Bloom filters created on startup; Bloom miss falls back to SET path without error
- [ ] Hot-path pipeline batching implemented; benchmark documents RTT reduction
- [ ] Pub/Sub subscriber running per instance; handles all message types without crash
- [ ] `blocking_acknowledged: false` on startup → dial resets to 0, WARN logged

### Configuration
- [ ] Hot config reload: SIGHUP reloads config; changes apply to next connection
- [ ] Hot config reload: pub/sub `config_reload` message triggers identical reload
- [ ] Non-reloadable config keys documented in code comments adjacent to each key
- [ ] Redis config: `maxmemory`, `maxmemory-policy allkeys-lru`, `hz 20` set in compose file
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart
- [ ] `upstream_trust.trusted_cidrs` and `static_ip_allowlist.ips` are hot-reloadable; Redis connection settings require restart

### Observability
- [ ] Prometheus gauge:   `ja4proxy_cache_hit_ratio{type}` — hit ratio per cache type, last 5 minutes
- [ ] Prometheus counter: `ja4proxy_config_reloads_total` — successful config reloads
- [ ] Prometheus counter: `ja4proxy_cache_operations_total{type,result}` — get/set operations by type and result
- [ ] `docs/REDIS_SCHEMA.md` created and populated with all Phase 0 key patterns

- [ ] JSON log: `{"type":"system","level":"INFO","subsystem":"proxy","event":"startup"}` emitted on proxy start with `version`, `listen`, and `dial` fields
- [ ] JSON log: `{"type":"system","level":"INFO","subsystem":"config","event":"reload_complete"}` emitted on every successful hot reload
- [ ] JSON log: `{"type":"system","level":"ERROR","subsystem":"config","event":"reload_failed"}` emitted with `error` field when config reload fails validation

### Unit Tests  (`tests/unit/test_local_cache.py`, `test_config_loader.py`, `test_pipeline.py`)
- [ ] `LocalCache`: hit returns value, miss returns None, eviction drops LRU entry
- [ ] `LocalCache`: TTL expiry verified per cache type
- [ ] `get_analysis_subnet()`: IPv4 → /24, IPv6 → /48, edge cases (loopback, ::1)
- [ ] Canonical IP normalisation: IPv4-mapped IPv6, leading zeros, mixed case
- [ ] Sliding window rate limiter: no boundary overcounting under concurrent load
- [ ] Bloom filter: true positive, false-positive rate within tolerance, fallback to SET
- [ ] Pub/Sub message handler: each message type dispatched correctly
- [ ] Hot config reload: changed keys returned in diff; unchanged keys not returned
- [ ] Non-reloadable key change: reload rejected with clear error

### Integration Tests  (`tests/integration/test_cache_hierarchy.py`, `test_hot_reload.py`)
- [ ] Cache hierarchy: in-process hit skips Redis; in-process miss hits Redis; both miss triggers enrichment
- [ ] Hot reload: SIGHUP applies new config values to next connection within one connection latency
- [ ] Pub/Sub reload: `config_reload` message produces same result as SIGHUP

### Chaos Tests  (`tests/chaos/test_redis_failure.py`)
- [ ] Redis: connection refused on startup → proxy starts; all decisions fail open; `ERROR redis event=connection_failed` logged
- [ ] Redis: connection refused mid-traffic → in-process cache used; decisions fail open; WARN logged once per minute
- [ ] Redis: `allkeys-lru` eviction under OOM → hot keys (whitelist, dial) survive; cold keys evicted first
