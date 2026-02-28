# Phase 11 — RDAP Enrichment & Block Expansion

## Goal

Pivot from individual bad IPs to their containing netblock and owning organisation. RDAP (Registration Data Access Protocol — the modern replacement for WHOIS) lets you discover who owns a netblock, when it was registered, and what organisation controls it. When a confirmed attacker IP is enriched via RDAP, the proxy can score every other IP in their netblock higher, flag brand-new netblocks registered within 90 days, and optionally auto-expand blocks to the whole /24 when confidence is high. This is entirely an offline enrichment loop — the hot path never awaits RDAP results.

## 11a. Module: `src/security/rdap_enrichment.py`

### 11a. Architecture: Offline Enrichment Queue

```
Hot path:  connection arrives → check Redis cache → return signal (or None)
                                                         ↓ cache miss
Background: ip added to queue → Bloom filter check → IANA bootstrap → RIR query
                                                         ↓ result
                                              write to Redis → maybe block expansion
```

The queue is an `asyncio.Queue`. Workers consume it. Queue overflow drops silently
(new items simply not enriched — correct behaviour; they'll be picked up next
connection).

### 11b. IANA Bootstrap

RDAP queries must go to the correct Regional Internet Registry. The IANA bootstrap
file maps IP prefixes to RIR RDAP base URLs:

```python
BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"  # Also ipv6.json
# Download on startup, cache in memory, refresh daily

async def get_rdap_base_url(ip: str) -> str:
    """Find the correct RIR for this IP using IANA bootstrap."""
    prefix = ip_network(ip, strict=False)
    # Walk bootstrap entries, find longest matching prefix
    # Returns e.g. "https://rdap.arin.net/registry/"
```

Cache the bootstrap mapping in Redis (`rdap:bootstrap:v4`, `rdap:bootstrap:v6`)
with TTL 86400s. Load from Redis on startup to avoid re-downloading on every restart.

### 11c. Per-Registry Rate Limiting

Each RIR has different rate limits. Implement independent token buckets per registry:

```python
class RegistryRateLimiter:
    LIMITS = {
        "rdap.arin.net":   (60, 60),   # 60 requests per 60 seconds
        "rdap.ripe.net":   (60, 60),
        "rdap.apnic.net":  (30, 60),
        "rdap.lacnic.net": (20, 60),
        "rdap.afrinic.net":(20, 60),
    }

    async def acquire(self, registry_host: str) -> None:
        """Sleeps until a token is available for this registry."""
        limit, window = self.LIMITS.get(registry_host, (10, 60))
        # Token bucket implementation using Redis sorted set or in-process semaphore
```

Implement as in-process asyncio semaphore per registry (not Redis-based — the rate
limit is per-deployment, not per-instance, but given workers run in one analytics-
delegating instance at a time, in-process is correct).

If `delegate_to_analytics: true`, the analytics node owns all RDAP workers and their
rate limiters — no conflict.

### 11d. RDAP Response Parsing

RDAP returns JSON following RFC 7483. Key fields to extract:

```python
@dataclass
class RDAPResult:
    netblock: str           # e.g. "185.220.0.0/15"
    org_name: str           # e.g. "Frantech Solutions"
    org_handle: str         # e.g. "FRANK-1"
    asn: str | None         # e.g. "AS53667"
    country: str | None     # e.g. "US"
    registration_date: str | None  # ISO date of netblock registration
    fetched_at: float       # unix timestamp
```

Handle RDAP quirks:
- Some registries return `entities` with `vcardArray` for org data — parse vCard
- ARIN uses `handle` for org identifier; RIPE uses `nic-hdl`
- Registration date may be in `events` array with `eventAction: "registration"`
- Some lookups return 404 (IP not in any database) — treat as unknown, not error
- Some return 301 redirects — follow up to 3 hops

### 11e. Known-Bad Org Detection

`config/known_bad_orgs.yml` — the agent must research and populate with ≥ 30 entries:

```yaml
orgs:
  - handle: "FRANC-1"         # ARIN handle
    name: "Frantech Solutions"
    reason: "Bulletproof hosting provider"
    score: 45
  - handle: "M247-MNT"        # RIPE mntner
    name: "M247 Ltd"
    reason: "Known bulletproof / abuse-tolerant hosting"
    score: 45
  # ... ≥30 entries
  # Research: Spamhaus ASN-DROP, abuse.ch, publicwww.com/bulletproof-hosting
```

Matching logic (first match wins):
1. Exact `org_handle` match (most reliable)
2. Case-insensitive substring match on `org_name` (catches aliases)

### 11f. Block Expansion — Safety Is Paramount

Block expansion automatically adds a /24 (IPv4) or /48 (IPv6) CIDR to the blocklist
when a confirmed bad actor is enriched. It is **off by default** and has four
independent safety guards that must ALL pass:

```python
async def maybe_expand_block(ip: str, rdap: RDAPResult,
                              trigger_score: int) -> bool:
    if not config.block_expansion.enabled:
        return False

    # Guard 1: Score threshold
    if trigger_score < config.block_expansion.min_trigger_score:  # default 75
        return False

    # Guard 2: Network prefix size
    net = ip_network(rdap.netblock, strict=False)
    if net.version == 4 and net.prefixlen < (32 - config.block_expansion.max_prefix_length_v4):
        return False  # Netblock larger than /24 — too broad
    if net.version == 6 and net.prefixlen < (128 - config.block_expansion.max_prefix_length_v6):
        return False  # Netblock larger than /48

    # Guard 3: No browser traffic from netblock
    subnet = get_analysis_subnet(ip)  # /24 or /48 (Phase 0)
    if await redis.exists(f"browser:seen:subnet:{subnet}"):
        return False  # Browser traffic seen here — do NOT expand

    # Guard 4: Known-bad org confirmation required
    if not rdap_result.is_known_bad_org:
        return False  # Only expand for confirmed bad orgs, not just high-score IPs

    # All guards passed — expand
    expansion_cidr = _compute_expansion_cidr(ip, net, config)
    await _apply_expansion(expansion_cidr, rdap, trigger_score)
    await _log_expansion_audit(ip, expansion_cidr, rdap, trigger_score)
    return True
```

**Browser traffic guard implementation:**

```python
# When any connection with h2/h1 ALPN is seen, record its subnet:
if alpn in ("h2", "h1"):
    subnet = get_analysis_subnet(ip)
    await redis.set(f"browser:seen:subnet:{subnet}", "1", ex=86400)
    # TTL 24h: if no browser seen in 24h, expansion is safe again
```

**Audit log:**
```
Redis key: rdap:expansions → LIST (last 1000)  no TTL

Each entry: JSON {
    "timestamp", "trigger_ip", "trigger_score", "expansion_cidr",
    "org_name", "org_handle", "netblock", "guards_checked": {...},
    "instance_id"
}
```

### 11g. New Netblock Flagging

Netblocks registered within the last 90 days (configurable) are higher risk — attack
infrastructure is often registered shortly before use.

```python
def new_netblock_signal(registration_date: str | None, max_age_days: int) -> RiskSignal | None:
    if not registration_date:
        return None
    age = (datetime.utcnow() - datetime.fromisoformat(registration_date)).days
    if age < max_age_days:
        return RiskSignal(
            name="rdap_new_netblock",
            score=config.new_netblock_flagging.score,
            reason=f"Netblock registered {age} days ago (< {max_age_days} day threshold)",
        )
    return None
```

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `rdap:ip:{ip}` | JSON (RDAPResult) | 86400s (24h) | RDAP worker | Full RDAP enrichment result for one IP |
| `rdap:org:{org_handle}` | JSON (org_name, known_bad, reason, score, netblocks[]) | 604800s (7d) | RDAP worker | Org reputation cache; `score` is risk contribution |
| `rdap:expansions` | List of JSON audit entries (capped at 1000) | none (no expiry) | RDAP worker | Audit trail of all automatic block expansions |
| `rdap:bootstrap:v4` | JSON IANA bootstrap mapping (IPv4) | 86400s (24h) | RDAP worker | IP → RDAP registry URL mapping |
| `rdap:bootstrap:v6` | JSON IANA bootstrap mapping (IPv6) | 86400s (24h) | RDAP worker | IP → RDAP registry URL mapping |
| `browser:seen:subnet:{sub}` | String ("1") | 86400s (24h) | Proxy hot path | Flag: browser traffic seen from this subnet today |
| `analytics:enrich:rdap` | Set of IPs | none (no expiry) | Proxy (delegate mode) | RDAP enrichment queue when delegated to analytics node |

Add all to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
rdap_enrichment:
  enabled: true
  queue_size: 500
  worker_count: 3
  min_enqueue_score: 20
  lookup_timeout_seconds: 15
  delegate_to_analytics: false

  org_reputation:
    enabled: true
    score: 45

  new_netblock_flagging:
    enabled: true
    max_age_days: 90
    score: 20

  block_expansion:
    enabled: false               # Default: false. Read Phase 11 operational guidance before enabling.
    min_trigger_score: 75
    max_prefix_length_v4: 24     # Never expand broader than /24
    max_prefix_length_v6: 48     # Never expand broader than /48
    require_no_browser_traffic: true
    require_known_bad_org: true
    expansion_ban_duration: 3600
    max_expansions_per_hour: 10  # Safety: cap automated expansions
```

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| RIR RDAP API unreachable | Fail open; skip enrichment; error counter |
| RDAP returns 404 (IP unknown) | Store "unknown" result; no signal; no retry |
| IANA bootstrap download fails | Use cached bootstrap; log warning; no crash |
| Queue full | Drop silently; counter; not re-queued |
| Block expansion guard race | Browser-seen check is atomic Redis GET — no race |
| Known-bad org file missing | Fatal error on startup with clear message |
| Registry returns unexpected JSON | Log parse error; skip entry; no crash |

---

## Acceptance Criteria

### Functional
- [ ] Async queue with configurable workers; queue overflow drops silently with counter increment
- [ ] IANA bootstrap downloaded on startup using the same leader election pattern as the Tor exit list (Phase 6) and blocklists (Phase 8): one instance acquires `leader:rdap_bootstrap_download` lock, downloads and writes to Redis; all other instances load from Redis
- [ ] Bootstrap cached in Redis (`rdap:bootstrap:v4`, `rdap:bootstrap:v6`) with 24h TTL; loaded from Redis on restart to avoid re-download
- [ ] Bootstrap loaded from Redis on startup (avoids re-download on restart)
- [ ] Per-registry rate limiting: independent token buckets per RIR with configured rates
- [ ] RDAP 404: stored as `unknown` result in Redis; not retried; not counted as error
- [ ] RDAP response parsed: vCard format, ARIN/RIPE handle variations, event dates
- [ ] Up to 3 redirect hops followed; fourth hop raises error and fails open
- [ ] Bloom filter dedup before enqueue (Phase 0 structure)
- [ ] Known-bad org detection: exact `org_handle` match OR case-insensitive `org_name` substring match
- [ ] `config/known_bad_orgs.yml` populated with ≥ 30 researched bulletproof hosting entries
- [ ] New netblock signal: registration age < `max_age_days` → `RiskSignal(name="rdap_new_netblock")`
- [ ] Block expansion guard 1: trigger IP composite score ≥ `min_trigger_score`
- [ ] Block expansion guard 2: expanded prefix not broader than `max_prefix_v4` (/24) or `max_prefix_v6` (/48)
- [ ] Block expansion guard 3: `browser:seen:subnet:{sub}` key absent (h2/h1 ALPN sets key on every connection)
- [ ] Block expansion guard 4: confirmed known-bad org only; high score alone insufficient
- [ ] Block expansion audit: JSON entry written to `rdap:expansions` LIST on every expansion
- [ ] `max_expansions_per_hour` safety cap enforced across all instances
- [ ] `delegate_to_analytics: true`: IPs published to Redis Set; local workers idle
- [ ] Output: `RiskSignal` objects with correct names and scores; consumed by Phase 1 scorer

### Configuration
- [ ] `block_expansion.enabled: false` by default; must be explicitly set to enable
- [ ] All score contributions, `max_age_days`, `min_trigger_score`, rate limits configurable
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart

### Observability
- [ ] Prometheus gauge:   `ja4proxy_rdap_enrichment_queue_depth` — current queue depth
- [ ] Prometheus counter: `ja4proxy_rdap_lookup_total{registry,result}` — lookups by registry and result
- [ ] Prometheus counter: `ja4proxy_rdap_block_expansions_total` — automatic block expansions applied
- [ ] Prometheus counter: `ja4proxy_rdap_parse_errors_total` — response parse failures
- [ ] `docs/REDIS_SCHEMA.md` updated with all seven key patterns

- [ ] JSON log: `{"type":"system","level":"INFO","subsystem":"rdap","event":"block_expansion_applied"}` emitted with `ip`, `cidr`, and `org_handle` when block expands
- [ ] JSON log: `{"type":"system","level":"ERROR","subsystem":"rdap","event":"registry_error"}` emitted with `registry` and `error` on RDAP lookup failure

### Unit Tests  (`tests/unit/test_rdap_enrichment.py`)
- [ ] Known-bad org: exact `org_handle` match → `RiskSignal(name="rdap_known_bad_org")`
- [ ] Known-bad org: `org_name` substring match (case-insensitive) → signal emitted
- [ ] Known-bad org: neither handle nor name matches → no signal
- [ ] New netblock: age < `max_age_days` → `RiskSignal(name="rdap_new_netblock")`
- [ ] New netblock: age ≥ `max_age_days` → no signal
- [ ] Block expansion guard 1: score below `min_trigger_score` → no expansion
- [ ] Block expansion guard 2: IPv4 block broader than /24 → no expansion
- [ ] Block expansion guard 2: IPv6 block broader than /48 → no expansion
- [ ] Block expansion guard 3: `browser:seen:subnet` key present → no expansion
- [ ] Block expansion guard 4: org not in known-bad list → no expansion
- [ ] All four guards pass → expansion occurs; audit entry written to `rdap:expansions`
- [ ] RDAP 404 response → stored as unknown; no error counter increment
- [ ] IANA bootstrap routing: IPv4 address → correct RIR URL selected
- [ ] IANA bootstrap routing: IPv6 address → correct RIR URL selected

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [ ] With `rdap_mock.py`: enqueue → lookup → signal emitted → consumed by scorer → block expansion audit written

### Chaos Tests  (`tests/chaos/test_external_api_failure.py`)
- [ ] RIR RDAP API unreachable: fail open; error counter incremented; queue drains normally
- [ ] IANA bootstrap download fails: last known bootstrap used; WARN logged
- [ ] RDAP response is malformed JSON: parse error counter incremented; fail open
- [ ] Queue overflow: items dropped silently; drop counter incremented; no crash
