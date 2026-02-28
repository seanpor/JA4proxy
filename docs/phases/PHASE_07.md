# Phase 7 — FCrDNS & Passive DNS Enrichment

## Goal

Enrich IP reputation using DNS-derived signals, entirely off the hot path. The core
technique — Forward-Confirmed Reverse DNS — classifies IPs by whether they have a
PTR record, and whether that PTR forward-resolves back. This is a surprisingly strong
signal: legitimate residential and business ISPs almost always have FCrDNS; attack
infrastructure and freshly-provisioned datacenter IPs often do not.

## 7a. Module: `src/security/dns_enrichment.py`

### 7a. The FCrDNS Check

For a given IP, three lookups determine its classification:

```
Step 1: PTR lookup  →  1.2.3.4 → "mail.example.com"
Step 2: A/AAAA lookup  →  "mail.example.com" → [1.2.3.4, ...]
Step 3: Does the forward result contain the original IP?
         Yes → FCrDNS confirmed (legitimate)
         No  → FCrDNS failed (suspicious — PTR is lying)
```

**All DNS lookups must be async.** Use `aiodns`. Never use `socket.gethostbyname` or
any blocking resolver. DNS is the most common source of unexpected blocking in async
code.

```python
async def fcrdns_check(ip: str, resolver: aiodns.DNSResolver) -> FCrDNSResult:
    # Step 1: reverse lookup
    try:
        ptr = await resolver.gethostbyaddr(ip)
        hostname = ptr.name
    except aiodns.error:
        return FCrDNSResult(ip=ip, has_ptr=False, confirmed=False,
                            classification="no_ptr")

    # Step 2: forward lookup
    try:
        addr_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        forward = await resolver.gethostbyname(hostname, addr_family)
        forward_ips = forward.addresses
    except aiodns.error:
        return FCrDNSResult(ip=ip, has_ptr=True, hostname=hostname,
                            confirmed=False, classification="fcrdns_failed")

    # Step 3: confirm
    canonical = str(ip_address(ip).compressed)
    confirmed = canonical in {str(ip_address(a).compressed) for a in forward_ips}
    return FCrDNSResult(ip=ip, has_ptr=True, hostname=hostname,
                        confirmed=confirmed,
                        classification=_classify_hostname(hostname, confirmed))
```

### 7b. PTR Hostname Classification

The PTR hostname itself carries signal even before FCrDNS is checked:

```python
def _classify_hostname(hostname: str, confirmed: bool) -> str:
    if not confirmed:
        return "fcrdns_failed"

    hostname_lower = hostname.lower()

    # Residential ISP patterns — these reduce risk
    RESIDENTIAL_PATTERNS = [
        r'\.dsl\.', r'\.cable\.', r'\.broadband\.', r'\.home\.',
        r'\.residential\.', r'-\d+\.dynamic\.', r'\.adsl\.',
        r'\.pppoe\.', r'cpc\d+\.', r'bchsia\.',         # Canadian ISPs
        r'\.eircom\.net', r'\.bskyb\.com',              # Irish/UK ISPs
    ]
    for pattern in RESIDENTIAL_PATTERNS:
        if re.search(pattern, hostname_lower):
            return "residential"

    # Datacenter patterns — confirm ASN classification
    DATACENTER_PATTERNS = [
        r'\.amazonaws\.com$', r'\.compute\.internal$',
        r'\.googleusercontent\.com$', r'\.digitalocean\.com$',
        r'ec2-', r'ip-\d+-\d+-\d+-\d+\.',
    ]
    for pattern in DATACENTER_PATTERNS:
        if re.search(pattern, hostname_lower):
            return "datacenter_confirmed"

    return "confirmed"  # Has PTR, FCrDNS passes, no pattern match
```

### 7c. Score Contributions

| Result | Score | Notes |
|--------|-------|-------|
| No PTR | +15 | Common in fresh attack infra |
| FCrDNS failed | +20 | PTR exists but lies — suspicious |
| PTR is IP literal | +20 | `4.3.2.1.in-addr.arpa` loops back |
| Residential confirmed | −10 | Reduces other scores |
| Datacenter confirmed | +0 | Already scored by Phase 6 ASN |
| Confirmed (generic) | +0 | Neutral — PTR is honest |

The −10 residential modifier is applied by the scorer (negative `RiskSignal`). The
Phase 1 scorer already supports negative contributions (Phase 1 acceptance criteria).

### 7d. Async Queue Architecture

Same pattern as RDAP enrichment (Phase 11). The hot path never awaits DNS results:

```python
class DNSEnrichmentQueue:
    async def enqueue(self, ip: str) -> None:
        # Check Bloom filter first (Phase 0)
        if not await self.redis.bf().add("bloom:dns_enriched", ip):
            return  # Already enriched recently
        await self.queue.put(ip)

    async def _worker(self) -> None:
        while True:
            ip = await self.queue.get()
            result = await fcrdns_check(ip, self.resolver)
            await self._write_to_redis(ip, result)
            await self._maybe_emit_signal(ip, result)
```

**Enqueue triggers:** same as RDAP — when risk score ≥ `min_enqueue_score` (default 10,
lower than RDAP since DNS is cheap) or connection is blocked/tarpitted.

**Never enqueue:** h2/h1 ALPN whitelist IPs. No value and wastes lookup budget.

### 7e. Redis Cache

```
dns:ptr:{ip}  →  JSON {ptr, confirmed, classification, risk_score, fetched_at}
              TTL: 21600s (6h) (6 hours — DNS can change but usually doesn't)
```

On cache hit, emit the stored `risk_score` directly as a `RiskSignal` without
re-querying. On cache miss, fail open (return no signal) and enqueue enrichment.

### 7f. IPv6 PTR Lookups

IPv6 reverse DNS uses `ip6.arpa` format. `aiodns.gethostbyaddr()` handles this
automatically — no special handling needed in application code. Verify in tests.

Example: `2001:db8::1` → `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa`

### 7g. Passive DNS (Optional — Off by Default)

Passive DNS feed downloads use the same leader election pattern as Phase 6 (Tor list)
and Phase 8 (blocklists): one instance holds the lock, writes to Redis, others load
from Redis. Redis key: `leader:passive_dns_download` → instance_id, TTL: half of
`refresh_interval_seconds`.

When a passive DNS feed is configured, correlate IPs with recently-observed domain
names. Flag IPs seen resolving to DGA-pattern or newly-registered domains.

```yaml
passive_dns:
  enabled: false
  feed: "circl"       # circl | dnsdb | custom
  api_key: ""
  cache_ttl_seconds: 3600
  score: 25
  new_domain_days: 7
  score: 20
```

If `enabled: false`, the module must start and log one message:
`"Passive DNS disabled — no feed configured"` then remain idle. Do not error.

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `dns:ptr:{ip}` | JSON (ptr_hostname, classification, fcrdns_pass, fetched_at) | 21600s (6h) | DNS enrichment worker | PTR lookup result and FCrDNS status per IP |
| `bloom:dns_enriched` | Bloom filter | none (no expiry) | DNS enrichment worker | Dedup filter; prevents re-queuing already-enriched IPs |

Add both to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
dns_enrichment:
  enabled: true
  queue_size: 1000
  worker_count: 5          # More workers than RDAP — DNS is faster
  min_enqueue_score: 10
  resolver_timeout_seconds: 5
  resolver_nameservers: [] # Empty = system default
  fcrdns:
    enabled: true
    cache_ttl_seconds: 21600
    score: 15
    score: 20
    residential_score_reduction: 10
  passive_dns:
    enabled: false
    feed: ""
    api_key: ""
```

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| DNS resolver unreachable | Fail open — return no signal, increment error counter |
| DNS query timeout | Fail open after `resolver_timeout_seconds` — do not hang |
| Malformed PTR response | Log and skip — do not crash worker |
| Queue full | Drop new items silently, increment `ja4proxy_dns_enrichment_queue_drops_total` |
| Redis unreachable on cache write | Log warning, continue (result lost but not fatal) |
| `aiodns` not installed | Fatal error on startup with install instructions |

---

## Acceptance Criteria

### Functional
- [ ] `DNSEnrichmentQueue.enqueue(ip)`: non-blocking; uses Bloom filter dedup; h2/h1 ALPN IPs never enqueued
- [ ] `fcrdns_check(ip, resolver)`: fully async using `aiodns`; no blocking DNS calls anywhere
- [ ] All three FCrDNS steps implemented: PTR lookup → A/AAAA forward lookup → confirmation
- [ ] PTR hostname classification: residential patterns produce `RiskSignal(name="residential_ptr", score=-10)`
- [ ] IPv6 PTR lookups use `ip6.arpa` reverse zone format; `aiodns.gethostbyaddr()` handles automatically
- [ ] Cache hierarchy: in-process LRU → Redis `dns:ptr:{ip}` → enqueue; each level checked in order
- [ ] Cache miss: fail open (no signal emitted), enqueue enrichment for next connection
- [ ] Queue overflow: item dropped silently; `ja4proxy_dns_enrichment_queue_drops_total` incremented
- [ ] Worker crash: restarted automatically via `asyncio.create_task` with restart logic
- [ ] DNS resolver timeout: fail open after `resolver_timeout_seconds`; no hanging coroutines
- [ ] Negative score output as `RiskSignal` with negative `score` field; Phase 1 scorer handles it
- [ ] Passive DNS submodule: starts cleanly when `passive_dns.enabled: false`; logs single INFO line

### Configuration
- [ ] `resolver_timeout_seconds`, `cache_ttl_seconds`, `queue_size`, `worker_count` all configurable
- [ ] `passive_dns.enabled: false` disables submodule without affecting FCrDNS
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart

### Observability
- [ ] Prometheus counter: `ja4proxy_dns_enrichment_total{result}` — enrichment outcomes (hit, miss, error, timeout)
- [ ] Prometheus counter: `ja4proxy_dns_ptr_classification_total{ptr_class}` — PTR outcomes by classification
- [ ] Prometheus gauge:   `ja4proxy_dns_enrichment_queue_depth` — current queue depth
- [ ] Prometheus counter: `ja4proxy_dns_enrichment_queue_drops_total` — items dropped from full queue
- [ ] Prometheus counter: `ja4proxy_dns_resolver_errors_total` — DNS resolver errors
- [ ] `docs/REDIS_SCHEMA.md` updated with `dns:ptr:{ip}` key

- [ ] JSON log: `{"type":"system","level":"ERROR","subsystem":"dns","event":"resolver_error"}` emitted with `ip` and `error` fields on DNS lookup failure
- [ ] JSON log: `{"type":"system","level":"WARN","subsystem":"dns","event":"queue_full"}` emitted with `dropped_ip` when enrichment queue is at capacity

### Unit Tests  (`tests/unit/test_dns_enrichment.py`)
- [ ] `fcrdns_check()`: PTR resolves and forward-confirms → `RiskSignal(name="fcrdns_failed", score=0)`
- [ ] `fcrdns_check()`: PTR resolves but forward-confirm fails → `RiskSignal(name="fcrdns_failed", score=20)`
- [ ] `fcrdns_check()`: no PTR record → `RiskSignal(name="no_ptr", score=15)`
- [ ] `fcrdns_check()`: PTR matches residential pattern (e.g. `.dsl.`) → `RiskSignal(name="residential_ptr", score=-10)`
- [ ] `fcrdns_check()`: IPv6 address → correct `ip6.arpa` PTR query formed
- [ ] `DNSEnrichmentQueue.enqueue()`: h2/h1 ALPN IP → not enqueued
- [ ] `DNSEnrichmentQueue.enqueue()`: Bloom filter hit → not re-enqueued
- [ ] `DNSEnrichmentQueue.enqueue()`: queue at capacity → drop with counter increment

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [ ] With `dns_mock.py`: enqueue → worker picks up → lookup → `RiskSignal` emitted and consumed by scorer

### Chaos Tests  (`tests/chaos/test_external_api_failure.py`)
- [ ] DNS resolver unreachable: fail open; `ERROR dns event=resolver_error` logged; no crash
- [ ] DNS query times out after `resolver_timeout_seconds`: fail open; no hanging coroutine
- [ ] Malformed PTR response: fail open; parse error counter incremented
- [ ] Queue overflow under load: drops silently; drop counter incremented; no crash
