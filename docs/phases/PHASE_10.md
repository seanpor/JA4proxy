# Phase 10 — AbuseIPDB Integration

## Goal

Add reputation scoring from AbuseIPDB's crowdsourced abuse confidence database.
This is a **score contribution only** — never a hard block on its own. The reason is
critical: AbuseIPDB scores reflect abuse reports against an IP, but IPs are shared.
A corporate NAT gateway, a VPN exit node, or a residential ISP's CG-NAT address can
have a high AbuseIPDB score because *some* of its thousands of users were abusive,
not the specific user connecting now. Hard-blocking these would create significant
false positives.

## 10a. Module: `src/security/abuseipdb.py`

### 10a. Cache Hierarchy

Three-tier cache. Check in order, write-through on miss:

```
Tier 1: LocalCache.abuseipdb_scores (in-process LRU, TTL 4h)
           ↓ miss
Tier 2: Redis "abuseipdb:score:{ip}" (shared across instances, TTL 4h)
           ↓ miss
Tier 3: AbuseIPDB v2 API  →  write result back to Tier 2, then Tier 1
```

**Why 4-hour TTL:** AbuseIPDB scores change slowly (daily aggregation). A 4-hour cache
means each IP is looked up at most 6 times per day per deployment, staying well within
free-tier quota (1,000 requests/day).

### 10b. Fire-and-Forget Pattern

The hot path **never awaits** an AbuseIPDB result. First connection from an unknown IP
always fails open. The lookup is queued as a background task:

```python
async def get_score(ip: str) -> int | None:
    """Returns cached score, or None if not yet known. Never blocks."""
    # Tier 1: in-process cache
    cached = local_cache.abuseipdb_scores.get(ip)
    if cached is not None:
        return cached

    # Tier 2: Redis
    redis_val = await redis.get(f"abuseipdb:score:{ip}")
    if redis_val is not None:
        score = int(redis_val)
        local_cache.abuseipdb_scores.set(ip, score)
        return score

    # Tier 3: Queue lookup (fire-and-forget)
    asyncio.create_task(_enqueue_lookup(ip))
    return None  # Fail open on this connection

async def _enqueue_lookup(ip: str) -> None:
    # Bloom filter dedup (Phase 0): skip if recently looked up
    if not await redis.bf().add("bloom:abuseipdb_enriched", ip):
        return
    await lookup_queue.put(ip)
```

On cache miss: return `None` → scorer produces `RiskSignal(score=0)` → connection
proceeds normally. Next connection from same IP finds the score in cache.

### 10c. API Client

```python
async def _api_lookup(ip: str) -> int:
    """Returns confidence score 0–100. Raises on quota exhaustion or API error."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 30, "verbose": False}
    headers = {"Key": api_key, "Accept": "application/json"}

    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status == 429:
                raise QuotaExhaustedException()
            resp.raise_for_status()
            data = await resp.json()
            return data["data"]["abuseConfidenceScore"]
```

**On API error (network, 5xx):** return 0 (fail open). Increment error counter.
Do not re-queue — the Bloom filter will clear after its TTL.

### 10d. Daily Quota Management

```python
QUOTA_KEY = "abuseipdb:quota:{YYYY-MM-DD}"  # Daily quota counter

async def _check_quota() -> bool:
    """Returns True if quota available. Uses Redis INCR for atomic tracking."""
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = f"abuseipdb:quota:{today}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 86400 + 3600)  # TTL: rest of today + 1h buffer
    if count > max_requests_per_day:
        await redis.decr(key)  # Roll back the increment
        return False
    return True
```

When quota is exhausted: log a warning once (not on every request), set a
`ja4proxy_abuseipdb_quota_exhausted` Prometheus gauge = 1, stop queuing new lookups,
serve from cache only. Gauge clears at midnight (new quota day).

### 10e. Score Calculation

```python
def abuseipdb_to_risk_signal(ip: str, confidence: int | None,
                              shared_ip_threshold: int) -> RiskSignal | None:
    if confidence is None:
        return None  # Unknown — fail open, no signal

    # Scale: confidence 0–100 → risk contribution 0–40
    contribution = round((confidence / 100) * 40)

    # Hard-block protection: if shared IP likely (below threshold),
    # cap contribution regardless of score
    if confidence < shared_ip_threshold:
        # Below threshold: still flag at reduced contribution
        contribution = round((confidence / shared_ip_threshold) * 15)

    return RiskSignal(
        name="abuseipdb",
        score=contribution,
        reason=f"AbuseIPDB confidence {confidence}% → contribution {contribution}",
    )
```

`shared_ip_threshold: 50` (default) — scores below this are common for IPs serving
thousands of users (CGN, VPN, corporate). Scale those contributions down to max 15
rather than cutting them off entirely.

### 10f. Delegation to Analytics Node

When `delegate_to_analytics: true` (set after Phase 12 is deployed):
- Local workers stop processing the lookup queue
- Instead, publish IPs to `analytics:enrich:abuseipdb` Redis Set (auto-deduplicated)
- Analytics node drains this set, performs lookups centrally with one shared quota budget
- Results written to same `abuseipdb:score:{ip}` Redis keys — proxy reads them normally

```python
if config.delegate_to_analytics:
    await redis.sadd("analytics:enrich:abuseipdb", ip)
    return  # Analytics node handles the rest
```

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `abuseipdb:score:{ip}` | String (integer 0–100) | 14400s (4h) | AbuseIPDB worker | Cached confidence score; 0 on API error (fail open) |
| `abuseipdb:quota:{YYYY-MM-DD}` | String (integer count) | 90000s (25h) | AbuseIPDB worker | Daily API request count; auto-expires next day |
| `bloom:abuseipdb_enriched` | Bloom filter | none (no expiry) | AbuseIPDB worker | Dedup filter; prevents re-queuing already-enriched IPs |
| `analytics:enrich:abuseipdb` | Set of IPs | none (no expiry) | Proxy (delegate mode) | AbuseIPDB enrichment queue when delegated to analytics node |

Add all to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
abuseipdb:
  enabled: false                    # Default: false. Set api_key (or ABUSEIPDB_API_KEY env var) before enabling.
  api_key: ""                       # Set via ABUSEIPDB_API_KEY environment variable. Never commit a key to config.
  max_requests_per_day: 1000        # Free tier limit
  cache_ttl_seconds: 14400          # 4 hours
  lookup_timeout_seconds: 10
  shared_ip_threshold: 50           # Cap contribution for potentially-shared IPs
  queue_size: 500
  worker_count: 3
  score_cap: 40                # Maximum contribution to composite score
  delegate_to_analytics: false      # Set true when Phase 12 is running
```

`ABUSEIPDB_API_KEY` must be documented in `.env.example` with instructions.

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| API key missing / invalid | Fail open; log clear error; disable self |
| API returns 429 (quota exceeded) | Stop lookups for today; serve cache only |
| API timeout (>10s) | Fail open; return None; error counter |
| Network unreachable | Fail open; return None; error counter |
| Redis unavailable for cache write | Log warning; result lost; not fatal |
| Bloom filter unavailable (non-Stack Redis) | Fall back to SET (Phase 0 fallback) |
| Queue full | Drop new items silently; counter |
| `delegate_to_analytics: true` but analytics down | Analytics SET accumulates; cleared when analytics recovers |

---

## Acceptance Criteria

### Functional
- [ ] `get_score(ip) -> int | None`: always returns immediately; never blocks the hot path
- [ ] Cache lookup order: in-process LRU → Redis `abuseipdb:score:{ip}` → enqueue; verified by tests
- [ ] Cache miss: returns `None` immediately; queues background lookup; does not block
- [ ] Write-through caching: API result written to both Redis and in-process LRU
- [ ] Bloom filter dedup: IP not re-enqueued if already in `bloom:abuseipdb_enriched`
- [ ] Daily quota tracked atomically with Redis INCR on `abuseipdb:quota:{YYYY-MM-DD}`
- [ ] Quota exhausted: WARN logged once (not per request); `ja4proxy_abuseipdb_quota_exhausted` set to 1; new-day reset
- [ ] `shared_ip_threshold`: confidence below threshold → score contribution capped at 15
- [ ] API error (network or 5xx): fail open (return 0); error counter incremented; no crash
- [ ] API timeout (>`lookup_timeout_seconds`): fail open; no hanging coroutine
- [ ] IPv6 addresses submitted to API in correct format
- [ ] `delegate_to_analytics: true`: IPs published to Redis Set; local workers idle
- [ ] `ABUSEIPDB_API_KEY` documented in `.env.example` with instructions

### Configuration
- [ ] `api_key` loaded from env var `ABUSEIPDB_API_KEY` if not set in config
- [ ] `max_requests_per_day`, `cache_ttl_seconds`, `lookup_timeout_seconds`, `shared_ip_threshold` all configurable
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart

### Observability
- [ ] Prometheus counter: `ja4proxy_abuseipdb_lookup_total{result}` — API outcomes (hit, miss, error, timeout, quota_exceeded)
- [ ] Prometheus gauge:   `ja4proxy_abuseipdb_enrichment_queue_depth` — current queue depth
- [ ] Prometheus gauge:   `ja4proxy_abuseipdb_quota_exhausted` — 1 if quota exhausted, else 0
- [ ] Prometheus gauge:   `ja4proxy_abuseipdb_quota_used_today` — requests used today
- [ ] Prometheus gauge:   `ja4proxy_abuseipdb_cache_hit_ratio` — cache hit ratio over last 5 minutes
- [ ] `docs/REDIS_SCHEMA.md` updated with all four key patterns

- [ ] JSON log: `{"type":"system","level":"WARN","subsystem":"abuseipdb","event":"quota_exhausted"}` emitted once when daily quota is reached; not repeated per connection
- [ ] JSON log: `{"type":"system","level":"ERROR","subsystem":"abuseipdb","event":"api_error"}` emitted with `ip` and `http_status` on API failure

### Unit Tests  (`tests/unit/test_abuseipdb.py`)
- [ ] `get_score()`: in-process cache hit → returns immediately; no Redis or API call
- [ ] `get_score()`: Redis cache hit → returns value; no API call
- [ ] `get_score()`: both caches miss → returns None immediately; enqueues lookup
- [ ] Score calculation: confidence 0 → score contribution 0
- [ ] Score calculation: confidence 50 → correct scaled score
- [ ] Score calculation: confidence 100 → score contribution 40
- [ ] `shared_ip_threshold`: confidence 49 → contribution capped at 15
- [ ] Quota enforcement: request at limit accepted; request at limit+1 rejected
- [ ] API error → fail open (return 0); error counter incremented
- [ ] IPv6 address: correct format submitted to API

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [ ] With `abuseipdb_mock.py`: full lookup → cache write → signal consumed by scorer

### Chaos Tests  (`tests/chaos/test_external_api_failure.py`)
- [ ] AbuseIPDB API unreachable: fail open; `ERROR abuseipdb event=api_error` logged; connections continue
- [ ] Quota exhausted: WARN logged once; subsequent requests return None without API call
- [ ] Redis unavailable for cache write: API result used for this connection; write failure logged
