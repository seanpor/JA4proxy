# Phase 10 — AbuseIPDB Integration

Status: COMPLETE

## Goal

Add reputation scoring from AbuseIPDB's crowdsourced abuse confidence database.
This is a **score contribution only** — never a hard block on its own. The reason is
critical: AbuseIPDB scores reflect abuse reports against an IP, but IPs are shared.
A corporate NAT gateway, a VPN exit node, or a residential ISP's CG-NAT address can
have a high AbuseIPDB score because *some* of its thousands of users were abusive,
not the specific user connecting now. Hard-blocking these would create significant
false positives.

---

## 10a. New Dependency

Phase 10 introduces `aiohttp` for async HTTP. Add to `requirements.txt`:

```
aiohttp>=3.9,<4
```

---

## 10b. Module: `src/security/abuseipdb.py`

### Class Interface

```python
class AbuseIPDBChecker:
    """
    Async AbuseIPDB reputation checker.

    Maintains a three-tier cache hierarchy and a background worker pool.
    get_signal() is the only hot-path entry point — it returns immediately
    and never makes a network call.
    """

    def __init__(
        self,
        config: AbuseIPDBConfig,
        redis: Redis,
        local_cache: LocalCache,
        session: aiohttp.ClientSession,  # shared, injected at startup
    ) -> None: ...

    async def start(self) -> None:
        """Start background worker coroutines. Called once at proxy startup."""

    async def stop(self) -> None:
        """Gracefully drain queue and cancel workers. Called on shutdown."""

    def get_signal(self, ip: str) -> RiskSignal | None:
        """
        Hot-path entry point. Returns cached signal or None. Never blocks.
        Queues a background lookup on cache miss.
        """

    async def get_score(self, ip: str) -> int | None:
        """Returns cached score, or None if not yet known. Never blocks."""
```

**Wiring into `../../src/security/pipeline.py`:** `AbuseIPDBChecker.get_signal(ip)` is called in
`_collect_signals()` alongside the other signal collectors. Because it returns
immediately from cache (or None), it imposes no latency on the hot path. Worker
startup (`await checker.start()`) is called once in `ProxyServer.initialize()`.

---

## 10c. Cache Hierarchy

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

---

## 10d. Fire-and-Forget Pattern

The hot path **never awaits** an AbuseIPDB result. First connection from an unknown IP
always fails open. The lookup is queued as a background task:

```python
async def get_score(self, ip: str) -> int | None:
    """Returns cached score, or None if not yet known. Never blocks."""
    # Tier 1: in-process cache
    cached = self._local_cache.abuseipdb_scores.get(ip)
    if cached is not None:
        return cached

    # Tier 2: Redis
    redis_val = await self._redis.get(f"abuseipdb:score:{ip}")
    if redis_val is not None:
        score = int(redis_val)
        self._local_cache.abuseipdb_scores.set(ip, score)
        return score

    # Tier 3: Queue lookup (fire-and-forget)
    asyncio.create_task(self._enqueue_lookup(ip))
    return None  # Fail open on this connection

async def _enqueue_lookup(self, ip: str) -> None:
    # Bloom filter dedup: skip if recently looked up
    # (BF.ADD returns 0 if already present, 1 if newly added)
    added = await self._redis.bf().add("bloom:abuseipdb_enriched", ip)
    if not added:
        return
    try:
        self._queue.put_nowait(ip)
    except asyncio.QueueFull:
        METRICS.abuseipdb_queue_dropped_total.inc()
```

On cache miss: return `None` → scorer produces `RiskSignal(score=0)` → connection
proceeds normally. Next connection from same IP finds the score in cache.

---

## 10e. Background Worker Lifecycle

```python
async def start(self) -> None:
    """Start `worker_count` background worker coroutines."""
    self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self._config.queue_size)
    self._workers = [
        asyncio.create_task(self._lookup_worker(), name=f"abuseipdb-worker-{i}")
        for i in range(self._config.worker_count)
    ]

async def stop(self) -> None:
    """Cancel workers gracefully; log any remaining queue depth."""
    for w in self._workers:
        w.cancel()
    await asyncio.gather(*self._workers, return_exceptions=True)
    remaining = self._queue.qsize()
    if remaining:
        log.warning("abuseipdb", event="shutdown_queue_not_empty", depth=remaining)

async def _lookup_worker(self) -> None:
    """Drain the enrichment queue. Runs until cancelled."""
    while True:
        try:
            ip = await self._queue.get()
            try:
                await self._process_lookup(ip)
            except Exception as exc:
                log.error("abuseipdb", event="worker_unhandled_error", error=str(exc))
                METRICS.abuseipdb_lookup_total.labels(result="error").inc()
            finally:
                self._queue.task_done()
        except asyncio.CancelledError:
            break  # Graceful shutdown
```

Workers handle `asyncio.CancelledError` cleanly so shutdown does not hang.

---

## 10f. API Client

`aiohttp.ClientSession` is **shared** across all workers and injected at construction
time. Do not create a new session per request — this leaks file descriptors and
generates deprecation warnings in recent aiohttp versions.

```python
async def _api_lookup(self, ip: str) -> int:
    """Returns confidence score 0–100. Raises on quota exhaustion or API error."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 30, "verbose": False}
    headers = {"Key": self._config.api_key, "Accept": "application/json"}

    async with self._session.get(
        url, params=params, headers=headers,
        timeout=aiohttp.ClientTimeout(total=self._config.lookup_timeout_seconds),
    ) as resp:
        if resp.status == 429:
            raise QuotaExhaustedException()
        resp.raise_for_status()
        data = await resp.json()
        return data["data"]["abuseConfidenceScore"]
```

**On API error (network, 5xx):** return 0 (fail open). Increment error counter.
Do not re-queue — the Bloom filter prevents immediate retry; it will clear after its
configured TTL (`bloom_ttl_seconds` — see §Redis Key Schema).

---

## 10g. Daily Quota Management

```python
QUOTA_KEY = "abuseipdb:quota:{YYYY-MM-DD}"  # Daily quota counter

async def _check_quota(self) -> bool:
    """Returns True if quota available. Uses Redis INCR for atomic tracking."""
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")  # not utcnow() — deprecated
    key = f"abuseipdb:quota:{today}"
    count = await self._redis.incr(key)
    if count == 1:
        await self._redis.expire(key, 86400 + 3600)  # TTL: rest of today + 1h buffer
    if count > self._config.max_requests_per_day:
        await self._redis.decr(key)  # Roll back the increment
        return False
    return True
```

When quota is exhausted: log a warning once (not on every request), set a
`ja4proxy_abuseipdb_quota_exhausted` Prometheus gauge = 1, stop queuing new lookups,
serve from cache only. Gauge clears at midnight (new quota day).

---

## 10h. Score Calculation

```python
def abuseipdb_to_risk_signal(
    ip: str,
    confidence: int | None,
    shared_ip_threshold: int,
    score_cap: int,
) -> RiskSignal | None:
    if confidence is None:
        return None  # Unknown — fail open, no signal

    # Scale: confidence 0–100 → risk contribution 0–score_cap
    contribution = round((confidence / 100) * score_cap)

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

Maximum contribution is bounded by `score_cap` (default 40). Even confidence=100 never
contributes more than 40 points to the composite score.

---

## 10i. Delegation to Analytics Node

When `delegate_to_analytics: true` (set after Phase 12 is deployed):
- Local workers stop processing the lookup queue
- Instead, publish IPs to `analytics:enrich:abuseipdb` Redis Set (auto-deduplicated)
- Analytics node drains this set, performs lookups centrally with one shared quota budget
- Results written to same `abuseipdb:score:{ip}` Redis keys — proxy reads them normally

```python
if self._config.delegate_to_analytics:
    await self._redis.sadd("analytics:enrich:abuseipdb", ip)
    return  # Analytics node handles the rest
```

---

## 10j. Mock Server for Tests

All AbuseIPDB API calls in tests must go through a mock server, never the real API.
Create `tests/mocks/abuseipdb_mock.py`:

```python
"""
Minimal aiohttp-compatible mock for the AbuseIPDB v2 /check endpoint.

Usage:
    mock = AbuseIPDBMock()
    mock.set_score("1.2.3.4", 85)
    mock.set_error("2.3.4.5", status=500)
    mock.set_quota_exhausted()  # next call returns 429
    # Pass mock.handler as an aiohttp test server handler
```

The mock must support:
- Returning a configurable score per IP
- Returning configurable HTTP error status codes
- Simulating 429 (quota exhausted)
- Simulating network timeout (never responds)
- Recording which IPs were requested (for assertion)

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `abuseipdb:score:{ip}` | String (integer 0–100) | 14400s (4h) | AbuseIPDB worker | Cached confidence score; 0 on API error (fail open) |
| `abuseipdb:quota:{YYYY-MM-DD}` | String (integer count) | 90000s (25h) | AbuseIPDB worker | Daily API request count; auto-expires next day |
| `bloom:abuseipdb_enriched` | Bloom filter | 86400s (24h) | AbuseIPDB worker | Dedup filter; 24h TTL ensures IPs re-checked daily; if RedisBloom unavailable use SET+TTL (Phase 0 fallback) |
| `analytics:enrich:abuseipdb` | Set of IPs | none (managed) | Proxy (delegate mode) | AbuseIPDB enrichment queue when delegated to analytics node |

> **Note:** The Bloom filter TTL (24h) means an IP that errored on first lookup will
> be retried the next day. This is intentional — it bounds memory and ensures re-enrichment.

Add all to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
abuseipdb:
  enabled: false                    # Default: false. Set api_key before enabling.
  api_key: ""                       # Set via ABUSEIPDB_API_KEY env var. Never commit a key.
  max_requests_per_day: 1000        # Free tier limit; shared across all proxy instances via Redis
  cache_ttl_seconds: 14400          # 4 hours; controls Redis key TTL
  lookup_timeout_seconds: 10        # aiohttp request timeout per API call
  shared_ip_threshold: 50           # Confidence below this → contribution capped at 15
  queue_size: 500                   # Max pending IPs; new items dropped silently if full
  worker_count: 3                   # Background worker coroutines; requires restart to change
  score_cap: 40                     # Maximum contribution to composite score (confidence 100 → 40pts)
  delegate_to_analytics: false      # Set true when Phase 12 analytics node is deployed
```

`ABUSEIPDB_API_KEY` must be documented in `.env.example` with instructions.

**Hot-reload caveats:** All keys except `worker_count` and `queue_size` are hot-reloadable
(changes apply to the next connection without restart). Changing `worker_count` or
`queue_size` requires a restart because the worker pool and queue are instantiated once at
startup. The proxy logs a `WARN` if these change during a hot reload without a restart.

**Enabled toggle via hot reload:** If `enabled` is toggled from `false` to `true` during
hot reload, the proxy logs `WARN abuseipdb event=enabled_requires_restart` and skips
starting workers. A restart is required to bring the worker pool up.

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| API key missing / invalid | Fail open; log clear error; disable self |
| API returns 429 (quota exceeded) | Stop lookups for today; serve cache only; WARN logged once |
| API timeout (>10s) | Fail open; return None; error counter incremented; no hanging coroutine |
| Network unreachable | Fail open; return None; error counter incremented |
| Redis unavailable for cache write | Log warning; result lost; not fatal |
| Bloom filter unavailable (non-Stack Redis) | Fall back to SET+TTL (Phase 0 fallback) |
| Queue full | Drop new items silently; `abuseipdb_queue_dropped_total` counter incremented |
| `delegate_to_analytics: true` but analytics down | `analytics:enrich:abuseipdb` SET accumulates; cleared when analytics recovers |
| AbuseIPDB confidence=100 for browser fingerprint | Score contribution bounded by `score_cap`; never a hard block |
| Worker encounters unhandled exception | Exception logged; worker continues (does not crash proxy) |

---

## Acceptance Criteria

### Functional
- [x] `get_score(ip) -> int | None`: always returns immediately; never blocks the hot path
- [x] Cache lookup order: in-process LRU → Redis `abuseipdb:score:{ip}` → enqueue; verified by tests
- [x] Cache miss: returns `None` immediately; queues background lookup; does not block
- [x] Write-through caching: API result written to both Redis and in-process LRU
- [x] Bloom filter dedup: IP not re-enqueued if already in `bloom:abuseipdb_enriched`
- [x] Bloom filter TTL is 24h; ensures IPs are re-enriched daily (not permanently suppressed)
- [x] Daily quota tracked atomically with Redis INCR on `abuseipdb:quota:{YYYY-MM-DD}`
- [x] Quota exhausted: WARN logged once (not per request); `ja4proxy_abuseipdb_quota_exhausted` set to 1; new-day reset
- [x] `shared_ip_threshold`: confidence below threshold → score contribution capped at 15
- [x] `score_cap`: confidence 100 → contribution exactly `score_cap` (default 40); never exceeded
- [x] API error (network or 5xx): fail open (return 0); error counter incremented; no crash
- [x] API timeout (>`lookup_timeout_seconds`): fail open; no hanging coroutine; worker continues
- [x] Worker `asyncio.CancelledError`: handled cleanly; `stop()` completes without hanging
- [x] IPv6 addresses submitted to API in correct canonical string format
- [x] `delegate_to_analytics: true`: IPs published to Redis Set; local workers idle
- [x] `ABUSEIPDB_API_KEY` documented in `.env.example` with instructions
- [x] `aiohttp` added to `requirements.txt`
- [x] `get_signal(ip)` wired into `../../src/security/pipeline.py` `_collect_signals()`; `start()`/`stop()` called in `ProxyServer`
- [x] `abuseipdb_to_risk_signal()` uses `score_cap` from config (not hard-coded)

### Configuration
- [x] `api_key` loaded from env var `ABUSEIPDB_API_KEY` if not set in config
- [x] `max_requests_per_day`, `cache_ttl_seconds`, `lookup_timeout_seconds`, `shared_ip_threshold`, `score_cap` all hot-reloadable
- [x] `worker_count` and `queue_size` changes during hot reload: WARN logged; old values kept until restart
- [x] `enabled` toggled false→true via hot reload: WARN logged; workers not started until restart

### Observability
- [x] Prometheus counter: `ja4proxy_abuseipdb_lookup_total{result}` — API outcomes (`hit`, `miss`, `error`, `timeout`, `quota_exceeded`)
- [x] Prometheus gauge:   `ja4proxy_abuseipdb_enrichment_queue_depth` — current queue depth
- [x] Prometheus gauge:   `ja4proxy_abuseipdb_quota_exhausted` — 1 if quota exhausted, else 0
- [x] Prometheus gauge:   `ja4proxy_abuseipdb_quota_used_today` — requests used today
- [x] Prometheus gauge:   `ja4proxy_abuseipdb_cache_hit_ratio` — cache hit ratio over last 5 minutes
- [x] Prometheus counter: `ja4proxy_abuseipdb_queue_dropped_total` — items dropped due to full queue
- [x] `docs/REDIS_SCHEMA.md` updated with all four key patterns
- [x] `CHANGELOG.md` updated with Phase 10 entry

- [x] JSON log: `{"type":"system","level":"WARN","subsystem":"abuseipdb","event":"quota_exhausted"}` emitted once when daily quota is reached; not repeated per connection
- [x] JSON log: `{"type":"system","level":"ERROR","subsystem":"abuseipdb","event":"api_error","ip":"...","http_status":N}` on API failure

### Unit Tests  (`tests/unit/test_abuseipdb.py`)
- [x] `get_score()`: in-process cache hit → returns immediately; no Redis or API call
- [x] `get_score()`: Redis cache hit → returns value; no API call
- [x] `get_score()`: both caches miss → returns None immediately; enqueues lookup
- [x] Score calculation: confidence 0 → contribution 0
- [x] Score calculation: confidence 50 → correct scaled score (≤ score_cap)
- [x] Score calculation: confidence 100 → contribution exactly score_cap (default 40)
- [x] Score calculation: confidence 49 (`< shared_ip_threshold`) → contribution ≤ 15
- [x] `score_cap` enforced: custom `score_cap=20` → confidence 100 → contribution 20
- [x] Quota enforcement: request at limit accepted; request at limit+1 rejected and rolled back
- [x] API error → fail open (return 0); error counter incremented
- [x] API timeout → fail open; no coroutine left hanging
- [x] Worker `CancelledError` → exits cleanly without re-raising
- [x] Queue full → item dropped; `abuseipdb_queue_dropped_total` counter incremented
- [x] IPv6 address: correct canonical format (`ipaddress.ip_address(ip).compressed`) submitted to API
- [x] `get_score()`: Bloom filter already contains IP → not re-enqueued

### Adversarial / False Positive Tests  (`tests/adversarial/test_abuseipdb_fp.py`)
- [x] Browser fingerprint (h2 ALPN) IP with AbuseIPDB confidence=100: composite score still below block threshold at dial=100 (score contribution bounded by score_cap=40; ban threshold is 85)
- [x] CGN / shared IP (confidence=49): contribution ≤ 15; does not push a legitimate-looking connection past flag threshold on its own
- [x] No single AbuseIPDB score, regardless of value, results in a hard block without other signals

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [x] With `AbuseIPDBMock` from `tests/mocks/abuseipdb_mock.py`: full lookup → Redis cache write → signal consumed by scorer → correct composite score

### Chaos Tests  (`tests/chaos/test_external_api_failure.py`)
- [x] AbuseIPDB API unreachable: fail open; `ERROR abuseipdb event=api_error` logged; connections continue unaffected
- [x] Quota exhausted (mock returns 429): WARN logged once; subsequent requests return None without API call; `ja4proxy_abuseipdb_quota_exhausted` gauge = 1
- [x] Redis unavailable for cache write: API result used for this connection; write failure logged; no crash
- [x] Worker pool stopped (`stop()` called): in-flight lookups complete or cancel cleanly; `stop()` returns within 5 seconds
