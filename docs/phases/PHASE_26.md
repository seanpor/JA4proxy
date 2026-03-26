# Phase 26 — Python Throughput Hardening

## Goal

Maximise connections/second from the Python proxy **without changing its security
semantics or correctness guarantees**. Target: ≥800 conn/s single process,
≥3,200 conn/s with 4 workers on a single server.

This phase is the correct answer to the question posed in Phase 24. It fixes the
real bottlenecks — not the imaginary ones.

---

## Background: What the Benchmarks Tell Us

### Measured baselines (i9-9900K, Redis in Docker, mock TLS backend)

| Scenario | conn/s | Notes |
|----------|--------|-------|
| Python, 1 thread, browser ALPN (bypass) | ~300–400 | No scoring; direct forward |
| Python, 1 thread, mixed traffic | 248 | Measured; ~half blocked by rate limit |
| Python, ≥2 threads, same source IP | 6 | Per-IP concurrent cap (tarpit) — correct behaviour |
| Go, 1 thread, pass-through | 335 | Backend-limited; no signals wired yet |
| Go, 32 threads, pass-through | 244 | Backend-limited |

### Real bottlenecks (confirmed by profiling and benchmark data)

```
1. Redis RTT — 5–7 sequential round trips per new-IP connection
   TCP analysis:    2 RTTs (hmget + zadd)
   DNS enrichment:  1 RTT  (get, cached ~5min after first hit)
   Rate tracker:    3 RTTs (evalsha × 3 strategies)
   Analytics:       1 RTT  (get)
   Total:           7 RTTs × 0.5ms = 3.5ms Redis overhead alone

2. Signal modules run sequentially
   All 8 modules in _collect_signals() called in series.
   They are independent and can run concurrently.
   Sequential cost: sum(latencies) ≈ 4–5ms
   Parallel cost:   max(latencies) ≈ 1–1.5ms

3. Single asyncio event loop (GIL)
   One Python process, one core, one event loop.
   At ~248 conn/s × 4ms = 992ms/s of Redis waiting → near saturation.
   Solution: multi-process workers (not threads — GIL prevents benefit).

4. TCP loopback overhead
   Redis over TCP loopback adds ~0.3–0.5ms vs Unix domain socket.
   7 RTTs × 0.3ms delta = 2.1ms saved per connection with Unix socket.
```

### Theoretical ceilings (single process, after all optimisations)

```
asyncio event-loop overhead:         ~0.2ms
Redis batch reads  (1 RTT, UDS):     ~0.1ms
In-process signal processing:        ~0.3ms
Redis batch writes (1 RTT, UDS):     ~0.1ms
TLS parse + forward to backend:      ~0.5ms
Total per-connection budget:         ~1.2ms → ~830 conn/s ceiling
```

With 4 worker processes (no GIL interaction, each core independent):
```
4 × 830 = ~3,300 conn/s
```

With 8 worker processes (saturating ~8 of 16 cores on i9-9900K):
```
8 × 830 = ~6,600 conn/s
```

---

## What Stays Python Forever

Python is the right language for:
- `analytics/` — scipy/pandas/numpy ecosystem, not performance-critical
- `management/` (Phase 13) — FastAPI, not performance-critical
- Config management, backup/restore, CLI tooling

The proxy core (connection handling, TLS parsing, signal pipeline) is being
rewritten in Go (Phase 15). Phase 26 is the "maximum value from existing Python"
bridge strategy for operators who need >250 conn/s before Phase 15 completes,
and for environments where Go deployment is not yet approved.

---

## Phase 26 Sub-Plans

### 26a — Parallel Signal Collection (`asyncio.gather`)

**What:** Replace sequential `await signal_module.get_signal(ctx)` calls in
`_collect_signals()` with concurrent execution using `asyncio.gather`.

**Current code path in `pipeline.py` `_collect_signals()`:**
```python
tcp_signals  = await self._tcp_analyzer.analyze(ctx)      # 2 Redis RTTs
asn_signals  = await self._asn_classifier.signals(ctx)    # MaxMind mmap
dns_signal   = await self._dns_enrichment.get_signal(ip)  # 1 Redis RTT
metrics      = await self._rate_tracker.track_connection(…)# 3 Redis RTTs
analytics    = await self._analytics.get_signals(ctx)     # 1 Redis RTT
```

These five modules are **fully independent** — none depends on another's output.
They can all fire simultaneously.

**Target code pattern:**
```python
results = await asyncio.gather(
    self._tcp_analyzer.analyze(ctx),
    self._asn_classifier.signals(ctx),
    self._dns_enrichment.get_signal(ctx.client_ip),
    self._rate_tracker.track_connection(…),
    self._get_analytics_signals(ctx),
    return_exceptions=True,          # fail-open per module
)
```

Each raised exception is caught individually; a module failure produces zero
signals (existing fail-open contract preserved).

**Acceptance criteria:**
- `_collect_signals()` uses `asyncio.gather` for all modules that have no
  inter-module dependency
- All existing tests pass unchanged (no behavioural change)
- New benchmark: `baseline_latency` p99 improves ≥30%
- New benchmark: `throughput_scaling` 1-thread result improves ≥40%

**Estimated gain:** 1.5–2× single-process throughput (3.5ms → 1.5ms per conn)
**Estimated effort:** 2–3 days

---

### 26b — Redis Pipeline Batching for Read Operations

**What:** Replace 3–4 sequential `evalsha` / `hmget` calls in the rate tracker
and TCP analyser with a single pipelined batch read. Separate reads (for the
decision) from writes (updating counters after decision).

**Current hot path Redis calls for a new IP:**
```
HMGET    session:{ip}           # TCP analyser: session resumption ratio
ZADD     lifespan:{ip}          # TCP analyser: connection timing
EVALSHA  rate:ip:{ip}           # Rate tracker: by_ip strategy
EVALSHA  rate:ja4:{ja4}         # Rate tracker: by_ja4 strategy
EVALSHA  rate:ipja4:{ip}:{ja4}  # Rate tracker: by_ip+ja4 strategy
GET      analytics:finding:{ip} # Analytics signals
```

**Target pattern (two phases):**
```python
# Phase 1: all reads in one pipeline (before decision)
async with redis.pipeline(transaction=False) as pipe:
    pipe.hmget(f"session:{ip}", ["total", "resumed"])
    pipe.get(f"analytics:finding:{ip}")
    hmget_result, analytics_result = await pipe.execute()

# Rate tracker evalsha cannot be pipelined (Lua side effects),
# but all three strategies can be gathered:
rate_results = await asyncio.gather(
    redis.evalsha(sha, …, "ip", ip),
    redis.evalsha(sha, …, "ja4", ja4),
    redis.evalsha(sha, …, "ipja4", f"{ip}:{ja4}"),
)

# Phase 2: all writes fire-and-forget (after decision)
asyncio.create_task(_flush_write_batch(writes))
```

**Acceptance criteria:**
- Redis call count per connection: ≤3 (down from 7)
- All rate limiting tests pass unchanged
- New benchmark: cold-cache throughput improves ≥25%
- No change to rate-limit semantics (Lua scripts unchanged)

**Estimated gain:** 1.3–1.5× (savings dominated by 26a; incremental here)
**Estimated effort:** 3–4 days

---

### 26c — Redis Unix Domain Socket

**What:** Change the Redis connection URL from `redis://127.0.0.1:6379` to
`redis:///var/run/redis/redis.sock` (Unix domain socket). Reduces per-RTT
overhead from ~0.5ms to ~0.1ms.

**Config change (`config/proxy.yml`):**
```yaml
redis:
  url: "redis:///var/run/redis/redis.sock"  # was: redis://127.0.0.1:6379
```

**Docker Compose changes:**
```yaml
services:
  redis:
    volumes:
      - redis-sock:/var/run/redis
  proxy:
    volumes:
      - redis-sock:/var/run/redis
volumes:
  redis-sock:
```

**Redis server config:**
```
unixsocket /var/run/redis/redis.sock
unixsocketperm 770
```

**Fallback:** if the socket path does not exist, `config/loader.py` falls back
to the TCP URL automatically. No hard dependency.

**Acceptance criteria:**
- Redis connection uses Unix socket when path exists
- Graceful fallback to TCP when socket unavailable
- Test: `test_redis_unix_socket_fallback` in `tests/integration/`
- New benchmark: `baseline_latency` mean latency improves ≥20%

**Estimated gain:** ~1.25× (saves ~1.5ms per connection with 7 RTTs)
**Estimated effort:** 1 day

---

### 26d — Multi-Process Worker Model

**What:** Run N Python proxy processes on distinct ports (8080, 8083, 8084…).
HAProxy (already present) load-balances TCP connections across them. Each
process is a full, independent proxy instance sharing only Redis for state.

This is the highest-leverage optimisation. It requires zero changes to the
proxy core — just orchestration.

**Architecture:**
```
Internet ──TLS──▶ HAProxy :443 ──TCP (round-robin)──▶ proxy-worker-1 :8080
                                                   ──▶ proxy-worker-2 :8083
                                                   ──▶ proxy-worker-3 :8084
                                                   ──▶ proxy-worker-4 :8085
                              ──▶ Redis :6379 (shared)
```

**HAProxy config fragment:**
```
backend ja4proxy_workers
    balance roundrobin
    server proxy1 127.0.0.1:8080 check
    server proxy2 127.0.0.1:8083 check
    server proxy3 127.0.0.1:8084 check
    server proxy4 127.0.0.1:8085 check
```

**Shared state correctness:**
All security-critical state lives in Redis (rate limits, bans, beaconing,
JA4 sets, AbuseIPDB cache, RDAP findings, analytics). Per-process state is
only:
- `max_per_ip` concurrent connection counter — counts per-process, so effective
  limit is `max_per_ip × N_workers`. Set `max_per_ip` to `ceil(3 / N_workers)`
  to preserve the global semantic (e.g. 2 workers → `max_per_ip=2`).
- In-process LRU cache — each worker has its own; they converge quickly.
- Dial setting — loaded from Redis at startup; hot-reloaded via PubSub, which
  reaches all workers independently.

**Docker Compose additions:**
```yaml
  proxy-worker-2:
    image: ja4proxy
    command: ["python3", "proxy.py", "--port", "8083"]
    environment: *proxy-env
  proxy-worker-3:
    image: ja4proxy
    command: ["python3", "proxy.py", "--port", "8084"]
    environment: *proxy-env
  proxy-worker-4:
    image: ja4proxy
    command: ["python3", "proxy.py", "--port", "8085"]
    environment: *proxy-env
```

**New `make` targets:**
```makefile
start-scaled:   # Start proxy + N workers + HAProxy
    @docker compose -f docker-compose.poc.yml \
                    -f docker-compose.scale.yml up -d

scale-workers N=4:
    @WORKERS=$(N) docker compose -f docker-compose.scale.yml up -d --scale proxy=$(N)
```

**Acceptance criteria:**
- `docker-compose.scale.yml` overlay supports N workers (configurable, default 4)
- HAProxy config routes connections across all workers
- Rate limiting semantics verified with 2-worker test:
  a. IP banned by worker-1 → subsequent connection to worker-2 is also blocked
     (ban:{ip} key in Redis is the source of truth)
  b. Rate limit windows aggregate correctly across workers (all use same
     Redis Lua scripts keyed by IP)
- `max_per_ip` config adjusted per-worker so effective global cap is preserved
- New benchmark: `throughput_scaling` with 4 workers shows ≥3.5× improvement
  vs single worker

**Estimated gain:** N× (measured: linear. 4 workers ≥ 3.5× accounting for
HAProxy overhead)
**Estimated effort:** 2–3 days

---

### 26e — Deferred Write Batching

**What:** Move all post-decision Redis writes (counter increments, event stream
writes, beaconing timestamps) to a background coroutine that flushes every
50ms using Redis pipeline. This removes all write I/O from the hot path.

**Current hot path writes (after decision):**
```python
asyncio.create_task(self._emit_stream_event(ctx, result))   # XADD
asyncio.create_task(self._beaconing_detector.maybe_record(…))# ZADD
# TCP analyser:
await self._redis.hmset(key, {"total": …, "resumed": …})    # HMSET
await self._redis.expire(key, 3600)                          # EXPIRE
await self._redis.zadd(lifespan_key, …)                      # ZADD
```

**Target:** A `WriteBuffer` coroutine that accumulates writes and flushes in
batches of up to 500 or every 50ms (whichever comes first) using
`redis.pipeline(transaction=False)`.

```python
class WriteBuffer:
    def __init__(self, redis, flush_interval_ms=50, max_batch=500): …
    def enqueue(self, op: Callable) -> None: …     # non-blocking
    async def _flush_loop(self) -> None: …         # background task
```

**Stale-write window:** 50ms. Rate limit counters could lag by up to 50ms.
This is acceptable — the write lag is much smaller than the 1s sliding window
and 30s block TTL. Any connection that crosses a rate-limit threshold within
a 50ms window will be caught at the next flush.

**Acceptance criteria:**
- All post-decision writes go through `WriteBuffer`
- Chaos test: `WriteBuffer` full (>500 queued) → overflow logged, oldest
  writes dropped (rate-limit stale, not security-critical path)
- Rate limit tests pass (may need 100ms sleep to allow flush in integration tests)
- New benchmark: `sustained_load` throughput improves ≥10%

**Estimated gain:** ~1.2× (writes are already async; incremental gain)
**Estimated effort:** 2 days

---

### 26f — Benchmark-Validated Capacity Report

**What:** Run the full benchmark suite and a PPv2-enabled `attack_500` test
against the optimised proxy to produce a validated capacity report. This is
the acceptance gate for the phase.

**Requires:**
- Phase 15 PPv2 implementation (or mock source IP injection)
- `bench-tls-backend.py` as the backend target (removes backend bottleneck)
- 4-worker Docker Compose scale overlay from 26d

**Scenarios:**
```
throughput_scaling   (1→2→4→8→16→32 threads)
peak_throughput      (32 threads × 60s)
sustained_load       (8/16/32 threads × 60s each)
attack_500           (with --use-proxy-protocol and fast backend)
```

**Acceptance criteria (Phase 26 overall):**
- Single optimised process: ≥600 conn/s sustained (1-thread peak_throughput)
- 4-worker configuration: ≥2,400 conn/s sustained
- False positive rate: 0% (browser ALPN traffic never blocked)
- attack_500 good-pass%: ≥99% (browsers pass under DDoS load)
- attack_500 bad-block%: as configured by dial (>0% if dial > 0)

---

## Implementation Order

```
Week 1:
  26a  Parallel signal collection     (2–3 days, highest ROI)
  26c  Redis Unix domain socket       (1 day, easy win)

Week 2:
  26b  Redis pipeline batching        (3–4 days)
  26e  Deferred write batching        (2 days)

Week 3:
  26d  Multi-process worker model     (2–3 days)
  26f  Benchmark validation           (2 days)
```

---

## Production Capacity Summary

### Python (this phase delivers):

| Configuration | Expected conn/s | Notes |
|--------------|----------------|-------|
| Current baseline (1 process) | 250–300 | Measured |
| After 26a + 26c (1 process) | 500–650 | Parallel signals + UDS |
| After 26a + 26b + 26c (1 process) | 700–950 | Full single-proc optimisation |
| 2 workers (after all opts) | 1,400–1,900 | Linear scaling |
| 4 workers (after all opts) | 2,800–3,800 | Practical DDoS defence floor |
| 8 workers (after all opts) | 5,600–7,600 | Upper bound on this hardware |

*All estimates for mixed traffic (5% browser bypass, 95% scored). Browser-only
traffic (ALPN bypass) is 40–60% higher as no signal collection runs.*

### Go (Phase 15, for comparison):

| Scenario | Expected conn/s | Notes |
|----------|----------------|-------|
| Pass-through (current) | 2,000+ | Backend is the only limit |
| Full signals, warm cache | 5,000–15,000 | GeoIP + in-process LRU |
| Full signals, mixed traffic | 2,000–8,000 | Redis-limited |
| DDoS (all new IPs) | ~50,000 | Redis Stack + pipeline batching |

*Go is the correct long-term answer for >1,000 conn/s on a single instance.*
*Python horizontal scaling is the correct short-term answer for <3,000 conn/s.*
*For >3,000 conn/s on a single machine, complete Phase 15.*

---

## Redis Impact

This phase introduces no new Redis key patterns. All existing `docs/REDIS_SCHEMA.md`
entries remain valid.

The `WriteBuffer` (26e) introduces a new Prometheus metric:
```
ja4proxy_write_buffer_flush_total{result="ok|overflow"}
ja4proxy_write_buffer_queue_depth   # Gauge
```

---

## Relationship to Other Phases

| Phase | Relationship |
|-------|-------------|
| Phase 15 (Go rewrite) | Phase 26 is the bridge. Run Phase 26 while Phase 15 is finishing. Once Phase 15 is production-ready, retire Phase 26 workers. |
| Phase 14 (production hardening) | Phase 26 must not weaken any Phase 14 security guarantee. max_per_ip adjustment must preserve global per-IP cap semantics. |
| Phase 12 (analytics) | WriteBuffer (26e) must still deliver stream events to analytics. Fire-and-forget enqueue replaces direct create_task. |
| Phase 24 (closed) | Phase 26 is the correct implementation of the intent behind Phase 24 — more throughput from existing investment. |
