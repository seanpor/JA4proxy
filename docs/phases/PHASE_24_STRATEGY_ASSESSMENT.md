# PHASE 24 — Go Strategy Assessment: Minimal Component vs Comprehensive Rewrite

Status: CLOSED (premise refuted by benchmarks; see Phase 26 and Phase 15)

> **TL;DR:** The minimal Go component (gRPC-based TLS parser) was based on a false
> premise. TLS parsing is not the bottleneck. This phase is closed. See Phase 26
> (Python throughput hardening) and Phase 15 (full Go rewrite) instead.

---

## Original Proposal

The original Phase 24 proposed a "hybrid" architecture where a small Go component
(500–2,000 lines) handled TLS ClientHello parsing and handed the result to Python
via gRPC, claiming 8–15× throughput improvement in 2–4 weeks.

---

## Why the Premise Was Wrong

### The bottleneck is not TLS parsing

The claim was "TLS ClientHello parsing consumes 80–90% of CPU time." Benchmark
data disproves this:

```
Python single-threaded, sequential connections: 248 conn/s
CPU usage at 248 conn/s on i9-9900K (16-core): <5% of one core
```

TLS ClientHello parsing is deterministic byte manipulation on 200–500 bytes.
At 250 conn/s it consumes ≈15–30ms of CPU per second. That is unmeasurable
against a 16-core machine.

### The real bottlenecks are:

| Bottleneck | Evidence |
|------------|---------|
| Redis RTT on hot path | 5–7 sequential Redis round trips per connection (2.5–3.5ms at 0.5ms/RTT) |
| asyncio single-threaded event loop | Collapses at 2+ concurrent clients from same IP (measured: 248→6 conn/s) |
| Per-IP concurrent cap (Phase 14c) | `max_per_ip=3` tarpits concurrent load; 12 threads from one IP → 6 conn/s |
| Signal collection is sequential | 8 signal modules called one-at-a-time; most are independent |

### The gRPC IPC would create a new bottleneck

A gRPC round-trip adds 0.5–2ms per connection — the same order of magnitude as
a Redis call. At 500 conn/s that is 250–1,000ms of extra latency budget
consumed by the Go↔Python handoff. Moving TLS parsing to Go while keeping
all Redis operations in Python leaves the dominant bottleneck untouched and
adds a new one.

### Architectural complexity with no net gain

Current stack: Python + Redis (2 technologies)
Proposed stack: Python + Go + gRPC + Redis (4 technologies)

Every debugging session would cross a process boundary. Every deployment would
need two binaries coordinated. The PPv2-handling bug demonstrated in the
attack_500 benchmark shows exactly this class of failure.

---

## Correct Alternatives

### For ≤500 conn/s (immediate need):
Two Python instances behind the existing HAProxy. HAProxy is already present.
Redis handles all shared security state. Takes 20 minutes to configure.
This is documented and recommended in Phase 26.

### For 500–1,000 conn/s (2–3 weeks):
Phase 26: Python throughput hardening. Four targeted optimizations
(parallel signal collection, Redis pipeline batching, Unix socket, multi-process
workers) increase single-server Python capacity to ~800–1,000 conn/s per
process, or 3,200–7,200 conn/s with 4–8 processes on this hardware.

### For 2,000–50,000 conn/s (4–6 weeks remaining):
Phase 15: Complete the Go rewrite. The skeleton is ~60% done.
Signal modules compile and fail-open but need wiring to data sources.
PPv2 parsing needs implementing (~100 LOC). Prometheus endpoint needed.
Expected ceiling: 2,000–8,000 conn/s (mixed traffic, Redis-limited),
5,000–15,000 conn/s (warm cache), ~50,000 conn/s (DDoS, Redis Stack).

---

## Benchmarks That Informed This Decision

All runs on: Intel i9-9900K, 16 cores, 62GB RAM, Linux 6.17.9, Go 1.26.1,
Python 3.10.12, Redis (Docker), mock TLS backend.

### Full benchmark suite (2026-03-25_18-08-44)

| Scenario | Go conn/s | Python conn/s | Speedup |
|----------|-----------|---------------|---------|
| throughput_scaling (1 thread) | 335 | 248 | 1.3× |
| peak_throughput (32 threads) | 244 | 16 | 15.3× |
| sustained_load | 250 | 16 | 15.7× |
| warm_cache | 254 | 4 | 63.7× |
| cold_cache | 254 | 4 | 63.5× |
| burst_load | 326 | 16 | 20.4× |

*Note: Python >1 thread collapses due to per-IP concurrent cap from single
source IP in benchmark. Go is backend-limited (mock backend ~250–335 TLS/s).
All Go signals score 0 → allow (Phase 15 gap, not a correctness baseline).*

### DDoS simulation (2026-03-25_20-12-46, no PPv2)

| Proxy | conn/s | Good pass % | Bad block % |
|-------|--------|-------------|-------------|
| Python | 6 | 0% | 100% |
| Go | 246 | 100% | 0% |

*Python 6 conn/s = tarpit rate from per-IP concurrent cap (12 concurrent from
127.0.0.1 → max_per_ip=3 → 9 tarpited × 2s timeout ÷ 12 threads = 6 conn/s).
This is correct security behaviour, not a bug.*

*Go 246 conn/s = backend-limited. 0% bot detection = all signals score 0
(Phase 15 gap: signal modules compile but not wired to real data sources).*

---

## Conclusion

Phase 24 is closed. The minimal Go component approach offers no net advantage
over the correct alternatives. Development effort is better spent on:

1. **Phase 26** — Python throughput hardening (immediate, low risk, ~2 weeks)
2. **Phase 15** — completing the Go rewrite (~4–6 more weeks to production-ready)

The "minimal component" recommendation from the original document assumed a
bottleneck that does not exist. Always profile before architecting.

---

*Closed: 2026-03-26. Decision based on benchmark runs in
`reports/benchmark/2026-03-25_*/`.*
