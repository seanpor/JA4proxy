<!--
title: Benchmark_History
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — Benchmark History

Record benchmark results here after each phase. Format: date, phase, metric, value, git commit hash.

---

## 2026-03-07 — Phase 8 (Spamhaus DROP/EDROP + rate limiting wired)

**Commit:** `eca7998` (latest on main as of 2026-03-07)
**Environment:** Python 3.12, single proxy instance, fakeredis in-process

| Benchmark | Value | Notes |
|-----------|-------|-------|
| Bypass decisions (ALPN/JA4 whitelist) | ~12 µs | In-process only; no Redis |
| Scoring path (full signal collection) | ~20 µs | In-process; Redis mocked |
| Full `handle_connection` — ALLOW | ~5.7 ms | Real Redis (~0.5 ms/call) |
| Full `handle_connection` — BLOCK | ~1.4 ms | Fewer Redis calls on block path |
| Throughput (real Redis, single instance) | ~350 conn/s | GIL + synchronous Redis |
| Throughput (in-process only) | ~550 conn/s | No Redis I/O |
| JA4 fingerprint computation | < 100 µs | Scapy parsing included |
| CIDR trie lookup (pytricia) | < 10 µs | In-process; Spamhaus DROP list |
| Local LRU cache hit | < 1 µs | In-process dict lookup |

**Bottleneck:** Python GIL + synchronous Redis calls (~0.5 ms each).
**Ceiling:** ~350 conn/s with real Redis. Phase 15 Go rewrite is the correct solution for throughput.

**Load test results (traffic generator, 20 workers, 60s):**

| Metric | Value |
|--------|-------|
| Legitimate traffic false positive rate | 0% |
| Malicious traffic blocked | N/A — traffic generator uses Python ssl stack, produces different JA4 fingerprints than real C2 tools; blacklist cannot match |
| p99 latency added by proxy | < 10 ms |

**Notes:**
- Rate limiting (`MultiStrategyRateTracker`) wired into pipeline as of 2026-03-07.
- JA4 fingerprint label truncation (`[:16]`) fixed — full fingerprints now appear in Prometheus.
- pytricia added to requirements.txt (was missing; caused startup crash).
- Mock backend TLS thread starvation fixed (settimeout(10) on SSL socket).
