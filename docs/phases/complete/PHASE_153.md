# Phase 153: Post-Release v2.0.x Performance Audit

> **Status:** COMPLETE
> **Size:** MEDIUM
> **Owner:** Gemini CLI

> **Note:** This record was reconstructed in Phase 224 to resolve manifest drift
> — the phase was completed (commit `7fcf870e`) but its plan document was never
> committed. The content below reflects the phase's actual deliverable.

## Goal

Conduct a definitive, high-load performance audit of the v2.0.x Go proxy daemon
(`ja4pd`): measure throughput and tail latency under enterprise-scale concurrency
(1,000+ conn/s) to establish a final, verified performance baseline for the
release.

## Deliverable

The audit produced the signed performance baseline at
[`docs/reports/PERFORMANCE_CERTIFICATE_V2.0.md`](../../reports/PERFORMANCE_CERTIFICATE_V2.0.md),
covering:

- **Internal latency matrix** (micro-benchmarks) isolating the security pipeline
  from network I/O — ALPN-bypass, full-scored-path, and JA4X-active scenarios.
- **System throughput** (macro-benchmarks) end-to-end through HAProxy + JA4proxy
  in a standard Docker-bridge environment.

## Outcome

The certificate is the authoritative v2.0.x performance baseline; the numbers it
records are reused by the marketing brochure and the reference manual. The
benchmark commands are standardized under `make bench-all` (Phase 224).

## Acceptance Criteria

1. Verified throughput at ≥1,000 conn/s concurrency — **met** (see certificate).
2. Tail-latency (p99) measured for the key traffic scenarios — **met**.
3. Results published to `docs/reports/PERFORMANCE_CERTIFICATE_V2.0.md` — **met**.
