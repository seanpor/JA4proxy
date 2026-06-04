# Phase 138: Hot-Path Performance Optimization & Zero-Copy Refactoring

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 129
> **Owner:** Gemini CLI

## Goal
Improve Go proxy throughput and reduce tail latency by optimizing memory allocations and refactoring the security pipeline for zero-copy operations.

## Scope
- **Allocation Audit**: Use `pprof` to identify and eliminate unnecessary heap allocations in the `internal/security` hot path.
- **Zero-Copy SNI/ALPN**: Refactor the ClientHello parser to use string headers/slices directly from the buffer without duplicating memory.
- **Redis PubSub Optimization**: Optimize the blocklist refresh logic to minimize RWMutex contention during high-churn update events.
- **Benchmarking**: Establish a new baseline for "allow-path" latency (target < 500ns) and "block-path" throughput.

## Acceptance Criteria
- [ ] 20% reduction in per-connection memory allocations.
- [ ] "Allow-path" latency reduced from ~733ns to < 500ns.
- [ ] Zero performance regression under high-churn Redis PubSub load.
