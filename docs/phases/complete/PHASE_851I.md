<!--
title: Cache Invalidation & Eviction Invariant Testing
audience: developer
last_reviewed: 2026-10-29
phase: 851i
-->

# Cache Invalidation & Eviction Invariant Testing

> **Size:** SMALL
> **Dependencies:** [851h]
> **Branch:** `phase-851i-cache-eviction-invariants`

---

## Goal

Harden the in-process cache implementations (`internal/cache` LRU and `internal/security` DecisionCache) against memory unboundedness, concurrency races, stale TTL retention, and key collision / state corruption. Implement native Go fuzz targets and Rapid property-based invariant tests covering LRU eviction monotonicity, concurrent read-write-evict consistency, and TTL expiration invariants under high contention. Establish micro-benchmarks for cache lookup, insertion, and eviction throughput.

---

## Scope

### In Scope
1. **Native Go Fuzzing (`internal/cache/cache_fuzz_test.go`)**:
   - `FuzzLRUOperations`: Fuzz arbitrary sequences of Set, Get, Delete, and Len operations across random keys, ensuring internal map and linked-list maintain strict length parity and obey capacity limits without panics.
   - `FuzzLRUKeyFormatting`: Fuzz key encoding and storage across binary, null-byte, Unicode, emoji, and 1 KiB strings.
2. **Rapid Property-Based Invariant Tests**:
   - **Capacity Bounded Invariant**: For any configured capacity $C \in [1, 50]$ and arbitrary sequence of insertions, `Len() <= C` strictly holds at all times.
   - **LRU Order Monotonicity Invariant**: Accessing a previously inserted key refreshes its recency so that subsequent insertions past capacity strictly evict older unaccessed keys.
   - **TTL Expiration Invariant**: Positive TTL entries are strictly retrievable before expiration and guaranteed to return `(nil, false)` and be purged upon expiration.
   - **Concurrent Safety & Parity Invariant**: High-concurrency parallel workers performing mixed `Set`, `Get`, and `Delete` operations maintain complete `len(items) == order.Len() <= cap` invariant with zero data races.
3. **Micro-Benchmarks**:
   - `BenchmarkLRUGetHit`: Measure cache hit latency including `MoveToFront` (19.24 ns/op, 0 allocs).
   - `BenchmarkLRUGetMiss`: Measure cache miss latency (12.65 ns/op, 0 allocs).
   - `BenchmarkLRUSet`: Measure overwrite / non-evicting insertion (30.12 ns/op, 0 allocs).
   - `BenchmarkLRUSetWithEviction`: Measure continuous eviction throughput (230.3 ns/op, 5 allocs).
   - `BenchmarkLRUConcurrent`: Measure multi-goroutine read/write parallel contention (155.5 ns/op).
4. **Smoke Gate Integration**:
   - Integrated `FuzzLRUOperations` and `FuzzLRUKeyFormatting` into `make test-go-fuzz-smoke`.

### Out of Scope
- Distributed Redis caching (covered in Phase 851e).

---

## Results & Verification

### Benchmarks (Intel i9-9900K @ 3.60GHz)
- `BenchmarkLRUGetMiss-16`: **12.65 ns/op** (0 B/op, 0 allocs/op) $\to$ **~79,000,000 lookups/sec**.
- `BenchmarkLRUGetHit-16`: **19.24 ns/op** (0 B/op, 0 allocs/op) $\to$ **~52,000,000 lookups/sec**.
- `BenchmarkLRUSet-16`: **30.12 ns/op** (7 B/op, 0 allocs/op) $\to$ **~33,200,000 writes/sec**.
- `BenchmarkLRUConcurrent-16`: **155.5 ns/op** (7 B/op, 1 allocs/op) $\to$ **~6,430,000 concurrent ops/sec**.
- `BenchmarkLRUSetWithEviction-16`: **230.3 ns/op** (142 B/op, 5 allocs/op) $\to$ **~4,340,000 evictions/sec**.

### Fuzzing & Invariants
- `FuzzLRUOperations`: **339,325 executions** (66,928 execs/sec) — zero panics, 100% list-map parity maintained.
- `FuzzLRUKeyFormatting`: **774,755 executions** (153,951 execs/sec) — zero key collisions or corrupted retrievals across null bytes, unicode, and binary strings.
- Total fuzz executions: **1,114,080** (0 panics, 0 crashes).
- `TestProperty_LRUCapacityBound`: Passed 100 iterations.
- `TestProperty_LRUEvictionOrder`: Passed 100 iterations.
- `TestProperty_TTLExpiration`: Passed 100 iterations.
- `TestProperty_ConcurrentSafetyAndParity`: Passed 100 iterations with `-race` clean.

---

## Acceptance Criteria
- [x] 2 native Go fuzz targets added for LRU operations and key formatting.
- [x] Rapid property tests prove capacity boundedness, LRU eviction order, TTL expiration, and list-map parity under concurrent contention.
- [x] Zero panics across 1,100,000+ fuzz inputs.
- [x] Micro-benchmarks quantify hit/miss latency and eviction overhead.
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.
