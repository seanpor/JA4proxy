# Phase 28 — Python Throughput Hardening - Phase 2: Redis Optimization

Status: COMPLETE

## Goal
Reduce Redis round-trip overhead in the Python proxy by 30-40% through pipeline batching of read/write operations and transitioning to Unix domain sockets for local connections.

## Background
Phase 26 established the foundation for performance (parallel signals, write buffer). Phase 28 focuses on deep-diving into individual signal modules to eliminate sequential Redis dependencies that remained after the broad-stroke optimizations.

### Current Bottlenecks
1.  **TCPAnalyzer Sequential Calls:** Currently performs multiple sequential RTTs for session resumption (HMGET then HMSET+EXPIRE) and connection lifespan (ZADD then ZCARD then ZRANGE).
2.  **TCP Loopback Overhead:** Connection to Redis via `127.0.0.1:6379` adds ~0.3-0.5ms per RTT compared to Unix domain sockets.
3.  **Redundant EXPIRE calls:** Many modules call `EXPIRE` as a separate command instead of using it within a pipeline or Lua script.

---

## Sub-Tasks

### 28a — Redis Pipeline Batching in TCPAnalyzer
**What:** Refactor `TCPAnalyzer` to use Redis pipelines for its I/O operations.
- Combine `hmget`, `hmset`, and `expire` in `_check_session_resumption`.
- Combine `zadd`, `expire`, and `zcard` in `_check_connection_lifespan`.
- Combine `incr` and `expire` in `_check_concurrent_connections` and `_check_tls_alerts`.

**Acceptance Criteria:**
- `TCPAnalyzer` Redis round-trips per connection reduced from ~10 to ≤4.
- All TCP analyzer tests pass.
- No changes to scoring semantics.

### 28b — Unix Domain Socket Integration
**What:** Enable and validate Redis Unix domain socket support across the stack.
- Update `deploy/docker/docker-compose.prod.yml` and `deploy/docker/docker-compose.poc.yml` to mount a shared `redis-sock` volume.
- Update Redis configuration to enable `unixsocket`.
- Update `config/proxy.yml` to use `unix_socket_path`.
- Verify graceful fallback to TCP when socket is missing.

**Acceptance Criteria:**
- Proxy successfully connects to Redis via `/var/run/redis/redis.sock` in Docker environment.
- `baseline_latency` benchmark (mean) improves ≥20%.
- Fallback to TCP verified by manually removing the socket file.

### 28c — Pipeline Batching in Signal Modules (Cleanup)
**What:** Audit other signal modules (`AbuseIPDB`, `RDAP`, `ASNClassifier`) for any remaining sequential Redis calls.
- `ASNClassifier`: Verify MaxMind mmap usage (already high-perf).
- `DNSEnrichment`: Optimize any Redis-backed caching.

**Acceptance Criteria:**
- All I/O-bound signal collection coroutines perform ≤2 Redis RTTs each.

---

## Implementation Plan (TDD)

### 1. Verification
- Run `benchmark_phase26.py` to establish current baseline.
- Run `pytest tests/integration/test_redis_performance.py` (to be created).

### 2. Implementation
- [ ] 28a: Refactor `src/security/tcp_analyzer.py`.
- [ ] 28b: Update Docker Compose files and `config/proxy.yml`.
- [ ] 28c: Audit and refactor remaining modules.

### 3. Validation
- [ ] All unit and integration tests pass.
- [ ] `make check-image-versions` passes.
- [ ] Final benchmark comparison report.

## Acceptance Criteria (Phase 28 Overall)
- [ ] Redis RTT overhead per connection reduced by ≥30%.
- [ ] Single-process throughput (peak) ≥ 700 conn/s.
- [ ] No regression in security enforcement or signal accuracy.
