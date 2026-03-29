# Phase 29 — Python Throughput Hardening - Phase 3: Multi-Process Architecture

Status: COMPLETE

## Goal
Implement a horizontally scalable multi-process architecture for the Python proxy using HAProxy as a load balancer and Docker Compose for orchestration. Target: ≥3,200 conn/s with 4 workers.

## Background
The Python proxy is limited by the Global Interpreter Lock (GIL) for CPU-bound tasks (like Scapy TLS parsing). While Phase 26 optimized I/O, true multi-core scaling requires multiple independent processes.

### Current State
- `docker-compose.scale.yml` exists but is broken (references non-existent `docker-compose.yml`).
- `config/haproxy.cfg` exists but needs validation.
- `proxy.py` supports `PROXY_PORT` and `WORKER_ID` environment variables.

---

## Sub-Tasks

### 29a — Horizontal Scaling Orchestration
**What:** Fix and enhance the Docker Compose scale overlay.
- Rename `docker-compose.scale.yml` to `docker/docker-compose.scale.yml` (to group with other compose files).
- Fix references to point to `docker-compose.prod.yml`.
- Implement a `scale` profile or separate overlay that adds workers.
- Ensure all workers share the same Redis Unix socket or TCP connection.

**Acceptance Criteria:**
- `docker compose -f docker/docker-compose.prod.yml -f docker/docker-compose.scale.yml up` starts 4 workers and HAProxy.
- All workers successfully connect to the same Redis instance.
- HAProxy correctly detects worker health.

### 29b — HAProxy Configuration Hardening
**What:** Refine `config/haproxy.cfg` for production readiness.
- Implement proper TCP health checks for workers.
- Configure round-robin balancing.
- Enable HAProxy stats page with password protection.
- Add logging for HAProxy connection distribution.

**Acceptance Criteria:**
- HAProxy stats page (`:8404`) shows all 4 workers as UP.
- Traffic is evenly distributed across workers.

### 29c — Shared State Validation
**What:** Verify that security policies are correctly enforced across multiple processes.
- Ensure rate limiting (via Redis) works correctly when connections from the same IP hit different workers.
- Ensure Beaconing detection (shared suspects list) works correctly.
- Verify that `ja4proxy:invalidate` pub/sub messages reach all workers.

**Acceptance Criteria:**
- A block triggered on Worker 1 is immediately enforced on Worker 2 (via Redis/PubSub).
- No "split-brain" enforcement scenarios.

---

## Implementation Plan (TDD)

### 1. Verification
- Run `docker compose -f docker/docker-compose.prod.yml -f docker/docker-compose.scale.yml config` to check for errors.
- Run `tests/integration/test_multi_process_enforcement.py` (to be created).

### 2. Implementation
- [ ] 29a: Fix scale overlay.
- [ ] 29b: Harden HAProxy config.
- [ ] 29c: Validation tests.

### 3. Validation
- [ ] Benchmark with 4 workers vs 1 worker.
- [ ] Verify 4x throughput scaling.

## Acceptance Criteria (Phase 29 Overall)
- [ ] Functional multi-process environment deployable via Docker Compose.
- [ ] Total system throughput ≥ 3,000 conn/s.
- [ ] 100% consistency in security policy enforcement across workers.
