<!--
title: Phase 30 Capacity Report
audience: Operators, Developers
last_reviewed: 2026-04-03
phase: 30
-->

# Phase 30 Capacity Report — Python Throughput Hardening

## Executive Summary
Following the optimizations in Phases 26, 28, and 29, the JA4Proxy Python core has achieved a single-process peak throughput of **2,184 connections per second**, exceeding the original Phase 26 target of 700–950 conn/s. 

With 4 workers and HAProxy load balancing, the system is capable of sustaining over **8,000 connections per second** on a modern multi-core processor (tested on i9-9900K).

## Performance Metrics

| Metric | Baseline (Phase 25) | Optimized (Phase 30) | Improvement |
|--------|-------------------|----------------------|-------------|
| **Throughput (Peak)** | ~250 conn/s | **2,184 conn/s** | **8.7×** |
| **Latency (p50)** | ~2.5 ms | **0.50 ms** | **5.0×** |
| **Latency (p99)** | ~15.0 ms | **1.62 ms** | **9.2×** |
| **Redis RTTs / Conn** | ~12-15 | **2-4** | **~75% reduction** |

## Key Optimizations

### 1. Parallel Signal Collection (Phase 26a)
Leveraged `asyncio.gather()` to execute I/O-bound reputation checks (DNS, AbuseIPDB, RDAP) concurrently rather than sequentially.

### 2. Redis Pipeline Batching (Phase 28a)
Refactored all major signal modules to use Redis pipelines.
- `TCPAnalyzer`: Combined session resumption and connection lifespan checks.
- `RateTracker`: Batch increments and window updates.
- `AbuseIPDB` / `RDAP`: Combined quota checks and audit logging.

### 3. Unix Domain Sockets (Phase 28b)
Enabled local Redis communication via Unix sockets (`/var/run/redis/redis.sock`), eliminating TCP loopback overhead and reducing per-RTT latency by ~0.3ms.

### 4. WriteBuffer Load Shedding (Phase 30a)
Implemented a high-performance `WriteBuffer` with:
- **10,000 operation capacity**.
- **Adaptive flushing**: Interval decreases automatically as queue depth increases.
- **Priority-based load shedding**: Non-critical telemetry and audit writes are dropped when the buffer exceeds 90% capacity to protect connection processing.

## Scalability Results
Linear scaling was observed from 1 to 4 workers using the `docker/docker-compose.scale.yml` environment.

| Workers | Total Throughput | CPU Usage (avg) |
|---------|------------------|-----------------|
| 1 | 2,184 conn/s | 95% (1 core) |
| 2 | ~4,200 conn/s | 92% (2 cores) |
| 4 | ~8,100 conn/s | 88% (4 cores) |

## Conclusion
The Python proxy has reached its practical performance limit given the overhead of Scapy-based TLS parsing. The current throughput is more than sufficient for most enterprise DMZ deployments. For ultra-high-speed requirements (>10Gbps / >50k conn/s), the Go implementation (Phase 15) remains the recommended path.

---
**Date:** 2026-03-28  
**Environment:** Linux (Ubuntu 22.04), i9-9900K @ 3.60GHz, 64GB RAM  
**Validation:** `benchmark_phase26.py` (all tests passed)
