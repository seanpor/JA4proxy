# Phase 159: Radical Performance Investigation & Optimization

> **Status:** PROPOSED
> **Size:** LARGE
> **Depends on:** Phase 157
> **Owner:** Gemini CLI

## Goal
Conduct a forensic "Deep Dive" investigation into the end-to-end performance bottleneck. We must identify why a Go-native stack on high-end hardware (i9-9900K @ 5GHz) is achieving only ~350 CPS when micro-benchmarks suggest a capacity of >1M CPS.

## Scope

### 1. Forensic Transaction Tracing
- **Hop-by-Hop Latency**: Instrument the system to measure the exact time spent at each stage for a single connection:
    1.  Client Handshake Initialization
    2.  HAProxy Processing (TCP Mode)
    3.  JA4proxy Parsing (ClientHello)
    4.  JA4proxy Scoring (Pipeline + Redis)
    5.  Backend Handshake Completion (Mock Backend)
- **Bottleneck Isolation**: Run isolated benchmarks bypassing HAProxy and the Mock Backend to determine their contribution to the latency ceiling.

### 2. Deep Profiling (pprof)
- **CPU Profiling**: Run `ja4pd` with the Go profiler (`pprof`) active during a 5-minute sustained load.
- **Lock Contention**: Identify any mutex contention or sequential bottlenecks in the connection accept/forward loop.
- **Allocation Audit**: Verify if heap allocations are spiking under real-world I/O compared to micro-benchmarks.

### 3. Environment & Infrastructure Audit
- **Docker Networking**: Analyze the overhead of the Docker bridge and the `docker-proxy` user-land process. Compare with `network: host` performance.
- **System Limits**: Check and optimize host-level TCP settings (`ip_local_port_range`, `tcp_tw_reuse`, `file-max`).
- **Redis Saturation**: Profile Redis latency under load to see if the scoring pipeline is waiting on synchronous I/O.

### 4. Brainstorming & Architecture Pivot
- Based on findings, evaluate if we need to:
    - Replace the Python Mock Backend with a Go version.
    - Implement more aggressive Redis pipelining.
    - Switch to an epoll-based raw socket listener if the Go `net` stack is the bottleneck.

## Acceptance Criteria
- [ ] **Bottleneck Identified**: A definitive report explaining exactly where the "missing" 99.9% of performance is being lost.
- [ ] **Isolated Speed Proof**: Demonstration of the JA4proxy engine reaching >10,000 CPS in an optimized local environment.
- [ ] **Infrastructure Optimization**: Verified improvements in Docker/Host network configuration.
- [ ] **Trace Logs**: Detailed timing logs for 100 sample transactions showing sub-millisecond precision for every hop.

---

## Strategic Intent
We have the most efficient TLS parser in the market (272ns). If the system-wide experience doesn't reflect that, our architectural advantage is lost. This phase is about reclaiming that performance and proving the "Ultra-Lite" promise on real-world hardware.
