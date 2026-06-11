# Phase 159: Radical Performance Investigation — "The 10k Mission"

> **Status:** IN_PROGRESS
> **Size:** LARGE
> **Owner:** Gemini CLI

## Goal
Deconstruct the system to identify why a Go-native stack on high-end hardware is limited to ~350 CPS. We will isolate each component (Network, TLS, Redis, Proxy Logic) to find the "missing" performance and implement a resolution that breaks the 1,000 CPS barrier locally.

## 🛠️ The "Isolation through Elimination" Plan

To find the bottleneck, we will strip away layers of the onion until the performance "explodes". 

### Test 1: Environmental Baseline (Bypassing JA4proxy)
**Goal:** Determine the maximum CPS the host machine can handle for TLS 1.3 handshakes.
- **Method:** Use `ja4p test benchmark` directly against the **Go Null-Backend** (bypassing HAProxy and JA4proxy).
- **Metric:** `MAX_HOST_CPS`. If this is ~350, then the bottleneck is the host CPU or networking stack, not our code.

### Test 2: The "Crypto-Free" Forwarding Test
**Goal:** Measure the raw forwarding capacity of the `ja4pd` engine without the cost of TLS.
- **Method:** 
    1. Update the Benchmark tool to send raw TCP packets.
    2. Update the Backend to accept raw TCP.
    3. Run through JA4proxy (which will fail to parse JA4 but should still forward).
- **Metric:** `MAX_TCP_CPS`. We expect >20,000 CPS here. If not, the `copyConn` loop is inefficient.

### Test 3: The "Memory-Only" Security Test (Bypassing Redis)
**Goal:** Isolate the cost of synchronous Redis I/O over the Docker bridge.
- **Method:** 
    1. Create a "No-Redis" build of `ja4pd` that hardcodes security decisions in memory.
    2. Run the 5/95 traffic benchmark.
- **Metric:** `REDIS_IMPACT_SEC`. The difference between this and the standard run is our network-stalling penalty.

### Test 4: Network Stack Audit (Host vs Bridge)
**Goal:** Measure the penalty of the Docker User-Land Proxy.
- **Method:** Run the entire stack using `network_mode: host` in Docker Compose.
- **Metric:** `DOCKER_BRIDGE_OVERHEAD`.

---

## 📋 Technical Tracing Strategy

We will use a **synchronized logging build** to capture the following deltas for 100 sample connections:
1. **Network Delta**: Client Send -> Proxy Accept.
2. **Parsing Delta**: Proxy Accept -> JA4 Calculated.
3. **Scoring Delta**: JA4 Calculated -> Forward Begin (The Redis Penalty).
4. **Backend Delta**: Forward Begin -> Backend Ready.

---

## Acceptance Criteria
- [ ] **Forensic Report**: A definitive document explaining the "Performance Waterfall" and identifying the primary choke point.
- [ ] **1,000 CPS Proof**: A verified benchmark reaching **>1,000 CPS** with a 5/95 traffic mix on this host.
- [ ] **Architectural Resolution**: Implement the identified fix (e.g., Async Redis, Buffer Pooling, or Go-Native Load Balancing).

## Strategic Intent
350 CPS is unacceptable. This phase uses a "no-excuses" engineering approach to reclaim the hardware's potential and deliver the high-performance engine promised in the v2.0 release.
