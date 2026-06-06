# Phase 159: Radical Performance Investigation & Root-Cause Resolution

> **Status:** IN_PROGRESS
> **Size:** LARGE
> **Owner:** Gemini CLI

## Goal
Conduct a forensic, high-fidelity investigation into the ~350 CPS bottleneck. We will use synchronized microsecond-precision tracing across the entire connection path (Client → Proxy → Backend) to pinpoint exactly where time is being lost.

## High-Rigor Tracing Strategy

### 1. Full-Path Instrumentation
We will instrument all three Go-native components to record the following timestamps using the Client Source Port as a correlation key:

| Event | Location | Description |
| :--- | :--- | :--- |
| **T1: Dial Start** | **Client** | Benchmark worker begins TLS Dial. |
| **T2: Accept** | **Proxy** | `ja4pd` kernel accept of the socket. |
| **T3: Dial Backend** | **Proxy** | `ja4pd` begins dialing the Go Null-Backend. |
| **T4: Backend Accept** | **Backend** | `nullbackend` accepts the proxied connection. |
| **T5: Backend Ready** | **Backend** | `nullbackend` finishes TLS handshake and is ready for data. |
| **T6: Proxy Ready** | **Proxy** | `ja4pd` has connected both ends and begins byte copying. |
| **T7: Client Ready** | **Client** | TLS Dial returns success to the benchmark worker. |

### 2. Forensic Analysis
- **OS/Docker Overhead**: Δ(T2 - T1). Time spent in the Linux/Docker networking stack before the proxy even sees the connection.
- **Proxy Logic Latency**: Δ(T3 - T2). Time spent reassembling ClientHello, calculating JA4, and running the Pipeline.
- **Backend Handshake Cost**: Δ(T5 - T4). Pure TLS handshake time in the Go standard library.
- **Connection Pipeline Lag**: Δ(T7 - T1). The total end-to-end "wait time" for a single connection.

### 3. Root Cause Brainstorming (P-0)
Based on deltas, we will evaluate:
- **I/O Starvation**: Is the Go `net` poller thrashing under 100+ concurrent workers?
- **Context Switch Penalty**: Are we spending more time switching CPU cores than doing TLS math?
- **Redis Sync Blocks**: Is the synchronous `pipeline.Process` holding up the entire accept loop?

## Acceptance Criteria
- [ ] **Synchronized Trace Log**: A CSV/JSON log capturing all T1-T7 events for a sample of 100 connections.
- [ ] **The "Choke Point" Identified**: A definitive conclusion (e.g., "The backend dial is blocking the proxy accept loop").
- [ ] **Fix Implemented**: At least one architectural fix (e.g., Async Backend Dialing) that demonstrably increases CPS.
- [ ] **Verified Report**: An in-depth forensic report documenting the deltas and the resolution.

---

## Strategic Intent
We will stop guessing. This phase uses hard data from every hop of the transaction to prove where the "missing" performance lives.
