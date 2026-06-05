# Phase 156: Operational Benchmarking & Observability Upgrades

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 155
> **Owner:** Gemini CLI

## Goal
Transform the integrated Go benchmark tool (`ja4p test benchmark`) from a simple traffic generator into a professional system validation utility suitable for high-trust performance audits.

## Scope

### 1. Advanced Latency Analytics
- **Percentile Calculation**: Implement logic to track and display **p50, p95, and p99** latencies.
- **Microsecond Precision**: Ensure timing capture is accurate to the microsecond to identify proxy jitters.

### 2. Live Observability
- **Heartbeat Reporting**: Print a periodic (default 5s) status line showing current Throughput (TPS), Latency, and Error count.
- **Totalizer Display**: Show a real-time count of total connections made during the test.

### 3. Fault Tolerance & Interactivity
- **Signal Handling**: Implement graceful handling of `SIGINT` (Ctrl+C). Upon interrupt, the tool must finalize its current buffers and print the full summary report for data collected so far.
- **Connection Deadlines**: Implement strict I/O timeouts to prevent "hanging" workers if the proxy becomes unresponsive.

### 4. Integration-Ready Output
- **Structured Format**: Add an `--output json` flag to generate a machine-readable result set.

## Acceptance Criteria
- [ ] **Tail Latency**: Final report includes verified p95 and p99 latency values.
- [ ] **Graceful Exit**: Pressing Ctrl+C during a test displays `(Interrupt received, finalizing...)` and prints the final report.
- [ ] **Live Progress**: Test prints a progress update at least every 5 seconds.
- [ ] **JSON Schema**: `--output json` produces a valid JSON object matching the `PERFORMANCE_SNAPSHOT.json` structure.
- [ ] **Verified Math**: Unit tests prove the percentile calculation logic is accurate.

---

## Strategic Intent
This phase provides Cyber Ops teams with the data they need to justify JA4proxy's inclusion in high-traffic production paths. By surfacing "Tail Latency" and providing a "Graceful Interruption" flow, we make the tool predictable and professional for real-world audits.
