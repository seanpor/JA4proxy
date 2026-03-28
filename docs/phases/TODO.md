# JA4proxy Phase TODO List

This document tracks the remaining work for both historical phases (gaps identified post-completion) and upcoming planned phases. Each item links to a detailed, actionable TDD work plan.

## 🔴 Critical Gaps in Completed Phases (<= 15)

### Phase 15 — Go Rewrite
*   **Gap:** Lua scripts not using //go:embed
*   **Gap:** JA4X missing in Go pipeline
*   **Status:** **PARTIAL** (10-50x throughput improvement via CPython/Go transition.)
*   **Action Plan:** [PHASE_15_WORK_PLAN.md](PHASE_15_WORK_PLAN.md)

---

## 🟡 Phases In Progress

---

## 🔵 Planned & Open Phases

### Phase 13 — Management UI
*   **Status:** **DEFERRED** (FastAPI + React dashboard for real-time monitoring.)
*   **Action Plan:** [PHASE_13_WORK_PLAN.md](PHASE_13_WORK_PLAN.md)

### Phase 22 — Backup System Enhancements - Phase 1: Core Features
*   **Status:** **PROPOSED** (Add backup scheduling, pipeline batching, and restore validation. Target: Production-ready backup system.)
*   **Action Plan:** [PHASE_22_WORK_PLAN.md](PHASE_22_WORK_PLAN.md)

### Phase 23 — Advanced Traffic Intelligence - Phase 1: Threat Intelligence Integration
*   **Status:** **PROPOSED** (Integrate external threat intelligence feeds (AbuseIPDB, AlienVault OTX, GreyNoise). Target: Real-time IP reputation.)
*   **Action Plan:** [PHASE_23_WORK_PLAN.md](PHASE_23_WORK_PLAN.md)

### Phase 28 — Python Throughput Hardening - Phase 2: Redis Optimization
*   **Status:** **PROPOSED** (Add Redis pipeline batching and Unix domain socket support. Target: 30-40% Redis latency reduction.)
*   **Action Plan:** [PHASE_28_WORK_PLAN.md](PHASE_28_WORK_PLAN.md)

### Phase 29 — Python Throughput Hardening - Phase 3: Multi-Process Architecture
*   **Status:** **PROPOSED** (Implement multi-process worker model with Docker Compose and HAProxy load balancing. Target: Linear scaling to 4 workers.)
*   **Action Plan:** [PHASE_29_WORK_PLAN.md](PHASE_29_WORK_PLAN.md)

### Phase 30 — Python Throughput Hardening - Phase 4: Write Optimization & Benchmarking
*   **Status:** **PROPOSED** (Add deferred write batching and comprehensive benchmark validation. Target: Final performance report.)
*   **Action Plan:** [PHASE_30_WORK_PLAN.md](PHASE_30_WORK_PLAN.md)

### Phase 31 — Advanced Traffic Intelligence - Phase 2: Geographical Intelligence
*   **Status:** **PROPOSED** (Add GeoIP lookup and country-based blocking capabilities. Target: Geographical threat analysis.)
*   **Action Plan:** [PHASE_31_WORK_PLAN.md](PHASE_31_WORK_PLAN.md)

### Phase 32 — Advanced Traffic Intelligence - Phase 3: Attacker Attribution
*   **Status:** **PROPOSED** (Implement attacker fingerprinting and behavioral correlation. Target: Advanced threat detection.)
*   **Action Plan:** [PHASE_32_WORK_PLAN.md](PHASE_32_WORK_PLAN.md)

### Phase 33 — Advanced Traffic Intelligence - Phase 4: Documentation Diagrams
*   **Status:** **PROPOSED** (Standardize all documentation diagrams to Mermaid format for consistent rendering.)
*   **Action Plan:** [PHASE_33_WORK_PLAN.md](PHASE_33_WORK_PLAN.md)

### Phase 34 — APT Resilience & Infrastructure Hardening
*   **Status:** **PROPOSED** (Defense-in-depth: Parser isolation, Redis mTLS/ACLs, long-tail correlation, and strict container seccomp profiles.)
*   **Action Plan:** [PHASE_34.md](PHASE_34.md)

### Phase 35 — Advanced APT Countermeasures & Integrity Enforcement
*   **Status:** **PROPOSED** (Proactive defense: Hardware-rooted integrity, eBPF-based kernel-level enforcement, honey-fingerprints, and two-stage seccomp lockdown.)
*   **Action Plan:** [PHASE_35.md](PHASE_35.md)

### Phase 36 — Go Test Quality & Parity Gaps
*   **Status:** **PROPOSED** (Fix broken JA4 fixture parity test, add real certificate JA4X tests, add cross-language JA4X parity, extended fingerprint family parity, and benchmark coverage.)
*   **Action Plan:** [PHASE_36.md](PHASE_36.md)
