# Phase 158: Revitalizing the Marketing & Technical Brochure

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 157
> **Owner:** Gemini CLI

## Goal
Update the official JA4proxy PDF brochure (`docs/pdf/brochure/`) to accurately reflect the v2.0.0 Go-native architecture, elite performance metrics, and production-ready status.

## Scope

### 1. Narrative Modernization
- **Go-First Messaging**: Remove all references to "Python implementation" or "Go rewrite in progress". The system is now 100% Go-native.
- **Elite Performance**: Lead with the **272ns** allow-path latency and the **3.6M conn/s** theoretical capacity.
- **Architectural Clarity**: Describe the two-binary model (`ja4pd` Engine + `ja4p` Toolset).

### 2. Metric Integration
- **Performance Matrix**: Update the throughput tables using the data from Phase 157 (Scenario A, B, C).
- **Resource Footprint**: Highlight the < 12MB RAM signature and sub-50ms startup time.

### 3. Feature Set Alignment
- **Integrated Benchmarking**: Mention the built-in `ja4p test benchmark` capability.
- **Cluster Sync**: Update the "Horizontal Scaling" section to reflect the now-integrated `ja4p cluster sync` mesh agent.
- **Security Hardening**: Reference the completed Phase 200 security posture (TLS for Redis, PROXY v2 TLVs, etc.).

### 4. Visual & Structural Polish
- **Status Update**: Move from "tested proof of concept" to "production-ready enterprise security proxy".
- **Call to Action**: Update repository links and contact points if necessary.

## Acceptance Criteria
- [ ] **Zero Legacy Bloat**: No mentions of Python on the hot path or "rewrite in progress".
- [ ] **Data Accuracy**: All latency and throughput figures match the certified `PERFORMANCE_SNAPSHOT.json`.
- [ ] **Build Success**: The LaTeX source compiles cleanly into `brochure.pdf`.
- [ ] **Professional Tone**: The brochure reads as a finished enterprise-grade security product.

---

## Strategic Intent
The brochure is often the first point of contact for CISOs and Enterprise Architects. This phase ensures that our physical documentation is as advanced as our code, providing a professional "leave-behind" that justifies the adoption of JA4proxy in critical infrastructure.
