# Phase 157: Standardized Performance Matrix & Reproducibility Audit

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 156
> **Owner:** Gemini CLI

## Goal
Create a definitive, reproducible "Performance Matrix" for JA4proxy v2.0.x. This document will serve as the ground truth for the marketing brochure and provide a push-button way for Ops teams to verify performance in their own environments.

## Scope

### 1. Definitive Test Scenarios
Define and implement four standard benchmarking profiles:
- **Scenario A: "The Fast Path" (ALPN/Whitelist Bypass)**
    - *Goal*: Measure minimal overhead for known-good traffic.
    - *Setup*: Enable ALPN bypass; use whitelisted JA4.
- **Scenario B: "The Scored Path" (Standard Security Enforcement)**
    - *Goal*: Measure latency when every packet is scored against GeoIP, Blocklists, and Signal logic.
    - *Setup*: Disable bypasses; use unknown fingerprints.
- **Scenario C: "The Wall" (Aggressive Attack Mitigation)**
    - *Goal*: Measure system stability and CPU impact during a high-rate volumetric attack.
    - *Setup*: 100 Good CPS + 5000 Bad CPS; dial at 100%.
- **Scenario D: "The Mesh" (Cluster Sync Overhead)**
    - *Goal*: Measure performance impact when the Sync Agent is active and replicating state.
    - *Setup*: 2-node cluster simulation.

### 2. Automation & Reproducibility
- **Make Matrix**: Implement `make perf-matrix` which executes all scenarios in sequence.
- **Artifact Generation**: Automatically generate `docs/reports/PERFORMANCE_MATRIX.md` and `docs/reports/PERFORMANCE_MATRIX.json` after every run.

### 3. Verification Report
The output report must include:
- **p99 Tail Latency** for every scenario.
- **CPU/Memory Efficiency** (MB per 1k connections).
- **Security Accuracy** (False Positive/Negative rates).

## Acceptance Criteria
- [ ] **Push-Button Execution**: Running `make perf-matrix` completes all 4 scenarios without manual intervention.
- [ ] **Structured Output**: Generates a clean, human-readable Markdown table and a machine-readable JSON file.
- [ ] **Reproducibility**: The results remain consistent within +/- 5% across multiple runs on the same hardware.
- [ ] **No Panics**: Zero system failures or data loss during a sustained 5-minute "Wall" scenario.

---

## Strategic Intent
This phase removes all ambiguity regarding "how fast is it?". By providing a standardized matrix and the tools to reproduce it, we build extreme trust with enterprise evaluators. This data will be the direct input for the v2.0.x Release Brochure.
