# Phase 140: Observability Hardening & Signal Drift Detection

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Depends on:** Phase 136
> **Owner:** Gemini CLI

## Goal
Enhance production observability by instrumenting the security pipeline with per-signal metrics and implementing automated detection for intelligence drift.

## Scope
- **Signal Latency Metrics**: Export Prometheus histograms for the execution time of every individual signal module (JA4, SNI, TI feeds).
- **Intelligence Drift Detection**: Implement a background worker to detect scoring divergence between proxy nodes (e.g., Node A blocks IP-X but Node B allows).
- **Grafana Dashboard v3**: Update the dashboard to visualize per-signal performance and highlight "Top 10 Slowest Signals."
- **Alerting Rules**: Add Alertmanager rules for high signal latency and scoring inconsistency across the mesh.

## Acceptance Criteria
- [ ] Prometheus metrics available for per-signal execution latency.
- [ ] Automated drift alerts triggered within 5 minutes of scoring divergence.
- [ ] Updated Grafana dashboard demonstrating 100% visibility into signal module health.
