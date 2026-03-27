<!--
title: JA4proxy Documentation
audience: All Users
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy Documentation

> **Audience:** All users — primary entry point for documentation
> **Purpose:** Guide readers to the most relevant documentation for their role

## Start here by role

| You are… | Read this first |
|----------|----------------|
| **Deploying for the first time** | [Quick-start (5 min)](POC_QUICKSTART.md) |
| **Daily operator / SecOps** | [Quick reference card](QUICK_REFERENCE.md) |
| **Investigating an incident** | [Incident response](INCIDENT_RESPONSE.md) |
| **Security architect / evaluator** | [Architecture overview](architecture/system-architecture.md) |
| **Contributing code** | [Contributing guide](../CONTRIBUTING.md) |
| **Compliance / audit** | [GDPR & compliance](compliance/GDPR_COMPLIANCE.md) |

**📖 [Full Documentation Index](INDEX.md)** — Complete map of all documentation

Select your audience below to go directly to what you need.

---

## Enterprise SecOps / CISO

Deployment architecture, security design, compliance posture, and readiness assessments.

| Document | Purpose |
|----------|---------|
| [Security Architecture](enterprise/security-architecture.md) | Defense-in-depth design, threat model, access controls, compliance framework |
| [Enterprise Deployment Guide](enterprise/deployment.md) | HA deployment topology, hardware sizing, network segmentation, hardening |
| [System Architecture](architecture/system-architecture.md) | Target enterprise architecture diagram and pipeline description |
| [Enterprise Readiness Report](reports/ENTERPRISE_READINESS_REPORT.md) | Strengths, open gaps, and remediation priorities |
| [Enterprise Review](reports/ENTERPRISE_REVIEW.md) | Full production readiness assessment |
| [DMZ Deployment Readiness](DMZ_DEPLOYMENT_READINESS.md) | Controls in place vs. required for DMZ placement |

---

## SecOps Operators

Day-to-day operations: starting the proxy, responding to alerts, tuning the blocking dial.

| Document | Purpose |
|----------|---------|
| [SecOps Operations Guide](SECOPS_OPERATIONS.md) | Start/stop, ports, backend config, passwords, troubleshooting |
| [Incident Response Runbook](INCIDENT_RESPONSE.md) | Step-by-step commands for responding to active attacks |
| [Quick Reference](QUICK_REFERENCE.md) | Command cheat sheet for daily operations |
| [Monitoring Setup](MONITORING_SETUP.md) | Prometheus, Grafana, Loki, and alerting configuration |
| [FAQ](FAQ.md) | Common operational questions with direct answers |
| [Blocking Guide](operator/blocking-guide.md) | How to enable blocking mode, dial progression, safety gates |
| [Blocking Analysis](operator/BLOCKING_ANALYSIS.md) | Effective thresholds at each dial level; expected block rates |
| [Blocking Test Analysis](operator/blocking-test-analysis.md) | Observed traffic patterns and expected behavior at dial=50 |
| [Final Blocking Test Summary](operator/FINAL_BLOCKING_TEST_SUMMARY.md) | Test session results and safety-gate validation |

---

## Security Auditors

Vulnerability assessments, threat models, compliance checklists, and scan results.

| Document | Purpose |
|----------|---------|
| [Comprehensive Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) | Vulnerability assessment snapshot (2026-02-14) |
| [Threat Model](security/threat-model.md) | STRIDE analysis covering the target enterprise architecture |
| [Security Checklist](security/SECURITY_CHECKLIST.md) | Pre-deployment validation checklist |
| [Redis Security Review](REDIS_SECURITY_REVIEW.md) | Current POC status and production hardening steps |
| [POC Security Scan](reports/POC_SECURITY_SCAN.md) | Vulnerability scan with POC vs. production context |
| [Security Testing](SECURITY_TESTING.md) | JA4 fingerprint blocking and rate-limit validation procedures |

---

## Compliance / Legal

Data handling, retention, GDPR obligations, and audit trail documentation.

| Document | Purpose |
|----------|---------|
| [GDPR Compliance](compliance/GDPR_COMPLIANCE.md) | Data minimisation, retention periods, right-to-erasure, lawful basis |
| [Documentation Standards](DOCUMENTATION_STANDARDS.md) | Changelog format, REDIS_SCHEMA policy, ADR format, audit log policy |

---

## Developers

Contributing to the proxy: coding standards, test structure, Redis schema, phase plans.

| Document | Purpose |
|----------|---------|
| [Style Guide](STYLE_GUIDE.md) | Config syntax, log format, test format, documentation language |
| [Testing Strategy](TESTING_STRATEGY.md) | Full testing methodology: categories, CI pipeline, FP monitoring, phase gate |
| [Test Organisation](TEST_ORGANIZATION.md) | Test file layout, conftest structure, fixture factories, parametrize patterns |
| [Observability Standards](OBSERVABILITY_STANDARDS.md) | Prometheus metric naming, JSON log schema, Grafana layout, SLIs |
| [Redis Schema](REDIS_SCHEMA.md) | All Redis key patterns with per-phase provenance |
| [Test Audit](developer/test-audit.md) | Audit of test categories, coverage, and quality assessment |
| [Testing Analysis](developer/testing-analysis.md) | Detailed breakdown of test legitimacy and mocking rationale |
| [Traffic Generator Fix](developer/traffic-generator-fix.md) | Fix log: error vs. blocked classification in tls-traffic-generator.py |
| [TLS Traffic Generator](TLS_TRAFFIC_GENERATOR.md) | Simulating legitimate and malicious TLS clients for testing |
| [Phase Plans](phases/PHASE_00.md) | Per-phase implementation plans and acceptance criteria (start at Phase 0) |

---

## Management / Stakeholders

High-level performance data, readiness status, and project state.

| Document | Purpose |
|----------|---------|
| [Performance Benchmark](reports/PERFORMANCE_BENCHMARK.md) | Measured throughput, latency, and blocking accuracy |
| [Enterprise Readiness Report](reports/ENTERPRISE_READINESS_REPORT.md) | Strengths and open gaps at a glance |
| [Testing Session Summary](reports/testing-session-summary.md) | Summary of traffic generator fix and test validation session |

---

## POC / Quick Start

| Document | Purpose |
|----------|---------|
| [POC Quick Start](POC_QUICKSTART.md) | 5-minute setup guide |
| [README](../README.md) | Project overview, architecture diagram, service table |
| [Changelog](../CHANGELOG.md) | Version history by phase |
