<!--
title: JA4proxy Documentation
audience: All Users
last_reviewed: 2026-04-25
phase: 105
-->

# JA4proxy Documentation

> **Audience:** All users — primary entry point for documentation
> **Purpose:** Guide readers to the most relevant documentation for their role

## Start by audience

| You are a… | Start here |
|------------|------------|
| **Website owner / CISO** evaluating fit | [`for-website-owners/`](for-website-owners/README.md) |
| **Security architect** designing integration | [`for-architects/`](for-architects/README.md) |
| **Operator** running it day-to-day | [`for-operators/`](for-operators/README.md) |
| **Compliance / audit** | [`for-compliance/`](for-compliance/README.md) |
| **Developer / contributor** | [`for-developers/`](for-developers/README.md) |

**[Full Documentation Index](INDEX.md)** — every doc, organised by role and topic.

---

## By area

Topical entry points. Each links to the canonical doc for that area.

### Standards & conventions

| Document | Purpose |
|----------|---------|
| [Style Guide](STYLE_GUIDE.md) | Config syntax, log format, test format, doc language |
| [Documentation Standards](DOCUMENTATION_STANDARDS.md) | CHANGELOG, REDIS_SCHEMA, runbook, ADR formats |
| [Observability Standards](OBSERVABILITY_STANDARDS.md) | Prometheus naming, JSON log schema, dashboards, alerts, SLIs |
| [Redis Schema](REDIS_SCHEMA.md) | All Redis key patterns with per-phase provenance |

### Testing

| Document | Purpose |
|----------|---------|
| [Testing Strategy](TESTING_STRATEGY.md) | Canonical testing methodology — categories, ratios, CI gates, phase completion criteria. Earlier `TEST_ORGANIZATION.md`, `TEST_SUITE.md`, `TESTING_GO.md`, and `TESTING.md` have been merged into this doc. |
| [TLS Traffic Generator](TLS_TRAFFIC_GENERATOR.md) | Simulating legitimate and malicious TLS clients |

### Operations

| Document | Purpose |
|----------|---------|
| [`for-operators/`](for-operators/README.md) | Day-to-day operator entry point |
| [SecOps Operations Guide](SECOPS_OPERATIONS.md) | Start/stop, ports, backend config, troubleshooting |
| [Incident Response Runbook](INCIDENT_RESPONSE.md) | Step-by-step playbooks for active attacks |
| [Quick Reference](QUICK_REFERENCE.md) | Command cheat sheet for daily operations |
| [Monitoring Setup](MONITORING_SETUP.md) | Prometheus, Grafana, Loki, Alertmanager configuration |
| [Blocking Operations](operator/BLOCKING_OPERATIONS.md) | Canonical blocking-ops doc — ISP/CIDR blocking, dial progression, safety gates, expected block rates, test results. Replaces the earlier four-file split (`blocking-guide.md`, `BLOCKING_ANALYSIS.md`, `blocking-test-analysis.md`, `FINAL_BLOCKING_TEST_SUMMARY.md`). |
| [Capacity Planning](operator/CAPACITY_PLANNING.md) | Instance sizing, Redis sizing, HAProxy tuning |
| [Troubleshooting](operator/TROUBLESHOOTING.md) | Diagnosis and resolution for common issues |
| [FAQ](FAQ.md) | Common operational questions with direct answers |

### Architecture & evaluation

| Document | Purpose |
|----------|---------|
| [`for-architects/`](for-architects/README.md) | Architect entry point |
| [System Architecture](architecture/system-architecture.md) | Target enterprise architecture, components, trust model |
| [DMZ Readiness](for-architects/DMZ_READINESS.md) | Production hardening checklist (current). Pre-Phase-200 snapshot archived at [`reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md`](reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md). |
| [Architecture Decisions Index](decisions/INDEX.md) | All ADRs with rationale |

### Security & compliance

| Document | Purpose |
|----------|---------|
| [`for-compliance/`](for-compliance/README.md) | Compliance/audit entry point |
| [Comprehensive Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) | Vulnerability assessment, pentest findings, mitigations |
| [Threat Model](security/threat-model.md) | STRIDE analysis, trust boundaries, adversarial assumptions |
| [Security Checklist](security/SECURITY_CHECKLIST.md) | Pre-deployment go/no-go checklist |
| [GDPR Compliance](compliance/GDPR_COMPLIANCE.md) | Data minimisation, retention, DSAR handling |
| [Security Controls Mapping](compliance/SECURITY_CONTROLS_MAPPING.md) | ISO 27001 control mapping |

### Developers

| Document | Purpose |
|----------|---------|
| [`for-developers/`](for-developers/README.md) | Developer/contributor entry point |
| [Contributing Guide](../CONTRIBUTING.md) | Branch strategy, commit style, PR process |
| [Signal Development](developer/SIGNAL_DEVELOPMENT.md) | How to implement and test new detection signals |
| [Go Port Guide](developer/GO_PORT_GUIDE.md) | Porting Python modules to Go |
| [Go Proxy Developer Guide](developer/go_proxy_guide.md) | Building, testing, and extending the Go proxy |
| [Mock Servers](developer/MOCK_SERVERS.md) | Test mock infrastructure |
| [Phase Plans](phases/PHASE_00.md) | Per-phase implementation plans (start at Phase 0) |

### Engineering method

| Document | Purpose |
|----------|---------|
| [Engineering Method](engineering-method/README.md) | Phase-based delivery, multi-agent coordination, retrospectives |

### Reference reports & archives

Historical reviews retained for audit traceability:

- [Enterprise Review (2026-02-15)](reports/archive/ENTERPRISE_REVIEW_2026-02-15.md) — pre-Phase-200 strengths/gaps assessment
- [GEMINI Critique (2026-03-21)](reports/archive/GEMINI_CRITIQUE_2026-03-21.md) — multi-perspective review
- [Cyber Risk Review (2026-04-09)](reports/archive/CYBER_RISK_REVIEW_2026-04-09.md)
- [Strategic Security Architecture Review (2026-04-08)](reports/archive/strategic_security_architecture_review_2026-04-08.md)

---

## POC quick start

| Document | Purpose |
|----------|---------|
| [POC Quick Start](POC_QUICKSTART.md) | 5-minute setup guide |
| [Project README](../README.md) | Project overview and audience router |
| [CHANGELOG](../CHANGELOG.md) | Version history by phase |
| [Project Status](PROJECT_STATUS.md) | Current phase completion |
| [Manifest](phases/manifest.yaml) | Canonical phase definitions |
