<!--
title: Documentation Index
audience: All Users
last_reviewed: 2026-04-25
phase: 105
-->

# JA4proxy Documentation Index

> **Purpose:** Central navigable map of all documentation, organised by reader persona

---

## Start by audience

The five audience entry points are the canonical front doors. Each one filters
the documentation set down to what that role actually needs.

| You are a… | Start here |
|------------|------------|
| **Website owner / CISO** evaluating fit | [`for-website-owners/`](for-website-owners/README.md) |
| **Security architect** designing integration | [`for-architects/`](for-architects/README.md) |
| **Operator** running it day-to-day | [`for-operators/`](for-operators/README.md) |
| **Compliance / audit** | [`for-compliance/`](for-compliance/README.md) |
| **Developer / contributor** | [`for-developers/`](for-developers/README.md) |

For a flatter topical view, see [`docs/README.md`](README.md).

---

## By role (detail)

### Operators & SecOps

**Starting point:** if you're deploying or operating JA4proxy, begin at
[`for-operators/`](for-operators/README.md), then drill down here.

- **[POC Quick Start](POC_QUICKSTART.md)** — 5-minute deployment guide
- **[Quick Reference Card](QUICK_REFERENCE.md)** — Day-to-day commands cheat sheet
- **[SecOps Operations Guide](SECOPS_OPERATIONS.md)** — Configuration, dial, lists, troubleshooting
- **[Incident Response Runbook](INCIDENT_RESPONSE.md)** — Step-by-step for common security incidents
- **[Blocking Operations](operator/BLOCKING_OPERATIONS.md)** — Canonical post-merge doc covering the dial, ISP/CIDR blocking, expected block rates, and safety-gate validation
- **[Capacity Planning](operator/CAPACITY_PLANNING.md)** — Instance/Redis/HAProxy sizing
- **[Troubleshooting](operator/TROUBLESHOOTING.md)** — Diagnosis and resolution

**Runbooks**

- [Redis Operations](runbooks/redis_operations.md) — Backup, restore, maintenance
- [Feed Management](runbooks/feed_management.md) — Spamhaus, AbuseIPDB, Tor updates
- [Scaling Guide](runbooks/scaling.md) — When and how to add capacity
- [External API Failures](runbooks/external_api_failures.md) — Handling enrichment outages
- [Security Policy](runbooks/security_policy.md) — Policy audit and compliance
- [Analytics Operations](operator/analytics-operations.md) — Analytics node management
- [Go Proxy Migration](runbooks/go_proxy_migration.md) — Transitioning to Go implementation
- [Go Proxy Operations](runbooks/go_proxy_operations.md) — Go-specific procedures
- [Zero-Downtime Rollouts](runbooks/zero_downtime_rollouts.md) — Blue/green deployment guide

**Monitoring & observability**

- [Monitoring Setup](MONITORING_SETUP.md) — Prometheus, Grafana, Loki configuration
- [Observability Standards](OBSERVABILITY_STANDARDS.md) — Metrics, logging, tracing conventions
- [FAQ](FAQ.md) — Common operational questions

### Security architects & evaluators

**Starting point:** [`for-architects/`](for-architects/README.md).

- **[System Architecture](architecture/system-architecture.md)** — Data flow, component boundaries, trust model
- **[Analytics Node Architecture](architecture/analytics-node-architecture.md)** — Stream processing pipeline
- **[Comprehensive Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md)** — Audit findings with remediation status
- **[Threat Model](security/threat-model.md)** — Threat actors, attack vectors, mitigations
- **[Security Checklist](security/SECURITY_CHECKLIST.md)** — Pre-production validation checklist
- **[DMZ Readiness](for-architects/DMZ_READINESS.md)** — Production hardening checklist (current). Pre-Phase-200 snapshot archived at [`reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md`](reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md)

**Decision rationale**

- **[ADR Index](decisions/INDEX.md)** — All architectural decisions with rationale
- **[GEMINI Critique (archived snapshot)](reports/archive/GEMINI_CRITIQUE_2026-03-21.md)** — Multi-perspective review (CEO, CTO, QA, Pentester, Compliance)

### Contributing developers

**Starting point:** [`for-developers/`](for-developers/README.md).

- **[Contributing Guide](../CONTRIBUTING.md)** — Branch strategy, commit style, PR process
- **[Style Guide](STYLE_GUIDE.md)** — Python + Go conventions, naming, log format
- **[Testing Strategy](TESTING_STRATEGY.md)** — Canonical testing methodology — categories, ratios, CI gates, phase completion criteria. Earlier `TEST_ORGANIZATION.md`, `TEST_SUITE.md`, `TESTING_GO.md`, and `TESTING.md` have been merged here.
- **[Observability Standards](OBSERVABILITY_STANDARDS.md)** — Prometheus metrics, health endpoint
- **[Redis Schema](REDIS_SCHEMA.md)** — All Redis key patterns with per-phase provenance

**Development guides**

- [Signal Development](developer/SIGNAL_DEVELOPMENT.md) — Adding new risk signals
- [Go Port Guide](developer/GO_PORT_GUIDE.md) — Porting Python modules to Go
- [Go Proxy Developer Guide](developer/go_proxy_guide.md) — Building and extending the Go proxy
- [Mock Servers](developer/MOCK_SERVERS.md) — Test mock infrastructure
- [Traffic Generator](TLS_TRAFFIC_GENERATOR.md) — Simulating TLS traffic for testing

**Phase implementation**

- **[Phase Plans](phases/PHASE_00.md)** — Start at Phase 0 for implementation specs
- **[Current Phase Status](PROJECT_STATUS.md)** — What's complete, what's open
- **[Manifest](phases/manifest.yaml)** — Canonical phase definitions
- **[Engineering Method](engineering-method/README.md)** — Phase-based delivery and retrospectives

### Compliance & audit

**Starting point:** [`for-compliance/`](for-compliance/README.md).

- **[GDPR Compliance](compliance/GDPR_COMPLIANCE.md)** — Data handling, retention, subject rights
- **[Security Controls Mapping](compliance/SECURITY_CONTROLS_MAPPING.md)** — ISO 27001 control mapping
- **[Security Checklist](security/SECURITY_CHECKLIST.md)** — Pre-deployment validation
- **[Security Policy Runbook](runbooks/security_policy.md)** — Policy audit log, change management
- **[Incident Response](INCIDENT_RESPONSE.md)** — Escalation paths, evidence preservation
- **[Backup Threat Model](security/BACKUP_THREAT_MODEL.md)** — Backup security analysis

**Audit evidence**

- [Comprehensive Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) — Independent assessment
- [Redis Security Review](REDIS_SECURITY_REVIEW.md) — POC vs production hardening
- [POC Security Scan](reports/POC_SECURITY_SCAN.md) — Vulnerability scan results

### Website owners / management & stakeholders

**Starting point:** [`for-website-owners/`](for-website-owners/README.md).

- **[Project Status](PROJECT_STATUS.md)** — Current phase completion status
- **[Performance Benchmark](reports/PERFORMANCE_BENCHMARK.md)** — Throughput, latency, accuracy
- **[Enterprise Review (archived snapshot)](reports/archive/ENTERPRISE_REVIEW_2026-02-15.md)** — Pre-Phase-200 strengths and gaps
- **[Testing Session Summary](reports/testing-session-summary.md)** — Test validation results
- **[CHANGELOG](../CHANGELOG.md)** — Version history by phase

---

## By topic

### Architecture

- [System Architecture](architecture/system-architecture.md) — Overall design and components
- [Analytics Node Architecture](architecture/analytics-node-architecture.md) — Stream processing details
- [Deployment Security Model](DEPLOYMENT_SECURITY_MODEL.md) — Security architecture

### Testing & quality

- [Testing Strategy](TESTING_STRATEGY.md) — Comprehensive testing methodology (canonical, post-merge)
- [TLS Traffic Generator](TLS_TRAFFIC_GENERATOR.md) — Simulating TLS clients

### Security

- [Threat Model](security/threat-model.md) — STRIDE analysis and mitigations
- [Security Checklist](security/SECURITY_CHECKLIST.md) — Hardening checklist
- [Comprehensive Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) — Independent audit
- [Backup Threat Model](security/BACKUP_THREAT_MODEL.md) — Backup-specific threats

### Operations

- [SecOps Operations Guide](SECOPS_OPERATIONS.md) — Daily operations
- [Incident Response](INCIDENT_RESPONSE.md) — Security incident handling
- [Quick Reference](QUICK_REFERENCE.md) — Command cheat sheet
- [Monitoring Setup](MONITORING_SETUP.md) — Observability configuration
- [Blocking Operations](operator/BLOCKING_OPERATIONS.md) — Canonical blocking-ops reference

### Development

- [Contributing Guide](../CONTRIBUTING.md) — Development workflow
- [Style Guide](STYLE_GUIDE.md) — Coding standards
- [Redis Schema](REDIS_SCHEMA.md) — Data model reference
- [Documentation Standards](DOCUMENTATION_STANDARDS.md) — Documentation requirements

### Compliance

- [GDPR Compliance](compliance/GDPR_COMPLIANCE.md) — Privacy and data protection
- [Security Controls Mapping](compliance/SECURITY_CONTROLS_MAPPING.md) — Framework mapping

---

## Documentation health

**Last reviewed:** 2026-04-25
**Status:** Active development (Phase 105 — Docs Restructure)
**Test count:** `python3 -m pytest tests/ --collect-only -q 2>/dev/null | tail -1`

**Documentation Standards:** All documentation follows [DOCUMENTATION_STANDARDS.md](DOCUMENTATION_STANDARDS.md)
**Style Guide:** All code follows [STYLE_GUIDE.md](STYLE_GUIDE.md)
