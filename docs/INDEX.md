<!--
title: Documentation Index
audience: All Users
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy Documentation Index

> **Purpose:** Central navigable map of all documentation, organized by reader persona

---

## By Role

### Operators & SecOps

**Starting Point:** If you're deploying or operating JA4proxy, begin here.

- **[POC Quick Start](POC_QUICKSTART.md)** — 5-minute deployment guide
- **[Quick Reference Card](QUICK_REFERENCE.md)** — Day-to-day commands cheat sheet
- **[SecOps Operations Guide](SECOPS_OPERATIONS.md)** — Configuration, dial, lists, troubleshooting
- **[Incident Response Runbook](INCIDENT_RESPONSE.md)** — Step-by-step for common security incidents

**Runbooks:** Detailed operational procedures
- [Redis Operations](runbooks/redis_operations.md) — Backup, restore, maintenance
- [Feed Management](runbooks/feed_management.md) — Spamhaus, AbuseIPDB, Tor updates
- [Scaling Guide](runbooks/scaling.md) — When and how to add capacity
- [External API Failures](runbooks/external_api_failures.md) — Handling enrichment outages
- [Security Policy](runbooks/security_policy.md) — Policy audit and compliance
- [Analytics Operations](operator/analytics-operations.md) — Analytics node management
- [Go Proxy Migration](runbooks/go_proxy_migration.md) — Transitioning to Go implementation
- [Go Proxy Operations](runbooks/go_proxy_operations.md) — Go-specific procedures

**Monitoring & Observability**
- [Monitoring Setup](MONITORING_SETUP.md) — Prometheus, Grafana, Loki configuration
- [Observability Standards](OBSERVABILITY_STANDARDS.md) — Metrics, logging, tracing conventions
- [FAQ](FAQ.md) — Common operational questions

### Security Architects & Evaluators

**Starting Point:** If you're assessing JA4proxy for adoption or designing an integration.

- **[System Architecture](architecture/system-architecture.md)** — Data flow, component boundaries, trust model
- **[Analytics Node Architecture](architecture/analytics-node-architecture.md)** — Stream processing pipeline
- **[Comprehensive Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md)** — 18-finding audit with remediation status
- **[Threat Model](security/threat-model.md)** — Threat actors, attack vectors, mitigations
- **[Security Checklist](security/SECURITY_CHECKLIST.md)** — Pre-production validation checklist
- **[DMZ Deployment Readiness](DMZ_DEPLOYMENT_READINESS.md)** — Production hardening checklist

**Decision Rationale**
- **[ADR Index](decisions/INDEX.md)** — All architectural decisions with rationale
- **[GEMINI Critique](GEMINI_CRITIQUE.md)** — Multi-perspective review (CEO, CTO, QA, Pentester, Compliance)

### Contributing Developers

**Starting Point:** If you're writing code for JA4proxy.

- **[Contributing Guide](../CONTRIBUTING.md)** — Branch strategy, commit style, PR process
- **[Style Guide](STYLE_GUIDE.md)** — Python + Go conventions, naming, log format
- **[Testing Strategy](TESTING_STRATEGY.md)** — Categories, ratios, CI gates, phase completion criteria
- **[Test Organisation](TEST_ORGANIZATION.md)** — File layout, conftest patterns, parametrize
- **[Observability Standards](OBSERVABILITY_STANDARDS.md)** — Prometheus metrics, health endpoint
- **[Redis Schema](REDIS_SCHEMA.md)** — All Redis key patterns with per-phase provenance

**Development Guides**
- [Signal Development](developer/SIGNAL_DEVELOPMENT.md) — Adding new risk signals
- [Go Port Guide](developer/GO_PORT_GUIDE.md) — Porting Python modules to Go
- [Mock Servers](developer/MOCK_SERVERS.md) — Test mock infrastructure
- [Traffic Generator](TLS_TRAFFIC_GENERATOR.md) — Simulating TLS traffic for testing

**Phase Implementation**
- **[Phase Plans](phases/PHASE_00.md)** — Start at Phase 0 for implementation specs
- **[Current Phase Status](PROJECT_STATUS.md)** — What's complete, what's open
- **[Manifest](phases/manifest.yaml)** — Canonical phase definitions

### Compliance & Audit

**Starting Point:** If you're reviewing JA4proxy for regulatory compliance.

- **[GDPR Compliance](compliance/GDPR_COMPLIANCE.md)** — Data handling, retention, subject rights
- **[Security Controls Mapping](compliance/SECURITY_CONTROLS_MAPPING.md)** — ISO 27001 control mapping
- **[Security Checklist](security/SECURITY_CHECKLIST.md)** — Pre-deployment validation
- **[Security Policy Runbook](runbooks/security_policy.md)** — Policy audit log, change management
- **[Incident Response](INCIDENT_RESPONSE.md)** — Escalation paths, evidence preservation
- **[Backup Threat Model](security/BACKUP_THREAT_MODEL.md)** — Backup security analysis

**Audit Evidence**
- [Comprehensive Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) — Independent assessment
- [Redis Security Review](REDIS_SECURITY_REVIEW.md) — POC vs production hardening
- [POC Security Scan](reports/POC_SECURITY_SCAN.md) — Vulnerability scan results

### Management & Stakeholders

**Starting Point:** If you need high-level project status and performance data.

- **[Project Status](PROJECT_STATUS.md)** — Current phase completion status
- **[Performance Benchmark](reports/PERFORMANCE_BENCHMARK.md)** — Throughput, latency, accuracy
- **[Enterprise Readiness Report](reports/ENTERPRISE_READINESS_REPORT.md)** — Strengths and gaps
- **[Testing Session Summary](reports/testing-session-summary.md)** — Test validation results
- **[CHANGELOG](../CHANGELOG.md)** — Version history by phase

---

## By Topic

### Architecture
- [System Architecture](architecture/system-architecture.md) — Overall design and components
- [Analytics Node Architecture](architecture/analytics-node-architecture.md) — Stream processing details
- [Deployment Security Model](DEPLOYMENT_SECURITY_MODEL.md) — Security architecture

### Testing & Quality
- [Testing Strategy](TESTING_STRATEGY.md) — Comprehensive testing methodology
- [Test Organisation](TEST_ORGANIZATION.md) — Test structure and patterns
- [Test Suite Overview](TEST_SUITE.md) — Test categories and coverage

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

### Development
- [Contributing Guide](../CONTRIBUTING.md) — Development workflow
- [Style Guide](STYLE_GUIDE.md) — Coding standards
- [Redis Schema](REDIS_SCHEMA.md) — Data model reference
- [Documentation Standards](DOCUMENTATION_STANDARDS.md) — Documentation requirements

### Compliance
- [GDPR Compliance](compliance/GDPR_COMPLIANCE.md) — Privacy and data protection
- [Security Controls Mapping](compliance/SECURITY_CONTROLS_MAPPING.md) — Framework mapping

---

## Documentation Health

**Last Reviewed:** 2026-03-27
**Status:** Active development (Phase 21 — Documentation Excellence)
**Test Count:** `python3 -m pytest tests/ --collect-only -q 2>/dev/null | tail -1`

**Documentation Standards:** All documentation follows [DOCUMENTATION_STANDARDS.md](DOCUMENTATION_STANDARDS.md)
**Style Guide:** All code follows [STYLE_GUIDE.md](STYLE_GUIDE.md)