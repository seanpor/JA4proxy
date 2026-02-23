# JA4proxy Documentation

## Getting Started

- [README](../README.md) — Project overview and quick start
- [POC Quick Start](POC_QUICKSTART.md) — 5-minute setup guide

## Operations

- [SecOps Operations Guide](SECOPS_OPERATIONS.md) — Backend config, passwords, start/stop, ports, troubleshooting
- [Incident Response Runbook](INCIDENT_RESPONSE.md) — Commands for responding to active attacks
- [Quick Reference](QUICK_REFERENCE.md) — Command cheat sheet for daily operations
- [Monitoring Setup](MONITORING_SETUP.md) — Prometheus, Grafana, Loki, and alerting

## Testing

- [Testing](TESTING.md) — Test suite execution and procedures
- [Security Testing](SECURITY_TESTING.md) — JA4 fingerprint blocking and rate limit validation
- [TLS Traffic Generator](TLS_TRAFFIC_GENERATOR.md) — Simulating legitimate and malicious TLS clients

## Security

- [Redis Security](REDIS_SECURITY_REVIEW.md) — Current POC status and production hardening steps
- [Security Audit](security/COMPREHENSIVE_SECURITY_AUDIT.md) — Vulnerability assessment (snapshot: 2026-02-14)
- [Security Checklist](security/SECURITY_CHECKLIST.md) — Pre-deployment validation
- [Threat Model](security/threat-model.md) — STRIDE analysis (covers target enterprise architecture)
- [DMZ Deployment Readiness](DMZ_DEPLOYMENT_READINESS.md) — Controls in place and gaps

## Reports

- [Performance Benchmark](reports/PERFORMANCE_BENCHMARK.md) — Measured throughput and blocking accuracy
- [Enterprise Review](reports/ENTERPRISE_REVIEW.md) — Production readiness assessment
- [Enterprise Readiness](reports/ENTERPRISE_READINESS_REPORT.md) — Strengths and open gaps
- [POC Security Scan](reports/POC_SECURITY_SCAN.md) — Vulnerability scan with POC vs production context

## Reference

- [Architecture](architecture/system-architecture.md) — Target enterprise architecture (aspirational)
- [Enterprise Deployment](enterprise/deployment.md) — Future production deployment guide
- [GDPR Compliance](compliance/GDPR_COMPLIANCE.md) — Data handling and retention
- [Changelog](../CHANGELOG.md) — Version history
