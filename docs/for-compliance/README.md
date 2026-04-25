<!--
title: "Compliance & Audit — Audience Entry Point"
audience: compliance
last_reviewed: 2026-04-25
phase: 105
-->

# Compliance & Audit

> **Audience entry point.** This page is a curated index for compliance,
> audit, and assurance reviewers. **Topical compliance content lives in
> `docs/compliance/`** — this directory adds two audit-facing summaries
> and points you to the canonical artefacts.

## Start here

| Concern | Document |
|---------|----------|
| What gets logged, where, for how long | [`AUDIT_TRAIL.md`](AUDIT_TRAIL.md) |
| How config changes are proposed, reviewed, applied, reverted | [`CHANGE_MANAGEMENT.md`](CHANGE_MANAGEMENT.md) |

## Canonical compliance documents

| Topic | Document |
|-------|----------|
| GDPR posture, data minimisation, retention, erasure | [`../compliance/GDPR_COMPLIANCE.md`](../compliance/GDPR_COMPLIANCE.md) |
| Mapping of ISO 27001 / NIST CSF / PCI DSS controls to JA4proxy implementation | [`../compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) |
| SOC 2 Trust Service Criteria narrative (CC6–CC9, A1) | [`../compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md) |
| ISO 27001 Annex A control-by-control mapping | [`../compliance/iso27001-annex-a-mapping.md`](../compliance/iso27001-annex-a-mapping.md) |

## Supporting references

| Document | Purpose |
|----------|---------|
| [`../RISK_REGISTER.md`](../RISK_REGISTER.md) | Consolidated risk register (Phase 106b) |
| [`../TRACEABILITY.md`](../TRACEABILITY.md) | Requirements-to-test traceability matrix (Phase 106d) |
| [`../QUALITY_PLAN.md`](../QUALITY_PLAN.md) | Quality plan (Phase 106h) |
| [`../security/COMPREHENSIVE_SECURITY_AUDIT.md`](../security/COMPREHENSIVE_SECURITY_AUDIT.md) | Latest comprehensive security audit |
| [`../security/threat-model.md`](../security/threat-model.md) | System threat model |
| [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) | Authoritative Redis key schema (cited by AUDIT_TRAIL) |

## Reading order for an external auditor

1. [`../compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) — control coverage at a glance.
2. [`../compliance/soc2-control-narrative.md`](../compliance/soc2-control-narrative.md) or [`../compliance/iso27001-annex-a-mapping.md`](../compliance/iso27001-annex-a-mapping.md) — pick the framework relevant to the engagement.
3. [`AUDIT_TRAIL.md`](AUDIT_TRAIL.md) — verify logging, retention, and evidence pipelines.
4. [`CHANGE_MANAGEMENT.md`](CHANGE_MANAGEMENT.md) — verify change-control evidence (config reload, policy audit).
5. [`../compliance/GDPR_COMPLIANCE.md`](../compliance/GDPR_COMPLIANCE.md) — data-protection posture and erasure procedures.
6. [`../RISK_REGISTER.md`](../RISK_REGISTER.md) and [`../TRACEABILITY.md`](../TRACEABILITY.md) for residual-risk and assurance evidence.

## Scope note

JA4proxy is a TLS-aware passthrough proxy. It never decrypts traffic, never
holds TLS keys, and forwards allowed connections byte-for-byte unchanged.
Compliance claims in this directory and in `docs/compliance/` are scoped to
the proxy and its management plane only — they do not extend to the backend
web application or its data tier.
