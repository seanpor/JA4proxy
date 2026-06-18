<!--
title: JA4proxy Documentation Index
audience: reference
last_reviewed: 2026-06-18
phase: v2.0
-->

# JA4proxy Documentation

Organized by audience. Every top-level document is listed below exactly once,
under the role that owns it (matching each file's `audience:` tag); shared
subsystems live in the subdirectories at the end.

---

## 🚀 Start here

- **Evaluating it?** → [Why JA4proxy?](WHY_JA4PROXY.md) then [Scope & Limitations](SCOPE_AND_LIMITATIONS.md)
- **Deploying a demo?** → [POC Quick Start](POC_QUICKSTART.md) (5 minutes)
- **Running it?** → [Operations Guide](OPERATIONS_GUIDE.md) (the operator source of truth)
- **Contributing?** → [Getting Started](GETTING_STARTED.md)

---

## 🏢 Product — website owners, CISOs & buyers

- [Why JA4proxy?](WHY_JA4PROXY.md) — plain-language business case.
- [Scope & Limitations](SCOPE_AND_LIMITATIONS.md) — the canonical "what it is and is **not**".
- [Deployment Options](DEPLOYMENT_OPTIONS.md) — POC, scaled, and cloud paths.
- [TCO & Licensing](TCO_AND_LICENSING.md) — cost of ownership and licensing.
- [Evaluation Checklist](EVALUATION_CHECKLIST.md) — 7-day POC / 30-day evaluation checklists.

## 🛡 Security & compliance — architects, SecOps, auditors

- [Deployment Security Model](DEPLOYMENT_SECURITY_MODEL.md) — OS users, permissions, network exposure, secrets.
- [DMZ Readiness](DMZ_READINESS.md) — DMZ posture and production-hardening checklist.
- [MITRE ATT&CK Mapping](ATTACK_MAPPING.md) — **authoritative** signal → technique mapping (CI-gated).
- [SecOps Triage & Remediation Playbooks](OPERATIONS_MAPPING.md) — what to do when an alert fires.
- [SIEM Integration](SIEM_INTEGRATION.md) — ECS-based SIEM ingestion recipes.
- [Audit Trail](AUDIT_TRAIL.md) — what is logged, where, and retention (audit source of truth).
- [Change Management](CHANGE_MANAGEMENT.md) — config change propose/review/apply/revert + evidence.
- [Risk Register](RISK_REGISTER.md) — consolidated risk index (auditor artefact).
- [Redis Security Review](REDIS_SECURITY_REVIEW.md) — Redis security posture vs production requirements.

## ⚙️ Operators & SecOps — running JA4proxy

- [Operations Guide](OPERATIONS_GUIDE.md) — **single source of truth** for running it (start/stop, config, monitoring, troubleshooting).
- [POC Quick Start](POC_QUICKSTART.md) — 5-minute demo bring-up for assessors.
- [Incident Response](INCIDENT_RESPONSE.md) — runbook for active attacks.
- [Scaling Guide](SCALING_GUIDE.md) — scaling out behind a load balancer.
- [Upgrade Path](UPGRADE_PATH.md) — upgrade and compatibility guidance.
- [FAQ](FAQ.md) — common operational questions.

## 🧑‍💻 Developers & contributors

- [Getting Started](GETTING_STARTED.md) — clone to green tests in ~30 minutes.
- [Onboarding](ONBOARDING.md) — orientation for new contributors.
- [How We Work](HOW_WE_WORK.md) — trunk-based dev, branching, PR etiquette.
- [Phase Lifecycle](PHASE_LIFECYCLE.md) — how phases are planned and tracked (human edition).
- [Quality Plan](QUALITY_PLAN.md) — consolidated quality plan and landing page.
- [Testing Strategy](TESTING_STRATEGY.md) — methodology and CI quality gates.
- [Security Testing](SECURITY_TESTING.md) — how to test fingerprint blocking and rate limiting.
- [Style Guide](STYLE_GUIDE.md) — config, log, test, and doc conventions.
- [Documentation Standards](DOCUMENTATION_STANDARDS.md) — CHANGELOG, ADR, and runbook formats.
- [TLS Traffic Generator](TLS_TRAFFIC_GENERATOR.md) — the load / traffic-generation tool.

## 📚 Reference & standards

- [Redis Schema](REDIS_SCHEMA.md) — every Redis key pattern (source of truth).
- [Observability Standards](OBSERVABILITY_STANDARDS.md) — Prometheus metrics, log schema, dashboards, alerts.
- [Makefile Targets](MAKEFILE_TARGETS.md) — every `make` target.
- [Scripts](SCRIPTS.md) — reference for `scripts/`.
- [Docker Images](DOCKER_IMAGES.md) — canonical registry of all images and pins.
- [Service Targets](SERVICE_TARGETS.md) — SLA / SLO / SLI commitments.
- [Traceability](TRACEABILITY.md) — requirements → code matrix *(auto-generated; do not edit)*.
- [Project Status](PROJECT_STATUS.md) — roadmap and status *(auto-generated; do not edit)*.

---

## 📂 Subsystems & deep references

| Area | What's there |
|------|--------------|
| [architecture/](architecture/) | System, network, isolation, and analytics-node architecture. |
| [decisions/](decisions/INDEX.md) | Architecture Decision Records (ADRs) + index. |
| [runbooks/](runbooks/) | The full operational runbook set (backup/DR, rotation, alerts, …). |
| [security/](security/) | Threat models, security audits, CVD/CVE policy. |
| [compliance/](compliance/) | CRA, GDPR, ISO 27001/27017/29100, SOC 2, controls mapping. |
| [performance/](performance/) | Benchmarks, benchmark history, capacity reports. |
| [developer/](developer/) | Go proxy/port internals, signal & analytics dev guides. |
| [api/](api/) | OpenAPI spec + the ECS log extension. |
| [phases/](phases/) | Per-phase plans and `manifest.yaml` (the phase source of truth). |

> **Information architecture (Phase 309 WP-10):** docs are grouped by `audience:`
> (`product` · `security` · `operator` · `developer` · `reference`). This index
> is the map; a follow-up may physically relocate files into per-audience
> subdirectories.
