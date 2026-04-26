<!--
title: "JA4proxy for Security Architects"
audience: architects
last_reviewed: 2026-04-25
phase: 105
-->

# JA4proxy for Security Architects

This is the curated entry point for security architects evaluating, integrating,
or extending JA4proxy. It is a **role-curated index**, not duplicate content —
each link points to the canonical document for that topic. Read in roughly the
order presented.

> Production runtime is the **Go proxy** (`cmd/proxy`, built to `bin/proxy`).
> The Python prototype (`proxy.py`) is a research surface only and never
> ships to production. Treat any Python-specific posture claim as
> non-authoritative.

---

## Start here

| What you need | Where it lives |
|---|---|
| What this product does and does not do | [Scope and Limitations](SCOPE_AND_LIMITATIONS.md) |
| STRIDE threat model and asset register | [`docs/security/threat-model.md`](../security/threat-model.md) |
| ISO 27001 control coverage | [`docs/compliance/SECURITY_CONTROLS_MAPPING.md`](../compliance/SECURITY_CONTROLS_MAPPING.md) |
| Trust boundaries, OS user model, secrets | [`docs/DEPLOYMENT_SECURITY_MODEL.md`](../DEPLOYMENT_SECURITY_MODEL.md) |
| Production deployment topology | [`docs/enterprise/deployment.md`](../enterprise/deployment.md) |
| Security architecture (target state) | [`docs/enterprise/security-architecture.md`](../enterprise/security-architecture.md) |
| DMZ readiness summary | [DMZ Readiness](DMZ_READINESS.md) |

---

## Integration

| Concern | Document |
|---|---|
| Forwarding logs to your SIEM | [SIEM Integration](SIEM_INTEGRATION.md) |
| ECS field reference (canonical schema) | [`docs/api/ecs_extension.md`](../api/ecs_extension.md) |
| Webhook payload, signing, and delivery semantics | [`docs/api/ecs_extension.md`](../api/ecs_extension.md) §"Webhook Events" |
| External Dynamic Lists (EDL) for firewall ingestion | [`docs/decisions/ADR-021.md`](../decisions/ADR-021.md) (pull-vs-push design) and [`docs/runbooks/tap_mode.md`](../runbooks/tap_mode.md) (operational guide) |

---

## Running an evaluation

| Stage | Document |
|---|---|
| 7-day POC and 30-day evaluation checklist | [Evaluation Checklist](EVALUATION_CHECKLIST.md) |
| Dial progression playbook | [`docs/operator/BLOCKING_OPERATIONS.md`](../operator/BLOCKING_OPERATIONS.md#how-to-change-the-dial) |
| Incident response procedures | [`docs/INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) |
| Capacity and scaling | [`docs/SCALING_GUIDE.md`](../SCALING_GUIDE.md) |

---

## Architecture-level decisions

The full ADR catalogue lives in [`docs/decisions/`](../decisions/). The ones
most useful to architects up front:

- **ADR-001** — Default dial = 0 (never block on first deploy)
- **ADR-003** — RDAP block expansion off by default; never expand beyond `/24`
  (v4) or `/48` (v6)
- **ADR-015** — Go promoted to production runtime; Python relegated to
  prototyping
- **ADR-020** — TAP/SPAN passive mode design (AF\_PACKET capture)
- **ADR-021** — EDL pull-not-push for firewall integration

---

## Historical and superseded reports

Pre-Phase-200 audits are preserved under
[`docs/reports/archive/`](../reports/archive/) for traceability. They are
**not authoritative** for current posture — defer to the documents linked
above.

---

## Related entry points for other audiences

- Website owners and CISOs: [`docs/for-website-owners/README.md`](../for-website-owners/README.md)
- SecOps operators: [`docs/for-operators/README.md`](../for-operators/README.md)
- Compliance and audit: [`docs/for-compliance/README.md`](../for-compliance/README.md)
- Developers and contributors: [`docs/for-developers/README.md`](../for-developers/README.md)
