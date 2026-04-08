# ISO 27001:2022 Annex A Control Mapping — JA4proxy

This document maps JA4proxy capabilities to ISO 27001:2022 Annex A controls.
Coverage is limited to controls that JA4proxy directly implements or contributes to.
A full ISMS implementation requires organisational controls (policy, HR, physical
security) that are outside this tool's scope.

---

## A.5 — Organisational Controls

| Control | Title | JA4proxy Coverage |
|---------|-------|------------------|
| A.5.7 | Threat intelligence | Phase 85 (TAXII 2.1 / MISP). Phase 84 provides historical threat data in evidence packs. |
| A.5.23 | Information security for use of cloud services | Risk scoring evaluates ASN/datacenter classification (Phase 6). |
| A.5.37 | Documented operating procedures | Runbooks in `docs/runbooks/`; emergency playbooks in `deploy/ansible/playbooks/`. |

---

## A.8 — Technological Controls

| Control | Title | JA4proxy Coverage |
|---------|-------|------------------|
| A.8.4 | Access to source code | RBAC enforces Operator+ for config changes; Auditor for read-only compliance access. |
| A.8.5 | Secure authentication | JWT authentication with `httpOnly` cookie; MFA via TOTP (Phase 79/100). |
| A.8.6 | Capacity management | Prometheus metrics + capacity Grafana dashboard (Phase 86). |
| A.8.7 | Protection against malware | JA4 fingerprint blocklist blocks known-bad TLS clients and scanner fingerprints. |
| A.8.9 | Configuration management | Policy-as-code (Phase 82): drift detection via `ja4proxy-cli policy diff`. Config audit log. |
| A.8.15 | Logging | ECS-structured logs (Phase 80); Redis Stream event log; audit log. |
| A.8.16 | Monitoring activities | Prometheus + Grafana; SLO burn-rate alerts (Phase 63). |
| A.8.20 | Network security | Spamhaus DROP/EDROP (Phase 8); GeoIP blocking (Phase 31); TLS version enforcement (Phase 3). |
| A.8.23 | Web filtering | JA4 fingerprint analysis blocks known-bad TLS clients before HTTP layer. |

---

## Gaps

The following Annex A controls are **not** covered by JA4proxy:

- A.5.1–A.5.6 — Governance policies: organisational controls outside tool scope
- A.6 — People controls: HR screening, NDAs, security awareness
- A.7 — Physical controls: physical access to data centres
- A.8.1 — User endpoint devices: laptop/desktop hardening
- A.8.12 — Data leakage prevention: JA4proxy operates at L4/L5; does not inspect payloads

---

*Last reviewed: 2026-04-08. Verify control references against your auditor's ISO 27001:2022 checklist.*
