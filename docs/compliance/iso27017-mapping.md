# ISO/IEC 27017 — Cloud Controls Mapping

> **Status:** DRAFT — self-assessed alignment (not certification)
> **Phase:** 107d (sub-phase 107d.1 scaffolding; CLD rows filled by 107d.2/.3)
> **Standard:** ISO/IEC 27017:2015 — Code of practice for information security controls based on ISO/IEC 27002 for cloud services

---

## Framing

ISO/IEC 27017 is a **guidance standard**, not a certifiable management-system
standard. It supplements ISO/IEC 27002 with cloud-specific controls (CLD.6.*
through CLD.12.*) and adds cloud-specific implementation guidance for many of
the existing 27002 controls. This document records JA4proxy's **alignment
with** the cloud-specific CLD controls, where each control is honestly
assessed as one of:

- **Applies** — JA4proxy implements or directly satisfies the control.
- **Customer responsibility** — the control is a cloud-deployer obligation,
  not a product obligation. Many CLD controls fall here.
- **Not applicable** — the control does not apply to JA4proxy's deployment
  model.

This is a **self-assessment**. No accredited body has assessed JA4proxy
against ISO/IEC 27017 and no third-party audit has been performed.

JA4proxy's deployment topology is also relevant: JA4proxy is **deployed by
the customer** into the customer's own environment (cloud or on-premises).
The product is therefore in the position of a *cloud service customer's
software component* rather than a Cloud Service Provider (CSP). Several CLD
controls phrased from the CSP perspective consequently fall to the
customer's CSP (AWS, GCP, Azure, etc.) and not to JA4proxy itself; those
rows are marked **Customer responsibility** with a deployer-guidance note.

---

## Applicability summary

| Total CLD controls | Applies to JA4proxy | Customer responsibility | Not applicable |
|--------------------|---------------------|-------------------------|----------------|
| 7                  | 3                   | 4                       | 0              |

The CLD families covered by ISO/IEC 27017:2015 contain 7 cloud-specific
controls in total (1 in CLD.6, 1 in CLD.8, 2 in CLD.9, 3 in CLD.12). The
counts above reflect every CLD control listed in the table below.

---

## Cross-references

- See also: [`iso27001-annex-a-mapping.md`](iso27001-annex-a-mapping.md) — ISO 27001 Annex A controls
- See also: [`CRA_CONFORMANCE.md`](CRA_CONFORMANCE.md) — EU CRA conformance
- See also: [`SSDF_MAPPING.md`](SSDF_MAPPING.md) — NIST SSDF mapping
- See also: [`GDPR_COMPLIANCE.md`](GDPR_COMPLIANCE.md) — GDPR mapping
- See also: [`iso29100-mapping.md`](iso29100-mapping.md) — ISO 29100 privacy framework

---

## CLD control mapping

### CLD.6 — Information security policies for cloud computing

| CLD ID | Name | Applicability | Evidence | Gap |
|--------|------|---------------|----------|-----|
| CLD.6.3.1 | Shared roles and responsibilities within a cloud computing environment | Customer responsibility | The customer-deployer is responsible for documenting how product, deployer, and CSP responsibilities split in their environment. JA4proxy's role assumptions (customer operates Redis, supplies TLS material to the backend, manages the cloud account) are recorded in [`docs/security/threat-model.md`](../security/threat-model.md). | None on the product side. Deployer-guidance: produce a one-page shared-responsibility matrix per deployment that names the CSP, the operator team, and the JA4proxy product role. |

### CLD.8 — Asset management for cloud computing

| CLD ID | Name | Applicability | Evidence | Gap |
|--------|------|---------------|----------|-----|
| CLD.8.1.5 | Removal of cloud service customer assets | Applies | When a deployment is decommissioned, all customer data held by JA4proxy is in Redis. The GDPR erasure script ([`scripts/gdpr_delete.py`](../../scripts/gdpr_delete.py)) removes per-IP records; the operator deletes the Redis instance to remove all aggregated state. Retention is bounded by per-key TTLs documented in [`docs/REDIS_SCHEMA.md`](../REDIS_SCHEMA.md). | None. |

### CLD.9 — Access control for cloud computing

| CLD ID | Name | Applicability | Evidence | Gap |
|--------|------|---------------|----------|-----|
| CLD.9.5.1 | Segregation in virtual computing environments | Customer responsibility | The CSP (or hypervisor operator) provides VM/container isolation. JA4proxy runs as a single-tenant process per deployment and does not host multiple tenants in one process. | None on the product side. Deployer-guidance: do not co-tenant JA4proxy instances belonging to different customers in the same Linux namespace; use one container per tenant. |
| CLD.9.5.2 | Virtual machine hardening | Customer responsibility | The customer hardens the VM/container host. The product ships with a seccomp profile ([`config/seccomp_tap.json`](../../config/seccomp_tap.json)) and capability-drop guidance for the TAP component (see [`docs/runbooks/go_proxy_operations.md`](../runbooks/go_proxy_operations.md)). | None on the product side. Deployer-guidance: apply CIS-Benchmark-style hardening to the host OS and container runtime; enable seccomp. |

### CLD.12 — Operations security for cloud computing

| CLD ID | Name | Applicability | Evidence | Gap |
|--------|------|---------------|----------|-----|
| CLD.12.1.5 | Administrator's operational security | Applies | Administrator actions against the Management API are bearer-token authenticated, RBAC-gated, and recorded to `management:audit_log` (see [`docs/REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) Phase 79 entry). Operator runbooks live in [`docs/runbooks/`](../runbooks/). | None. |
| CLD.12.4.5 | Cloud service customer's monitoring of cloud services | Applies | JA4proxy exports Prometheus metrics and ECS-structured logs that the customer can aggregate into their own observability stack; the schema is documented in [`docs/OBSERVABILITY_STANDARDS.md`](../OBSERVABILITY_STANDARDS.md). The customer remains responsible for collecting and reviewing the telemetry. | None on the product side. Deployer-guidance: scrape `/metrics` and ship logs to a SIEM the customer controls. |
| CLD.12.* | Operational logging guidance per ISO/IEC 27017:2015 §12 | Applies | All connection decisions, configuration reloads, and security-policy changes are logged to ECS-structured JSON sinks (see [`docs/OBSERVABILITY_STANDARDS.md`](../OBSERVABILITY_STANDARDS.md)) and to Redis audit lists (`management:audit_log`, `management:policy_audit` — see [`docs/REDIS_SCHEMA.md`](../REDIS_SCHEMA.md)). The operator owns retention and forwarding. | None on the product side. Deployer-guidance: forward audit and access logs into the customer's existing log-retention system. |

> **Note on CLD coverage breadth.** ISO/IEC 27017 also adds *implementation
> guidance* to many existing ISO/IEC 27002 controls (e.g. A.9, A.10, A.12,
> A.13, A.18) for cloud contexts. Those non-CLD controls are mapped in
> [`iso27001-annex-a-mapping.md`](iso27001-annex-a-mapping.md); duplicating
> them here would not add information. The table above covers only the
> *cloud-specific* CLD.* additions.

---

## Status & review schedule

| Item | Date | Notes |
|------|------|-------|
| Initial mapping | Phase 107d.1 | Scaffolding |
| CLD.6/8/9 rows | Phase 107d.2 | Filled |
| CLD.12 rows + cross-link | Phase 107d.3 | Filled |
| Refresh on next ISO/IEC 27017 revision | TBD | Standard last revised 2015; revision tracked on the ISO website |
