# ISO/IEC 29100 — Privacy Framework Mapping

> **Status:** DRAFT — self-assessed alignment (not certification)
> **Phase:** 107e (sub-phase 107e.1 scaffolding; principle bodies filled by 107e.2)
> **Standard:** ISO/IEC 29100:2011 — Privacy framework

---

## Framing

ISO/IEC 29100 is the international **privacy framework** standard. It defines
a vocabulary and 11 privacy principles that ISO auditors look for regardless
of regulatory regime; it is referenced by ISO/IEC 27701 (the Privacy
Information Management System standard) which some buyers require.

This mapping is a **self-assessment**. It is **not** a certification. PII
handling content is **not duplicated** here — every principle row links the
authoritative source ([`GDPR_COMPLIANCE.md`](GDPR_COMPLIANCE.md) for legal
basis and data-subject rights, and [`../REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md)
for retention via TTL). This document is a navigation layer, not a
re-statement of the data-handling design.

---

## Cross-references

- See also: [`GDPR_COMPLIANCE.md`](GDPR_COMPLIANCE.md) — GDPR mapping (the
  authoritative source for PII handling, retention, and data-subject rights)
- See also: [`../REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) — Redis key TTLs (the
  authoritative source for retention periods)
- See also: [`CRA_CONFORMANCE.md`](CRA_CONFORMANCE.md) — EU CRA conformance
- See also: [`iso27017-mapping.md`](iso27017-mapping.md) — ISO 27017 cloud controls

---

## The 11 ISO 29100 privacy principles

Each row records JA4proxy's alignment with a principle and links the
authoritative section in `GDPR_COMPLIANCE.md` or `REDIS_SCHEMA.md`. Bodies
are intentionally short — the substantive content lives at the linked
location and must not be duplicated here.

| # | Principle | Implementation (one-line summary) | Evidence (link, do not duplicate) | Gap |
|---|-----------|------------------------------------|------------------------------------|-----|
| 1 | Consent and choice | Not used as the lawful basis. JA4proxy processes IP addresses on the legitimate-interest basis (Art. 6(1)(f) GDPR); consent cannot meaningfully be obtained from arbitrary connection sources. | [`GDPR_COMPLIANCE.md` §3.1 Legitimate Interest](GDPR_COMPLIANCE.md), §3.2 Alternative Legal Bases | None. |
| 2 | Purpose legitimacy and specification | Purposes (network security, fraud prevention, service availability) are explicitly declared and limited; no secondary use. | [`GDPR_COMPLIANCE.md` §3.1](GDPR_COMPLIANCE.md), §13 ROPA | None. |
| 3 | Collection limitation | Only IP addresses and TLS-handshake-derived fingerprints are collected; no HTTP body, headers, or session content. | [`GDPR_COMPLIANCE.md` §4.1 What We Do NOT Collect](GDPR_COMPLIANCE.md), §4.2 What We DO Collect | None. |
| 4 | Data minimization | Derived data (JA4 fingerprints, ASN, country) preferred over raw IP wherever a signal is sufficient. | [`GDPR_COMPLIANCE.md` §4.3 Derived vs Raw Data](GDPR_COMPLIANCE.md) | None. |
| 5 | Use, retention, and disclosure limitation | Per-key TTLs bound retention; no third-party disclosure beyond enrichment lookups (AbuseIPDB, RDAP) documented in the GDPR doc §7. | [`../REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md), [`GDPR_COMPLIANCE.md` §5 Storage Limitation, §7 Data Transfers](GDPR_COMPLIANCE.md) | None. |
| 6 | Accuracy and quality | IP addresses are factual at observation time; derived fingerprints are deterministic from the TLS handshake. No corrective workflow needed because no profile is stored. | [`GDPR_COMPLIANCE.md` §6.2 Right to Rectification](GDPR_COMPLIANCE.md) | None. |
| 7 | Openness, transparency, and notice | Processing is documented in this repository; the deployer remains the data controller and is responsible for notice to data subjects in their own privacy notice. | [`GDPR_COMPLIANCE.md` §2 Data Inventory](GDPR_COMPLIANCE.md), §13 Glossary | Deployer-responsibility: publish a privacy notice that references this processing. |
| 8 | Individual participation and access | Access, erasure, restriction, and objection procedures are documented and operator-runnable. | [`GDPR_COMPLIANCE.md` §6 Data Subject Rights](GDPR_COMPLIANCE.md), [`scripts/gdpr_delete.py`](../../scripts/gdpr_delete.py) | None. |
| 9 | Accountability | DPIA, ROPA template, and audit-log entries (`management:audit_log`, `management:gdpr_erasure_log`) record processing decisions. | [`GDPR_COMPLIANCE.md` §10 DPIA, §13 ROPA](GDPR_COMPLIANCE.md), [`../REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) (`management:gdpr_erasure_log`) | None. |
| 10 | Information security | Technical and organisational measures (TLS, RBAC, audit logging, access control) per GDPR Art. 32. | [`GDPR_COMPLIANCE.md` §8 Security of Processing](GDPR_COMPLIANCE.md), [`../security/COMPREHENSIVE_SECURITY_AUDIT.md`](../security/COMPREHENSIVE_SECURITY_AUDIT.md) | None. |
| 11 | Privacy compliance | Periodic review (quarterly), DPIA refresh (annual), CVD intake for privacy-impacting findings. | [`GDPR_COMPLIANCE.md` §11 Compliance Verification & Auditing](GDPR_COMPLIANCE.md), [`../security/CVD_POLICY.md`](../security/CVD_POLICY.md) | Deployer-responsibility: schedule the deployer's own annual review of this mapping against any updates published by the project. |

---

## Data-flow paragraph

The only PII JA4proxy handles is the source IP address of inbound TLS
connections (and, in a typical deployment, the PROXY-protocol-extracted real
client IP behind a load balancer). Derived fingerprints (JA4, JA4T, ASN,
country code) are not PII because they cannot single out a natural person.
IP addresses are stored in Redis under the keys documented in
[`../REDIS_SCHEMA.md`](../reference/REDIS_SCHEMA.md) — every key has an explicit TTL
that bounds retention (typically 24 hours to 30 days; the longest are
analytics-aggregation keys at 90 days). The full data inventory, lawful
basis analysis, retention rationale, third-country transfer mechanisms,
data-subject-rights procedures, and breach-notification process are all in
[`GDPR_COMPLIANCE.md`](GDPR_COMPLIANCE.md); this document is a navigation
layer over that authoritative source and intentionally does not restate
the design.

---

## Status & review schedule

| Item | Date | Notes |
|------|------|-------|
| Initial mapping | Phase 107e.1 | Scaffolding |
| 11 principles + cross-links | Phase 107e.2 | Filled |
| Refresh on next ISO/IEC 29100 revision | TBD | Standard last revised 2011 (technical corrigendum 2018); revision tracked on the ISO website |
