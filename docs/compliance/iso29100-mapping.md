# ISO/IEC 29100 — Privacy Framework Mapping

> **Status:** DRAFT — self-assessed alignment (not certification)
> **Phase:** 107e (sub-phase 107e.1 scaffolding; principle bodies to be filled by 107e.2)
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
basis and data-subject rights, and [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md)
for retention via TTL). This document is a navigation layer, not a
re-statement of the data-handling design.

---

## Cross-references

- See also: [`GDPR_COMPLIANCE.md`](GDPR_COMPLIANCE.md) — GDPR mapping (the
  authoritative source for PII handling, retention, and data-subject rights)
- See also: [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) — Redis key TTLs (the
  authoritative source for retention periods)
- See also: [`CRA_CONFORMANCE.md`](CRA_CONFORMANCE.md) — EU CRA conformance

---

## The 11 ISO 29100 privacy principles

<!-- TODO 107e.2 — fill all 11 principle rows. For each: implementation summary, link to authoritative source (GDPR doc / REDIS_SCHEMA), gap. Do NOT duplicate GDPR content. -->

| # | Principle | Implementation | Evidence (link, do not duplicate) | Gap |
|---|-----------|----------------|------------------------------------|-----|
| 1 | Consent and choice | <!-- TODO 107e.2 --> | | |
| 2 | Purpose legitimacy and specification | <!-- TODO 107e.2 --> | | |
| 3 | Collection limitation | <!-- TODO 107e.2 --> | | |
| 4 | Data minimization | <!-- TODO 107e.2 --> | | |
| 5 | Use, retention, and disclosure limitation | <!-- TODO 107e.2 --> | | |
| 6 | Accuracy and quality | <!-- TODO 107e.2 --> | | |
| 7 | Openness, transparency, and notice | <!-- TODO 107e.2 --> | | |
| 8 | Individual participation and access | <!-- TODO 107e.2 --> | | |
| 9 | Accountability | <!-- TODO 107e.2 --> | | |
| 10 | Information security | <!-- TODO 107e.2 --> | | |
| 11 | Privacy compliance | <!-- TODO 107e.2 --> | | |

---

## Data-flow paragraph

<!-- TODO 107e.2 — one short paragraph: PII = IP addresses, retention per Redis TTLs, see GDPR doc for full picture. Do not restate the GDPR doc content. -->
