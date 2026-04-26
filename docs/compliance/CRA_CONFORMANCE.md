# EU Cyber Resilience Act — Conformance Statement

> **Status:** DRAFT — self-assessed conformance statement (not certification)
> **Phase:** 107a (sub-phase 107a.1 scaffolding; Annex content to be filled by 107a.2/.3/.4/.5)
> **Regulation:** Regulation (EU) 2024/2847 — Cyber Resilience Act
> **Effective date:** December 2027 (full application)
> **Reviewer:** Self-assessed by the JA4proxy maintainers

---

## Cross-references

- See also: [`SSDF_MAPPING.md`](SSDF_MAPPING.md) — NIST SP 800-218 control mapping
- See also: [`iso27001-annex-a-mapping.md`](iso27001-annex-a-mapping.md) — ISO 27001 Annex A controls
- See also: [`GDPR_COMPLIANCE.md`](GDPR_COMPLIANCE.md) — GDPR + ISO 29100 privacy mapping
- Vulnerability handling: [`../security/CVD_POLICY.md`](../security/CVD_POLICY.md)
- Build provenance: [`../decisions/ADR-107a-slsa-level-3.md`](../decisions/ADR-107a-slsa-level-3.md), [`../for-architects/SLSA_VERIFICATION.md`](../for-architects/SLSA_VERIFICATION.md)

---

## Scope determination

JA4proxy is a TLS-aware passthrough security proxy distributed as source code
under an open-source licence, as a published container image
(`ghcr.io/anomalyco/ja4proxy-go`), and as a standalone CLI binary
(`ja4proxy-cli`). It is a **product with digital elements** within the meaning
of Regulation (EU) 2024/2847 Article 3(1). JA4proxy is **self-assessed** as
falling under the **default** category of products with digital elements; it is
**not** within the **important** or **critical** classes (Annex III / Annex
IV) — JA4proxy is a general-purpose security product, not an
identity-management product, network management system, hypervisor, or any
other category enumerated as important-class or critical-class.

**Monetisation position (CRA "commercial activity" exemption analysis).** As of
the date of this statement the JA4proxy project does **not** have a paid
support offering, commercial licence tier, or other monetisation arrangement
that would convert open-source distribution into a commercial activity within
the meaning of Recital (15). The project nonetheless **treats the CRA as
in-scope** in this conformance statement, on the basis that any future
commercial-support offering would remove the exemption, and producing the
conformance evidence proactively is cheaper than producing it under deadline
pressure once a commercial offering exists. Where the present statement
identifies a gap, the project commits to closing it before any commercial
offering is announced.

This statement uses the language **"self-assessed"** and **"aligned with"**
throughout. It does **not** claim certification; no accredited body has
assessed JA4proxy against the CRA.

---

## Annex I — Essential cybersecurity requirements

<!-- TODO 107a.2 — fill ER1-ER4 (security by default, no known exploitable vulns, protection from unauthorised access, attack-surface minimisation) -->
<!-- TODO 107a.3 — fill ER5-ER8 (data minimisation, DoS resilience, security logging, integrity protection) -->
<!-- TODO 107a.4 — fill ER9-ER13 (vulnerability handling, secure-by-default config, secure update, etc. — confirm exact list against EU 2024/2847 Annex I) -->

| ER | Requirement | Current evidence | Gap | Remediation |
|----|-------------|------------------|-----|-------------|
| ER1 | Security by default | <!-- TODO 107a.2 --> | | |
| ER2 | No known exploitable vulnerabilities | <!-- TODO 107a.2 --> | | |
| ER3 | Protection from unauthorised access | <!-- TODO 107a.2 --> | | |
| ER4 | Attack-surface minimisation | <!-- TODO 107a.2 --> | | |
| ER5 | Data minimisation | <!-- TODO 107a.3 --> | | |
| ER6 | DoS resilience | <!-- TODO 107a.3 --> | | |
| ER7 | Security logging | <!-- TODO 107a.3 --> | | |
| ER8 | Integrity protection | <!-- TODO 107a.3 --> | | |
| ER9 | Vulnerability handling process | <!-- TODO 107a.4 --> | | |
| ER10–ER13 | Remaining Annex I requirements | <!-- TODO 107a.4 — confirm against EU 2024/2847 --> | | |

---

## Annex II — Vulnerability-handling and post-market obligations

<!-- TODO 107a.4 — fill SBOM / CVD / free patches / support period rows -->

| Annex II item | Evidence | Notes |
|---------------|----------|-------|
| Software Bill of Materials (SBOM) | <!-- TODO 107a.4 — link `.github/workflows/go-proxy-image.yml` SBOM step + `../decisions/ADR-202d.md` --> | CycloneDX format, OCI-attached |
| Coordinated vulnerability disclosure (CVD) | <!-- TODO 107a.4 — link `../security/CVD_POLICY.md` --> | See 107g |
| Free security patches | <!-- TODO 107a.4 — confirm position --> | |
| Support period | <!-- TODO 107a.4 — recommend 5 years from first stable release; FLAG FOR HUMAN DECISION before publishing --> | Multi-year commitment |

---

## Conformity-assessment procedure

<!-- TODO 107a.5 — describe self-assessment route + EU Declaration of Conformity TEMPLATE (un-signed placeholder) -->

JA4proxy follows the **self-assessment** route under the CRA (default-class
products), per Article 24(1)(a). An EU Declaration of Conformity template will
be added here as a placeholder; it cannot be signed until a designated EU
representative or manufacturer entity exists.

---

## Post-market vulnerability management

<!-- TODO 107a.5 — link CVD_POLICY.md once 107g lands; reference ISO/IEC 29147 + 30111 alignment -->

Vulnerability handling and disclosure procedures are documented in
[`../security/CVD_POLICY.md`](../security/CVD_POLICY.md) (created by Phase
107g).

---

## Status & review schedule

| Item | Date | Notes |
|------|------|-------|
| Initial conformance assessment | Phase 107 | Self-assessed |
| Annex I expansion to all ERs | 107a.2/.3/.4 | Pending |
| Conformity assessment + DoC template | 107a.5 | Pending |
| Refresh after harmonised standards published | 2027 Q1 (planned) | ETSI / CEN-CENELEC harmonised standards still in draft through 2026 |
