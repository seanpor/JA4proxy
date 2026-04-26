# NIST SSDF (SP 800-218) — Control Mapping

> **Status:** DRAFT — self-assessed mapping (not certification)
> **Phase:** 107b (sub-phase 107b.1 scaffolding; rows to be filled by 107b.2/.3)
> **Standard:** NIST SP 800-218 — Secure Software Development Framework v1.1

---

## Summary

<!-- TODO 107b.3 — replace placeholders with actual counts after 107b.2/.3 fill the tables -->

| Total practices | Fully implemented | Partial | Not applicable |
|-----------------|-------------------|---------|----------------|
| 19 | 0 (TODO 107b.3) | 0 (TODO 107b.3) | 0 (TODO 107b.3) |

This mapping records JA4proxy's **alignment with** SSDF practices as a
self-assessment. It is **not** a NIST certification or attestation. Every
"implemented" claim links to a file path or workflow that exists in the
repository.

---

## Cross-references

- See also: [`CRA_CONFORMANCE.md`](CRA_CONFORMANCE.md) — EU CRA Annex I/II
- Vulnerability handling: [`../security/CVD_POLICY.md`](../security/CVD_POLICY.md)
- Build provenance: [`../decisions/ADR-107a-slsa-level-3.md`](../decisions/ADR-107a-slsa-level-3.md)

---

## PO — Prepare the Organization

<!-- TODO 107b.2 — fill PO.1 through PO.5 -->

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| PO.1 | Define security requirements for software development | <!-- TODO 107b.2 --> | | |
| PO.2 | Implement roles and responsibilities | <!-- TODO 107b.2 --> | | |
| PO.3 | Implement supporting toolchains | <!-- TODO 107b.2 --> | | |
| PO.4 | Define and use criteria for software security checks | <!-- TODO 107b.2 --> | | |
| PO.5 | Implement and maintain secure environments for software development | <!-- TODO 107b.2 --> | | |

---

## PS — Protect the Software

<!-- TODO 107b.3 — fill PS.1 through PS.3 -->

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| PS.1 | Protect all forms of code from unauthorized access and tampering | <!-- TODO 107b.3 --> | | |
| PS.2 | Provide a mechanism for verifying software release integrity | <!-- TODO 107b.3 --> | | |
| PS.3 | Archive and protect each software release | <!-- TODO 107b.3 --> | | |

---

## PW — Produce Well-Secured Software

<!-- TODO 107b.3 — fill PW.1 through PW.8 -->

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| PW.1 | Design software to meet security requirements and mitigate security risks | <!-- TODO 107b.3 --> | | |
| PW.2 | Review the software design to verify compliance with security requirements and risk information | <!-- TODO 107b.3 --> | | |
| PW.3 | Reuse existing, well-secured software when feasible | <!-- TODO 107b.3 --> | | |
| PW.4 | Create source code by adhering to secure coding practices | <!-- TODO 107b.3 --> | | |
| PW.5 | Configure the compilation, interpreter, and build processes to improve executable security | <!-- TODO 107b.3 --> | | |
| PW.6 | Review and/or analyze human-readable code to identify vulnerabilities and verify compliance with security requirements | <!-- TODO 107b.3 --> | | |
| PW.7 | Test executable code to identify vulnerabilities and verify compliance with security requirements | <!-- TODO 107b.3 --> | | |
| PW.8 | Configure software to have secure settings by default | <!-- TODO 107b.3 --> | | |

---

## RV — Respond to Vulnerabilities

<!-- TODO 107b.2 — fill RV.1 through RV.3 -->

| Practice ID | Practice | Implementation | Evidence | Gap |
|-------------|----------|----------------|----------|-----|
| RV.1 | Identify and confirm vulnerabilities on an ongoing basis | <!-- TODO 107b.2 --> | | |
| RV.2 | Assess, prioritize, and remediate vulnerabilities | <!-- TODO 107b.2 --> | | |
| RV.3 | Analyze vulnerabilities to identify their root causes | <!-- TODO 107b.2 --> | | |
