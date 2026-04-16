# Phase 107 — Regulatory & Supply-Chain Conformance

> **Status:** PROPOSED
> **Size:** LARGE (7 sub-phases, ~8–10 engineer-days)
> **Dependencies:** Phase 105 (`docs/for-*/` and `docs/compliance/` entry
> points exist); Phase 202 (SBOM + Cosign signing already in place — the
> starting point for SLSA Level 3)
> **Triggered by:** Best-practices alignment review 2026-04-16; EU CRA
> December 2027 deadline
> **Review:** `docs/phases/PHASE_107_review.md` (to be written on close)

---

## Goal

Align JA4proxy with the regulatory and supply-chain standards that enterprise
buyers, auditors, and regulators will expect by the end of 2027. Specifically:
produce the EU Cyber Resilience Act conformance documentation (mandatory for
EU sales from December 2027), map the existing control set to NIST SSDF
(SP 800-218) and to ISO 27017/29100, achieve SLSA Level 3 build provenance
(a jump from the SBOM + Cosign work already shipped in Phase 202), and
produce a MITRE ATT&CK technique mapping that SOC teams can consume directly.

Phase 107 is half documentation and half real CI/build work. The SLSA L3
push (107c) is the only substantive code/infrastructure change; the rest is
mapping, conformance statements, and policy — but the mapping work is
genuinely load-bearing because it is what auditors and procurement teams
actually read.

---

## Current State

| Standard | Current state | Gap |
|----------|--------------|-----|
| EU Cyber Resilience Act (CRA) | Not addressed. Deadline Dec 2027 | Full conformance assessment + statement |
| NIST SSDF (SP 800-218) | ~70% implemented (threat model, SBOM, SAST, dep audits, CI gates) | No explicit mapping; RFPs increasingly require one |
| SLSA (Supply-chain Levels for Software Artifacts) | ~Level 2 via Phase 202 (SBOM + Cosign) | Push to Level 3: hermetic, signed, non-falsifiable provenance |
| ISO 27017 (cloud security controls) | Not mapped (27001 Annex A is mapped) | Companion mapping for cloud-deployed buyers |
| ISO 29100 (privacy framework) | Not mapped (GDPR is covered) | Companion mapping; ISO auditors ask |
| MITRE ATT&CK | Implicit — fingerprint list names specific C2 frameworks | No explicit technique-ID mapping for SOC consumption |
| Coordinated Vulnerability Disclosure | Basic — `SECURITY.md` | Formal CVD policy aligned to CRA Annex II |

---

## 107a. EU Cyber Resilience Act conformance statement

### Problem

The CRA enters full application December 2027 for any digital product with
"digital elements" sold in the EU. JA4proxy qualifies. Essential
requirements (Annex I) include security-by-default, no known exploitable
vulnerabilities at release, protection against unauthorised access, attack-
surface minimisation, data-minimisation, DoS resilience, security logging,
and a coordinated vulnerability disclosure process. Annex II adds SBOM,
free security patches for a minimum support period (guidance: 5 years),
and public vulnerability reporting.

Open-source projects may qualify for the CRA "commercial activity" exemption
*only* if there is no monetisation. Any commercial support offering removes
the exemption. Document the current monetisation position explicitly; if
commercial support is on any roadmap, treat the CRA as in-scope regardless.

### Fix

Create `docs/compliance/CRA_CONFORMANCE.md` containing:

- **Scope determination**: is JA4proxy a "product with digital elements"
  (yes); default category (self-assessed); "important" / "critical" class
  determination (argue: not important-class by default — general-purpose
  security product, not identity-management or network-device-per-Annex-III)
- **Annex I mapping**: one row per essential requirement, current evidence
  (link to existing doc/code/runbook), gap, remediation plan if any
- **Annex II mapping**: vulnerability handling — SBOM (Phase 202 ✅),
  CVD (see 107g), free patches (confirm), support period (state the target
  — recommend 5 years from first stable release)
- **Conformity assessment procedure**: self-assessment route; EU Declaration
  of Conformity template (not signed until a real EU entity exists to sign)
- **Post-market vulnerability management**: process for disclosure and
  patch publication — link 107g

**Constraint:** this is a conformance *statement*, not an independent
assessment. Do not claim certification where none exists. The document is
the evidence that a buyer or auditor reviews to decide whether to trust
the product.

### Size

**L** — CRA mapping is substantive; Annex I has 13 essential requirements
each needing evidence cross-referencing.

---

## 107b. NIST SSDF (SP 800-218) control mapping

### Problem

NIST Secure Software Development Framework is required for US federal
software procurement via OMB M-22-18, and increasingly appears in
enterprise RFPs. JA4proxy already implements most SSDF practices —
threat modelling (PW.1), SAST (PW.7), dependency scanning (PW.4), secure
build (PO.3), vulnerability disclosure (RV.1). Without an explicit mapping
document, procurement teams can't verify it.

### Fix

Create `docs/compliance/SSDF_MAPPING.md`:

- Table with SSDF practice ID, current implementation, evidence link, gap
- Four groups: **PO** (Prepare the Organization), **PS** (Protect the
  Software), **PW** (Produce Well-Secured Software), **RV** (Respond to
  Vulnerabilities)
- Each practice: how implemented, which file / workflow / runbook is the
  evidence, outstanding gaps
- Summary box at the top: X of 19 practices fully implemented, Y partial,
  Z not applicable

**Source material:** existing CI workflows, `docs/security/`,
`docs/runbooks/`, `SECURITY.md`, `CONTRIBUTING.md`.

### Size

**S** — most evidence already exists; this is curation, not new work.

---

## 107c. SLSA Level 3 build provenance

### Problem

Phase 202 shipped SBOM + Cosign signing, which puts JA4proxy at SLSA
Level 2 (hosted, tamper-resistant build with signed artefacts). Level 3
adds: hardened build, isolated build environment per artefact, and
non-falsifiable provenance — signed attestations that cryptographically
bind the build inputs (source revision, build parameters) to the output
artefact. GitHub's `slsa-github-generator` is the reference
implementation for GitHub Actions.

SLSA L3 is the first level that genuinely defends against a compromised
CI infrastructure producing a backdoored artefact. It is increasingly
expected by security-conscious buyers and is a prerequisite for several
CRA-class attestations.

### Fix

Two tracks — documentation (107c.1) and build-pipeline implementation
(107c.2).

**107c.1 — Design doc and ADR**

Write `docs/decisions/ADR-107a-slsa-level-3.md` recording:

- Why Level 3 (not Level 2 or Level 4)
- Choice between `slsa-github-generator` (recommended) vs in-toto-based
  custom attestation
- Artefact scope: the Go proxy container image is the primary target;
  `ja4proxy-cli` binary is secondary; Python source is out of scope
- Verifier story: how downstream consumers verify the attestation
  (Cosign + SLSA verifier)

**107c.2 — Implementation**

Update `.github/workflows/go-proxy-image.yml` to:

- Use `slsa-framework/slsa-github-generator` reusable workflow
  (SHA-pinned per existing policy in `ci.yml`)
- Emit SLSA provenance attestation alongside the container image push
- Push attestation to the same OCI registry as a separate artefact
- Add a verification step in a test workflow that fetches the image +
  attestation and runs `slsa-verifier` against it — must exit 0

Update `.github/workflows/release-cli.yml` similarly for the
`ja4proxy-cli` binary.

Document the verification procedure in
`docs/for-architects/SLSA_VERIFICATION.md` — a short runbook showing
buyers how to verify provenance at install time.

### Size

**L** — 107c.1 is XS (ADR), 107c.2 is M–L (real CI work with security
implications; budget for debug cycles against the GitHub-hosted runner
environment).

---

## 107d. ISO 27017 cloud-controls mapping

### Problem

`docs/compliance/iso27001-annex-a-mapping.md` covers ISO 27001. ISO 27017
is the cloud-specific companion — additional controls (CLD.6.3.1 through
CLD.12.4.5) that cloud-deployed buyers' auditors check. Without this
mapping, JA4proxy cannot cleanly satisfy cloud-security assessments.

### Fix

Create `docs/compliance/iso27017-mapping.md`:

- Row per CLD control: ID, control name, applicability (applies / does not
  apply / customer-responsibility), current evidence, gap
- Several CLD controls are explicitly "shared-responsibility" — document
  which half is JA4proxy's and which is the deployer's
- Cross-link from `docs/compliance/iso27001-annex-a-mapping.md`

**Caveat:** ISO 27017 is a *guidance* standard (ISO 27002-style). The
document should frame this accurately — "alignment" rather than
"certification".

### Size

**M** — ~20 additional cloud-specific controls.

---

## 107e. ISO 29100 privacy framework mapping

### Problem

`docs/compliance/GDPR_COMPLIANCE.md` covers GDPR. ISO 29100 is the
international privacy framework — provides a vocabulary and 11 privacy
principles that ISO auditors look for regardless of regulatory regime
(it is referenced by ISO 27701 — the Privacy Information Management System
standard — which some buyers require).

### Fix

Create `docs/compliance/iso29100-mapping.md`:

- Row per privacy principle: consent, purpose legitimacy, collection
  limitation, data minimisation, use-retention-disclosure limitation,
  accuracy and quality, openness and transparency, individual participation,
  accountability, information security, privacy compliance
- For each: current implementation, evidence link, gap
- Data-flow diagram reference: what PII does JA4proxy handle (IP addresses
  are PII under GDPR), where it flows, retention periods
- Cross-link from `docs/compliance/GDPR_COMPLIANCE.md`

### Size

**S** — 11 principles; content already in GDPR doc and REDIS_SCHEMA.

---

## 107f. MITRE ATT&CK technique mapping

### Problem

JA4proxy's fingerprint list already names specific C2 frameworks (Sliver,
CobaltStrike, Evilginx) and its signal modules detect specific
adversarial behaviours. SOC teams consume ATT&CK technique IDs; without
explicit mapping, they cannot correlate JA4proxy events with their
existing ATT&CK-based detection coverage.

### Fix

Create `docs/for-architects/ATTACK_MAPPING.md`:

- Mapping table: JA4proxy signal/detection → ATT&CK technique ID(s) →
  tactic
- Expected coverage (non-exhaustive starting set):
  - **TA0043 Reconnaissance:** T1595 Active Scanning (signal: TCP behaviour,
    rate limiting by IP)
  - **TA0042 Resource Development:** T1583 Acquire Infrastructure (signal:
    ASN/datacenter classifier, RDAP)
  - **TA0001 Initial Access:** T1110.004 Credential Stuffing (signal:
    by-IP-JA4-pair rate limit with low thresholds)
  - **TA0011 Command and Control:** T1573 Encrypted Channel, T1071
    Application Layer Protocol (signal: JA4 blacklist fingerprints
    — Sliver t13d190900_*, CobaltStrike t12d*, Evilginx)
  - **TA0005 Defense Evasion:** T1090 Proxy (signal: Tor ASN classifier),
    T1070 Indicator Removal (signal: beaconing-detector IAT coefficient
    of variation)
- Link each row to the source signal module
- Include "reverse lookup" view: for each technique, which JA4proxy
  detection fires
- SIEM-integration section (link to `docs/for-architects/SIEM_INTEGRATION.md`
  from Phase 105) showing how to express the ATT&CK mapping in Splunk /
  Sentinel / QRadar search queries

### Size

**M** — ~15–25 technique mappings; each needs code-traceback.

---

## 107g. Coordinated vulnerability disclosure policy

### Problem

`SECURITY.md` provides basic vulnerability disclosure contact and timeline
but does not meet CRA Annex II requirements for a formal CVD process, and
does not align to ISO 29147 (the international CVD standard). The same
gap blocks some SSDF RV-practice mappings.

### Fix

Promote `SECURITY.md` content into a full CVD policy at
`docs/security/CVD_POLICY.md`:

- Scope: what is in scope for coordinated disclosure (proxy core, CLI,
  integrations); what is out of scope (experimental Python prototype,
  documentation)
- Submission: reporting channels, PGP key (publish or note unavailability),
  expected contents
- Acknowledgement SLA: 2 business days
- Triage SLA: 10 business days
- Fix SLA: by severity — Critical 30 days, High 60 days, Medium 90 days,
  Low next release
- Disclosure: embargo policy, credit / acknowledgement, CVE assignment
- Safe harbour: research conducted per the policy is authorised and will
  not result in legal action
- Alignment: reference ISO/IEC 29147 (vulnerability disclosure) and
  ISO/IEC 30111 (vulnerability handling)

Update `SECURITY.md` to a short summary that links the full policy.

Cross-link from: Phase 107a (CRA Annex II), Phase 107b (SSDF RV practices).

### Size

**S** — policy writing; content largely already implicit.

---

## Acceptance Criteria

**Core deliverables**

- [ ] `docs/compliance/CRA_CONFORMANCE.md` exists with full Annex I + Annex II
      evidence mapping and a scope determination
- [ ] `docs/compliance/SSDF_MAPPING.md` exists with all 19 SSDF practices
      addressed; summary box shows X/Y/Z counts
- [ ] `docs/decisions/ADR-107a-slsa-level-3.md` exists and is approved
- [ ] `.github/workflows/go-proxy-image.yml` uses `slsa-github-generator`
      with SHA-pinned action; provenance attestation is pushed to OCI
      registry
- [ ] A test workflow runs `slsa-verifier` against the published image +
      attestation and exits 0
- [ ] `.github/workflows/release-cli.yml` produces SLSA L3 provenance for
      `ja4proxy-cli`
- [ ] `docs/for-architects/SLSA_VERIFICATION.md` exists with a copy-paste
      verification procedure
- [ ] `docs/compliance/iso27017-mapping.md` exists with all CLD.* controls
      addressed
- [ ] `docs/compliance/iso29100-mapping.md` exists with all 11 privacy
      principles addressed
- [ ] `docs/for-architects/ATTACK_MAPPING.md` exists with ≥ 15 MITRE
      technique mappings, each linked to a source signal module
- [ ] `docs/security/CVD_POLICY.md` exists with submission, SLAs, safe
      harbour, ISO 29147/30111 alignment
- [ ] `SECURITY.md` updated to point to CVD_POLICY.md

**Integration**

- [ ] `docs/for-architects/README.md` links CRA_CONFORMANCE, SSDF_MAPPING,
      ATTACK_MAPPING, SLSA_VERIFICATION
- [ ] `docs/for-compliance/README.md` links CRA_CONFORMANCE, SSDF_MAPPING,
      iso27017-mapping, iso29100-mapping, CVD_POLICY
- [ ] `docs/compliance/iso27001-annex-a-mapping.md` cross-links to
      iso27017-mapping
- [ ] `docs/compliance/GDPR_COMPLIANCE.md` cross-links to iso29100-mapping
- [ ] `docs/RISK_REGISTER.md` (from Phase 106b) has rows added for any
      gaps discovered during the mapping work
- [ ] `docs/for-website-owners/FAQ.md` (from Phase 105) adds entries for
      "Are you CRA-compliant?" and "Do you support SLSA provenance
      verification?"

**Verification**

- [ ] Running `cosign verify-attestation` against the current container
      image returns a valid SLSA v1.0 provenance statement
- [ ] Every `uses:` in the new workflow changes is SHA-pinned per
      `tests/test_workflow_pinning.py`
- [ ] A dry-run of an RFP questionnaire covering CRA / SSDF / SLSA / ISO
      27017 / 29100 can be fully answered from the new docs alone

**Close-out**

- [ ] `docs/phases/manifest.yaml` has Phase 107 entry marked COMPLETE
- [ ] `CHANGELOG.md` has Phase 107 entry
- [ ] `make sync` clean

---

## Files to Modify

| File | Change |
|------|--------|
| `docs/compliance/CRA_CONFORMANCE.md` | New |
| `docs/compliance/SSDF_MAPPING.md` | New |
| `docs/compliance/iso27017-mapping.md` | New |
| `docs/compliance/iso29100-mapping.md` | New |
| `docs/compliance/iso27001-annex-a-mapping.md` | Cross-link to 27017 |
| `docs/compliance/GDPR_COMPLIANCE.md` | Cross-link to 29100 |
| `docs/decisions/ADR-107a-slsa-level-3.md` | New |
| `docs/decisions/INDEX.md` | Add ADR-107a |
| `docs/for-architects/SLSA_VERIFICATION.md` | New |
| `docs/for-architects/ATTACK_MAPPING.md` | New |
| `docs/for-architects/README.md` | Add four new links |
| `docs/for-compliance/README.md` | Add five new links |
| `docs/for-website-owners/FAQ.md` | Add CRA + SLSA entries |
| `docs/security/CVD_POLICY.md` | New |
| `SECURITY.md` | Replace detailed content with pointer to CVD_POLICY |
| `.github/workflows/go-proxy-image.yml` | Add SLSA generator; pin action |
| `.github/workflows/release-cli.yml` | Add SLSA generator for CLI binary |
| `.github/workflows/slsa-verify.yml` | New — verification test workflow |
| `docs/RISK_REGISTER.md` | Add rows for discovered gaps (from Phase 106) |
| `docs/phases/manifest.yaml` | Add Phase 107 entry; mark COMPLETE |
| `CHANGELOG.md` | Phase 107 entry |

---

## Sizing Summary

| Sub-phase | Size | Notes |
|-----------|------|-------|
| 107a — CRA conformance | L | Annex I has 13 essential requirements; load-bearing |
| 107b — SSDF mapping | S | Most evidence exists; curation |
| 107c — SLSA Level 3 | L | 107c.1 ADR is XS; 107c.2 CI implementation is M–L |
| 107d — ISO 27017 | M | ~20 cloud controls |
| 107e — ISO 29100 | S | 11 principles; content largely in GDPR doc |
| 107f — MITRE ATT&CK | M | ~15–25 mappings with code-traceback |
| 107g — CVD policy | S | Policy writing; content implicit |

**Total effort:** LARGE. Suggested parallelism:

- **Wave 1** (parallel, 5 agents): 107a, 107b, 107d, 107e, 107f, 107g
  — all documentation mappings, no code dependencies
- **Wave 2**: 107c.1 ADR (can run anytime in Wave 1 window)
- **Wave 3**: 107c.2 SLSA L3 implementation — sequential after ADR approved
  and Wave 1 landed (so docs link to the verification procedure correctly)
- **Wave 4**: integration + close-out

One engineer full-time: ~10 working days. Five-agent fan-out in Wave 1: ~5
working days, with 107c.2 sequential on top.

---

## Notes for Implementer

- **CRA conformance is a moving target.** The technical standards harmonised
  under the CRA are still being drafted by ETSI / CEN-CENELEC through 2026.
  Write the mapping against the regulation text (EU 2024/2847) directly,
  and note where harmonised standards are expected to land. Plan a
  refresh pass in 2027 Q1 after the harmonised standards are final.
- **"Self-assessed" vs "independent certification".** Every doc produced
  here is a self-assessment. Do not use the word "certified" anywhere
  unless an accredited body has actually certified the project — which
  is not the case. Use "aligned with", "conformant to", "mapped against".
- **SLSA Level 3 verifier UX matters more than the attestation itself.**
  The whole point is buyers being able to verify provenance. The
  `SLSA_VERIFICATION.md` runbook must be copy-paste-runnable and work on
  a clean machine with only `cosign` and `slsa-verifier` installed.
- **ATT&CK mapping risks overclaiming.** A signal that *can* detect a
  technique under ideal conditions is not the same as reliably detecting
  it. Each mapping row should include a confidence note: "high — reliably
  detects", "medium — detects common variants", "low — detects known
  samples only". Do not inflate.
- **ISO-27017 applicability is the honest-work part.** Many CLD controls
  are explicitly the responsibility of the cloud service *customer*, not
  the product vendor. Mark these clearly as "customer responsibility" with
  a one-line deployer guidance note, rather than fudging them as
  "implemented".
- **CVD safe-harbour language is legal territory.** Use established
  templates (e.g., the disclose.io SAFE HARBOUR) and do not invent
  language. If a lawyer review is available, route the policy through it
  before publishing.
- **Out of scope:** FedRAMP authorisation (requires a sponsor and is a
  ~$1M+ engagement), PCI-DSS formal assessment, HIPAA BAA templates, CNCF
  graduation. These are product-maturity milestones, not phase work.
- **Relation to Phase 105/106:** 107 adds content that slots into
  `docs/for-architects/` and `docs/for-compliance/` entry points created
  by 105, and adds rows to the risk register created by 106. Running 107
  before 105 is possible but means temporary link-dangling; prefer
  sequencing 105 → 106 → 107.
