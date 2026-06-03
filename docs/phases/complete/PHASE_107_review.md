# Phase 107 Review — Regulatory & Supply-Chain Conformance

> **Reviewer:** Independent critical review (cybersecurity / DevOps / SRE / architecture lenses)
> **Date:** 2026-04-26
> **Phase status (manifest):** PROPOSED · size LARGE · 7 sub-phases
> **Verdict:** **READY TO START**, with mitigations on three flagged risks.
> **Sub-task count:** 27 (24 XS/S, 3 M) — designed for parallel junior-engineer execution.

---

## Step 1 — Context & Dependency Check

| Item | Status |
|---|---|
| `docs/phases/complete/PHASE_107.md` | ✅ Exists (476 lines, well-structured) |
| Dependency: Phase 105 (audience-scoped doc directories) | ✅ COMPLETE — `docs/for-{architects,compliance,website-owners}/` all populated |
| Dependency: Phase 106 (`RISK_REGISTER.md` etc.) | ✅ COMPLETE — `docs/RISK_REGISTER.md` exists for new rows |
| Dependency: Phase 202 (SBOM + Cosign baseline = SLSA L2) | ✅ COMPLETE — `.github/workflows/go-proxy-image.yml` already does keyless cosign + SBOM (see `ADR-202d`) |
| Dependency: workflow SHA-pin enforcement | ✅ `tests/test_workflow_pinning.py` exists |
| Existing CRA/SSDF/27017/29100/ATT&CK docs | ❌ None — all net-new (intended) |
| Existing CVD policy | Partial — `SECURITY.md` (125 lines) present; needs promotion |

**Production runtime context (CLAUDE.md rule):** Phase 107 is **not** Go vs Python — it is overwhelmingly documentation + CI/build pipeline work. The single Go-side touchpoint is the build provenance for the `bin/proxy` container image. No source files in `cmd/proxy/` or `internal/` change. No Python prototype work either.

---

## Step 2 — Critical Review (Six Lenses)

### 2a. Security review

| Finding | Detail |
|---|---|
| **S-1 (HIGH)** Sub-phase 107c.2 modifies the production release pipeline | A botched `slsa-github-generator` wiring could (a) break the release path so no images publish, or (b) emit attestations that don't actually bind to the right digest — *worse than no attestation* because consumers may trust them. Treat 107c.2 as a release-engineering change, not a doc change. |
| **S-2 (HIGH)** Overclaiming risk | Documents that say "certified" / "compliant" when the project is self-assessed = fraudulent representation under CRA Article 24. Mitigation already noted in §"Notes for Implementer" — but must be enforced by a **review checklist** the junior follows on every sub-task, plus a CI grep gate. |
| **S-3 (MEDIUM)** CVD safe-harbour is legal language | Junior must use the **disclose.io SAFE template verbatim**, not paraphrase. Add explicit "do not modify legal text" instruction to 107g sub-tasks. |
| **S-4 (MEDIUM)** SHA-pinning of new `slsa-framework/slsa-github-generator` action | New workflow `uses:` lines must be SHA-pinned per `tests/test_workflow_pinning.py`. The pinning test must be **updated to cover the new workflow file** before merge, otherwise it can silently regress. |
| **S-5 (LOW)** PII scope | ATT&CK + ISO 29100 mappings touch IP-address handling. Cross-reference must point to **existing** GDPR doc + REDIS_SCHEMA, not duplicate the data-handling description (single source of truth). |
| **S-6 (INFO)** No new external dependencies | Only the SLSA generator workflow (already a SHA-pinned reusable workflow). No new Go modules, no new pip packages. Supply-chain delta is minimal. |

### 2b. DevOps review

| Finding | Detail |
|---|---|
| **D-1 (HIGH)** Build path mutation in 107c.2 | `go-proxy-image.yml` has explicit `permissions:` blocks with `id-token: write` for keyless cosign. SLSA generator needs `id-token: write` *at the workflow level* — moving it from the job to the workflow may be required, which is a non-trivial diff. Junior should land it under `workflow_dispatch` first, manually verify a published artefact, *then* enable on `push` triggers. |
| **D-2 (MEDIUM)** No rollback hazard for docs | All 107a/b/d/e/f/g sub-phases are pure docs adds — `git revert` is safe. |
| **D-3 (MEDIUM)** Hot-reload N/A | No runtime config keys. No `config/proxy.yml` changes. |
| **D-4 (LOW)** New CI workflow `slsa-verify.yml` | Net-new workflow; should be `workflow_dispatch` only initially, promoted to scheduled / push-triggered after first successful run. |

### 2c. SRE review

| Finding | Detail |
|---|---|
| **R-1 (LOW)** No new metrics, log lines, alerts | Phase 107 is documentation/CI-only. Observability lens largely N/A. |
| **R-2 (MEDIUM)** SLAs in CVD policy create operational obligations | The CVD doc commits the project to **2-day acknowledgement, 10-day triage, 30/60/90-day fix SLAs**. There is no oncall rotation today. Junior must **flag this commitment for human review** before publishing — these are promises with reputational cost if missed. |
| **R-3 (LOW)** Runbook impact | Add CVD intake to `docs/security/INTAKE_RUNBOOK.md`. Add SLSA verification to `docs/runbooks/` (or link from `ADR-107a-slsa-level-3.md`). |
| **R-4 (LOW)** Fail-open principle | Not applicable — no proxy hot path touched. |

### 2d. Architecture review

| Finding | Detail |
|---|---|
| **A-1 (LOW)** No pipeline impact | Pipeline (TCP accept → bypass → signals → scorer → action) untouched. |
| **A-2 (LOW)** Doc topology already handles this | Phase 105 created `` and ``. New docs slot in cleanly. Risk: link rot — every new doc must be added to its directory's `README.md` index in the same PR. |
| **A-3 (INFO)** ATT&CK mapping creates a coupling | `ATTACK_MAPPING.md` rows reference signal modules by file path. If those signal modules are renamed/moved, the mapping rots silently. Add a `make test-traceability` style check that grep-verifies each linked file still exists. |
| **A-4 (LOW)** IPv6 N/A | No IP code paths changed. |
| **A-5 (LOW)** Redis schema N/A | No new Redis keys. |

### 2e. Testing review

| Finding | Detail |
|---|---|
| **T-1 (HIGH)** SLSA verifier test must run end-to-end | The 107c.2 acceptance criterion *"slsa-verifier exits 0"* must run against a **real published artefact**, not a fake. Junior must wire the verifier as a separate `slsa-verify.yml` workflow that runs after `go-proxy-image.yml` completes. |
| **T-2 (MEDIUM)** Doc tests are weak by default | "doc exists" is not a test. Add a CI grep check: every claim of "implemented" in a mapping doc must reference a file path or workflow that exists. Run a link-check (e.g., `lychee`) over `docs/compliance/` and `docs/for-{architects,compliance}/`. |
| **T-3 (MEDIUM)** ATT&CK confidence labels | Notes for Implementer requires confidence labels (high/medium/low). Add a CI grep check: every mapping row in `ATTACK_MAPPING.md` must contain `confidence: ` with one of the three values. |
| **T-4 (LOW)** No `test_pages.py` / `test_container_config.py` needed | Not a web service phase. |
| **T-5 (LOW)** Test ratio impact | Phase adds zero source code (CI YAML doesn't count toward Python ratio). Ratio neutral. |

### 2f. Documentation review

| Finding | Detail |
|---|---|
| **C-1 (MEDIUM)** Acceptance criteria are mostly SMART | All "doc X exists with Y rows" are checkable. The exception: *"a dry-run of an RFP questionnaire can be fully answered from the new docs alone"* — not testable as written. Replace with a checklist file (`docs/compliance/RFP_DRYRUN.md`) the reviewer ticks. |
| **C-2 (LOW)** CHANGELOG format | Project uses `## [Unreleased] - Phase XX — title (date)` per recent merges; junior should follow that. |
| **C-3 (LOW)** ADR template exists | `docs/decisions/ADR-202d.md` is the model to follow for ADR-107a; same shape (Decision / Context / Rationale / Consequences). |
| **C-4 (LOW)** Phase doc itself is well-written | Acceptance criteria cleanly listed, sub-phase splits sensible, file table exhaustive — junior can follow it directly. |

---

## Step 3 — Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---|---|---|---|
| S-1 | 107c.2 modifies production release pipeline | HIGH | Security | Land under `workflow_dispatch`-only first; verify a real published artefact end-to-end *before* enabling on push triggers |
| S-2 | "Certified" / "compliant" overclaim risk | HIGH | Security | CI grep gate: `rg -nE '\b(certified|compliant)\b' docs/compliance/` must return zero matches outside an explicit allowlist (e.g. ISO 27001 *if* the project ever certifies) |
| T-1 | SLSA verifier must run against real artefact | HIGH | Testing | Separate `slsa-verify.yml` workflow gated on successful image push, exit-code-strict |
| D-1 | `id-token: write` permissions reshape | HIGH | DevOps | Sub-task 107c.3 splits "permissions move" into its own commit so it can be reverted in isolation |
| S-3 | CVD safe-harbour is legal text | MEDIUM | Security | Use disclose.io SAFE template **verbatim**; flag for human/legal review before merge |
| S-4 | SHA-pin new SLSA generator workflow | MEDIUM | Security | Sub-task 107c.6 dedicated to updating `tests/test_workflow_pinning.py` allowlist |
| R-2 | CVD SLAs create operational obligations | MEDIUM | SRE | Sub-task 107g.4 explicitly flags the SLA commitments for human review before publishing |
| T-2 | "Doc exists" ≠ test | MEDIUM | Testing | Sub-task 107z.2 adds `lychee` link-check + grep-evidence-link check |
| T-3 | ATT&CK confidence labels | MEDIUM | Testing | Sub-task 107f.4 adds CI grep gate enforcing confidence labels |
| C-1 | RFP-questionnaire criterion not testable | MEDIUM | Documentation | Replace with concrete `RFP_DRYRUN.md` checklist (sub-task 107z.3) |
| S-5 | PII description duplication risk | LOW | Security | Cross-link to GDPR + REDIS_SCHEMA; do not duplicate |
| A-2 | Index/link rot | LOW | Architecture | Every new doc PR must update the parent README index in the same PR |
| A-3 | ATT&CK mapping ↔ signal-module path coupling | LOW | Architecture | Add file-existence check to `make test-traceability` (sub-task 107f.4) |
| R-3 | CVD intake runbook | LOW | SRE | Sub-task 107g.4 covers |
| D-4 | New `slsa-verify.yml` triggers | LOW | DevOps | `workflow_dispatch` only initially; promote later |
| C-2 / C-3 / C-4 | Format alignment | LOW | Documentation | Follow established CHANGELOG / ADR templates |
| R-1 / R-4 / T-4 / T-5 / A-1 / A-4 / A-5 / S-6 / D-2 / D-3 | Various N/A or trivial | INFO | No action |

**Critical blockers before implementation:** none. All HIGH-severity findings are mitigated by sub-task structure rather than blocking.

---

## Step 4 — Junior-Engineer Sub-Task Decomposition

**Design principle:** Every sub-task is XS (≤2h) or S (2-4h). No task can take down production by being done wrong (107c.3 and 107c.4 are the closest — mitigated by `workflow_dispatch`-only landing).

**Naming convention:** `107<sub>.<n>` where `<sub>` is the original sub-phase letter (a/b/c/d/e/f/g) and `<n>` is the slice. Wiring + close-out are `107w.<n>` and `107z.<n>`.

### Phase 1 — Scaffolding (parallel-safe, day 1)

#### Sub-task 107a.1: CRA scaffold + scope determination
- **Size:** S (2h) · **Depends on:** none · **Parallel with:** 107b.1, 107c.1, 107d.1, 107e.1, 107f.1, 107g.1
- **Files to touch:** `docs/compliance/CRA_CONFORMANCE.md` (new)
- **What to do:**
  - Create file with title, status banner, and three top-level sections: "Scope determination", "Annex I mapping", "Annex II mapping". Leave Annex sections as `<!-- TODO 107a.2-4 -->`.
  - Fill **Scope determination** only: argue JA4proxy is "product with digital elements", default category, **not** important/critical class. Two paragraphs max.
  - Add monetisation-position paragraph (per phase doc §107a Problem para 2).
- **Done when:**
  - [ ] File exists, parses as Markdown
  - [ ] Scope determination section is non-empty and uses "self-assessed" / "aligned with" — never "certified"
- **Watch out for:** S-2 overclaim — never use "certified" / "compliant" anywhere

#### Sub-task 107b.1: SSDF mapping scaffold + summary box
- **Size:** XS (1h) · **Depends on:** none · **Parallel with:** all other scaffolding
- **Files to touch:** `docs/compliance/SSDF_MAPPING.md` (new)
- **What to do:**
  - Create file with title, summary box (`X/Y/Z fully implemented / partial / N/A — initial counts: 0/0/0, filled in 107b.3`), and four empty group tables: `## PO — Prepare the Organization`, `## PS — Protect the Software`, `## PW — Produce Well-Secured Software`, `## RV — Respond to Vulnerabilities`.
  - Each table has columns: `Practice ID | Practice | Implementation | Evidence | Gap`.
  - Leave rows as `<!-- TODO 107b.2 / 107b.3 -->`.
- **Done when:** [ ] File parses; 4 group headers + summary box present
- **Watch out for:** S-2 overclaim

#### Sub-task 107c.1: SLSA L3 ADR
- **Size:** S (2h) · **Depends on:** none · **Parallel with:** all scaffolding
- **Files to touch:** `docs/decisions/ADR-107a-slsa-level-3.md` (new), `docs/decisions/README.md` (add row)
- **What to do:**
  - Copy structure from `docs/decisions/ADR-202d.md`: Status / Context / Decision / Consequences.
  - **Decision:** adopt SLSA Level 3 via `slsa-framework/slsa-github-generator` reusable workflow (vs in-toto custom).
  - **Context:** current state (L2 from Phase 202), buyer expectations, CRA prerequisite link.
  - **Consequences:** added `id-token: write` workflow-level permission; added `slsa-verify.yml` test workflow; `cosign verify-attestation` becomes operator-runnable.
  - Add row to `docs/decisions/README.md`.
- **Done when:**
  - [ ] ADR file follows ADR-202d shape (Status: Proposed initially)
  - [ ] README.md has new row
- **Watch out for:** Status field — set to `Proposed` here; flip to `Accepted` only when 107c.2/3/4 land

#### Sub-task 107d.1: ISO 27017 scaffold + applicability table
- **Size:** S (2h) · **Depends on:** none · **Parallel with:** all scaffolding
- **Files to touch:** `docs/compliance/iso27017-mapping.md` (new)
- **What to do:**
  - Create file with title, "alignment **not** certification" framing paragraph, and an **applicability summary table** at the top:
    `Total CLD controls: 20 | Applicable to JA4proxy: X | Customer responsibility: Y | Not applicable: Z` (numbers filled in 107d.2/.3).
  - Empty mapping table with columns: `CLD ID | Name | Applicability | Evidence | Gap`.
  - Leave rows as `<!-- TODO 107d.2 / 107d.3 -->`.
- **Done when:** [ ] File parses; applicability summary table present (with placeholders); mapping table headers present
- **Watch out for:** S-2 overclaim ("guidance standard" framing must be in the intro)

#### Sub-task 107e.1: ISO 29100 scaffold + 11 principle stubs
- **Size:** XS (1h) · **Depends on:** none · **Parallel with:** all scaffolding
- **Files to touch:** `docs/compliance/iso29100-mapping.md` (new)
- **What to do:**
  - Create file with title and a single mapping table with one row per ISO 29100 principle (consent, purpose legitimacy, collection limitation, data minimisation, use-retention-disclosure limitation, accuracy and quality, openness and transparency, individual participation, accountability, information security, privacy compliance).
  - Each row body left as `<!-- TODO 107e.2 -->`.
- **Done when:** [ ] All 11 principles have a row; mapping table parses
- **Watch out for:** S-5 — do not duplicate GDPR/REDIS_SCHEMA content; cross-link instead

#### Sub-task 107f.1: ATT&CK mapping scaffold
- **Size:** XS (1h) · **Depends on:** none · **Parallel with:** all scaffolding
- **Files to touch:** `ATTACK_MAPPING.md` (new)
- **What to do:**
  - Create file with two top-level views: `## Forward mapping (signal → ATT&CK)` and `## Reverse lookup (ATT&CK → signal)`.
  - Forward table columns: `Signal module | Detection | Tactic | Technique ID | Confidence (high/medium/low) | Source file`.
  - Reverse table columns: `Technique ID | Technique | JA4proxy detection(s)`.
  - Leave rows as `<!-- TODO 107f.2 / 107f.3 / 107f.4 -->`.
- **Done when:** [ ] File parses; both view headers + tables present
- **Watch out for:** T-3 — every row will need a `Confidence` value in the next slice (CI gate enforced in 107f.4)

#### Sub-task 107g.1: CVD policy scaffold (sections only)
- **Size:** XS (1h) · **Depends on:** none · **Parallel with:** all scaffolding
- **Files to touch:** `docs/security/CVD_POLICY.md` (new)
- **What to do:**
  - Create file with these section headers (no body): Scope, Reporting channels, Acknowledgement & triage SLAs, Fix SLAs, Disclosure & embargo, Credit & CVE assignment, Safe harbour, Standards alignment (ISO/IEC 29147 + 30111).
- **Done when:** [ ] File exists with all 8 section headers
- **Watch out for:** R-2 — SLAs commit the project to operational work; do not fill in numbers in this slice

---

### Phase 2 — Core content (parallel-safe per sub-phase, day 2-4)

#### Sub-task 107a.2: CRA Annex I — ER1-ER4
- **Size:** S (3h) · **Depends on:** 107a.1 · **Parallel with:** 107a.3 (different sections of same file)
- **Files to touch:** `docs/compliance/CRA_CONFORMANCE.md`
- **What to do:**
  - For each of ER1 (security by default), ER2 (no known exploitable vulnerabilities), ER3 (protection from unauthorised access), ER4 (attack-surface minimisation): one mapping row with current evidence (file path + line refs), gap (or "none"), remediation (or "N/A").
  - Evidence sources: `docs/security/threat-model.md`, `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`, existing config defaults in `config/proxy.yml`, the bypass + dial=0 design (CLAUDE.md).
- **Done when:**
  - [ ] 4 ER rows, each with non-empty evidence column referencing real files
  - [ ] No "certified" / "compliant" claims
- **Watch out for:** Evidence claim must reference an existing file at a real path — verify with `ls` before committing

#### Sub-task 107a.3: CRA Annex I — ER5-ER8
- **Size:** S (3h) · **Depends on:** 107a.1 · **Parallel with:** 107a.2 (different sections)
- **Files to touch:** `docs/compliance/CRA_CONFORMANCE.md`
- **What to do:** ER5 (data minimisation), ER6 (DoS resilience), ER7 (security logging), ER8 (integrity protection). Same row format as 107a.2.
- **Done when:** [ ] 4 ER rows; evidence paths verified `ls`-clean
- **Watch out for:** ER7 evidence is `docs/OBSERVABILITY_STANDARDS.md` + `docs/runbooks/audit_log.md`-style refs; do not invent docs that don't exist

#### Sub-task 107a.4: CRA Annex I — ER9-ER13 + Annex II
- **Size:** S (3h) · **Depends on:** 107a.1 · **Parallel with:** 107a.2, 107a.3
- **Files to touch:** `docs/compliance/CRA_CONFORMANCE.md`
- **What to do:**
  - ER9 (vulnerability handling) + ER10-ER13 (remaining requirements per CRA Annex I — confirm exact list against EU 2024/2847).
  - Annex II rows: SBOM (link `.github/workflows/go-proxy-image.yml` SBOM step + `docs/decisions/ADR-202d.md`), CVD (link `docs/security/CVD_POLICY.md` — to be filled by 107g), free patches (state position), support period (recommend 5 years, flag for human decision).
- **Done when:** [ ] All ER rows present; Annex II has SBOM + CVD + patches + support rows
- **Watch out for:** Support-period number is a multi-year commitment — flag for human review in PR description

#### Sub-task 107a.5: CRA conformity assessment + EU DoC template + cross-links
- **Size:** S (2h) · **Depends on:** 107a.2/.3/.4 · **Parallel with:** none
- **Files to touch:** `docs/compliance/CRA_CONFORMANCE.md`
- **What to do:**
  - Add "Conformity assessment procedure" section: self-assessment route, references EU DoC template (un-signed placeholder until EU entity exists).
  - Add "Post-market vulnerability management" section linking `docs/security/CVD_POLICY.md`.
  - Add cross-link block at top: see also SSDF_MAPPING, iso27001-annex-a-mapping, GDPR_COMPLIANCE.
- **Done when:** [ ] All sections present; cross-links resolve via `lychee` check
- **Watch out for:** EU DoC must be marked "**TEMPLATE — not signed**" prominently

#### Sub-task 107b.2: SSDF — PO + RV groups
- **Size:** S (2h) · **Depends on:** 107b.1 · **Parallel with:** 107b.3
- **Files to touch:** `docs/compliance/SSDF_MAPPING.md`
- **What to do:**
  - Fill PO group (5 practices: PO.1–PO.5) and RV group (3 practices: RV.1–RV.3).
  - For each: implementation summary, evidence file/workflow link, gap.
  - Evidence: existing CI workflows (`.github/workflows/`), `SECURITY.md`, `CONTRIBUTING.md`, `docs/runbooks/`.
- **Done when:** [ ] 8 rows filled; each row's evidence path verified
- **Watch out for:** "Implemented" must be backed by a file path — no hand-waving

#### Sub-task 107b.3: SSDF — PS + PW groups + summary count
- **Size:** S (3h) · **Depends on:** 107b.1 · **Parallel with:** 107b.2
- **Files to touch:** `docs/compliance/SSDF_MAPPING.md`
- **What to do:**
  - Fill PS group (3 practices: PS.1–PS.3) and PW group (8 practices: PW.1–PW.8).
  - Update summary box at top with actual `X/Y/Z` (fully implemented / partial / N/A) counts.
- **Done when:** [ ] 11 rows filled; summary box numbers match content
- **Watch out for:** PW.7 (SAST) evidence is the Semgrep CI job; PW.4 (deps) is govulncheck + pip-audit jobs — verify they exist in `.github/workflows/`

#### Sub-task 107c.2: SLSA verify test workflow (`slsa-verify.yml`)
- **Size:** S (2h) · **Depends on:** 107c.1 · **Parallel with:** can run before 107c.3 (verifier itself works against any image)
- **Files to touch:** `.github/workflows/slsa-verify.yml` (new)
- **What to do:**
  - Net-new workflow, `workflow_dispatch`-only initially.
  - Steps: install `slsa-verifier` (SHA-pinned), pull image + attestation from GHCR, run `slsa-verifier verify-image` against a configurable image ref (input parameter), exit-code-strict.
  - Image input default: `ghcr.io/<owner>/ja4proxy-go:latest`.
  - Run **once manually** against an existing pre-SLSA-L3 image — expect "no attestation found" failure (proves the workflow itself is wired correctly).
- **Done when:**
  - [ ] Workflow file SHA-pins all `uses:`
  - [ ] Manual trigger against current image runs to completion (with expected failure mode documented)
- **Watch out for:** S-4 — every `uses:` must be SHA-pinned; D-4 — keep `workflow_dispatch`-only until 107c.3 lands

#### Sub-task 107c.3: SLSA generator wiring — go-proxy-image.yml
- **Size:** M (4h, the riskiest task in the phase) · **Depends on:** 107c.1 · **Parallel with:** 107c.4
- **Files to touch:** `.github/workflows/go-proxy-image.yml`
- **What to do:**
  - Move `permissions: id-token: write` from the job to the **workflow-level** `permissions:` block (required by `slsa-github-generator`).
  - Add a **separate job** `slsa-provenance:` that calls `slsa-framework/slsa-github-generator/.github/workflows/generator-container-slsa3.yml@<SHA>` with the pushed image digest as input.
  - Land first under `workflow_dispatch`-only (comment out the `push:` trigger temporarily); manually verify the published artefact + attestation; then re-enable `push:` in a follow-up commit.
- **Done when:**
  - [ ] Workflow runs to completion under `workflow_dispatch`
  - [ ] `cosign verify-attestation` against the published image returns valid SLSA v1.0 statement
  - [ ] `push:` trigger restored in follow-up commit
- **Watch out for:** D-1, S-1 — this is the production release path; do not enable `push:` until manual verification passes; commit the `permissions:` move *separately* from the generator wiring so revert is clean

#### Sub-task 107c.4: SLSA generator wiring — release-cli.yml
- **Size:** S (3h) · **Depends on:** 107c.3 (learn from any debug there) · **Parallel with:** none (sequential after 107c.3 is verified)
- **Files to touch:** `.github/workflows/release-cli.yml`
- **What to do:**
  - Same pattern as 107c.3 but for the binary path: use `slsa-framework/slsa-github-generator/.github/workflows/generator-generic-slsa3.yml@<SHA>` against the built `ja4proxy-cli` binary's sha256.
  - `workflow_dispatch`-first; manual verification; restore `push:` triggers.
- **Done when:** [ ] Verified attestation produced for the CLI binary
- **Watch out for:** S-1 same as 107c.3

#### Sub-task 107c.5: SLSA verification runbook
- **Size:** S (2h) · **Depends on:** 107c.3 (need real artefact to test instructions against) · **Parallel with:** 107c.4
- **Files to touch:** `ADR-107a-slsa-level-3.md` (new)
- **What to do:**
  - Copy-paste-runnable runbook: install `cosign` + `slsa-verifier`, pull image, run verification, expected output.
  - Test the runbook by **running every command yourself on a clean shell** before committing.
  - Add a "what failure looks like" section.
- **Done when:**
  - [ ] Every command in the runbook executes successfully when copy-pasted
  - [ ] Expected output captured verbatim
- **Watch out for:** Notes-for-Implementer says verifier UX matters more than the attestation — don't ship runbook without dry-running it

#### Sub-task 107c.6: Update workflow_pinning test allowlist
- **Size:** XS (1h) · **Depends on:** 107c.2/.3/.4 (whichever lands first) · **Parallel with:** documentation tasks
- **Files to touch:** `tests/test_workflow_pinning.py` (extend allowlist if needed)
- **What to do:**
  - Run `python3 -m pytest tests/test_workflow_pinning.py -v` after each of 107c.2/.3/.4 lands.
  - If it fails on a `slsa-framework/slsa-github-generator` reference (which is a *reusable workflow*, not a regular action — pinning convention may differ), update the test rather than the workflow.
- **Done when:** [ ] `pytest tests/test_workflow_pinning.py` exits 0
- **Watch out for:** S-4 — the test is the gate; don't bypass it

#### Sub-task 107d.2: ISO 27017 — CLD.6 + CLD.8 + CLD.9 controls
- **Size:** S (3h) · **Depends on:** 107d.1 · **Parallel with:** 107d.3
- **Files to touch:** `docs/compliance/iso27017-mapping.md`
- **What to do:**
  - Fill rows for CLD.6.* (information security policies), CLD.8.* (asset management), CLD.9.* (access control). ~10 controls total.
  - For each: explicit applicability ("applies" / "customer responsibility" / "not applicable"); evidence link if applies.
- **Done when:** [ ] ~10 rows filled; applicability honestly assessed
- **Watch out for:** Notes-for-Implementer §4 — many CLD controls are explicitly customer-responsibility; mark them so, do not fudge

#### Sub-task 107d.3: ISO 27017 — CLD.12 + applicability summary + 27001 cross-link
- **Size:** S (2h) · **Depends on:** 107d.1 · **Parallel with:** 107d.2
- **Files to touch:** `docs/compliance/iso27017-mapping.md`, `docs/compliance/iso27001-annex-a-mapping.md`
- **What to do:**
  - Fill rows for CLD.12.* (operations security). ~10 controls.
  - Update applicability summary table with actual counts.
  - Add cross-link from `iso27001-annex-a-mapping.md` to the new 27017 doc (one-paragraph "see also" block).
- **Done when:**
  - [ ] CLD.12 rows filled
  - [ ] Summary table numbers match content
  - [ ] Cross-link present in 27001 doc
- **Watch out for:** Same overclaim risk as 107d.2

#### Sub-task 107e.2: ISO 29100 — fill 11 principles + cross-links
- **Size:** S (3h) · **Depends on:** 107e.1 · **Parallel with:** anything
- **Files to touch:** `docs/compliance/iso29100-mapping.md`, `docs/compliance/GDPR_COMPLIANCE.md`
- **What to do:**
  - Fill all 11 principle rows. Most evidence already in `GDPR_COMPLIANCE.md` and `docs/REDIS_SCHEMA.md` — **link, don't duplicate**.
  - Add data-flow paragraph: PII = IP addresses, retention per Redis TTL, see GDPR doc for full picture.
  - Add cross-link from `GDPR_COMPLIANCE.md` to the new 29100 doc.
- **Done when:** [ ] 11 rows filled; cross-links resolve
- **Watch out for:** S-5 — must cross-link, not copy-paste, GDPR content

#### Sub-task 107f.2: ATT&CK — Recon + Resource Development + Initial Access tactics
- **Size:** S (3h) · **Depends on:** 107f.1 · **Parallel with:** 107f.3
- **Files to touch:** `ATTACK_MAPPING.md`
- **What to do:**
  - Forward-mapping rows for: TA0043 (T1595 → TCP signals + per-IP rate limit), TA0042 (T1583 → ASN/datacenter classifier, RDAP enrichment), TA0001 (T1110.004 → by-IP-JA4-pair rate limit).
  - Each row: signal module file path + line range, technique URL, confidence (high/medium/low) **with a one-sentence justification**.
  - ~5-7 rows.
- **Done when:** [ ] Rows filled; every signal-module path verified `ls`-clean; every confidence has a justification
- **Watch out for:** T-3, A-3 — confidence labels mandatory; file paths must exist; A-3 — favour stable signal-module *file* names over function-internal references

#### Sub-task 107f.3: ATT&CK — C2 + Defense Evasion tactics + reverse view
- **Size:** S (3h) · **Depends on:** 107f.1 · **Parallel with:** 107f.2
- **Files to touch:** `ATTACK_MAPPING.md`
- **What to do:**
  - Forward rows: TA0011 (T1573, T1071 → JA4 blacklist for Sliver/CobaltStrike/Evilginx), TA0005 (T1090 → Tor ASN, T1070 → beaconing-detector IAT-CV).
  - Reverse view: same data inverted (technique → signals).
  - Add SIEM-integration section linking `SIEM_INTEGRATION.md` with example Splunk/Sentinel/QRadar searches.
- **Done when:** [ ] Forward + reverse views consistent (every forward row appears reversed); SIEM section non-empty
- **Watch out for:** Notes-for-Implementer §3 — do not inflate confidence; "low" is a perfectly honest label

#### Sub-task 107f.4: ATT&CK — confidence-label CI gate + traceability check
- **Size:** XS (1h) · **Depends on:** 107f.2, 107f.3 · **Parallel with:** documentation tasks
- **Files to touch:** `Makefile` (add target `test-attack-mapping`), `tests/test_attack_mapping.py` (new, ~20 lines)
- **What to do:**
  - Tiny pytest that opens `ATTACK_MAPPING.md`, regex-matches every forward-table row, asserts `confidence: (high|medium|low)` is present and signal-module file path exists on disk.
  - Add Makefile target `test-attack-mapping: ; python3 -m pytest tests/test_attack_mapping.py`.
  - Wire into `make test` aggregate.
- **Done when:**
  - [ ] `make test-attack-mapping` exits 0
  - [ ] Removing a confidence label from a row makes the test fail
- **Watch out for:** A-3, T-3 — this is the regression guard for both findings

#### Sub-task 107g.2: CVD policy — Scope + Reporting + SLAs (sections 1-4)
- **Size:** S (2h) · **Depends on:** 107g.1 · **Parallel with:** 107g.3
- **Files to touch:** `docs/security/CVD_POLICY.md`
- **What to do:**
  - Scope: in (proxy core, CLI, integrations); out (experimental Python prototype, docs).
  - Reporting channels: from existing `SECURITY.md`; PGP key — note as "not currently published" if true.
  - SLAs (per phase doc §107g): 2-day ack, 10-day triage, 30/60/90-day fix.
  - **Add explicit `<!-- HUMAN REVIEW REQUIRED -->` marker** flagging the SLAs as operational commitments.
- **Done when:**
  - [ ] Sections 1-4 filled
  - [ ] Human-review marker present on SLAs
- **Watch out for:** R-2 — these SLAs are commitments; flag for human approval in PR description

#### Sub-task 107g.3: CVD policy — Disclosure + Credit + Safe Harbour + Standards (sections 5-8)
- **Size:** S (2h) · **Depends on:** 107g.1 · **Parallel with:** 107g.2
- **Files to touch:** `docs/security/CVD_POLICY.md`
- **What to do:**
  - Disclosure: embargo policy, default 90 days.
  - Credit: opt-in researcher credit, CVE assignment via GitHub Security Advisories.
  - Safe harbour: **paste disclose.io SAFE template verbatim**; do not paraphrase legal text.
  - Standards alignment: ISO/IEC 29147 + 30111 reference paragraph.
- **Done when:**
  - [ ] Sections 5-8 filled
  - [ ] Safe-harbour text is verbatim disclose.io SAFE (verifiable by checksum/diff against source)
- **Watch out for:** S-3 — never paraphrase legal text; if disclose.io SAFE template is unavailable offline, flag as blocker rather than guess

#### Sub-task 107g.4: SECURITY.md update + CVD intake runbook
- **Size:** XS (1h) · **Depends on:** 107g.2, 107g.3 · **Parallel with:** any
- **Files to touch:** `SECURITY.md` (rewrite to short pointer), `docs/security/INTAKE_RUNBOOK.md` (add CVD intake section)
- **What to do:**
  - Replace `SECURITY.md` body with a 10-line summary + link to `docs/security/CVD_POLICY.md`.
  - Add a "Coordinated vulnerability disclosure intake" section to `INTAKE_RUNBOOK.md`: triage steps, who acknowledges within 2 days, escalation path.
- **Done when:**
  - [ ] `SECURITY.md` ≤ 30 lines and points to CVD_POLICY
  - [ ] INTAKE_RUNBOOK has CVD intake section
- **Watch out for:** R-3 — do not delete SECURITY.md content without confirming the link target exists

---

### Phase 3 — Wiring & integration (sequential after Phase 2, day 5)

#### Sub-task 107w.1: README index updates
- **Size:** XS (1h) · **Depends on:** all 107a/b/c/d/e/f/g content tasks · **Parallel with:** 107w.2, 107w.3
- **Files to touch:** `README.md`, `README.md`
- **What to do:**
  - `README.md`: add links to `CRA_CONFORMANCE.md`, `SSDF_MAPPING.md`, `ATTACK_MAPPING.md`, `ADR-107a-slsa-level-3.md`.
  - `README.md`: add links to `CRA_CONFORMANCE.md`, `SSDF_MAPPING.md`, `iso27017-mapping.md`, `iso29100-mapping.md`, `CVD_POLICY.md`.
- **Done when:** [ ] Every new doc has at least one inbound link from its audience README
- **Watch out for:** A-2 — link rot is the single biggest doc-PR risk

#### Sub-task 107w.2: FAQ + risk register additions
- **Size:** XS (1h) · **Depends on:** 107a content + 107c.5 done · **Parallel with:** 107w.1, 107w.3
- **Files to touch:** `FAQ.md`, `docs/RISK_REGISTER.md`
- **What to do:**
  - FAQ: add Q "Are you CRA-compliant?" → "We have a self-assessed CRA conformance statement: [link]" — and Q "Do you support SLSA provenance verification?" → link `ADR-107a-slsa-level-3.md`.
  - RISK_REGISTER: add rows for any *real* gap discovered during 107a/d/e content work (don't invent risks; link only to genuine TODO/gap entries in the new mapping docs).
- **Done when:**
  - [ ] FAQ has both new entries
  - [ ] Risk register additions reference real gap entries
- **Watch out for:** S-2 — FAQ wording must say "self-assessed" / "aligned with"

#### Sub-task 107w.3: Doc-existence link-check CI gate
- **Size:** S (2h) · **Depends on:** 107w.1, 107w.2 · **Parallel with:** none
- **Files to touch:** `.github/workflows/docs-link-check.yml` (extend if exists, else new), `Makefile`
- **What to do:**
  - Use `lychee` (SHA-pinned) to walk `docs/compliance/`, ``, ``, `docs/security/CVD_POLICY.md`.
  - Reject internal broken links; allow external 4xx (vendor sites flake).
  - Add `make test-doc-links` target.
- **Done when:**
  - [ ] `make test-doc-links` exits 0 against current docs
  - [ ] Breaking a link in any of the new docs makes the workflow fail
- **Watch out for:** T-2 — this is the regression guard

---

### Phase 4 — Hardening (parallel-safe, day 5-6)

#### Sub-task 107h.1: Overclaim-language CI gate
- **Size:** XS (1h) · **Depends on:** 107a/b/d/e/g content done · **Parallel with:** 107w.*
- **Files to touch:** `Makefile`, `tests/test_compliance_language.py` (new, ~25 lines), optional allowlist file
- **What to do:**
  - Tiny pytest that greps `docs/compliance/` and `docs/security/CVD_POLICY.md` for `\b(certified|compliant)\b`. Fails if found outside an allowlist (initially empty).
  - `make test-compliance-language` target.
- **Done when:**
  - [ ] Test exits 0 against current docs
  - [ ] Adding the word "certified" anywhere in `docs/compliance/` makes it fail
- **Watch out for:** S-2 — this is the regression guard

#### Sub-task 107h.2: Evidence-path existence check
- **Size:** S (2h) · **Depends on:** 107a/b content done · **Parallel with:** 107h.1
- **Files to touch:** `tests/test_compliance_evidence_paths.py` (new, ~40 lines), `Makefile`
- **What to do:**
  - Parse `CRA_CONFORMANCE.md` and `SSDF_MAPPING.md` evidence columns. For every relative path matching `(\.github|docs|cmd|internal|src|tests|config)/[\w/.-]+`, assert it exists.
  - `make test-evidence-paths` target.
- **Done when:**
  - [ ] Test exits 0
  - [ ] Renaming an evidence-linked file breaks it
- **Watch out for:** A-3 — this catches signal-module renames that would silently rot the mapping

---

### Phase 5 — Documentation & close-out (sequential, day 6-7)

#### Sub-task 107z.1: CHANGELOG entry
- **Size:** XS (0.5h) · **Depends on:** all content tasks done · **Parallel with:** 107z.2
- **Files to touch:** `CHANGELOG.md`
- **What to do:** Prepend `## [Unreleased] - Phase 107 — Regulatory & Supply-Chain Conformance (YYYY-MM-DD)` block following the format of recent entries. Summarise: new docs, SLSA L3 wiring, CVD policy, sub-phase status table.
- **Done when:** [ ] Entry follows project format; mentions all 7 new/updated `docs/compliance/*` + `docs/security/CVD_POLICY.md` + SLSA L3 wiring
- **Watch out for:** None

#### Sub-task 107z.2: RFP dry-run checklist
- **Size:** S (2h) · **Depends on:** all 107a/b/d/e/f/g content done · **Parallel with:** 107z.1
- **Files to touch:** `docs/compliance/RFP_DRYRUN.md` (new)
- **What to do:**
  - Replaces the unmeasurable acceptance criterion C-1 with a concrete checklist: 15-20 typical RFP questions (CRA scope, SSDF coverage, SLSA level, ISO 27017 cloud applicability, ISO 29100 privacy mapping, ATT&CK coverage, CVD process, SBOM availability, vulnerability disclosure timeline). Each question links the answering doc + section.
  - Reviewer ticks each box only after confirming the linked section answers the question without ambiguity.
- **Done when:** [ ] All boxes ticked; reviewer initials at bottom
- **Watch out for:** C-1 — this is the regression guard for the unmeasurable original acceptance criterion

#### Sub-task 107z.3: Manifest + sync
- **Size:** XS (0.5h) · **Depends on:** 107z.1, 107z.2, all CI gates green · **Parallel with:** none
- **Files to touch:** `docs/phases/manifest.yaml` (status PROPOSED → COMPLETE), regenerated `docs/phases/TODO.md` + `docs/PROJECT_STATUS.md`
- **What to do:** Bump status, run `make sync`, commit the regenerated index files.
- **Done when:** [ ] `make sync` clean; manifest reflects COMPLETE
- **Watch out for:** Don't mark COMPLETE if any of 107c.3/.4 is still under `workflow_dispatch`-only — push triggers must be re-enabled and verified first

---

## Step 5 — Summary

**Total sub-task count:** 27
- **Phase 1 — Scaffolding:** 7 tasks (5 XS, 2 S) — fully parallel, ~1 day
- **Phase 2 — Core content:** 12 tasks (1 XS, 10 S, 1 M) — parallel within sub-phases, ~3 days
- **Phase 3 — Wiring:** 3 tasks (2 XS, 1 S) — ~½ day
- **Phase 4 — Hardening:** 2 tasks (1 XS, 1 S) — parallel, ~½ day
- **Phase 5 — Close-out:** 3 tasks (2 XS, 1 S) — ~½ day

**Estimated total effort:** ~52 hours (XS=1h × 11 + S=2.5h avg × 14 + M=4h × 1 = 11 + 35 + 4 = 50–55h) ≈ **6.5–7 engineer-days**.

**With 5-agent parallelism (per phase doc Wave 1 plan):** ~3 calendar days end-to-end.

**Critical blockers before implementation:** **none**. All HIGH-severity findings (S-1, S-2, T-1, D-1) are mitigated *by sub-task structure* (e.g., 107c.3 splits the riskiest CI change into a `workflow_dispatch`-first commit + push-trigger follow-up; 107h.1 adds a CI gate that catches future overclaim regressions).

**Three flags for human review (do not auto-merge):**
1. **107a.4** — CRA support-period commitment (recommended 5 years from first stable release) is a multi-year promise.
2. **107c.3 / 107c.4** — production release pipeline mutations; each requires a manual `workflow_dispatch` verification before re-enabling `push:` triggers.
3. **107g.2** — CVD SLAs (2-day ack, 10-day triage, 30/60/90-day fix) are operational commitments without an existing oncall rotation.

**Files net-new:** 9 docs + 1 ADR + 1 workflow + 3 small test files = 14 net-new files.
**Files modified:** 8 (existing docs cross-links, 2 existing workflows for SLSA wiring, `SECURITY.md`, `Makefile`, `tests/test_workflow_pinning.py`).

---

*This review was generated 2026-04-26 against `docs/phases/complete/PHASE_107.md` rev as of commit `df542c9`. Re-run if the phase doc is materially edited.*
