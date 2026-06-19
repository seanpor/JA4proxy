# Phase 105 Review — Documentation Restructure by Audience

> **Reviewed:** 2026-04-16
> **Phase doc:** `docs/phases/complete/PHASE_105.md`
> **Phase status:** PROPOSED (manifest entry missing — see blocker B1)
> **Review lens:** docs-only phase. Security / SRE / architecture lenses are narrow; documentation and DevOps lenses carry the weight.

---

## Summary

Phase 105 is a docs-restructure phase that does not touch production code. It
creates five audience-curated entry points (`docs/for-*/`), consolidates four
sets of overlapping docs (testing, deployment, blocking, stale reports),
archives pre-Phase-200 artefacts, refreshes three PDF artefacts, and adds a
developer-onboarding track including a written keep-main-green policy.

The plan is sound but has two structural risks (content duplication, PDF CI
scope creep) and several tactical issues (a factual error about the PDF
toolchain, manifest entry missing, README badges not updated in the plan, no
link-check tooling specified). All are fixable in the sub-task decomposition
below.

**Production-runtime determination:** neither Go nor Python. This is a docs
phase; the only "production" dimension is CI workflow changes (one new job
proposed in 105h) which must follow the same SHA-pinning discipline as
existing workflows.

---

## Step 1 — Prerequisite Checks

| Check | Result |
|-------|--------|
| `CLAUDE.md` read | ✅ |
| `docs/phases/complete/PHASE_105.md` exists | ✅ |
| `docs/phases/manifest.yaml` entry for 105 | ❌ **MISSING** (blocker B1) |
| All declared dependencies complete | ✅ (phase declares "none") |
| `config/proxy.yml` read | ✅ (no new config keys proposed — correct for docs phase) |
| `docs/reference/OBSERVABILITY_STANDARDS.md` read | ✅ (no new metrics proposed — correct) |

**Blocker B1:** Phase 105 must be added to `docs/phases/manifest.yaml` under
an appropriate epic (suggested: "Quality Assurance & Test Maturity" or a new
"Documentation" epic). The phase cannot close without this entry per the
phase protocol in CLAUDE.md.

---

## Step 2 — Six-Lens Review

### 2a. Security Review

Docs-only phase, so security scope is narrow. Risks are around what gets
written into new docs, not around code execution.

| # | Finding | Notes |
|---|---------|-------|
| S1 | **SIEM integration doc (105c) risks leaking internal log schema specifics that are customer-sensitive** | `SIEM_INTEGRATION.md` should reference the *public* ECS log schema (`docs/api/ecs_extension.md`) and not expose any internal correlation fingerprints or operator-only field names. Pair with the existing threat model. |
| S2 | **Brochure perf numbers must match `docs/performance/BENCHMARK_HISTORY.md`** | The phase doc flags this but does not say how to enforce it. Brochure claims that drift from measured numbers would be a reputational risk; add a sub-task that reconciles every number against the history doc before the PDF rebuild. |
| S3 | **Archived reports must preserve evidence banners verbatim** | `ENTERPRISE_REVIEW.md` and `GEMINI_CRITIQUE.md` are part of the audit trail. Moving them is fine; editing their body contents is not. The banner must be additive, added above the original content, never in place of it. |
| S4 | **No hardcoded secrets in any new doc** | Low risk for prose-only docs, but the SIEM integration doc will include forwarder config snippets. Any snippet must use obvious placeholders (`<YOUR_HEC_TOKEN>`, not real-looking hex). Add a grep-for-secret-shapes check to the acceptance. |
| S5 | **CI PDF rebuild job adds supply-chain surface** | 105h proposes a new CI job to rebuild PDFs. Every action used (checkout, tex install, artefact upload) must be SHA-pinned per the existing `.github/workflows/ci.yml` discipline (see file lines 10–16). Phase doc does not call this out. |
| S6 | **Supersede banners on archived reports must not alter security claims** | Banners should describe snapshot-date and *link to* current posture docs; they must not assert "vulnerability fixed" without the current doc actually proving it. |

**Core asymmetry check:** Phase 105 is docs-only, so the false-positive/false-negative
cost asymmetry does not apply directly. But one indirect concern: **if a
rewritten operator doc drops a safety callout, an operator acting on the new
doc might raise the dial too fast**. See 2e for the corresponding test.

**OWASP applicability:** None directly. No web-facing components are added.

### 2b. DevOps Review

| # | Finding | Notes |
|---|---------|-------|
| D1 | **PDF toolchain mis-specified** | Phase 105 §105h notes "prefer `tectonic`". In reality `docs/pdf/Makefile` uses `pdflatex` + `makeindex`. Switching toolchains is a scope expansion. Stick with `pdflatex` for this phase; record a future option in an ADR if `tectonic` is wanted later. |
| D2 | **New CI workflow job for PDFs — scope** | 105h proposes adding PDF rebuild to `.github/workflows/ci.yml`. This is a new supply-chain surface (TeXLive install or container). Two options: (a) add a new dedicated workflow `docs-pdf.yml` triggered on `docs/pdf/**`, (b) extend `ci.yml`. Option (a) is cleaner and avoids slowing every PR. Decide in a scaffolding sub-task before any implementation. |
| D3 | **Build speed / runner cost** | A full TeXLive install per CI run is ~20 minutes on GitHub runners. Use a pinned TeXLive container image (SHA-pinned) or the `xu-cheng/latex-action` action (SHA-pinned) to cut this to 2–3 minutes. Must remain non-blocking for 14 days per phase-doc §Notes. |
| D4 | **Release workflow attachment** | 105h asks `release-cli.yml` to attach three PDFs to the release. `release-cli.yml` is 105 lines and currently scoped to the CLI binary release; adding PDF attachment changes its scope. Either extend it (simple) or split PDF release into a separate workflow (cleaner). |
| D5 | **Config hot-reload** | Not applicable — no config changes. |
| D6 | **Rollback** | Docs changes roll back via `git revert`. No data-loss risk. |
| D7 | **Feature flags** | Not applicable. |
| D8 | **Resource requirements** | PDF rebuild job needs ~1 GB disk for TeXLive. Default GitHub runner (14 GB free) handles this comfortably. |

### 2c. SRE Review

Docs-only phase so most SRE questions don't apply. The ones that do:

| # | Finding | Notes |
|---|---------|-------|
| R1 | **"Keep-main-green" SLA needs a concrete definition** | Phase 105 §105k proposes a policy but leaves "red" fuzzy. Define: any `ci.yml` job that is both (a) marked as required on `main` and (b) red for ≥ 15 minutes. `smoke-docker` and `dependency-review` are currently `continue-on-error` or `if: pull_request` — they do not trigger the SLA. Write this precisely in HOW_WE_WORK. |
| R2 | **Observability for docs** | No metrics proposed — correct. But consider an ADR on "docs drift detection": how do we notice when `config/proxy.yml` adds a key that the reference manual never learns about? Suggest a future sub-task (out of scope for 105): a CI check that greps `config/proxy.yml` keys against the reference manual `.tex`. |
| R3 | **Runbook updates** | 105k hints at an optional `docs/runbooks/main_is_red.md`. This should not be optional — a policy without an operational runbook is just prose. Promote to required sub-task. |
| R4 | **Capacity / unbounded growth** | Not applicable. |
| R5 | **Graceful degradation** | Not applicable. |

### 2d. Architecture Review

The architecture here is the **documentation architecture**, not the runtime.

| # | Finding | Notes |
|---|---------|-------|
| A1 | **Duplication risk between `docs/for-*/` and existing topical dirs** | Plan says "for-* are curated indexes, not duplicates" but the line is easy to cross. SCOPE_AND_LIMITATIONS, SIEM_INTEGRATION, AUDIT_TRAIL, CHANGE_MANAGEMENT are **new** content that must live in `for-*/`. All the other links should be references to existing docs in `docs/compliance/`, `docs/enterprise/`, `docs/operator/`, `docs/runbooks/`. Enforce with a line-count cap per `for-*/README.md` (≤ 120 lines). |
| A2 | **Name collision risk with existing dirs** | `docs/developer/` exists; `` is new. `docs/compliance/` exists; `` is new. `docs/operator/` exists; `` is new. Dual directories are tolerable only if each has a distinct role — **`for-*` is the audience entry point, the unsuffixed dir is the topical content**. Every `for-*/README.md` must have a one-line disambiguation callout at the top. |
| A3 | **README → INDEX → for-\*/README redirection depth** | Three-hop navigation (`README.md` → `docs/for-X/README.md` → topical doc) adds friction. Ensure every `docs/for-*/README.md` is reachable in **one click** from `README.md`. Add a direct "Start by role" table in root README per 105a. |
| A4 | **README.md preservation** | `docs/README.md` is the exhaustive map for power users (phase doc correctly keeps it). Add a sub-task that re-validates every row after the restructure. |
| A5 | **Single source of truth** | CI details live in `.github/workflows/*.yml`. The new `QUALITY_PLAN.md` must be a **description**, not a duplication of the YAML. Link to the file + line ranges, don't transcribe job definitions. |
| A6 | **Cross-cutting `IPv6` / concurrency / Redis schema** | Not applicable for docs phase. |

### 2e. Testing Review

Docs phases don't get a normal test suite, but they need verification:

| # | Finding | Notes |
|---|---------|-------|
| T1 | **Link-checking is not specified** | No tool proposed. Add `lychee` (SHA-pinned action) or `markdown-link-check` as a one-shot verification step in a sub-task. Must be run locally by the agent before phase close, and ideally added as a non-blocking CI check. |
| T2 | **Redirect stub verification** | Plan creates multiple "redirect stubs" for old docs (`docs/TESTING.md`, 4 blocking docs, etc.). Each stub must (a) contain a single-line redirect, (b) still be reachable via its old URL. Add a sub-task that greps the tree for incoming links to each redirected doc and updates them. |
| T3 | **PDF reproducibility check** | Plan says "rebuilds with zero warnings" but pdflatex always emits warnings (overfull hbox, missing references on first pass). The acceptance should be "pdflatex exits 0; the number of Warning lines is ≤ current baseline". Measure baseline before starting. |
| T4 | **Operator safety regression** | Per S3 / core-asymmetry concern in 2a: when merging 4 blocking docs into one, add a diff review sub-task that lists every unique safety callout (threshold, dial-progression advice, rollback step) and asserts it survives the merge. |
| T5 | **`test_pages.py` / `test_container_config.py`** | Not applicable — no web changes. |
| T6 | **Test-to-code ratio** | Not applicable — no code. |
| T7 | **SIEM snippets should be executable** | Splunk / QRadar / Sentinel snippets in 105c-SIEM_INTEGRATION should be realistic enough that a customer can paste them and confirm ingestion. Add a "snippet validity" review sub-task using public vendor docs as ground truth. |

### 2f. Documentation Review (Meta — the phase doc itself)

The phase doc is the deliverable; review its own quality.

| # | Finding | Notes |
|---|---------|-------|
| Q1 | **Acceptance criteria are numerous but mostly SMART** | 27 criteria; most pass SMART. Three are soft: "[ ] No doc under `docs/` claims Phase N as current where N < latest-complete-phase in manifest" is hard to automate — pair it with a CI grep check or drop the "no doc" wording for a named list. |
| Q2 | **`Files to Modify` table missing a few derived targets** | `docs/api/ecs_extension.md` is cross-referenced by 105c but not listed; `docs/runbooks/main_is_red.md` promoted by R3 is not listed. Re-pass the Files table before execution. |
| Q3 | **Sizing is high-confidence for prose, low-confidence for PDF work** | PDF chapter refresh effort depends heavily on how out-of-date the `.tex` chapters are. Add a 30-minute timeboxed "PDF drift audit" sub-task **first**, and re-size the PDF track after. |
| Q4 | **CHANGELOG entry format not specified** | CLAUDE.md §Documentation Standards requires a specific CHANGELOG entry format. The phase doc says "CHANGELOG Phase 105 entry" but does not include the sample. Reference `docs/developer/DOCUMENTATION_STANDARDS.md` and include a draft entry. |
| Q5 | **ADR candidates not named** | The phase creates at least two non-obvious decisions that should be ADRs: (a) the `docs/for-*/` naming convention vs. reorganising existing dirs, (b) keep-main-green SLA definition. Add ADR drafting sub-tasks. |
| Q6 | **Phase size mismatch with style guide** | `docs/phases/STYLE_GUIDE.md` recommends splitting phases that grow beyond ~500 lines of substantive content. PHASE_105.md is 589 lines. Consider splitting into PHASE_105a (audience tracks) and PHASE_105b (PDFs + archival). Not required if execution stays parallel and well-bounded; flag as optional. |
| Q7 | **Python badge in README still claims "Python 3.14+"** | Top-level README line 4 badge. After Phase 15 promoted Go to production, this badge is misleading even with the "dual" badge. 105a should replace/reorder badges. Phase doc mentions runtime banner but not the badges. Add to 105a. |

---

## Step 3 — Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| B1 | Phase 105 missing from `manifest.yaml` | **CRITICAL** | Prereq | Add entry before any sub-task begins |
| Q6 | Phase doc 589 lines — above style-guide split threshold | LOW | Docs | Optional split; keep if execution stays parallel |
| D1 | PDF toolchain mis-specified (pdflatex, not tectonic) | HIGH | DevOps | Correct phase doc; stick with pdflatex |
| D2 | PDF CI workflow scope ambiguous (new file vs. extend ci.yml) | MEDIUM | DevOps | Decision sub-task before implementation — recommend new `docs-pdf.yml` |
| D4 | Release PDF attachment placement ambiguous | MEDIUM | DevOps | Decide in same decision sub-task as D2 |
| A1 | Duplication risk between `for-*/` and topical dirs | HIGH | Architecture | Line-count cap (≤120 lines) per `for-*/README.md` |
| A2 | Directory name collision (`developer` vs `for-developers`) | MEDIUM | Architecture | Disambiguation callout at top of each `for-*/README.md` |
| A5 | CI doc risks transcribing YAML | MEDIUM | Architecture | Link to file + line ranges; don't duplicate job definitions |
| S1 | SIEM doc could leak internal field names | MEDIUM | Security | Review against public ECS schema only |
| S2 | Brochure perf numbers vs. BENCHMARK_HISTORY drift | MEDIUM | Security | Explicit reconciliation sub-task |
| S3 | Archived reports must preserve original body verbatim | MEDIUM | Security | Banner additive, not edit-in-place |
| S4 | SIEM snippets could contain real-looking tokens | LOW | Security | Placeholder convention + grep check |
| S5 | PDF CI job SHA-pinning | HIGH | Security | Mandatory per existing workflow discipline |
| S6 | Supersede banners must not overstate remediation | MEDIUM | Security | Banner review by phase reviewer |
| R1 | "Keep-main-green" SLA fuzzy | MEDIUM | SRE | Define: required job red on `main` ≥ 15 min → incident |
| R3 | `main_is_red.md` runbook was optional | MEDIUM | SRE | Promote to required |
| T1 | No link-check tool specified | HIGH | Testing | Add `lychee` or equivalent; run pre-close |
| T2 | Redirect stubs lack incoming-link update sub-task | MEDIUM | Testing | Grep-and-fix sub-task per redirect |
| T3 | "Zero warnings" PDF criterion unrealistic for pdflatex | LOW | Testing | Measure baseline, target "≤ baseline" |
| T4 | Blocking-doc merge risks dropping safety callouts | HIGH | Testing | Explicit safety-callout diff review sub-task |
| T7 | SIEM snippets need vendor-doc validation | MEDIUM | Testing | Cross-check against Splunk/QRadar/Sentinel public docs |
| Q1 | Soft acceptance criterion re: phase numbers | LOW | Docs | Convert to grep-based check |
| Q2 | Files-to-Modify table has small gaps | LOW | Docs | Re-pass before execution |
| Q3 | PDF sizing low-confidence | MEDIUM | Docs | Timeboxed drift-audit sub-task first |
| Q4 | CHANGELOG entry format not drafted | LOW | Docs | Include sample in close-out sub-task |
| Q5 | Two ADR candidates unnamed | LOW | Docs | Add ADR drafting sub-tasks |
| Q7 | README badges (Python 3.14+, Dual Proxy) stale | MEDIUM | Docs | Fold into 105a sub-task |

**CRITICAL blockers (must resolve before any sub-task starts):** B1

**HIGH issues (must address in scaffolding before core work):** D1, S5, A1, T1, T4

---

## Step 4 — Junior-Engineer Sub-Task Decomposition

Sub-tasks below are numbered `105.N.M` to match the phase's `105a/b/c/...`
section layout. All are sized for a single focused session (XS = ≤ 1 h,
S = 1–2 h, M = 2–4 h). Each sub-task is self-contained and safe; a junior
engineer completing it incorrectly cannot break production (worst case: a
doc is wrong and needs another PR).

### Wave 0 — Scaffolding (must complete before any Wave 1 work)

#### Sub-task 105.0.1: Add Phase 105 to manifest.yaml

**Size:** XS (15 min)
**Depends on:** none
**Parallel with:** 105.0.2
**Files to touch:** `docs/phases/manifest.yaml`
**What to do:**
- Add a `105` entry under the appropriate epic (suggested: "Quality Assurance & Test Maturity")
- Set `name: "Documentation Restructure by Audience"`, `status: PROPOSED`, `action_plan: docs/phases/complete/PHASE_105.md`, `dependencies: []`, `size: LARGE`
- Include `sub_phases:` with the 11 tracks (a through k) and one-line summaries

**Done when:**
- [ ] `grep -A1 '105:' docs/phases/manifest.yaml` shows the new entry
- [ ] `make sync` runs cleanly and `docs/phases/TODO.md` includes Phase 105

**Watch out for:** YAML indentation in `manifest.yaml` is strict; match surrounding entries exactly.

---

#### Sub-task 105.0.2: Fix PDF toolchain references in the phase doc

**Size:** XS (15 min)
**Depends on:** none
**Parallel with:** 105.0.1
**Files to touch:** `docs/phases/complete/PHASE_105.md`
**What to do:**
- Remove the "prefer `tectonic`" line from 105h Notes
- Replace with a line confirming `pdflatex + makeindex` per `docs/pdf/Makefile`
- Add a line noting "future ADR may reconsider tectonic for reproducibility"

**Done when:**
- [ ] `grep -i tectonic docs/phases/complete/PHASE_105.md` returns zero matches (or only the "future ADR" line)
- [ ] `pdflatex` is the named toolchain in §105h

**Watch out for:** Don't edit the `Files to Modify` table for PDF chapters — those paths are correct.

---

#### Sub-task 105.0.3: Decide PDF CI workflow placement (ADR)

**Size:** S (1 h)
**Depends on:** none
**Parallel with:** 105.0.1, 105.0.2, 105.0.4
**Files to touch:** `docs/decisions/ADR-105a-pdf-ci-placement.md` (new)
**What to do:**
- Write a short ADR (≤ 60 lines) deciding between: (a) new workflow `.github/workflows/docs-pdf.yml` triggered on `docs/pdf/**` path filter, or (b) new job in `ci.yml`
- Recommendation: option (a) — cleaner separation, does not slow every PR
- Capture the decision, alternatives, consequences per ADR template in `docs/developer/DOCUMENTATION_STANDARDS.md`

**Done when:**
- [ ] ADR exists at `docs/decisions/ADR-105a-pdf-ci-placement.md`
- [ ] Linked from `docs/decisions/README.md`

**Watch out for:** This ADR governs sub-task 105.8.13; block that sub-task until this one is approved.

---

#### Sub-task 105.0.4: Create `docs/for-*/` skeleton directories

**Size:** XS (30 min)
**Depends on:** none
**Parallel with:** 105.0.1, 105.0.2, 105.0.3
**Files to touch:**
- `README.md` (placeholder)
- `README.md` (placeholder)
- `README.md` (placeholder)
- `README.md` (placeholder)
- `README.md` (placeholder)
**What to do:**
- Each placeholder contains: H1 title, one-line purpose, a "PHASE 105 — content coming" banner, and the disambiguation callout distinguishing `for-X/` from any existing `docs/X/`
- Keep each file ≤ 20 lines

**Done when:**
- [ ] Five placeholders exist
- [ ] Each has the disambiguation callout (e.g., "This is the **audience entry point** for developers. Topical developer content lives in `docs/developer/`.")

**Watch out for:** Do not link anything yet — real links come in Wave 2 (105.9.1).

---

#### Sub-task 105.0.5: Pick and pin a link-check tool

**Size:** S (1 h)
**Depends on:** none
**Parallel with:** 105.0.1–4
**Files to touch:** `docs/decisions/ADR-105b-link-checker.md` (new), `Makefile`
**What to do:**
- Write a short ADR recommending `lychee` (Rust, fast, supports Markdown and HTML, SHA-pinnable via GitHub Action `lycheeverse/lychee-action`)
- Add a `make link-check` target that runs `lychee --offline --no-progress docs/ README.md CONTRIBUTING.md SECURITY.md AGENTS.md CLAUDE.md`
- Do not add a CI job yet — that's sub-task 105.10.3

**Done when:**
- [ ] `make link-check` exits 0 on a clean repo (or reports a known-acceptable baseline — document it)
- [ ] ADR exists

**Watch out for:** Use `--offline` initially to avoid flaky external-URL failures; enable network checks only after a 14-day stability window.

---

### Wave 1 — Core content (all sub-tasks in this wave are parallel-safe)

#### Track A — Website-owner docs (105b)

##### Sub-task 105.1.1: Write `README.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Parallel with:** all other Wave 1 sub-tasks
**Files to touch:** `README.md`
**What to do:**
- Replace placeholder with curated index linking to WHY_JA4PROXY, DEPLOYMENT_OPTIONS, FAQ (to be written in 105.1.2–4)
- Open with a one-paragraph problem framing: credential-stuffing, form abuse, scraper costs
- End with a "next steps" block pointing to the POC quick-start and the brochure PDF
- Cap at 120 lines per finding A1

**Done when:**
- [ ] File ≤ 120 lines
- [ ] All three sub-doc links are present (may be dead until 105.1.2–4 land)
- [ ] Disambiguation callout retained from scaffolding

---

##### Sub-task 105.1.2: Write `WHY_JA4PROXY.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Parallel with:** all Wave 1
**Files to touch:** `WHY_JA4PROXY.md`
**What to do:**
- Problem statement in business language (no JA4 / TLS jargon in the first paragraph)
- Cite the brochure `docs/pdf/brochure/brochure-body.tex` for the value-prop prose — extract and reframe, do not link unreachable PDF text
- Before/after narrative scaffold: before = "% of form traffic is automated"; after = "% is real humans"
- "Zero false-positives by design" explained without jargon — reference the ALPN bypass concept in plain terms

**Done when:**
- [ ] 400–800 words
- [ ] First paragraph contains zero terms from {JA4, ALPN, fingerprint, TLS, ClientHello}
- [ ] Links to `DEPLOYMENT_OPTIONS.md` and `FAQ.md`

---

##### Sub-task 105.1.3: Write `DEPLOYMENT_OPTIONS.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Parallel with:** all Wave 1
**Files to touch:** `DEPLOYMENT_OPTIONS.md`
**What to do:**
- Three deployment paths: cloud (Docker / K8s), on-prem (RHEL/Podman), managed-service (if offered — otherwise mark "not currently offered; see README for self-host")
- Time-to-deploy: "30 minutes to a POC"
- Integration prerequisites table: load balancer, Redis, observability stack
- Link to `docs/enterprise/deployment.md` for the deep technical version

**Done when:**
- [ ] Three paths present; each has a time-to-deploy estimate
- [ ] No technical jargon undefined (e.g., "Helm chart" gets a parenthetical "Kubernetes package")

---

##### Sub-task 105.1.4: Write `FAQ.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Parallel with:** all Wave 1
**Files to touch:** `FAQ.md`
**What to do:**
- 12–15 buyer questions. Source from: existing `docs/operations/FAQ.md` (operator-focused — reframe), brochure Q&A, common security-evaluation questionnaires
- Must include: cost model, risk of blocking real users, GDPR posture, works-behind-Cloudflare, uptime impact, how-we-know-it-works, integration with existing WAF, comparison to Cloudflare Bot Management
- Each answer ≤ 200 words

**Done when:**
- [ ] 12–15 Q&A entries
- [ ] No overlap with `docs/operations/FAQ.md` (operator) entries
- [ ] Every answer under 200 words

---

#### Track B — Architect docs (105c)

##### Sub-task 105.2.1: Write `README.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Files to touch:** `README.md`
**What to do:**
- Curated index linking: threat model (`docs/security/threat-model.md`), controls matrix (`docs/compliance/SECURITY_CONTROLS_MAPPING.md`), deployment security model (`docs/security/DEPLOYMENT_SECURITY_MODEL.md`), enterprise deployment (`docs/enterprise/deployment.md`), enterprise security architecture (`docs/enterprise/security-architecture.md`)
- Then the three new docs written in 105.2.2–4
- Cap at 120 lines

**Done when:**
- [ ] All six existing docs linked
- [ ] All three new-doc links present (may be dead until 105.2.2–4)

---

##### Sub-task 105.2.2: Write `SCOPE_AND_LIMITATIONS.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Files to touch:** `SCOPE_AND_LIMITATIONS.md`
**What to do:**
- Explicit non-goals: not a WAF, does not decrypt, does not re-encrypt, does not inspect HTTP bodies, does not prevent SQLi/XSS/CSRF, does not detect insider threats, does not replace endpoint protection
- For each non-goal: one sentence on *why* (architectural reason), and a pointer to the right tool category
- Complementary-controls section: what to pair JA4proxy with (WAF, EDR, SIEM, SOAR)
- Source material: `docs/security/threat-model.md` §scope

**Done when:**
- [ ] ≥ 8 explicit non-goals
- [ ] Each non-goal has a one-sentence rationale
- [ ] Complementary-controls section names ≥ 4 tool categories

**Watch out for:** Do not overstate *current* threat coverage — this doc defines the edge of the box, not marketing claims.

---

##### Sub-task 105.2.3: Write `SIEM_INTEGRATION.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Files to touch:** `SIEM_INTEGRATION.md`
**What to do:**
- Recap ECS 8.x log schema (link `docs/api/ecs_extension.md` — do not duplicate)
- Four ingestion recipes: Splunk HEC, QRadar DSM, Microsoft Sentinel CEF, Wazuh syslog
- Each recipe = forwarder config snippet + index/parser snippet + one sample correlation rule
- All tokens are placeholders: `<YOUR_HEC_TOKEN>`, `<WORKSPACE_ID>` — never realistic-looking hex
- Cite each recipe against the vendor's public documentation

**Done when:**
- [ ] Four recipes present, each with three parts (forwarder, parser, correlation)
- [ ] Grep for realistic-looking tokens (`[a-f0-9]{32}`) returns zero matches
- [ ] Each recipe cites a vendor doc URL

**Watch out for:** S1 — any internal-only field names must not appear. Cross-check against `docs/api/ecs_extension.md` public fields only.

---

##### Sub-task 105.2.4: Write `EVALUATION_CHECKLIST.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Files to touch:** `EVALUATION_CHECKLIST.md`
**What to do:**
- 7-day POC checklist and 30-day evaluation checklist
- Day 1–7: what metrics to watch (FP rate, score distribution, block rate at dial=0)
- Day 8–30: dial-progression safely (0 → 25 → 50), rollback triggers, success criteria
- Link to `docs/operator/blocking-guide.md` (or its successor `BLOCKING_OPERATIONS.md` after 105.4.2)

**Done when:**
- [ ] Two checklists present
- [ ] Each item is a checkable yes/no criterion

---

##### Sub-task 105.2.5: Archive `GEMINI_CRITIQUE.md` and `ENTERPRISE_REVIEW.md`

**Size:** XS (30 min)
**Depends on:** none
**Parallel with:** all Wave 1
**Files to touch:** `docs/GEMINI_CRITIQUE.md` (move), `docs/reports/ENTERPRISE_REVIEW.md` (move), `docs/reports/archive/` (new dir)
**What to do:**
- `git mv docs/GEMINI_CRITIQUE.md docs/reports/archive/GEMINI_CRITIQUE_2026-03-21.md`
- `git mv docs/reports/ENTERPRISE_REVIEW.md docs/reports/archive/ENTERPRISE_REVIEW_2026-02-15.md`
- Prepend a 5-line supersede banner to each: snapshot date, "pre-Phase 200 hardening", link to current equivalent in ``
- **Do not edit the body** — banner is additive (per finding S3)

**Done when:**
- [ ] Both files in `docs/reports/archive/`
- [ ] Each has a banner above the original H1 heading
- [ ] `grep -r "GEMINI_CRITIQUE.md" docs/` returns only archive path or updated links

**Watch out for:** Grep for every incoming link to these files in `docs/` and update — redirect stubs are not an option for moved content.

---

##### Sub-task 105.2.6: Decide fate of `DMZ_READINESS.md`

**Size:** S (1–2 h)
**Depends on:** none
**Files to touch:** `docs/security/DMZ_READINESS.md` (rewrite or move)
**What to do:**
- 30-minute audit: walk every claim in the doc; mark each as "current" or "pre-Phase 200"
- If ≥ 70% pre-Phase-200: archive to `docs/reports/archive/DMZ_DEPLOYMENT_READINESS_2026-03-15.md` with supersede banner and write a thin replacement `DMZ_READINESS.md` summarising current Phase-200-series state
- Otherwise: re-date, fix the stale claims, retain path

**Done when:**
- [ ] Decision recorded in the sub-task's commit message
- [ ] No claim in the live doc references Phase < 200 as current

---

#### Track C — Operator docs (105d)

##### Sub-task 105.3.1: Write `README.md`

**Size:** S (1 h)
**Depends on:** 105.0.4
**Files to touch:** `README.md`
**What to do:**
- Curated index; link (do not copy) `docs/OPERATIONS.md`, `docs/operations/INCIDENT_RESPONSE.md`, `docs/QUICK_REFERENCE.md`, `docs/MONITORING_SETUP.md`, the runbooks, the new `BLOCKING_OPERATIONS.md` (from 105.4.2)
- Cap at 120 lines

**Done when:** [ ] File ≤ 120 lines; all links present.

---

##### Sub-task 105.3.2: Write `UPGRADE_PATH.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Files to touch:** `UPGRADE_PATH.md`
**What to do:**
- Summarise `docs/runbooks/rolling_upgrade.md` and `docs/runbooks/disaster_recovery.md`
- Version-compatibility matrix (proxy version ↔ Redis schema version ↔ config version)
- Rollback procedure summary with link to detailed runbook

**Done when:** [ ] Matrix present; rollback summary present; links to runbooks.

---

##### Sub-task 105.3.3: Expand `docs/operations/SCALING_GUIDE.md` with worked examples

**Size:** M (2–4 h)
**Depends on:** none
**Files to touch:** `docs/operations/SCALING_GUIDE.md`
**What to do:**
- Add three capacity scenarios: small site (100 req/s), enterprise (2,000 req/s), high-volume API (15,000 req/s)
- Each scenario: instance count, Redis sizing, expected conn/s per instance, recommended dial progression, monitoring thresholds
- Cite measured numbers from `docs/performance/BENCHMARK_HISTORY.md`

**Done when:**
- [ ] Three scenarios present
- [ ] Each number in the scenarios traces to BENCHMARK_HISTORY or is marked "estimate"

---

##### Sub-task 105.4.1: Safety-callout diff baseline for blocking docs merge

**Size:** S (1–2 h)
**Depends on:** none
**Blocks:** 105.4.2
**Files to touch:** `docs/phases/PHASE_105_blocking_safety_callouts.md` (temporary working doc)
**What to do:**
- Read the four source docs: `blocking-guide.md`, `BLOCKING_ANALYSIS.md`, `blocking-test-analysis.md`, `FINAL_BLOCKING_TEST_SUMMARY.md`
- Extract every unique safety callout (threshold number, dial-progression advice, rollback step, FP-rate warning) into a checklist
- This checklist is the **acceptance input** for 105.4.2

**Done when:** [ ] ≥ 15 unique safety callouts enumerated.

**Watch out for:** Finding T4 — every enumerated callout must survive the merge; if one cannot, it goes in an appendix, never dropped.

---

##### Sub-task 105.4.2: Merge blocking docs into `docs/operator/BLOCKING_OPERATIONS.md`

**Size:** M (3–4 h)
**Depends on:** 105.4.1
**Files to touch:**
- `docs/operator/BLOCKING_OPERATIONS.md` (new)
- `docs/operator/blocking-guide.md` (redirect stub)
- `docs/operator/BLOCKING_ANALYSIS.md` (redirect stub)
- `docs/operator/blocking-test-analysis.md` (redirect stub)
- `docs/operator/FINAL_BLOCKING_TEST_SUMMARY.md` (redirect stub)
**What to do:**
- Create BLOCKING_OPERATIONS with sections: overview, dial progression, thresholds, expected block rates, test-run observations, safety gates
- Every callout from 105.4.1 must appear verbatim in the merged doc or in its "Test Observations" appendix
- Each old file becomes a 5-line redirect stub pointing at the new doc
- Grep the tree and update every incoming link

**Done when:**
- [ ] New doc exists; every 105.4.1 callout present
- [ ] Four stubs exist, each ≤ 5 lines
- [ ] `grep -r "blocking-guide.md" docs/` returns stub path or updated links only

---

#### Track D — Compliance docs (105e)

##### Sub-task 105.5.1: Write `README.md`

**Size:** XS (30 min)
**Depends on:** 105.0.4
**What to do:** Curated index linking the four existing compliance docs + the two new ones. Cap at 80 lines.

**Done when:** [ ] All links present.

---

##### Sub-task 105.5.2: Write `AUDIT_TRAIL.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Files to touch:** `AUDIT_TRAIL.md`
**What to do:**
- What gets logged, where, for how long
- Policy-change audit — reference `management:policy_audit` Redis list from `docs/reference/REDIS_SCHEMA.md`
- Operator action log — reference existing mechanisms
- Cross-reference `docs/reference/REDIS_SCHEMA.md` for every key mentioned

**Done when:**
- [ ] Every Redis key cited also appears in `docs/reference/REDIS_SCHEMA.md`
- [ ] Retention periods explicit for each log source

---

##### Sub-task 105.5.3: Write `CHANGE_MANAGEMENT.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Files to touch:** `CHANGE_MANAGEMENT.md`
**What to do:**
- How config changes are proposed, reviewed, applied, reverted
- SIGHUP flow vs. UI flow vs. pub/sub propagation — cite `config/proxy.yml` hot-reload invariants from CLAUDE.md §Config-Driven
- Map to auditor-expected Change Management evidence (four-eyes where applicable — reference Phase 82 policy-as-code)

**Done when:** [ ] All three flows documented; ≥ 2 auditor-evidence mappings.

---

#### Track E — Developer docs (105f)

##### Sub-task 105.6.1: Write `README.md`

**Size:** XS (30 min)
**Depends on:** 105.0.4

**Done when:** [ ] Curated index linking all six developer-track docs.

---

##### Sub-task 105.6.2: Write `GETTING_STARTED.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Files to touch:** `GETTING_STARTED.md`
**What to do:**
- 30-minute-to-productive walkthrough: prereqs (Go 1.25.9, Python 3.14, Docker, Redis Stack), clone, build, test, run
- Link to `CONTRIBUTING.md` for reference; don't duplicate its contents
- Include troubleshooting for first-run failures (common: Docker not installed, Redis port 6379 occupied)

**Done when:** [ ] A fresh clone reaches `make test` green following only this doc.

---

##### Sub-task 105.6.3: Write `HOW_WE_WORK.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Files to touch:** `HOW_WE_WORK.md`
**What to do:**
- Trunk-based development with short-lived `claude/phase-NN-*` and `feat/*` branches
- Never commit to main (restate CLAUDE.md §Git Rules)
- **Keep-main-green policy** — precise SLA per finding R1: "any required CI job on `main` that is red for ≥ 15 minutes during working hours triggers an incident; fix or revert within 1 hour; revert-first preferred over debug-in-place"
- Commit-message convention (match recent history: `phase-NN: description`)
- PR size expectations, review etiquette (one concern per PR, max ~400 lines diff preferred)
- File-ownership rules per CLAUDE.md §File Ownership

**Done when:**
- [ ] Keep-main-green SLA precise (required job + 15 min + working hours)
- [ ] Revert-first-debug-later explicit
- [ ] Links to `CLAUDE.md` and `AGENTS.md` for agent-specific variants

---

##### Sub-task 105.6.4: Write `TESTING_STRATEGY.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Files to touch:** `TESTING_STRATEGY.md`
**What to do:**
- TDD loop: red → green → refactor
- Ratio target ~1.3× test-to-code (cite current ratio from `make test-ratio`)
- Test-category matrix (unit / integration / chaos / adversarial / FP corpus / performance / E2E) with "when to write each"
- Mock rules (mocks in `tests/mocks/`, no real external API calls)
- Link to `docs/developer/TESTING_STRATEGY.md` as the deep reference
- Phase-gate-must-pass rule per CLAUDE.md

**Done when:** [ ] TDD loop documented; test matrix present; `docs/developer/TESTING_STRATEGY.md` linked as canonical.

---

##### Sub-task 105.6.5: Write `QUALITY_PLAN.md`

**Size:** M (2–4 h)
**Depends on:** 105.0.4
**Files to touch:** `QUALITY_PLAN.md`
**What to do:**
- One paragraph per workflow: `ci.yml` (9 jobs: test-go, test-python, lint, secrets-scan, sast, dep-audit-py, dep-audit-go, dep-review, smoke-docker), `go-proxy-image.yml`, `ja4proxy-policy.yml`, `release-cli.yml`
- Cite file paths with line ranges — do not transcribe YAML (finding A5)
- Reproduce-CI-locally section: `make quality`, `make test`, `make lint-all`
- SHA-pinning rule (cite `tests/test_workflow_pinning.py`)
- Weekly CVE sweep (Mondays 06:00 UTC)

**Done when:**
- [ ] All 4 workflows described
- [ ] Every job in `ci.yml` named
- [ ] Grep for `run:` or `uses:` blocks copied verbatim from YAML returns zero matches

**Watch out for:** Finding A5 — this doc must describe, not duplicate. If a reviewer asks "what does this job do?", point to the file:line, don't answer directly.

---

##### Sub-task 105.6.6: Write `PHASE_LIFECYCLE.md`

**Size:** S (1–2 h)
**Depends on:** 105.0.4
**Files to touch:** `PHASE_LIFECYCLE.md`
**What to do:**
- Mandatory planning protocol (phase doc before code — cite AGENTS.md)
- Branch naming, commit cadence, `make sync`
- Manifest update + CHANGELOG entry
- Phase-close checklist
- Link to `AGENTS.md` for agent orchestration variant

**Done when:** [ ] End-to-end phase run describable in ≤ 10 checkboxes.

---

##### Sub-task 105.6.7: Write / promote `docs/runbooks/main_is_red.md`

**Size:** S (1–2 h)
**Depends on:** 105.6.3
**Files to touch:** `docs/runbooks/main_is_red.md` (new)
**What to do:**
- Operational runbook for the keep-main-green SLA from HOW_WE_WORK
- Steps: detect (CI status + notifications), acknowledge, decide (revert or fix-forward), act, post-incident note
- Link from HOW_WE_WORK.md

**Done when:** [ ] Runbook exists; reciprocal link from HOW_WE_WORK.

**Watch out for:** R3 — this was optional in phase doc; R3 promoted to required.

---

#### Track F — TESTING doc consolidation (105g)

##### Sub-task 105.7.1: Merge TEST_ORGANIZATION + TEST_SUITE + TESTING_GO into TESTING_STRATEGY

**Size:** M (2–4 h)
**Depends on:** none
**Files to touch:**
- `docs/developer/TESTING_STRATEGY.md` (expand)
- `docs/developer/TESTING_STRATEGY.md` (redirect stub)
- `docs/TEST_SUITE.md` (redirect stub)
- `docs/TESTING_GO.md` (redirect stub)
- `docs/TESTING.md` (redirect stub)
**What to do:**
- Append TEST_ORGANIZATION as Appendix A "Test File Organisation"
- Append TEST_SUITE as Appendix B "Test Categories"
- Append TESTING_GO as Appendix C "Go-Specific Testing"
- `TESTING.md` becomes a 5-line redirect to TESTING_STRATEGY
- Preserve every unique paragraph (do not lose content during merge)
- Grep and update every incoming link in `docs/`

**Done when:**
- [ ] TESTING_STRATEGY has 3 new appendices
- [ ] Four stubs exist
- [ ] `diff <(cat OLD_DOCS | sort -u) <(cat MERGED | sort -u)` shows zero loss of unique content lines

---

#### Track G — Staleness repair (105i)

##### Sub-task 105.8.1: Sweep phase numbers and Python-vs-Go ambiguity

**Size:** S (1–2 h)
**Depends on:** none
**Files to touch:**
- `docs/README.md` (frontmatter + content)
- `docs/README.md` (frontmatter + content)
- `docs/security/DEPLOYMENT_SECURITY_MODEL.md`
- `CONTRIBUTING.md`
- Any doc with `proxy.py` mention lacking "prototyping" qualifier
**What to do:**
- Update `last_reviewed` and `phase` frontmatter fields in `docs/README.md` and `docs/README.md` to today's date and current phase number from manifest
- `grep -rn 'Phase 1[0-9] ' docs/ | grep -vE '(PHASE_|archive/|decisions/|manifest)'` — triage each hit, update or banner as stale
- `grep -rn 'proxy\.py' README.md CONTRIBUTING.md docs/` — ensure every mention carries the "prototyping surface" qualifier

**Done when:**
- [ ] Frontmatter dates current
- [ ] Every non-archive mention of Phase < 80 as "current" is fixed or bannered
- [ ] `proxy.py` always qualified

**Watch out for:** Archive dirs (`docs/phases/archive/`, `docs/reports/archive/`) must NOT be edited — they are historical snapshots.

---

#### Track H — PDF refresh (105h)

##### Sub-task 105.8.2: PDF drift audit (timeboxed)

**Size:** S (1–2 h, strict timebox)
**Depends on:** none
**Blocks:** 105.8.3 through 105.8.12
**Files to touch:** `docs/phases/PHASE_105_pdf_drift.md` (temporary working doc)
**What to do:**
- Open each of the 12 listed `.tex` chapters
- For each: list every claim that references the system (Phase numbers, features, config keys, metrics)
- Mark each claim: ✅ current / ⚠️ stale / ❌ removed feature
- This output sizes the remaining PDF sub-tasks

**Done when:** [ ] Drift report complete; any chapter with ≥ 40% stale claims gets its sub-task bumped M → L.

**Watch out for:** Finding Q3 — if this audit runs over 2 h, escalate rather than proceed.

---

##### Sub-task 105.8.3: Refresh `brochure/brochure-body.tex`

**Size:** S (1–2 h)
**Depends on:** 105.8.2
**Files to touch:** `docs/pdf/brochure/brochure-body.tex`
**What to do:**
- Reconcile every perf number against `docs/performance/BENCHMARK_HISTORY.md` (finding S2)
- Add one paragraph on Phase 200-series hardening (Redis TLS, PROXY v2, default-cred removal)
- Link (as plain URL) to `README.md`

**Done when:** [ ] `make -C docs/pdf brochure` rebuilds clean.

---

##### Sub-tasks 105.8.4 – 105.8.8: Refresh 5 user-guide chapters

Each sub-task is **S (1–2 h)**, depends on **105.8.2**, parallel-safe.
Files: `docs/pdf/user-guide/chapters/ch01-introduction.tex`, `ch02-installation.tex`, `ch04-configuration.tex`, `ch05-operations.tex`, `ch07-incident-response.tex`.
Per-chapter work: reconcile against the living-doc equivalent named in PHASE_105 §105h Files-to-Modify table; update Phase references; rebuild verifies.

**Done when (each):** [ ] `make -C docs/pdf user-guide` rebuilds clean; chapter opens with current-state framing.

---

##### Sub-tasks 105.8.9 – 105.8.12: Refresh 4 reference-manual chapters

Each is **S (1–2 h)** unless the drift audit bumped it to **M**.
Files: `ch01-architecture.tex`, `ch04-signals.tex`, `ch06-redis-schema.tex`, `ch09-security-ref.tex`, `ch10-compliance.tex` — merge two of these into one sub-task if drift is minor.

---

##### Sub-task 105.8.13: New workflow `docs-pdf.yml` for PDF rebuild

**Size:** M (2–4 h)
**Depends on:** 105.0.3 (ADR must be approved first), 105.8.3–12 complete
**Files to touch:** `.github/workflows/docs-pdf.yml` (new)
**What to do:**
- SHA-pinned `actions/checkout`, SHA-pinned LaTeX action (suggest `xu-cheng/latex-action`), SHA-pinned `actions/upload-artifact`
- Triggers: `paths: ['docs/pdf/**']` on PR and push-to-main
- `continue-on-error: true` for 14 days (non-blocking initial window)
- Uploads three PDFs as workflow artefacts named `brochure`, `user-guide`, `reference-manual`
- Matches SHA-pin policy verified by `tests/test_workflow_pinning.py`

**Done when:**
- [ ] Workflow green on a test PR touching `docs/pdf/`
- [ ] `tests/test_workflow_pinning.py` passes
- [ ] All three PDFs downloadable from workflow artefacts

**Watch out for:** S5 — every `uses:` line needs a 40-char SHA plus a version comment.

---

### Wave 2 — Wiring (after Wave 1)

#### Sub-task 105.9.1: Rewrite root `README.md` as role-router

**Size:** M (3–4 h)
**Depends on:** 105.1.1, 105.2.1, 105.3.1, 105.5.1, 105.6.1 (all five `for-*/README.md` must exist)
**Files to touch:** `README.md`
**What to do:**
- New structure per phase doc §105a: banner, value prop, Start-by-role table (5 rows), runtime-is-Go banner, 30-sec pitch, architecture diagram, PDF downloads row, links to CHANGELOG/PROJECT_STATUS/CONTRIBUTING/SECURITY
- Cap at 150 lines
- Replace "Python 3.14+" and "Dual Proxy" badges with accurate alternatives (e.g., "Runtime: Go 1.25.9", "Prototyping: Python 3.14") per finding Q7
- Migrate unique content (e.g., Deployment section details) into the appropriate `for-*` doc before deleting — do not lose anything

**Done when:**
- [ ] README ≤ 150 lines
- [ ] Start-by-role table links all five `for-*/README.md`
- [ ] Runtime banner above the fold
- [ ] PDF downloads row present
- [ ] No unique content lost (spot-check against pre-rewrite diff)

---

#### Sub-task 105.9.2: Update `docs/README.md` with `for-*/` links

**Size:** S (1 h)
**Depends on:** all Wave 1 complete
**Files to touch:** `docs/README.md`
**What to do:** Add `for-*/README.md` links to the existing "Start here by role" table; update frontmatter date + phase.

**Done when:** [ ] All five `for-*` entries linked.

---

#### Sub-task 105.9.3: Reorder `CONTRIBUTING.md`

**Size:** S (1 h)
**Depends on:** none (parallel with 105.9.1/2)
**Files to touch:** `CONTRIBUTING.md`
**What to do:**
- Project-structure block: Go production (`cmd/proxy/`, `internal/`) first with "production runtime" header; `proxy.py` and `src/` second with "prototyping surface" header
- Link `README.md` early in the doc

**Done when:** [ ] Go listed first; prototyping qualifier present.

---

### Wave 3 — Hardening & Close

#### Sub-task 105.10.1: Full link-check sweep

**Size:** S (1–2 h)
**Depends on:** all Wave 1 and Wave 2 complete
**Files to touch:** none (verification only)
**What to do:**
- Run `make link-check` (from 105.0.5)
- Fix every broken internal link
- External-URL failures: triage — replace, remove, or document as known-flaky

**Done when:** [ ] `make link-check` exits 0 or with only pre-approved known-flaky external URLs.

---

#### Sub-task 105.10.2: Incoming-link grep for every moved/merged doc

**Size:** S (1–2 h)
**Depends on:** 105.4.2, 105.2.5, 105.7.1
**What to do:**
- For each moved or stubbed doc, `grep -r <old-path> docs/ README.md CONTRIBUTING.md AGENTS.md CLAUDE.md` and update every hit
- Covers: 4 blocking docs, 3 testing docs, GEMINI_CRITIQUE, ENTERPRISE_REVIEW, DMZ doc (if moved)

**Done when:** [ ] Zero incoming links to any old path remain (outside archive directories).

---

#### Sub-task 105.10.3: Add link-check as non-blocking CI job

**Size:** S (1 h)
**Depends on:** 105.10.1 (baseline must be clean)
**Files to touch:** `.github/workflows/docs-pdf.yml` (extend) OR new `.github/workflows/link-check.yml`
**What to do:**
- SHA-pinned `lycheeverse/lychee-action`
- `continue-on-error: true` for 14 days
- Triggers on `docs/**` and `*.md`

**Done when:** [ ] Workflow green on a test PR.

---

#### Sub-task 105.10.4: CHANGELOG and manifest close-out

**Size:** XS (30 min)
**Depends on:** everything else
**Files to touch:** `CHANGELOG.md`, `docs/phases/manifest.yaml`, `docs/phases/TODO.md` (regenerated), `docs/reference/PROJECT_STATUS.md` (regenerated)
**What to do:**
- Prepend CHANGELOG entry for Phase 105 in the format required by `docs/developer/DOCUMENTATION_STANDARDS.md`
- Flip `status: PROPOSED` → `COMPLETE` in manifest.yaml
- Add `completed: '2026-04-NN'` field
- Run `make sync`; commit regenerated TODO.md and PROJECT_STATUS.md

**Done when:**
- [ ] CHANGELOG has Phase 105 entry
- [ ] Manifest status is COMPLETE
- [ ] `make sync` produced no further diff on re-run

---

## Step 5 — Summary

**Total sub-tasks:** 36 (excluding mini sub-tasks for individual PDF chapters
that share a template). Count by size: **5 XS**, **17 S**, **14 M**, **0 L**.

**Estimated total effort:** ~65 hours of focused junior-engineer time. At
one engineer full-time that's ~2 weeks. Most tracks parallelise cleanly so
a 5-agent fan-out completes the core waves in ~3 working days.

**Critical blockers that must resolve before any core work:**
1. **B1** — Add Phase 105 to `docs/phases/manifest.yaml` (sub-task 105.0.1)
2. **D1** — Correct the PDF toolchain reference in the phase doc (sub-task 105.0.2)
3. **D2** — Approve the PDF CI placement ADR (sub-task 105.0.3) before 105.8.13
4. **T1** — Pick and pin a link-check tool (sub-task 105.0.5) before 105.10.1

**Strongly recommended before core work (HIGH severity):**
- **A1** — Enforce 120-line cap on every `for-*/README.md` (build into sub-task acceptance)
- **S5** — SHA-pin every action in the new PDF workflow (built into sub-task 105.8.13 acceptance)
- **T4** — Enumerate blocking-doc safety callouts (sub-task 105.4.1) before the merge (sub-task 105.4.2)

**Parallel execution plan:**

| Wave | Duration | Parallelism |
|------|----------|-------------|
| 0 — Scaffolding | ~1 day | 5 agents: 105.0.1, 105.0.2, 105.0.3, 105.0.4, 105.0.5 all parallel |
| 1 — Core content | ~3 days | 7 agents: Tracks A, B, C, D, E, F, G, H run in parallel |
| 2 — Wiring | ~0.5 days | 3 agents: 105.9.1, 105.9.2, 105.9.3 |
| 3 — Hardening | ~1 day | 1 agent sequential (depends on all prior); close-out |

**Next step:** Once blockers B1, D1, D2, T1 are resolved, use `/run-phase 105`
to execute Wave 0 scaffolding, then fan out to Wave 1 tracks in parallel.
