# Phase 121 — Pentest Remediation Consolidation & Program Discipline

> **Status:** PROPOSED
> **Size:** XLARGE — 11 sub-phases, plan-only; execution deferred to successor phases or absorbed into revised 118/119/120.
> **Dependencies:** Phase 108 (pentest framework), Phase 118 (attack-surface remediation, XXLARGE), Phase 119 (connection lifecycle, LARGE), Phase 120 (red team findings, LARGE). Supersedes or absorbs scope of 117 (already DEFERRED), and will retire 120 as a duplicate of 119 once reconciled.
> **Drafted:** 2026-04-19

---

## 1. Why this phase exists

Between 2026-04-09 and 2026-04-19 the team ran four overlapping security
assessments (Phase 108 campaign, 2026-04-16 leader campaign report, 2026-04-17
red team audit, 2026-04-17 white-box assessment) and spawned Phases 109 through
120 to remediate the output. That output now stands at roughly **98 sub-phase
entries across 13 phase documents, ~4,800 lines**, with no shared finding IDs,
no dedup across reports, no regression-test-per-finding rule, no SLA
enforcement, and at least one phase (118) carrying a visible merge conflict.

This is classic bug-hunt mode: findings are being *enumerated* but not
*managed*. A second red team pass is already rediscovering issues identified
by the first one under new names (PROXY smuggling, tarpit exhaustion, metrics
exposure each appear in 3–5 phases). If we ship the current backlog as-is, we
will either duplicate fixes, miss fixes, or mark a phase COMPLETE with an
unfixed finding hiding behind a different ID in a sibling phase.

**Phase 121 converts the pile of findings into a program.** It does three
things, all plan-only at this stage:

| | What | Why |
|---|---|---|
| **(a) Meta-plan** | Sequence 108–120 into waves with explicit dependencies, owners, entry criteria, and exit gates. | Today no phase doc knows which others it blocks or is blocked by. Fixes get reverted or duplicated. |
| **(b) Consolidation** | Collapse duplicate findings across 108/117/118/119/120 into a single canonical register. Retire or rescope the phases that are now redundant. | A finding should be fixed once, tested once, and closed once — not three times under three IDs. |
| **(c) Process reform** | Establish finding ID scheme, severity rubric, SLA policy, regression-test-per-finding rule, and a `make verify-findings` gate so the *next* red team report does not produce this mess again. | The tooling gap is what let the bug-hunt pattern emerge. Fix the tooling or it repeats. |

This phase produces **documents and automation**, not code fixes. Code fixes
continue under 118/119 (possibly rescoped by 121e) and any successor phases.

---

## 2. Sub-phase index

| ID | Sub-phase | Deliverable | Size | Depends on |
|---|---|---|---|---|
| **121a** | Findings register schema & tooling | `docs/security/FINDINGS_REGISTER.md` + `scripts/findings_register.py` | M | none |
| **121b** | Ingest & dedup all 108–120 findings into canonical IDs | First populated register | M | 121a |
| **121c** | Severity rubric & SLA policy | `docs/security/SEVERITY_RUBRIC.md` | S | none |
| **121d** | Regression-test-per-finding rule | `docs/developer/TESTING_STRATEGY.md` addendum + `make verify-findings` target | M | 121a, 121c |
| **121e** | Rescope 117/118/119/120 against the canonical register | Revised phase docs, retirement notes, updated manifest | M | 121b |
| **121f** | Remediation waves & sequencing DAG | `docs/security/REMEDIATION_WAVES.md` | S | 121e |
| **121g** | Ownership & RACI | Owner column populated in register; escalation ladder | S | 121b |
| **121h** | Closure verification protocol | `docs/security/CLOSURE_VERIFICATION.md` + CI wiring spec | S | 121a, 121d |
| **121i** | Cross-assessment dedup for future reports | `docs/security/INTAKE_RUNBOOK.md` for the next red team report | S | 121a, 121c |
| **121j** | CVSS version reconciliation (v4 vs v3.1) | ADR-NNN + rubric update | XS | 121c |
| **121k** | Phase-121 close-out gate | Acceptance checklist + `make phase-121-verify` | XS | all above |

**Start here:** 121a and 121c are independent and can run in parallel. They
are the foundation — every other sub-phase depends on at least one of them.

### Parallelism

| Stream | Sub-phases | Engineer count |
|--------|-----------|---------------|
| Register & tooling | 121a → 121b → 121e → 121f | 1 (tooling) + 1 (ingest) |
| Policy | 121c → 121d, 121j | 1 |
| Process | 121g, 121h, 121i | 1 |
| Close-out | 121k | 1 |

Up to **3 people** can work this in parallel without file conflicts.

---

## 3. Sub-phase detail

### 3.1 Sub-phase 121a — Findings register schema & tooling

**Goal:** A single machine-readable source of truth for every security finding,
past and future.

**Deliverable:** `docs/security/FINDINGS_REGISTER.md` with schema + `scripts/findings_register.py` with validate/list/add commands.

**Schema (one row per canonical finding):**

| Column | Type | Example |
|---|---|---|
| `id` | `JA4PROXY-YYYY-NNNN` | `JA4PROXY-2026-0001` |
| `title` | short string | PROXY protocol v2 spoofing from untrusted source |
| `severity` | enum (CRITICAL/HIGH/MEDIUM/LOW) | HIGH |
| `cvss_v3_1` | float + vector | 8.6 / `CVSS:3.1/AV:N/AC:L/…` |
| `source_refs` | list of `{report, original_id}` | `[{report: "PHASE_108", id: "L1-001"}, {report: "RED_TEAM_AUDIT", id: "R-017"}]` |
| `remediation_phases` | list of phase IDs | `[118a, 109]` |
| `owner` | GitHub handle | `@seanpor` |
| `discovered` | ISO date | 2026-04-09 |
| `due` | ISO date (from SLA) | 2026-05-09 |
| `status` | OPEN/IN_PROGRESS/FIXED/VERIFIED/CLOSED/DUPLICATE | OPEN |
| `supersedes` | list of canonical IDs | `[]` |
| `regression_test` | path | `tests/pentest/layer1/test_proxy_spoofing.py::test_untrusted_source_rejected` |
| `closed_commit` | SHA | — |

**Steps:**
1. Create `docs/security/FINDINGS_REGISTER.md` with frontmatter explaining the schema and usage.
2. Create `scripts/findings_register.py` implementing:
   - `validate` — parses the register, asserts schema, unique IDs, referenced phase docs exist, referenced test files exist when status ≥ FIXED.
   - `list --status=OPEN --severity=HIGH` — filtered view.
   - `add --source=PHASE_118 --source-id=118a-01 ...` — append a new row, allocate next canonical ID.
   - `dedup-hint` — fuzzy match title+location against existing entries, flag likely duplicates.
3. Wire `make verify-findings` to `scripts/findings_register.py validate` and fail CI on schema or referential errors.
4. Document: register entries are **append-only for facts**; status/owner/test path fields may be updated in place; `DUPLICATE` status requires a `supersedes` list.

**Verify:**
- `make verify-findings` exits 0 on an empty register.
- `scripts/findings_register.py add …` round-trips correctly.
- `scripts/findings_register.py dedup-hint` catches a deliberate test duplicate.

---

### 3.2 Sub-phase 121b — Ingest & dedup all 108–120 findings

**Goal:** Every finding currently scattered across 13 phase docs and 3 red team reports lives in the register with a canonical ID, and duplicates are linked via `supersedes`.

**Input documents (full list):**

- `docs/phases/complete/PHASE_108.md` (L1-NNN, L2-NNN, … L7-NNN)
- `docs/phases/complete/PHASE_109.md` through `PHASE_117.md` (per-phase findings, no IDs)
- `docs/phases/complete/PHASE_118.md` (18 sub-phases, 53 findings, IDs 118a…118r)
- `docs/phases/complete/PHASE_119.md` (R-NNN / RT-NNN — 17 findings)
- `docs/phases/complete/PHASE_120.md` (119a–t — 20 findings; overlaps 119)
- `docs/reports/2026-04-16_LEADER_PENTEST_CAMPAIGN.md`
- `docs/reports/2026-04-17_RED_TEAM_AUDIT.md`
- `docs/reports/2026-04-17_REDTEAM_WHITEBOX_ASSESSMENT.md`

**Duplicate clusters already identified in survey (not exhaustive — full dedup is the work of 121b itself):**

| Theme | Phases that touch it | Expected canonical count |
|---|---|---|
| PROXY protocol spoofing / smuggling / fragmentation | 108 (L1-001), 109, 116, 117, 118a/b | 2–3 (spoofing, smuggling, fragmentation are distinct) |
| TLS parser robustness (fragmentation, truncation, oversized) | 108 (L2, 108d), 117, 118b, 119 (R-016) | 2 |
| IP spoofing via X-Forwarded-For | 108 (L1-001), 110, 117, 118c/h | 1–2 |
| Redis hygiene (ACLs, fail-closed, KEYS → SCAN, unbounded sets) | 108 (L5), 110, 113, 118d/e/g/i, 119 | 4–5 (distinct root causes) |
| Metrics/health endpoint exposure | 108 (L5), 118c/h, 119 | 1 |
| Auth/rate-limit (management API, health, shared state) | 110, 118e, 119 | 2 |
| Webhook SSRF | 108 (L4-006), 110, 118g | 1 |
| Tarpit exhaustion & DoS | 111, 113, 117, 118f, 119 | 2 (timeouts, overflow) |
| Credential hygiene (git history, defaults, rotation) | 108 (L6, 107g), 118d, 119 | 3 (distinct surfaces) |
| JWT/session (CSRF, blacklist, secure flag, signature) | 108 (L4), 110, 112, 118k, 119i | 3 |
| Log injection / sanitisation | 111, 118l/n, 119 | 1–2 |
| Protocol confusion / ALPN bypass / X-JA4 header | 108 (L1), 116, 117, 118b, 119a/b | 2 |

Expected outcome: the ~98 sub-phase entries across 108–120 collapse to **~40–55 canonical findings**.

**Steps:**
1. For each source document, extract every finding into the register with `source_refs` populated. Keep the original ID verbatim.
2. Run `scripts/findings_register.py dedup-hint` and manually review. For each duplicate pair, pick a canonical entry, mark the other `DUPLICATE`, set `supersedes`.
3. For each canonical finding, assign severity per 121c rubric (may differ from source — source reports drift between CVSS v3.1 and informal labels).
4. For each canonical finding, record the remediation phase(s) in `remediation_phases` (may be more than one where a fix spans Go and Python).
5. Commit the populated register in a single atomic commit titled `phase-121b: populate FINDINGS_REGISTER from phases 108–120`.

**Verify:**
- `make verify-findings` exits 0.
- Every L-NNN / R-NNN / RT-NNN / 119a–t / 118a–r / 120 ID appears in at least one `source_refs` field.
- No canonical ID has more than one `status: OPEN` sibling via transitive `supersedes`.

---

### 3.3 Sub-phase 121c — Severity rubric & SLA policy

**Goal:** Stop copying severity labels from external CVSS vectors without reconciling to this product's risk model.

**Deliverable:** `docs/security/SEVERITY_RUBRIC.md` defining:

| Severity | Criteria (any of) | Remediation SLA | Example |
|---|---|---|---|
| CRITICAL | RCE / full auth bypass / unauthenticated data exfil / blocks legitimate traffic at scale | 7 days to fix, 14 days to verify closed | Metrics endpoint unauthenticated + leaks client IPs |
| HIGH | Auth bypass for specific role / DoS of proxy / material FP risk | 30 days | JA4 fingerprint bypass via fragmentation |
| MEDIUM | Info leak / exploitability limited / requires prior compromise | 60 days | Log injection without downstream consumer |
| LOW | Cosmetic / defence-in-depth / no direct exploit path | 120 days | Missing security header on admin-only route |

**Steps:**
1. Write the rubric with 3–5 worked examples per severity, drawn from the register populated in 121b.
2. Codify the **asymmetry rule** from `CLAUDE.md`: any finding whose worst-case remediation could block legitimate traffic must carry a **fail-open** acceptance criterion regardless of severity. This is a project-specific constraint that standard CVSS does not capture.
3. Define escalation: any CRITICAL missing its SLA pages the on-call; HIGH missing its SLA is reviewed weekly.
4. Require every register entry to cite the rubric clause it was classified under (`severity_rationale` free-text field).

**Verify:**
- Every register entry has a non-empty `severity_rationale`.
- Running `scripts/findings_register.py list --sla-breach` returns only entries past their `due` date.

---

### 3.4 Sub-phase 121d — Regression-test-per-finding rule

**Goal:** A finding cannot transition to `CLOSED` without a dedicated test that fails on the unfixed code and passes on the fix.

**Deliverable:** `docs/developer/TESTING_STRATEGY.md` addendum + `make verify-findings` extension.

**Steps:**
1. Extend `scripts/findings_register.py validate`: for each entry with status `FIXED`, `VERIFIED`, or `CLOSED`, assert `regression_test` is populated and the referenced file and test name exist.
2. Add a convention: regression tests live under `tests/pentest/` (Python) or `internal/security/pentest/` (Go) in files named after the canonical ID, e.g. `tests/pentest/test_ja4proxy_2026_0001_proxy_v2_spoofing.py`.
3. Require each regression test to have a docstring block citing the canonical finding ID, the original source ID(s), and the CVSS vector.
4. Wire a lightweight `make verify-findings-green` that runs only the regression tests listed in the register (fast signal when triaging a new report).

**Verify:**
- Attempting to set status `CLOSED` on an entry without a regression test causes `make verify-findings` to fail.
- A deliberately broken regression test (asserting the vulnerable behaviour) fails `make verify-findings-green`.

---

### 3.5 Sub-phase 121e — Rescope 117/118/119/120 against the canonical register

**Goal:** After dedup (121b), the existing phase docs are stale. Reconcile them so each phase points at canonical IDs and duplicates are retired.

**Expected outcomes (draft, confirm during execution):**

- **117** is already DEFERRED / superseded by 118. Confirm every 117 finding has a canonical register entry; no doc rewrite needed.
- **118** rescoped to reference canonical IDs. Sub-phases that now duplicate 119 work are retired (status in sub-phase header changes to SUPERSEDED). Merge conflict visible in the current doc is resolved as part of this sub-phase.
- **119** and **120** are near-duplicates (both cover the independent red team's 17–20 findings). **Recommendation: retire 120 as DUPLICATE_OF 119**, fold any novel items from 120 into 119, delete PHASE_120.md (or leave a short redirect stub).
- **108** is the campaign framework itself — stays as-is; sub-phases 108k/108n are the source of many governance items that Phase 121 is now operationalising, so update 108n's acceptance criteria to point at the register instead of re-describing it.

**Steps:**
1. For each phase doc in scope, insert a header table mapping its local IDs to canonical register IDs.
2. For each sub-phase whose remediation is entirely covered by another phase's work, mark it SUPERSEDED and link to the canonical owner.
3. Update `docs/phases/manifest.yaml`:
   - Add `121` entry (done as part of closing 121 — see §6).
   - Set `120.status: DEFERRED` with `superseded_by: 119` if the recommendation holds.
   - Set `117.superseded_by: 118` (already present — confirm).
   - Add a `canonical_findings: [JA4PROXY-2026-NNNN, …]` list to each remediation phase entry for traceability.
4. Run `make sync` so `TODO.md` and `PROJECT_STATUS.md` reflect the new layout.

**Out of scope:** code changes, test changes. This is document reconciliation only.

---

### 3.6 Sub-phase 121f — Remediation waves & sequencing DAG

**Goal:** Given the canonical findings, produce an explicit execution order.

**Deliverable:** `docs/security/REMEDIATION_WAVES.md` with:

- **Wave 1 — Now (CRITICAL, independent):** findings that can be fixed immediately and unblock everything else. Expected to include: unauth metrics endpoint, Redis fail-closed on error, PROXY spoofing rejection, JA4 fragmentation bypass.
- **Wave 2 — Next 30 days (HIGH, mostly independent):** management API auth hardening, tarpit exhaustion fixes, Redis ACLs, credential rotation.
- **Wave 3 — Next 60 days (MEDIUM, and HIGH with dependencies):** audit log migration, webhook SSRF, session hygiene.
- **Wave 4 — Next 120 days (LOW + design):** ALPN design-flaw mitigation, infrastructure hardening, documentation polish.

Present as a DAG (mermaid or ASCII) showing blocking relationships between canonical IDs.

**Steps:**
1. For each canonical finding, populate `depends_on` in the register (optional new column).
2. Topologically sort, group by severity-derived SLA window.
3. Document in `REMEDIATION_WAVES.md` with explicit acceptance "Wave N complete = all IDs in wave status ≥ VERIFIED".

---

### 3.7 Sub-phase 121g — Ownership & RACI

**Goal:** Every finding has a named owner; escalation is unambiguous.

**Deliverable:** `owner` column populated for every OPEN/IN_PROGRESS register entry + ownership policy in `docs/security/OWNERSHIP.md`.

**Policy:**
- R (Responsible) = named owner in register.
- A (Accountable) = security lead (currently single-handed — document this as a risk).
- C (Consulted) = subject-matter experts (e.g. Redis for ACL work).
- I (Informed) = release manager.

**Escalation:** missed SLA → Slack `#sec-ops` + manifest annotation `breach_acknowledged: true`.

---

### 3.8 Sub-phase 121h — Closure verification protocol

**Goal:** A finding goes OPEN → IN_PROGRESS → FIXED → VERIFIED → CLOSED on clear criteria, each transition auditable.

**Deliverable:** `docs/security/CLOSURE_VERIFICATION.md` + PR template.

**State machine:**

| From | To | Trigger | Evidence |
|---|---|---|---|
| OPEN | IN_PROGRESS | PR opened referencing canonical ID | PR link in register |
| IN_PROGRESS | FIXED | PR merged; regression test added and green | Merge SHA + test path |
| FIXED | VERIFIED | Independent reviewer re-runs the proof-of-exploit or reviews the fix against the original report | Reviewer handle + date |
| VERIFIED | CLOSED | 14 calendar days with no regression report | Automated by `scripts/findings_register.py promote-verified` |

PRs that touch security-sensitive code must cite at least one canonical ID or state "no finding — net-new feature". This is enforced by a CI check, not by reviewer diligence.

---

### 3.9 Sub-phase 121i — Intake runbook for the next red team report

**Goal:** When the next report lands, the team does not spawn a new phase — they ingest into the existing register.

**Deliverable:** `docs/security/INTAKE_RUNBOOK.md` + template for report receipt.

**Steps (runbook content, not execution):**
1. Assign a report ID (`RT-YYYY-MM-DD-source`).
2. For each finding in the report, run `scripts/findings_register.py dedup-hint`. For each hit, either merge into an existing canonical entry (append to `source_refs`) or open a new one.
3. Assign severity per 121c rubric, not per the report's own labels.
4. Assign to an existing remediation phase, or open a new one only if the scope does not fit anywhere.
5. Publish a short `docs/reports/YYYY-MM-DD_INTAKE_<source>.md` summarising the triage outcome.

**Success criterion:** future red team reports produce **zero new phase documents** unless they open a genuinely new remediation category.

---

### 3.10 Sub-phase 121j — CVSS version reconciliation

**Goal:** Pick one CVSS version and use it consistently.

**Context:** Phase 108n's acceptance criteria cite CVSS v4, but every downstream report (red team audit, white-box assessment, 118/119) uses v3.1. The register schema in 121a lists `cvss_v3_1` as a field; this sub-phase either ratifies that choice or flips the project to v4.

**Deliverable:** `docs/decisions/ADR-NNN-cvss-version.md` + rubric update.

**Recommendation (to be ratified here):** stay on **CVSS v3.1** until external auditors require v4, because (a) every existing finding is scored in v3.1, (b) the NVD and most commercial scanners still primarily emit v3.1, (c) a rescore of 40–55 findings is busywork with no security delta. Update 108n's acceptance criteria to match.

---

### 3.11 Sub-phase 121k — Phase 121 close-out gate

**Goal:** This phase cannot be marked COMPLETE unless the program discipline is actually operational.

**Acceptance (run `make phase-121-verify`):**
- `make verify-findings` passes with ≥40 canonical entries populated.
- Every entry in source reports has a traceable canonical ID.
- `scripts/findings_register.py list --status=OPEN` returns the remediation backlog sorted by severity+due date.
- `docs/security/{SEVERITY_RUBRIC,REMEDIATION_WAVES,CLOSURE_VERIFICATION,INTAKE_RUNBOOK,OWNERSHIP}.md` all exist.
- `docs/phases/manifest.yaml` updated: 121 registered, 120 marked DEFERRED (or redirected) if 121e recommendation holds, 117 confirmed superseded.
- `docs/reference/PROJECT_STATUS.md` regenerated via `make sync` and shows the wave structure at a glance.
- ADR on CVSS version merged.

---

## 4. Recommendation (as requested)

Adopt the combined approach — **meta-plan + consolidation + process reform** —
as a single phase, plan-only in this pass, because the three cannot be done
cleanly in isolation:

- Consolidation without a severity rubric and a canonical ID scheme just
  reshuffles chaos.
- A severity rubric without a consolidated register has nothing to classify.
- A sequencing plan built on the pre-dedup backlog sequences phantom work.

By the end of Phase 121 the team has: (1) a single register, (2) clear
rules for how findings enter and leave it, (3) a sequenced backlog, and
(4) retired or rescoped pseudo-duplicate phases. **No code changes.** Fix
execution resumes under 118/119 (possibly slimmed by 121e) with far less
risk of duplicate or missed work.

**One explicit recommendation to confirm during 121e:** retire `PHASE_120.md`
as a duplicate of `PHASE_119.md`. The 2026-04-17 survey shows 120 is a thin
restatement of 119's 20 findings with the same IDs; keeping both doubles
remediation accounting forever.

---

## 5. Out of scope

- **Any code fix.** Every fix remains under 118/119 (and their eventual
  successors after 121e rescopes). If a fix is trivially landed during 121
  execution, note it in the register with a closed commit — but do not pad
  121's scope with implementation.
- **External pentest commissioning.** Phase 108 already frames this.
- **Changes to existing production security controls.** Register tooling is
  meta; it does not run in production.
- **Bug bounty or CVD policy.** Worth doing, but belongs in its own phase.
- **Cross-project harmonisation** with other internal security programs
  (nothing else uses this register).

---

## 6. Acceptance criteria

- [x] `docs/security/FINDINGS_REGISTER.md` exists with documented schema. *(121a)*
- [x] `scripts/findings_register.py` implements validate / list / add / dedup-hint / promote-verified. *(121a, tightened in 121h)*
- [x] `make verify-findings` wired and green. *(121a)*
- [x] ≥40 canonical findings populated; every 108–120 source finding reachable via `source_refs`. *(121b — 54 findings)*
- [x] `docs/security/SEVERITY_RUBRIC.md` exists with worked examples and SLA table. *(121c)*
- [x] `docs/security/REMEDIATION_WAVES.md` exists with an explicit DAG and wave completion criteria. *(121f)*
- [x] `docs/security/CLOSURE_VERIFICATION.md` exists; PR template updated; CI check for canonical ID citation on security-sensitive diffs. *(121h)*
- [x] `docs/security/INTAKE_RUNBOOK.md` exists. *(121i)*
- [x] `docs/security/OWNERSHIP.md` exists; every OPEN/IN_PROGRESS finding has a named owner. *(121g)*
- [x] `docs/decisions/ADR-121a-cvss-version.md` merged. *(121j)*
- [x] `docs/phases/manifest.yaml` updated: 121 registered; 120 adjusted per 121e outcome (DEFERRED + superseded_by 119); 117 confirmed superseded by 118. *(121e)*
- [x] `make sync` run; `TODO.md` and `PROJECT_STATUS.md` reflect the new layout. *(121e)*
- [x] `make phase-121-verify` exits 0. *(121k)*

---

## 7. Confirmed decisions (2026-04-19)

All five open questions were resolved with the recommendations below. These
bind the execution of 121b–121k.

1. **PHASE_120.md disposition:** **retire as redirect stub.** Replace body with
   a 5-line header citing `DUPLICATE_OF: 119` so external links survive and
   git-blame context is preserved. Executed under 121e.
2. **CVSS version:** **stay on v3.1.** Every existing finding is scored in
   v3.1; NVD leads with v3.1; rescoring ~50 findings is busywork. Phase 108n's
   "CVSS v4" specification is updated to match. ADR under 121j.
3. **Accountable owner model:** **split by layer even while single-handed.**
   Three lanes — Go proxy, Python management plane, infrastructure — with the
   same person holding multiple hats for now. `OWNERSHIP.md` documents this
   and flags the concentration risk. Keeps the split ready for hiring without
   a future rewrite. Executed under 121g.
4. **Register storage:** **single `docs/security/findings.yaml` as source of
   truth, `FINDINGS_REGISTER.md` as a generated human-readable view.** YAML
   diffs cleanly; the tooling has one file to parse. **Migration trigger**
   (written into `INTAKE_RUNBOOK.md`): when canonical entry count exceeds 100,
   move to GitHub Projects board and regenerate the markdown from the API.
5. **New-phase threshold:** **new phase only when ≥1 finding maps to a
   category with no existing remediation phase owner.** If a new report's
   findings all fit into existing phases (109–119), they are absorbed via
   `scripts/findings_register.py add` with `remediation_phases` pointing at
   the existing phase. A net-new category (e.g. "SBOM generation",
   "SLSA L3 provenance") triggers a new phase. Documented in
   `INTAKE_RUNBOOK.md` with worked examples.

---

## 8. File ownership (per Multi-Agent rules)

| File | Owner |
|---|---|
| `docs/phases/complete/PHASE_121.md` | this phase |
| `docs/security/FINDINGS_REGISTER.md` | this phase (creates); all subsequent phases append to it |
| `docs/security/{SEVERITY_RUBRIC,REMEDIATION_WAVES,CLOSURE_VERIFICATION,INTAKE_RUNBOOK,OWNERSHIP}.md` | this phase |
| `docs/decisions/ADR-NNN-cvss-version.md` | this phase |
| `scripts/findings_register.py` | this phase |
| `Makefile` | append `verify-findings`, `verify-findings-green`, `phase-121-verify` targets only |
| `docs/phases/manifest.yaml` | only entries for 117, 118, 119, 120, 121 |
| `docs/reference/PROJECT_STATUS.md`, `docs/phases/TODO.md` | regenerated by `make sync` — do not hand-edit |

Do not touch phase docs 108–116 except to append a canonical-ID mapping header in 121e.
