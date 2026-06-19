# Phase 106 — SWEBOK v4 Alignment — Critical Review

> **Reviewer:** Claude (automated `/review-phase 106`)
> **Date:** 2026-04-24
> **Target production stack:** documentation + tooling only (Python for scripts;
> **no Go proxy code is touched** in this phase)
> **Phase doc under review:** [docs/phases/complete/PHASE_106.md](PHASE_106.md)
> **Status:** PROPOSED
> **Dependencies declared:** Phase 105 (PROPOSED — **INCOMPLETE**)

---

## 0. Executive Summary

Phase 106 is a **pure-documentation phase** with two small script additions
(`scripts/traceability.py`, `scripts/process_metrics.py`) and minimal CI wiring.
It does not touch the Go hot path, not the Python proxy, not the TAP consumer,
not the Management API, not Redis, and not `config/proxy.yml`. The CLAUDE.md
"Go is production" directive is unaffected: this is a docs-and-tooling phase.

**The phase doc itself is well-structured** — clear problem/fix/size blocks
per sub-phase, honest scope notes, explicit acceptance criteria — and the
author has already applied lessons from prior phases (scope caps, estimate
hedges, "not marketing" constraints).

However, there are **five blocking issues** that must be resolved before
any implementation begins, plus a number of smaller risks worth addressing.

### Blocking issues (must resolve before starting)

| # | Issue | Severity |
|---|-------|----------|
| B1 | **Dependency Phase 105 is still PROPOSED.** 106c/106a/106g explicitly target ``, ``, `` — none of which exist. 106 cannot land those docs in a yet-to-be-created audience tree without either guessing at Phase 105's structure or producing work that Phase 105 will later move. | HIGH |
| B2 | **Phase doc references `docs/phases/STYLE_GUIDE.md`** (line 448) but the actual file is `docs/developer/STYLE_GUIDE.md`. | MEDIUM |
| B3 | **"SHA-pinned" CI acceptance criterion (line 410-411) is miscategorised.** The project SHA-pins third-party actions, not local workspace scripts. `scripts/traceability.py` is not a third-party action. | LOW (wording) |
| B4 | **106d "CI blocks if any `REQ-*` tag has no `Verified by:` clause"** conflicts with the retroactive scope cap of seven phases. If CI enforces `Verified by:` for every `REQ-*` tag, only the seven tagged phases can use the tag — but future phases will need it too. The rule needs to be "CI blocks if any `REQ-*` tag has no `Verified by:` **AND the phase's acceptance-criteria section uses `REQ-*` at all**" (opt-in per phase until universal). | MEDIUM |
| B5 | **106g CASE_STUDIES.md requires reading 3 existing phase docs in full.** No sizing contingency if a case study turns out not to be load-bearing. Mitigation: pre-select the three case-study phases and verify each has enough "what went wrong" material before committing. | LOW |

Proceed to implementation only after resolving B1-B4 and documenting the
case-study selection for B5.

---

## 1. Context Loaded

1. ✅ `CLAUDE.md` — core asymmetry, cross-cutting rules, Go-is-prod directive.
   None of the phase's sub-phases are on the proxy hot path, so cross-cutting
   rules (IPv6, async, fail-open, hot-reload) are **not applicable**. The
   core asymmetry (FP-cost ≫ FN-cost) surfaces only in 106a (SLOs cite FP
   rate targets) and 106b (risk register entries).
2. ✅ `docs/phases/complete/PHASE_106.md` — read in full (532 lines).
3. ✅ `docs/phases/manifest.yaml` — Phase 106 is PROPOSED. **Dependency
   Phase 105 is also PROPOSED** (see B1 above).
4. ✅ `config/proxy.yml` — not touched by this phase.
5. ✅ `docs/reference/OBSERVABILITY_STANDARDS.md` — §1 (Prometheus Metrics) cited as
   source material for 106a SERVICE_TARGETS. SLI runbooks exist:
   `slo_availability.md`, `slo_fp_rate.md`, `slo_latency.md`,
   `slo_redis_correctness.md` (the fourth is uncited in the phase doc — a gap).
6. ✅ Source files spot-checked:
   - `docs/security/findings.yaml` (1802 lines) — canonical findings register.
     Required reading for 106b RISK_REGISTER curation.
   - `docs/security/threat-model.md` — exists; required for 106b.
   - `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` — exists; required for 106b.
   - All seven retro-tag target phase docs exist (PHASE_15, 79, 82, 102,
     103, 104, 200).
   - Five audience directories (`docs/for-*/`) **do not exist** — see B1.
7. **Go vs Python:** this phase is **documentation** with two Python
   scripts. No proxy code is modified. No production data plane is touched.

---

## 2. Critical Review — Six Lenses

### 2a. Security Review

**Threat model changes:** none — no new attack surface. The phase adds
documentation, two read-only scripts, and two non-blocking CI jobs.

**Findings:**

- **S1 (INFO):** `scripts/traceability.py` and `scripts/process_metrics.py`
  read `docs/phases/*.md`, `docs/phases/manifest.yaml`, and GitHub Actions
  history. Neither opens a socket, neither takes untrusted input. Threat
  surface is the CI runner only. **Recommendation:** explicit "does not
  make network calls beyond the GitHub Actions API, does not accept user
  input" note in each script's module docstring.
- **S2 (LOW):** 106e process-metrics script "parses GitHub Actions history"
  (line 245). If this uses the GitHub REST API it needs a token; if rate-
  limited the script must fail gracefully. **Recommendation:** document the
  token scope required (`actions:read`, `contents:read`) and the rate-limit
  behaviour in the script's header.
- **S3 (INFO):** 106c TCO doc references "public pricing" for GeoIP,
  AbuseIPDB, Spamhaus. No credentials involved. No secrets to leak.
- **S4 (LOW):** 106b RISK_REGISTER is a curated index of findings already
  public. It must not leak pre-disclosure vulnerability information. The
  security-team process in the project already gates this via
  `docs/security/findings.yaml` disclosure status — the register must
  respect that status field.
- **S5 (INFO):** No new dependencies. Both scripts should work on the
  Python 3.10 stdlib (PyYAML is already in requirements for `manifest.yaml`
  parsing). **Verify**: do not add new pip dependencies.

**OWASP top 10 applicability:** none — no web-facing code changes.

**Core asymmetry check:** 106a SERVICE_TARGETS must cite the FP-rate SLO
(`docs/runbooks/slo_fp_rate.md`) with its current target, and must frame it
as the dominant quality attribute — not as one of several equal ones.

### 2b. DevOps Review

- **D1 (MEDIUM):** 106d / 106e add two CI jobs. Acceptance criterion says
  "non-blocking for 14 days, then blocking". **Who flips the switch?** The
  phase doc doesn't say. **Recommendation:** bake the blocking behaviour
  into a dated conditional (`if: github.event.head_commit.timestamp >
  '2026-05-08T00:00:00Z'`) or a variable. Don't rely on a human remembering.
- **D2 (LOW):** Both new CI jobs must run on the existing Python 3.10 GHA
  runner. The PR template should document CI runtime impact — two doc-
  validation jobs will add ~30-60s. Acceptable.
- **D3 (INFO):** No changes to Dockerfile, docker-compose, Helm chart, or
  release pipeline. No rollback risk. No data-migration risk. No feature
  flag needed — this is documentation.
- **D4 (LOW):** `scripts/traceability.py` generates `docs/reference/TRACEABILITY.md`.
  Is this file committed, or generated in CI? Phase doc is ambiguous.
  **Recommendation:** commit the generated file and have CI fail if it's
  out of sync with the source phase docs (same pattern as
  `docs/phases/TODO.md` via `make sync`).

### 2c. SRE Review

- **R1 (INFO):** No new Prometheus metrics. No new log lines. No new
  alerts. No SLI/SLO impact (106a **documents** SLOs, doesn't change them).
- **R2 (LOW):** 106e process metrics are **engineering process metrics**
  (phase throughput, CI reliability), not runtime metrics. They should
  not land in Prometheus — they land in `docs/engineering-method/retrospectives/`
  as markdown. **Confirm** the phase doc's intent here: it says "metric-
  collection script … emits the numbers automatically" — emits where?
  **Recommendation:** clarify output target is a markdown file, not a
  `/metrics` endpoint.
- **R3 (INFO):** No failure-mode changes. Nothing breaks if Redis is down.
  Scripts are offline-capable (read local files + GHA REST API).
- **R4 (INFO):** No capacity impact. Each new markdown doc is ≤10KB
  repo growth.
- **R5 (LOW):** 106a SERVICE_TARGETS must be kept in sync with the four
  SLO runbooks. **Recommendation:** add a test
  (`tests/docs/test_service_targets_sync.py`) that fails if an SLO runbook
  cites a target not reflected in SERVICE_TARGETS.md, or vice versa.

### 2d. Architecture Review

- **A1 (INFO):** No changes to the proxy pipeline (TCP accept → bypass
  → signals → scorer → action). No new modules introduced. No Redis
  schema changes — `docs/reference/REDIS_SCHEMA.md` unchanged.
- **A2 (INFO):** No concurrency implications. Scripts are offline
  analysis tools run by CI.
- **A3 (INFO):** IPv6 not applicable (no IP-touching code).
- **A4 (LOW):** 106f component-design-index is **structural documentation**.
  The phase doc correctly restricts it to an index, not deep design docs
  (line 291-292). **Recommendation:** add an explicit NON-GOAL line:
  "this is not an architecture-decision-record; ADRs live in
  `docs/decisions/`".
- **A5 (MEDIUM):** 106d requires a schema for acceptance criteria
  (`REQ-105-01: …`). This is a **cross-cutting convention** that affects
  every future phase doc. **Recommendation:** the schema addition in
  `docs/developer/STYLE_GUIDE.md` (note: not `docs/phases/STYLE_GUIDE.md` — see B2)
  should be landed **before** any retroactive tagging, so the convention
  is clear and doesn't need re-work.

### 2e. Testing Review

- **T1 (HIGH):** Phase has **zero test coverage plan** despite adding two
  Python scripts (`scripts/traceability.py`, `scripts/process_metrics.py`).
  Per CLAUDE.md §Testing Standards, scripts need unit tests. **Required:**
  - `tests/unit/test_traceability.py` — extract REQ IDs from a fixture
    phase doc, assert the generated matrix is correct, assert CI failure
    on missing `Verified by:`.
  - `tests/unit/test_process_metrics.py` — parse a fixture manifest.yaml
    and fixture GHA history, assert the four metrics match expected values.
- **T2 (MEDIUM):** 106a SERVICE_TARGETS sync test (see R5).
- **T3 (MEDIUM):** 106b RISK_REGISTER structure test — assert the table
  header matches the spec, assert every row has a Mitigation column,
  assert every row has a source link resolvable to an existing file.
- **T4 (LOW):** Retro-tagging of seven phases (106d.2) must not break
  their existing `/run-phase` automation if any is in-flight. Verify none
  of the seven target phases are mid-execution.
- **T5 (MEDIUM):** No FP corpus tests needed (no scoring code touched).
- **T6 (INFO):** No perf / E2E tests needed.
- **T7 (LOW):** Test-to-code ratio check: the phase adds ~2 scripts
  (~200 LOC) plus ~11 markdown docs. Proposed test code: ~300 LOC.
  Ratio for code-only: 1.5x — meets the ~1.3x target.
- **T8 (MEDIUM):** **No `test_pages.py` needed** (non-web phase). **No
  `test_container_config.py` needed** (no new services). Explicitly note
  this in the phase doc to close the audit checklist.

### 2f. Documentation Review

- **Doc1 (HIGH, see B1 above):** 106c/106a/106g link into `docs/for-*/`
  directories that don't exist. Depends on Phase 105 delivering them.
- **Doc2 (MEDIUM, see B2 above):** phase doc line 448 references
  `docs/phases/STYLE_GUIDE.md` — correct path is `docs/developer/STYLE_GUIDE.md`.
- **Doc3 (LOW):** CHANGELOG entry format — the phase doc says "Phase 106
  entry" (line 413) without specifying the format. Use the project's
  existing format (see recent `## [Unreleased] - Phase 101 — …` entries).
- **Doc4 (MEDIUM):** 106b RISK_REGISTER claims 30-50 rows after dedup.
  Provide a **dedup methodology**: two risks are "the same" if they have
  the same (attack surface, failure mode, primary mitigation). Without a
  rule, the count becomes arbitrary.
- **Doc5 (LOW):** No new ADR required — this phase creates documentation
  about existing decisions, it doesn't make new ones. (Exception: if 106d
  introduces a new REQ-ID convention, an ADR is warranted. See A5.)
- **Doc6 (LOW):** 106 references `docs/runbooks/slo_redis_correctness.md`
  nowhere (line 83-85 cites only availability, FP rate, latency).
  **Recommendation:** 106a must include Redis-correctness SLO in
  SERVICE_TARGETS.
- **Doc7 (INFO):** Acceptance criteria at lines 371-415 are SMART for the
  most part: specific, measurable (file existence, row counts, line
  caps), achievable, relevant. **Time-bound is weak** — "non-blocking for
  14 days" is the only time-bound criterion. Rest are gated by the phase-
  completion merge, which is fine.

---

## 3. Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| B1 | Phase 105 (dependency) is PROPOSED; `docs/for-*/` dirs missing | HIGH | Doc | Either wait for Phase 105 Wave 1 to land audience scaffolding, or pre-create minimal `docs/for-*/README.md` stubs within Phase 106 and reconcile with Phase 105 on merge |
| B2 | Path typo `docs/phases/STYLE_GUIDE.md` | MEDIUM | Doc | Fix to `docs/developer/STYLE_GUIDE.md` before task decomposition |
| B4 | CI blocks on any `REQ-*` tag missing `Verified by:` — conflicts with 7-phase scope cap | MEDIUM | DevOps | Make tag-enforcement opt-in per phase (phase must mark itself REQ-tagged in its front-matter) |
| T1 | Two new scripts have no test plan | HIGH | Testing | Add unit tests for `traceability.py` and `process_metrics.py` |
| A5 | REQ-tag schema is cross-cutting; must land before retro-tagging | MEDIUM | Arch | Sequence: STYLE_GUIDE edit → retro-tag first phase → expand |
| Doc4 | RISK_REGISTER dedup methodology undefined | MEDIUM | Doc | Define: "same risk = same attack surface + failure mode + primary mitigation" |
| Doc6 | Redis-correctness SLO (4th runbook) not cited | LOW | Doc | Include in 106a SERVICE_TARGETS |
| D1 | "Non-blocking for 14 days then blocking" has no mechanism | MEDIUM | DevOps | Use dated conditional in `ci.yml` or a flipped-by-PR boolean |
| D4 | Generated TRACEABILITY.md — committed or CI-only? | LOW | DevOps | Commit it; CI fails if out of sync (same pattern as TODO.md) |
| R2 | 106e metric output target unclear | LOW | SRE | Markdown file output, not Prometheus |
| R5 | SERVICE_TARGETS / SLO runbook drift risk | LOW | SRE | Add sync test |
| S2 | process_metrics GitHub API rate-limit behaviour undocumented | LOW | Sec | Document token scope + rate-limit handling |
| S5 | No new pip deps explicitly | INFO | Sec | Verify and state in CHANGELOG |
| B5 | Case-study pre-selection | LOW | Planning | Pre-select Phase 15, 82, 200; verify each has "what went wrong" content |
| T2 | SERVICE_TARGETS sync test missing | MEDIUM | Test | Add |
| T3 | RISK_REGISTER structure test missing | MEDIUM | Test | Add |
| Doc7 | "Time-bound" acceptance weak | INFO | Doc | Acceptable — phase-close timing suffices |
| A4 | 106f missing explicit non-goal | LOW | Arch | Add "not an ADR" disclaimer |

**Severity breakdown:** 0 CRITICAL, 2 HIGH, 7 MEDIUM, 8 LOW, 2 INFO.

---

## 4. Decomposition into Junior-Engineer Sub-Tasks

### Phase 1 — Scaffolding (unblocks everything)

#### Sub-task 1.1: Fix the STYLE_GUIDE path typo in the phase doc
**Size:** XS (5 min)
**Depends on:** none
**Parallel with:** all of Phase 1
**Files to touch:** `docs/phases/complete/PHASE_106.md`
**What to do:**
- Change `docs/phases/STYLE_GUIDE.md` → `docs/developer/STYLE_GUIDE.md` on line 448
- Verify no other references to the wrong path in the file
**Done when:**
- [ ] `grep -n "phases/STYLE_GUIDE" docs/phases/complete/PHASE_106.md` returns nothing
**Watch out for:** nothing — trivial fix.

#### Sub-task 1.2: Pre-create audience-doc stub directories
**Size:** XS (15 min)
**Depends on:** none
**Parallel with:** 1.1
**Files to touch:**
- `README.md` (new, minimal placeholder)
- `README.md` (new, minimal placeholder)
- `README.md` (new, minimal placeholder)
- `README.md` (new, minimal placeholder)
- `README.md` (new, minimal placeholder)
**What to do:**
- Each README starts with: `# <Audience> Documentation` then a single paragraph: "Placeholder — Phase 105 will land the full audience entry point. Phase 106 deliverables link into this directory and will be reconciled."
- Make the file ≤ 20 lines. No content other than the placeholder.
- Add a `<!-- phase-106-placeholder -->` HTML comment so Phase 105 can grep-and-merge later.
**Done when:**
- [ ] 5 README files exist under `docs/for-*/`
- [ ] Each is ≤ 20 lines
- [ ] Each contains the `<!-- phase-106-placeholder -->` marker
**Watch out for:** Phase 105 will later restructure these dirs — the placeholder
marker makes its job easy (merge, don't overwrite).

#### Sub-task 1.3: Extend the STYLE_GUIDE with REQ-tag convention
**Size:** S (30 min)
**Depends on:** 1.1 (path fix)
**Parallel with:** 1.2
**Files to touch:** `docs/developer/STYLE_GUIDE.md`
**What to do:**
- Add a new section "Acceptance-Criteria Tags" that defines:
  - Optional `REQ-NNN-MM:` prefix (NNN = phase number, MM = sequential 2-digit ID)
  - Optional `Verified by: path/to/test.py::test_name` clause
  - If a phase uses `REQ-*` tags, **every** acceptance criterion in that phase must carry a `REQ-NNN-MM:` prefix (enforced by CI)
  - If a phase doesn't use tags, CI skips it — enforcement is opt-in per phase via `req_tagged: true` in the phase's frontmatter in `manifest.yaml`
- Include one worked example.
**Done when:**
- [ ] New section exists in `docs/developer/STYLE_GUIDE.md` with worked example
- [ ] Section states opt-in-per-phase rule clearly
**Watch out for:** Don't make tagging mandatory for existing phases; the enforcement is opt-in.

#### Sub-task 1.4: Add `req_tagged` field to manifest schema
**Size:** XS (15 min)
**Depends on:** 1.3
**Parallel with:** 1.2
**Files to touch:** `docs/phases/manifest.yaml` (schema doc at top if present, else just document in 1.3)
**What to do:**
- Ensure `req_tagged: true` is a recognised optional frontmatter field on phase entries in `manifest.yaml`.
- No phase entries actually set it yet — that happens in Phase 3.
**Done when:**
- [ ] The field's semantics documented in `docs/developer/STYLE_GUIDE.md` (same edit as 1.3)
**Watch out for:** If there's a schema file for manifest.yaml (JSON-schema?), update it. Otherwise this is documentation-only.

---

### Phase 2 — Core docs (Wave 1, five agents can run in parallel)

#### Sub-task 2.1: Write `docs/reference/SERVICE_TARGETS.md` (106a)
**Size:** S (2-3h)
**Depends on:** 1.2
**Parallel with:** 2.2, 2.3, 2.7, 2.8
**Files to touch:** `docs/reference/SERVICE_TARGETS.md` (new)
**What to do:**
- Read all four SLO runbooks: `slo_availability.md`, `slo_fp_rate.md`, `slo_latency.md`, `slo_redis_correctness.md` (←**remember the 4th**)
- For each SLI: name, what it measures, target (SLO), measurement window, source runbook link, alert name
- SLA posture: "zero-commitment open source; commercial support not currently offered" (copy language from `SECURITY.md` if it exists)
- Error-budget policy: cite existing alert rules (e.g. `JA4ProxyAvailabilityFastBurn`)
- Reporting cadence: quarterly retrospective doc (link to 106e output)
- Add links from `README.md` and `README.md` (the placeholder files from 1.2)
**Done when:**
- [ ] `docs/reference/SERVICE_TARGETS.md` exists with ≥ 4 SLIs (availability, FP rate, latency, Redis correctness)
- [ ] Each SLI cites its source runbook by file path
- [ ] Two audience READMEs link back to SERVICE_TARGETS
- [ ] Doc is ≤ 150 lines
**Watch out for:** Don't invent SLOs. Only cite what's already in the runbooks. If an SLO is missing a number, write "TARGET TBD — see <runbook>" rather than guessing.

#### Sub-task 2.2: Write `docs/security/RISK_REGISTER.md` (106b)
**Size:** M (3-4h)
**Depends on:** 1.2
**Parallel with:** 2.1, 2.3, 2.7, 2.8
**Files to touch:** `docs/security/RISK_REGISTER.md` (new)
**What to do:**
- Read:
  - `docs/security/findings.yaml` (1802 lines — canonical findings)
  - `docs/security/threat-model.md`
  - `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`
  - `docs/security/DMZ_READINESS.md`
  - `docs/security/EXCEPTIONS.md`, `CVE_EXCEPTIONS.md`
- **Dedup rule (document at top of file):** two risks are the same if they share (attack surface, failure mode, primary mitigation).
- Produce a table: `| ID | Risk | Category | Likelihood | Impact | Owner | Mitigation | Residual | Status |`
- Categories: `technical | operational | security | compliance | supply-chain | commercial`
- Each row must link to the authoritative source doc
- **Do not** include findings still under disclosure embargo (check `disclosure_status` field in findings.yaml if present)
- **Minimum 30 rows** after dedup (acceptance criterion)
- Add link from `README.md` and `README.md`
**Done when:**
- [ ] Table has ≥ 30 distinct rows, each with a non-empty Mitigation column
- [ ] Every row links to an authoritative source
- [ ] Dedup rule documented at top of file
- [ ] No pre-disclosure vulnerabilities included
**Watch out for:** Don't do new risk analysis. This is a curated index of existing risks — every entry must be traceable to an existing doc.

#### Sub-task 2.3: Write `TCO_AND_LICENSING.md` (106c)
**Size:** M (3h)
**Depends on:** 1.2
**Parallel with:** 2.1, 2.2, 2.7, 2.8
**Files to touch:** `TCO_AND_LICENSING.md` (new)
**What to do:**
- License section: cite `LICENSE` (MIT) — what it permits, what it does not
- Commercial-support section: explicit statement ("community support only via GitHub Issues" unless something has changed — **ask** if unsure)
- Three worked TCO examples: small / enterprise / high-volume — each covering (a) infra cost estimate, (b) ops FTE estimate, (c) observability stack cost, (d) total monthly cost band
- Hidden-costs section: GeoIP feed licensing, AbuseIPDB quota, Spamhaus, 3rd-party threat-intel
- SSL-inspection comparison framing
- **Every number must carry footnote:** "Estimates based on public pricing as of YYYY-MM-DD. Your costs will vary."
- Add link from `README.md`
**Done when:**
- [ ] Three TCO scenarios present
- [ ] Every dollar figure carries the estimate footnote
- [ ] Explicit commercial-support statement
- [ ] Link from the audience README
**Watch out for:** Ask the user before claiming a specific support tier exists. Default to "community only" if uncertain.

#### Sub-task 2.4: Write `scripts/traceability.py` + unit tests (106d.2 tooling)
**Size:** M (3h)
**Depends on:** 1.3 (REQ-tag schema defined)
**Parallel with:** 2.5 (process_metrics)
**Files to touch:**
- `scripts/traceability.py` (new)
- `tests/unit/test_traceability.py` (new)
- `tests/fixtures/traceability/` (new — fixture phase docs)
**What to do:**
- Walk `docs/phases/PHASE_*.md`, extract `REQ-NNN-MM:` tags and `Verified by:` clauses
- Opt-in per phase: read `manifest.yaml`, skip phases without `req_tagged: true`
- Emit `docs/reference/TRACEABILITY.md` as a sortable table: REQ-ID | description | verifying test | status
- Exit 1 if a phase marked `req_tagged: true` has a REQ-tag without a `Verified by:` clause — otherwise exit 0
- Unit tests: fixture phase doc with tagged / untagged criteria, assert correct extraction, assert CI-failure exit on missing clause
- Module docstring must state: "Reads local files + manifest.yaml only. No network."
**Done when:**
- [ ] `python3 scripts/traceability.py` runs clean on the current repo (exits 0)
- [ ] `tests/unit/test_traceability.py` has ≥ 5 tests covering extraction, error paths
- [ ] Generated `docs/reference/TRACEABILITY.md` exists
**Watch out for:** Don't add `pip install` requirements. Use stdlib + PyYAML (already in `requirements.txt`).

#### Sub-task 2.5: Write `scripts/process_metrics.py` + unit tests (106e tooling)
**Size:** M (3h)
**Depends on:** 1.4 (manifest schema)
**Parallel with:** 2.4
**Files to touch:**
- `scripts/process_metrics.py` (new)
- `tests/unit/test_process_metrics.py` (new)
- `tests/fixtures/process_metrics/` (new)
**What to do:**
- Emit a **markdown file** to `docs/engineering-method/retrospectives/latest-metrics.md` containing four metrics:
  - Phase throughput (phases completed / quarter) — derive from `manifest.yaml`
  - Average phase duration — from `manifest.yaml` `completed` timestamps
  - CI reliability (% green builds on main) — from GHA API
  - Mean-time-to-green after main breaks — from GHA API
- GitHub API: use `GITHUB_TOKEN` env var; degrade gracefully on rate limit (emit a warning line in the markdown, don't crash)
- Module docstring: document token scope required (`actions:read`, `contents:read`)
- Unit tests: fixture manifest + mocked GHA response, assert correct metric values; one test for rate-limit degradation
**Done when:**
- [ ] `python3 scripts/process_metrics.py --output <path>` emits valid markdown
- [ ] Rate-limit path tested and produces valid (if warning-annotated) output
- [ ] ≥ 4 unit tests
**Watch out for:** Don't write to `/metrics` (Prometheus). Markdown output only.

#### Sub-task 2.6: Write first retrospective `docs/engineering-method/retrospectives/2026-Q2.md` (106e)
**Size:** S (2h)
**Depends on:** 2.5 (metrics script exists)
**Parallel with:** 2.7, 2.8
**Files to touch:**
- `docs/engineering-method/retrospectives/README.md` (new — index)
- `docs/engineering-method/retrospectives/2026-Q2.md` (new — first retro)
- `docs/engineering-method/retrospectives/TEMPLATE.md` (new — future retros)
**What to do:**
- Read `docs/phases/PHASE_NN_notes.md` files for Phases 100-104 (if they exist) plus close notes in recent phase docs
- Template: "what went well / what didn't / method changes proposed / outcomes from previous quarter"
- First retro: draft content based on real observations from the notes files
- Auto-include latest metrics by linking to `latest-metrics.md` (generated by 2.5)
**Done when:**
- [ ] Template file exists
- [ ] First retro has ≥ 3 entries under each of "went well" / "didn't"
- [ ] Retro links the metrics markdown
**Watch out for:** Honest — include real friction points, not just wins.

#### Sub-task 2.7: Write `docs/design/README.md` (106f)
**Size:** M (3h)
**Depends on:** 1.2
**Parallel with:** 2.1, 2.2, 2.3, 2.8
**Files to touch:** `docs/design/README.md` (new)
**What to do:**
- NON-GOAL at top: "This is a component index. Deep design docs are out of scope. ADRs live in `docs/decisions/`."
- Table: `| Component | Source file(s) | Design origin (phase) | Current owner | Test coverage |`
- Minimum 20 components (phase criterion): TLS parser, risk scorer, action decider, each signal module (~14), Redis cache, config loader, rate limiters (3 strategies), beaconing, RDAP/AbuseIPDB/Spamhaus/GeoIP enrichers, TAP consumer, Go proxy hot path, Management API/UI
- `Design origin` = one phase-doc link
- `Test coverage` = path to the primary test file
- Do not write new design prose
**Done when:**
- [ ] Table has ≥ 20 rows
- [ ] Every row's `Source` path resolves to an existing file
- [ ] Every row's `Design origin` links to an existing phase doc
- [ ] Every row's `Test coverage` links to an existing test file
**Watch out for:** Scope creep. If a row needs more than one-line description, it's too much — keep it an index.

#### Sub-task 2.8: Write `docs/developer/QUALITY_PLAN.md` (106h)
**Size:** S (2h)
**Depends on:** 2.1 (SERVICE_TARGETS) — should cite it
**Parallel with:** 2.2, 2.3, 2.7
**Files to touch:** `docs/developer/QUALITY_PLAN.md` (new)
**What to do:**
- Quality attributes (6 rows): performance, availability, security, maintainability, portability, usability — each with target + verification source
- Defect management: reporting / triage / fix / verify. Cite `SECURITY.md` for security-bug SLA
- Quality gates: pre-merge, pre-release, pre-phase-close — each with a link
- Review roles: who reviews what; multi-agent review points
- SWEBOK v4 KA coverage table (from the phase doc's §"SWEBOK v4 KA Coverage After Phase 106")
- ≤ 5 pages (~400 lines max)
- Add link from `README.md` and `README.md`
**Done when:**
- [ ] Doc is ≤ 400 lines
- [ ] All sections present (attributes, defects, gates, roles, SWEBOK table)
- [ ] ≥ 10 outgoing links to existing docs
**Watch out for:** Don't duplicate content. This is a navigation doc — links, not prose.

---

### Phase 3 — Retro-tagging (after schema exists)

Each of these is independent and parallelizable. Each is XS (~30 min per phase doc).

#### Sub-task 3.1-3.7: Retro-tag acceptance criteria for 7 phases
**Size:** XS each (30 min × 7 = ~3.5h total)
**Depends on:** 1.3 (REQ-tag convention in STYLE_GUIDE)
**Parallel with:** each other (seven agents can do this in parallel)
**Files to touch:** one of `docs/phases/PHASE_{15,79,82,102,103,104,200}.md` per sub-task
**What to do (per phase doc):**
- Add `req_tagged: true` to the phase's entry in `docs/phases/manifest.yaml`
- For each acceptance-criterion line, prefix with `REQ-{NNN}-{MM}:` (NNN = phase number, MM = sequential)
- For each criterion that maps to an automated test, add ` Verified by: tests/…/test_file.py::test_name`
- For each criterion that cannot be automated, add ` [MANUAL-REVIEW]`
**Done when:**
- [ ] Every acceptance-criterion line has a `REQ-NNN-MM:` prefix
- [ ] Each has either `Verified by: …` or `[MANUAL-REVIEW]`
- [ ] `req_tagged: true` set in manifest.yaml for this phase
- [ ] `python3 scripts/traceability.py` passes (exit 0) after this phase's tagging
**Watch out for:** Do not rewrite acceptance criteria content — just prefix them. If a criterion has no test, mark `[MANUAL-REVIEW]` not invented test names.

---

### Phase 4 — Engineering-method narrative (106g)

#### Sub-task 4.1: `docs/engineering-method/METHOD.md`
**Size:** S (2h)
**Depends on:** 2.6 (retrospective exists to cite), 1.2
**Parallel with:** 4.2 (same-wave docs, different content)
**Files to touch:** `docs/engineering-method/METHOD.md` (new)
**What to do:**
- Formal statement of the method: phase-based incremental delivery, mandatory planning protocol, TDD, multi-agent coordination, keep-main-green
- Why chosen; what it is NOT (not Scrum, not SAFe, not XP)
- No marketing language. No "best practices". No "world-class".
- Cite `CLAUDE.md` for the method rules
**Done when:**
- [ ] Doc is ≤ 250 lines
- [ ] "What it is not" section present
- [ ] Cites `CLAUDE.md` by path
**Watch out for:** Tone check — if it reads as marketing, rewrite.

#### Sub-task 4.2: `docs/engineering-method/CASE_STUDIES.md`
**Size:** L (4h)
**Depends on:** none
**Parallel with:** 4.1
**Files to touch:** `docs/engineering-method/CASE_STUDIES.md` (new)
**What to do:**
- Three case studies — pre-selected phases (confirm with user if uncertain):
  1. Phase 15 — Go rewrite (architecture evolution): what was deferred, what was implemented, what got cut
  2. Phase 82 — policy-as-code (feature design): design-to-impl trajectory
  3. Phase 200-series — security hardening (incident-to-improvement): how pentest findings fed back into the plan
- Each case study: what was planned / what was delivered / **what went wrong or had to be revised** / lessons
- Include at least **one revised-scope example per case study**. If a phase was pure success, pick a different one.
**Done when:**
- [ ] Three case studies
- [ ] Each has a "what went wrong / had to revise" section
- [ ] No case study is a pure-win narrative
**Watch out for:** The load-bearing risk here is honesty. If you can't find friction in a case study, pick a different phase — don't paper over it.

#### Sub-task 4.3: `docs/engineering-method/PHASE_ANATOMY.md`
**Size:** M (3h)
**Depends on:** 2.6 (retro exists), 4.1
**Parallel with:** 4.2
**Files to touch:** `docs/engineering-method/PHASE_ANATOMY.md` (new)
**What to do:**
- Annotated walk-through of Phase 104 or 105 from plan → review → implementation → close
- Show each artefact: the phase doc, the review (`PHASE_XX_review.md`), the branch, commits, PR, tests, CHANGELOG, manifest update
- **Use real file paths and real commit SHAs** from the repo, not made-up examples
**Done when:**
- [ ] Every cited artefact link resolves to a real file / commit in this repo
- [ ] Each stage (plan/review/impl/close) is covered
**Watch out for:** Time sink if the chosen phase has incomplete artefacts. Check first.

#### Sub-task 4.4: `docs/engineering-method/README.md` (entry point)
**Size:** XS (30 min)
**Depends on:** 4.1, 4.2, 4.3
**Parallel with:** none
**Files to touch:** `docs/engineering-method/README.md` (new)
**What to do:**
- Entry point: why this section exists, who should read it, links to METHOD / CASE_STUDIES / PHASE_ANATOMY / retrospectives
- ≤ 60 lines
- Link from root `README.md` — single prominent line: "**How we build →** [engineering-method](../../engineering-method/README.md)"
**Done when:**
- [ ] README exists with all four cross-links
- [ ] Root `README.md` has the "How we build →" line
**Watch out for:** Don't duplicate content from METHOD.md — this README is a nav shim.

---

### Phase 5 — CI integration + sync tests

#### Sub-task 5.1: Wire `traceability.py` into CI (non-blocking first)
**Size:** S (1h)
**Depends on:** 2.4
**Parallel with:** 5.2, 5.3, 5.4
**Files to touch:** `.github/workflows/ci.yml`
**What to do:**
- Add a new job `doc-traceability` that runs `python3 scripts/traceability.py`
- **Initially `continue-on-error: true`.** Use a dated conditional to flip it after a stability window:
  ```yaml
  continue-on-error: ${{ github.event.head_commit.timestamp < '2026-05-08T00:00:00Z' }}
  ```
- Also run `make sync`-style drift check: if `docs/reference/TRACEABILITY.md` differs from regenerated output, fail.
- Third-party actions (checkout, setup-python) must be SHA-pinned per existing CI style (see ci.yml line 38). Local scripts do NOT need SHA-pinning — that's for Actions from external repos.
**Done when:**
- [ ] CI job runs green on the current repo
- [ ] Dated conditional for blocking-enforcement in place
- [ ] Drift-check fails if TRACEABILITY.md is stale
**Watch out for:** The "SHA-pinned" acceptance criterion (line 410 of phase doc) is miscategorised — it applies to Actions, not local scripts. Don't invent a pinning mechanism for local files.

#### Sub-task 5.2: Wire `process_metrics.py` into CI (scheduled monthly)
**Size:** S (1h)
**Depends on:** 2.5
**Parallel with:** 5.1, 5.3, 5.4
**Files to touch:** `.github/workflows/ci.yml` (or new `.github/workflows/process-metrics.yml`)
**What to do:**
- Scheduled cron job (monthly, first of month 08:00 UTC)
- Runs `python3 scripts/process_metrics.py --output docs/engineering-method/retrospectives/latest-metrics.md`
- Opens a PR with the updated metrics (use `peter-evans/create-pull-request` SHA-pinned)
- Does NOT block main CI
**Done when:**
- [ ] Scheduled workflow file exists
- [ ] Workflow runs green on workflow_dispatch
**Watch out for:** The create-PR action needs `pull-requests: write` permission — add to the job permissions block, not globally.

#### Sub-task 5.3: Add SERVICE_TARGETS ↔ SLO-runbook sync test
**Size:** S (1h)
**Depends on:** 2.1
**Parallel with:** 5.1, 5.2, 5.4
**Files to touch:** `tests/docs/test_service_targets_sync.py` (new)
**What to do:**
- Parse `docs/reference/SERVICE_TARGETS.md` — extract SLI name → target
- Parse each runbook — extract its target
- Assert every runbook SLO appears in SERVICE_TARGETS with the same target
- Assert every SERVICE_TARGETS row links to an existing runbook
**Done when:**
- [ ] Test file exists; passes on current repo state
- [ ] Test fails if someone adds a new SLO runbook without updating SERVICE_TARGETS
**Watch out for:** Target-string parsing is brittle. Use a loose match (e.g. both mention `99.9%` somewhere) rather than exact string equality.

#### Sub-task 5.4: Add RISK_REGISTER structure test
**Size:** S (1h)
**Depends on:** 2.2
**Parallel with:** 5.1, 5.2, 5.3
**Files to touch:** `tests/docs/test_risk_register.py` (new)
**What to do:**
- Assert table header matches the phase-doc-specified columns
- Assert ≥ 30 rows
- Assert every row has a non-empty Mitigation column
- Assert every row has a link; assert every link's target file exists
**Done when:**
- [ ] Test file passes
- [ ] Test fails on a malformed row
**Watch out for:** Don't parse markdown tables with regex alone — use a small helper or handle edge cases (pipes in text). The `markdown-it-py` lib is overkill; a careful regex with `\s*\|\s*` split is fine.

---

### Phase 6 — Close-out

#### Sub-task 6.1: Add CHANGELOG entry
**Size:** XS (15 min)
**Depends on:** all Phase 5 tasks
**Parallel with:** 6.2
**Files to touch:** `CHANGELOG.md`
**What to do:**
- Prepend `## [Unreleased] - Phase 106 — SWEBOK v4 Alignment (YYYY-MM-DD)` entry
- Summarise deliverables in 3-5 bullets
- Reference the 9 acceptance-criteria deliverables (SERVICE_TARGETS, RISK_REGISTER, TCO, TRACEABILITY, traceability.py, process_metrics.py, design index, engineering-method/, QUALITY_PLAN)
**Done when:**
- [ ] Entry present at top of CHANGELOG.md following existing format
**Watch out for:** Use the exact format from existing entries. Don't invent a new section structure.

#### Sub-task 6.2: Flip manifest + make sync
**Size:** XS (10 min)
**Depends on:** all others
**Parallel with:** 6.1
**Files to touch:** `docs/phases/manifest.yaml`
**What to do:**
- Set `status: COMPLETE`, `completed: YYYY-MM-DD` for Phase 106
- Run `make sync`
- Commit the generated `docs/phases/TODO.md` and `docs/reference/PROJECT_STATUS.md` drift alongside the manifest change
**Done when:**
- [ ] Manifest shows COMPLETE
- [ ] `make sync` output committed
**Watch out for:** Run `make sync` **after** the manifest edit, not before.

---

## 5. Summary

- **Total sub-tasks:** 28 (1.1-1.4, 2.1-2.8, 3.1-3.7, 4.1-4.4, 5.1-5.4, 6.1-6.2)
- **Estimated effort:**
  - Phase 1 (scaffolding): ~1.5h
  - Phase 2 (core docs, parallel): ~24h single-threaded, ~5h with five parallel agents
  - Phase 3 (retro-tagging, parallel): ~3.5h single-threaded, ~30min with seven parallel agents
  - Phase 4 (method narrative, partially parallel): ~9.5h single-threaded, ~4.5h with three parallel agents
  - Phase 5 (CI integration, parallel): ~4h single-threaded, ~1h with four parallel agents
  - Phase 6 (close-out): ~30min
  - **Single-threaded total: ~43h (~5.5 engineer-days)**
  - **Maximum-parallelism total: ~12h (~1.5 engineer-days)**
- **Critical blockers to resolve before implementation:**
  1. Decide on Phase 105 coordination (either wait for its Wave 1, or accept 1.2's placeholder-dir approach)
  2. Fix STYLE_GUIDE path typo (1.1 — trivial)
  3. Confirm case-study pre-selection for 4.2
  4. Confirm no commercial-support tier exists (2.3 assumes "community only")
- **No Go code is modified.** No runtime risk. No proxy-hot-path risk.
- **Test-to-code ratio:** the two new scripts (~200 LOC) get ≥ 300 LOC of tests (unit + integration). Meets the 1.3× target.

**Recommended execution order:** 1.1–1.4 serially, then Wave 2 (2.1-2.8) with
five parallel agents, then Wave 3 (retro-tagging 3.1-3.7) with seven parallel
agents, then Wave 4 (method narrative 4.1-4.4) with three agents, then Wave
5 (CI 5.1-5.4) with four agents, then close-out. Realistic wall-clock: 2-3
working days with heavy parallelism; 5-6 working days single-threaded.
