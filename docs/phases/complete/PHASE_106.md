# Phase 106 — SWEBOK v4 Alignment

> **Status:** PROPOSED
> **Size:** LARGE (8 sub-phases, ~6–8 engineer-days)
> **Dependencies:** Phase 105 (audience docs restructure) should be underway
> or complete so Phase 106 deliverables can be slotted into the right entry
> points (`docs/for-*/`) without rework.
> **Triggered by:** SWEBOK v4 gap analysis 2026-04-16
> **Review:** `docs/phases/complete/PHASE_106_review.md` (to be written on close)

---

## Goal

Close the documentation gaps identified by benchmarking JA4proxy against the
IEEE / ISO / IEC Software Engineering Body of Knowledge v4 (2024). Phase 105
restructured documentation by audience; Phase 106 adds the management,
process, economics, and quality artefacts that mature engineering
organisations carry and that enterprise auditors, procurement teams, and
security questionnaires expect.

Not every SWEBOK KA needs new documentation. This phase targets the six KAs
where JA4proxy is currently weak and where the absence is externally
visible — to an auditor, a buyer, an RFP, or a regulator.

---

## SWEBOK v4 KA Coverage After Phase 106

| KA | Current | Phase 106 delivers | Post-106 |
|----|---------|--------------------|----------|
| 1. Software Requirements | 🟡 | Traceability matrix (106d) | ✅ |
| 2. Software Architecture | ✅ | — | ✅ |
| 3. Software Design | 🟡 | Component-level design index (106f) | ✅ |
| 4. Software Construction | ✅ | — | ✅ |
| 5. Software Testing | ✅ | Traceability matrix ties requirements→tests (106d) | ✅ |
| 6. Software Engineering Operations | 🟡 | Consolidated SLA/SLO doc (106a) | ✅ |
| 7. Software Configuration Management | 🔴 | Deferred to Phase 105 (versioning/release policy) | 🟡 |
| 8. Software Engineering Management | 🟡 | Risk register (106b) | ✅ |
| 9. Software Engineering Process | ✅ | Retrospective mechanism + process metrics (106e) | ✅ |
| 10. Software Engineering Models and Methods | 🔴 | Formal method statement (106g) | ✅ |
| 11. Software Quality | 🟡 | Quality plan consolidation (106h) | ✅ |
| 12. Software Security | ✅ | — | ✅ |
| 13. Software Engineering Professional Practice | 🔴 | Deferred to Phase 105 (CoC, CLA, AI disclosure) | 🟡 |
| 14. Software Engineering Economics | 🔴 | TCO & commercial model doc (106c) | ✅ |

Target: **12 of 14 applicable KAs green** after Phase 106 (KAs 7 and 13 close
out in Phase 105). KAs 15–17 (Computing / Mathematical / Engineering
Foundations) are prerequisite knowledge, not project documentation.

---

## 106a. Consolidated service targets (SLA / SLO / SLI)

### Problem

JA4proxy has SLO content scattered across `docs/OBSERVABILITY_STANDARDS.md`,
`docs/runbooks/slo_*.md` (availability, FP rate, latency), `docs/SCALING_GUIDE.md`,
and `docs/enterprise/security-architecture.md`. There is no single page that
an architect, buyer, or operator can read to answer "what does JA4proxy
commit to?". SWEBOK KA 6 (Operations) expects a consolidated service-targets
artefact. Enterprise procurement expects it too.

### Fix

Create `docs/SERVICE_TARGETS.md` that collects:

- **SLIs** (what we measure): connection-accept latency p50/p99, FP rate on
  browser traffic, proxy availability, Redis availability, risk-score compute
  latency, signal-collection error rate
- **SLOs** (thresholds): per SLI, the target. Cite the existing SLO runbooks
  as canonical and summarise here
- **SLA posture**: what the open-source project commits to (zero-commitment,
  best-effort) vs. what a commercial support contract would add. If no
  commercial support exists, say so explicitly
- **Measurement window and reporting cadence**
- **Error-budget policy**: when an SLO is burned, what happens (pause
  feature work, page oncall, etc.)

Cross-link from `DEPLOYMENT_OPTIONS.md`,
`README.md`, `README.md`.

**Source material:** `docs/runbooks/slo_availability.md`,
`docs/runbooks/slo_fp_rate.md`, `docs/runbooks/slo_latency.md`,
`docs/OBSERVABILITY_STANDARDS.md` §SLIs.

### Size

**S** — content largely exists; reconciliation + framing.

---

## 106b. Risk register

### Problem

Risk discussion is scattered across `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md`,
`docs/security/threat-model.md`, `docs/DMZ_READINESS.md`, phase
review docs, and ADRs. SWEBOK KA 8 (Engineering Management) expects a
consolidated risk register. SOC 2 and ISO 27001 auditors expect one too.

### Fix

Create `docs/RISK_REGISTER.md` with entries structured as:

| ID | Risk | Category | Likelihood | Impact | Owner | Mitigation | Residual | Status |
|----|------|----------|------------|--------|-------|------------|----------|--------|

Categories: technical, operational, security, compliance, supply-chain,
commercial. One row per distinct risk; no overlap. Entries source from:

- **Threat model** (attack-surface risks)
- **Security audit** (vulnerability-driven risks)
- **DMZ readiness** (deployment-context risks)
- **Dependency audit results** (supply-chain risks)
- **Operational runbooks** (what-if failure-mode risks)

Each entry links to the authoritative source. The register is a **curated
index**, not a new risk analysis — do not introduce risks not already
documented.

**Review cadence:** quarterly. Ownership: maintainer + security lead.

### Size

**M** — enumeration + deduplication is genuinely time-consuming; expect
30–50 distinct risks after merging duplicates.

---

## 106c. Total cost of ownership & commercial model

### Problem

No document answers "what does it cost to run JA4proxy?" or "how do I buy
support?". SWEBOK KA 14 (Engineering Economics) expects this. Buyers ask.
RFPs require it. A zero-commercial-offering project still benefits from
stating that explicitly.

### Fix

Create `TCO_AND_LICENSING.md` (slot into the Phase
105 website-owner track) containing:

- **License:** MIT — what it permits, what it does not
- **Commercial support:** state current position explicitly. If none:
  "community support only via GitHub Issues; commercial support is not
  currently offered". If a support tier exists: tiers, response times,
  channels
- **TCO model:** one worked example for each DEPLOYMENT_OPTIONS scenario
  (small / enterprise / high-volume) covering infrastructure cost estimate,
  operational FTE estimate, observability stack cost estimate, and a
  total-monthly-cost band
- **Hidden costs:** GeoIP feed licensing (IP2Location LITE vs. paid),
  AbuseIPDB API quota, Spamhaus commercial tier options, third-party
  threat-intel feeds
- **Comparison framing:** TCO versus the SSL-inspection alternative
  (infrastructure + key management + compliance exposure). Cite public
  pricing where available

**Constraint:** numbers are estimates, clearly marked. Do not claim
accuracy the data does not support.

### Size

**M** — TCO tables require research and honest estimation.

---

## 106d. Requirements-to-test traceability matrix

### Problem

JA4proxy's phase acceptance criteria function as requirements and are
directly testable — but there is no matrix linking requirements to the
specific tests that verify them. SWEBOK KAs 1 + 5 expect traceability.
Auditors ask for it. The absence is invisible day-to-day but blocks
enterprise-audit evidence packs.

### Fix

Two parts:

**106d.1 — Schema and one-time extraction**

Add a lightweight schema to phase-doc acceptance criteria so traceability
can be generated:

```markdown
## Acceptance Criteria

- [ ] REQ-105-01: `README.md` is ≤ 150 lines. Verified by:
      `tests/docs/test_readme_structure.py::test_readme_line_cap`
```

Where a requirement cannot be verified by an automated test (e.g. prose
quality), mark it `MANUAL-REVIEW` and capture the reviewer sign-off.

**106d.2 — Tooling and generated artefact**

Write a small generator (`scripts/traceability.py`) that walks
`docs/phases/PHASE_*.md`, extracts acceptance-criteria lines bearing the
`REQ-NNN-MM:` tag, parses the `Verified by:` clauses, and produces
`docs/TRACEABILITY.md` as a table: requirement ID → description → verifying
test(s) → status (PASS / FAIL / NOT-RUN / MANUAL).

CI runs the generator and fails the build if any `REQ-*` tag has no
`Verified by:` clause.

Apply the tagging retroactively only to the **three most recent complete
phases** (currently 102, 103, 104) plus Phases 15, 79, 82, 200 (the ones
called out as case studies in the engineering-method narrative, §106g).
Tagging all 200+ historical phases is not a good use of time.

### Size

**L** — schema + tool + retroactive tagging of seven phases + CI wiring.
Split into 106d.1 (schema) and 106d.2 (tooling) at execution time if needed.

---

## 106e. Retrospective mechanism and process metrics

### Problem

Individual `PHASE_NN_notes.md` files capture per-phase lessons learned, but
there is no rollup and no process-metric collection. SWEBOK KA 9 (Engineering
Process) expects a process-improvement loop: measure, reflect, adjust. The
engineering-method narrative (§106g) has nothing to point at if no
retrospective cadence exists.

### Fix

Establish `docs/engineering-method/retrospectives/`:

- **Quarterly retrospective doc template** — what went well, what did not,
  method changes proposed, outcomes from previous quarter's changes
- **Process metrics dashboard**: phase throughput (phases completed per
  quarter), average phase duration, proportion of phases requiring revised
  scope, CI reliability (% green builds on main), mean-time-to-green after
  main breaks
- **First retrospective**: covering Phases 100–104 (the current quarter),
  capturing real observations from `PHASE_NN_notes.md` files
- **Metric-collection script** (`scripts/process_metrics.py`): parses
  manifest.yaml and GitHub Actions history to emit the numbers automatically.
  Idempotent, runs monthly

### Size

**M** — template + first retrospective + metric script.

---

## 106f. Component-level design index

### Problem

JA4proxy has per-phase design documentation (`docs/phases/PHASE_NN.md`) but
not per-component. A new engineer asking "where is the Redis connection pool
designed?" has no single doc to land on — they must trace which phase
introduced it. SWEBOK KA 3 (Software Design) expects per-component design
documentation.

### Fix

Create `docs/design/README.md` as a **component index** (not a content
duplication). For each major component, one row:

| Component | Source | Design origin | Current owner | Test coverage |
|-----------|--------|---------------|---------------|---------------|

Components to enumerate (approximate list; final list derived from repo):

- TLS fingerprint parser (JA4 / JA4X / JA4T)
- Risk scorer + action decider
- Signal modules (one row each — 14+ signals)
- Redis connection pool + cache layer
- Hot-reload config loader
- Rate limiters (three strategies)
- Beaconing detector
- RDAP / AbuseIPDB / Spamhaus / GeoIP enrichers
- TAP mode consumer
- Go proxy hot path
- Management API + UI

For each, `Design origin` points at the originating phase doc (one link) and
the current canonical source file. If the component has grown beyond its
origin phase (most have), add a "see also" line with the phases that
extended it.

**Do not write new design prose.** This phase creates an index; deep design
docs, if needed, are a future phase.

### Size

**M** — enumeration + cross-referencing; ~20–25 component rows.

---

## 106g. Engineering-method narrative

### Problem

The phase-based build method is JA4proxy's biggest differentiator for
architects and technical buyers — and it is invisible. Raw phase docs are
developer-facing artefacts; they do not tell the story. The earlier
recommendation (in the Phase 105 follow-up discussion) was to create a
curated narrative. SWEBOK KA 10 (Engineering Models and Methods) expects a
formal method statement.

### Fix

Create `docs/engineering-method/`:

| File | Content |
|------|---------|
| `docs/engineering-method/README.md` | Entry point. Why this section exists. Who should read it |
| `docs/engineering-method/METHOD.md` | Formal statement of the method: phase-based incremental delivery, mandatory planning protocol, TDD, multi-agent coordination, keep-main-green. Why we chose it. What it is not (not Scrum, not SAFe, not XP) |
| `docs/engineering-method/CASE_STUDIES.md` | Three worked examples: Phase 15 Go rewrite (architecture evolution), Phase 82 policy-as-code (feature design), Phase 200-series security hardening (incident-to-improvement) |
| `docs/engineering-method/PHASE_ANATOMY.md` | Annotated walk-through of a representative phase from plan → review → implementation → close. Uses Phase 104 or 105 as the example |
| `docs/engineering-method/retrospectives/` | Populated by 106e |

Link from root `README.md` as a single prominent line (per earlier advice)
and from `README.md`.

**Constraint:** narrative, not marketing. No "best practices". No
"world-class". Show the work.

### Size

**L** — four substantive docs; CASE_STUDIES and PHASE_ANATOMY each require
careful reading of source phase docs.

---

## 106h. Consolidated quality plan

### Problem

Quality information is scattered across `docs/TESTING_STRATEGY.md`,
`docs/DOCUMENTATION_STANDARDS.md`, coverage gates in `Makefile`, per-phase
acceptance criteria, and `QUALITY_PLAN.md`
(new in Phase 105). SWEBOK KA 11 (Software Quality) expects a single
quality-plan artefact.

### Fix

Create `docs/QUALITY_PLAN.md` as a short (~5 page) index covering:

- **Quality attributes and their targets**: performance, availability,
  security, maintainability, portability, usability. Each attribute lists
  its measurable target and where it is verified
- **Defect management process**: how bugs are reported, triaged, fixed,
  verified. Where the bug tracker lives. SLA for security bugs
  (cross-reference `SECURITY.md`)
- **Quality gates**: what must be green before merge (link
  `QUALITY_PLAN.md`), what must be green before release (link
  `release-cli.yml`), what must be green before a phase closes (link
  `TESTING_STRATEGY.md §phase gate`)
- **Quality-assurance roles**: who reviews what. Human review points in the
  multi-agent workflow

This doc should be mostly links. Its value is that one page exists.

### Size

**S** — mostly curation and linking.

---

## Acceptance Criteria

**Core deliverables**

- [ ] `docs/SERVICE_TARGETS.md` exists, lists every SLI and SLO cited in
      existing runbooks, and is linked from the three `docs/for-*/README.md`
      entry points that need it
- [ ] `docs/RISK_REGISTER.md` exists with ≥ 30 rows, each with a non-empty
      Mitigation column and a link to the authoritative source
- [ ] `TCO_AND_LICENSING.md` exists with three
      TCO scenarios and an explicit commercial-support statement
- [ ] `docs/TRACEABILITY.md` exists and is auto-generated from phase docs
- [ ] `scripts/traceability.py` runs clean and is called from CI (non-blocking
      for 14 days, then blocking)
- [ ] Phases 15, 79, 82, 102, 103, 104, 200 have acceptance criteria
      re-tagged with `REQ-NNN-MM:` identifiers and `Verified by:` clauses
- [ ] `docs/engineering-method/` exists with README, METHOD, CASE_STUDIES,
      PHASE_ANATOMY, and retrospectives subdirectory
- [ ] First retrospective for Phases 100–104 exists under
      `docs/engineering-method/retrospectives/`
- [ ] `scripts/process_metrics.py` exists and emits the four core metrics
      (phase throughput, duration, CI reliability, mean-time-to-green)
- [ ] `docs/design/README.md` exists with ≥ 20 component rows
- [ ] `docs/QUALITY_PLAN.md` exists (≤ 5 pages) and links all referenced docs

**Integration**

- [ ] Root `README.md` links `docs/engineering-method/README.md` with a
      single prominent line
- [ ] `README.md` links `docs/SERVICE_TARGETS.md`,
      `docs/RISK_REGISTER.md`, `docs/engineering-method/README.md`,
      `docs/QUALITY_PLAN.md`
- [ ] `README.md` links `docs/RISK_REGISTER.md`,
      `docs/TRACEABILITY.md`, `docs/QUALITY_PLAN.md`
- [ ] `README.md` links `TCO_AND_LICENSING.md`
- [ ] No new doc exceeds its stated line-count target

**Process**

- [ ] `scripts/traceability.py` CI job is SHA-pinned per existing discipline
- [ ] `scripts/process_metrics.py` CI job is SHA-pinned per existing discipline
- [ ] `docs/phases/manifest.yaml` has Phase 106 entry marked COMPLETE
- [ ] `CHANGELOG.md` has Phase 106 entry
- [ ] SWEBOK v4 KA coverage table in `docs/QUALITY_PLAN.md` matches the
      post-106 target state (12 / 14 green)

---

## Files to Modify

| File | Change |
|------|--------|
| `docs/SERVICE_TARGETS.md` | New |
| `docs/RISK_REGISTER.md` | New |
| `docs/TRACEABILITY.md` | New — auto-generated |
| `docs/QUALITY_PLAN.md` | New |
| `docs/design/README.md` | New |
| `docs/engineering-method/README.md` | New |
| `docs/engineering-method/METHOD.md` | New |
| `docs/engineering-method/CASE_STUDIES.md` | New |
| `docs/engineering-method/PHASE_ANATOMY.md` | New |
| `docs/engineering-method/retrospectives/2026-Q2.md` | New — first retrospective |
| `TCO_AND_LICENSING.md` | New |
| `README.md` | Add links to SERVICE_TARGETS, RISK_REGISTER, engineering-method, QUALITY_PLAN |
| `README.md` | Add links to RISK_REGISTER, TRACEABILITY, QUALITY_PLAN |
| `README.md` | Add link to TCO_AND_LICENSING |
| `README.md` | Add link to SERVICE_TARGETS |
| `README.md` | Add "How we build →" link to engineering-method |
| `scripts/traceability.py` | New |
| `scripts/process_metrics.py` | New |
| `docs/phases/complete/PHASE_15.md` | Retro-tag acceptance criteria with REQ-IDs |
| `docs/phases/complete/PHASE_79.md` | Retro-tag |
| `docs/phases/complete/PHASE_82.md` | Retro-tag |
| `docs/phases/complete/PHASE_102.md` | Retro-tag |
| `docs/phases/complete/PHASE_103.md` | Retro-tag |
| `docs/phases/complete/PHASE_104.md` | Retro-tag |
| `docs/phases/complete/PHASE_200.md` | Retro-tag |
| `docs/STYLE_GUIDE.md` | Add REQ-tagging convention to the acceptance-criteria section |
| `.github/workflows/ci.yml` | Add traceability + process-metrics jobs (both `continue-on-error` for 14 days) |
| `docs/phases/manifest.yaml` | Add Phase 106 entry; mark COMPLETE on close |
| `CHANGELOG.md` | Phase 106 entry |

---

## Sizing Summary

| Sub-phase | Size | Notes |
|-----------|------|-------|
| 106a — SERVICE_TARGETS | S | Reconciliation of existing SLO runbooks |
| 106b — RISK_REGISTER | M | Enumeration + dedup of 30–50 risks |
| 106c — TCO & commercial | M | Research + three worked examples |
| 106d — Traceability matrix | L | Schema + tool + 7 phase retro-tags + CI |
| 106e — Retrospectives + metrics | M | Template + first retro + metric script |
| 106f — Component design index | M | ~20–25 component rows |
| 106g — Engineering-method narrative | L | Four docs, CASE_STUDIES + PHASE_ANATOMY are load-bearing |
| 106h — QUALITY_PLAN | S | Curation + linking |

**Total effort:** LARGE. Suggested parallelism:

- **Wave 1** (parallel): 106a, 106b, 106c, 106f, 106h — five agents
- **Wave 2** (parallel, may start after Wave 1): 106d, 106e, 106g — three
  agents. 106g depends on 106e having produced the first retrospective
- **Wave 3**: integration + close-out

One engineer full-time: ~8 working days. Five-agent fan-out in Wave 1 and
three in Wave 2: ~4 working days.

---

## Dependencies On / Sequencing With Phase 105

Phase 106 depends on Phase 105's `docs/for-*/` entry points existing so that
106 deliverables slot into the right audience tracks. Specifically:

- 106c (TCO) lands in `` — Phase 105.1.x must have
  created the directory
- 106a (SERVICE_TARGETS) is linked from `` and
  `` — Phase 105.3.1 and 105.2.1 must have created those
- 106g (engineering method) is linked from `` —
  Phase 105.2.1 must exist

**Preferred ordering:** finish Phase 105 Wave 1 (audience doc scaffolding),
then start Phase 106 Wave 1 in parallel with Phase 105 Waves 2–3. This
front-loads the most externally visible work (audience docs, service
targets, risk register) while leaving Phase 106's tooling sub-tasks (106d,
106e, 106f) to land after.

If Phases 105 and 106 must run strictly sequentially, budget ~3 weeks total
for both.

---

## Notes for Implementer

- **Do not reinvent risk-analysis work in 106b.** Risks sourced from the
  threat model / security audit / DMZ readiness doc are already analysed.
  The register is a curated index, not a new analysis.
- **Case studies in 106g must be honest.** Include phases that went wrong
  (e.g. phases that required revised scope) alongside the successes. An
  engineering-method narrative that only shows wins reads as marketing and
  damages credibility with the technical audience.
- **Retro-tagging (106d) is scope-capped at seven phases.** Do not expand.
  The value is establishing the pattern and satisfying audit-evidence
  sampling, not covering every phase historically.
- **TCO numbers (106c) are estimates.** Every table must carry a footnote:
  "Estimates based on public pricing as of YYYY-MM-DD. Your costs will
  vary." Anything claiming specific dollar amounts without this hedge is a
  defect.
- **Process metrics (106e) are informational, not targets.** Do not turn a
  metric into a KPI in this phase. Measuring first, target-setting later
  (a future phase, if warranted).
- **SWEBOK alignment is the framing, not the goal.** The goal is
  documentation that external audiences (auditors, buyers, architects) can
  use. SWEBOK tells us *what to cover*; the audience docs tell us *how to
  frame it*. If SWEBOK asks for something no audience benefits from,
  reconsider including it.
- **Out of scope for this phase:** formal requirements specification
  document (the phase-acceptance-criteria-as-requirements approach with
  traceability from 106d is sufficient), component deep-design docs
  (106f is an index only), ISO 9001 QMS documentation (over-reach for
  current project stage).
