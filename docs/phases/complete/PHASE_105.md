# Phase 105 — Documentation Restructure by Audience

> **Status:** PROPOSED
> **Size:** LARGE (26 sub-tasks across 6 audience tracks)
> **Dependencies:** None (docs-only; no code change)
> **Triggered by:** Documentation audit 2026-04-16
> **Review:** `docs/phases/complete/PHASE_105_review.md` (to be written on close)

---

## Goal

The documentation corpus is comprehensive (~92K lines in `/docs/`, 200+ files)
but incoherent as a reading experience. README mixes four audiences and loses
each of them. There is no buyer-facing one-pager despite an existing (but
buried) brochure. Six overlapping TESTING docs, three overlapping deployment
docs, four overlapping blocking docs. Stale phase references (Phase 14/19/21
treated as current while the project is at 104+). The Go-is-production reality
from Phase 15 is still not unambiguous in top-level docs. No coherent
developer-onboarding track explaining how the team actually works (TDD,
keep-main-green, CI gates, phase protocol, PR etiquette).

Restructure documentation around the five audiences below, consolidate
duplicates, retire stale artefacts, and rebuild the PDF brochure / user guide /
reference manual so they match current reality. No code changes — docs and
PDF-build scripts only.

---

## Audiences (canonical list for this phase)

| # | Audience | Primary concern | Entry doc |
|---|----------|-----------------|-----------|
| 1 | **Website owner / CISO** (primary) | "Will this stop the bots hitting my forms without blocking customers?" | `README.md` |
| 2 | **Security architect** (primary) | Threat model, control coverage, trust boundaries, SIEM integration, scope & limitations | `README.md` |
| 3 | **SecOps operator** (secondary) | Start/stop, dial tuning, incident response, dashboards, alerts | `README.md` |
| 4 | **Compliance / audit** (secondary) | Data handling, retention, PII posture, audit trail, control mapping | `README.md` |
| 5 | **Developer / contributor** (secondary) | Local dev, phase protocol, TDD, keep-main-green rules, CI gates, how to land a PR | `README.md` |

The top-level `README.md` becomes a role-router that dispatches to these five.
`docs/README.md` remains the exhaustive map for power users.

---

## Findings Summary (from audit)

Full audit in this phase's opening commit message. Issues actioned below:

| # | Severity | Issue |
|---|----------|-------|
| F1 | CRITICAL | Python-vs-Go production status ambiguous in top-level docs |
| F2 | CRITICAL | No website-owner one-pager / buyer's guide; brochure buried in `docs/pdf/` |
| F3 | HIGH | `README.md` mixes 4 audiences; no clear entry point per role |
| F4 | HIGH | No developer-onboarding track covering TDD, trunk discipline, CI gates |
| F5 | HIGH | Stale pre-Phase 200 reports read as current (`ENTERPRISE_REVIEW.md`, `GEMINI_CRITIQUE.md`, `DMZ_READINESS.md`) |
| F6 | MEDIUM | 4 overlapping TESTING docs, 3 overlapping deployment docs, 4 overlapping blocking docs |
| F7 | MEDIUM | Missing architect docs: SIEM/SOAR integration runbooks, "what JA4proxy is NOT" scope doc |
| F8 | MEDIUM | PDF brochure / user guide / reference manual reference Phase-15-era reality; not discoverable from README |
| F9 | MEDIUM | `docs/README.md` last reviewed Phase 21; positioned at end of README, not top |
| F10 | LOW | Minor link issues (README → `docs/enterprise/` directory, not file); possibly stale perf numbers |

---

## 105a. Top-level README as role-router

### Problem

`README.md` is 431 lines. Lines 1–40 market, 41–104 architect-diagram, 112–296
operator/deploy, 278+ developer. Website owners scroll past credential-stuffing
framing they need; architects hunt for threat model links; developers read
marketing prose before getting to `make test`.

### Fix

Rewrite `README.md` to ≤150 lines with this shape:

1. One-line value proposition + elevator paragraph (unchanged core message)
2. **"Start by role"** table at the top (not the bottom) — 5 rows linking to
   the five `docs/for-*/README.md` entry points
3. **Unambiguous runtime banner**: "Production runtime is the Go proxy
   (`cmd/proxy`). The Python proxy (`proxy.py`) is a prototyping surface."
4. 30-second product pitch, compressed
5. Architecture diagram (keep; it's the one thing all audiences reference)
6. **Download** row for PDF brochure / user guide / reference manual
7. Link to `CHANGELOG.md` and `docs/reference/PROJECT_STATUS.md`
8. Link to `CONTRIBUTING.md` and `SECURITY.md`

Everything currently in README lines 112–350 moves into the audience-specific
entry docs (105b–105f). README becomes signpost, not encyclopaedia.

### Size

**M** — rewrite plus careful content-migration so nothing unique is lost.

---

## 105b. Website-owner / CISO track

### Problem

No document answers "I run a website, bots are hammering my login/signup/
checkout forms, is this for me?" in under 5 minutes. The brochure does — but
it's in `docs/pdf/brochure/` and not linked from any top-level doc.

### Fix — new files

| File | Content |
|------|---------|
| `README.md` | Role router: problem framing → links to the three below |
| `WHY_JA4PROXY.md` | Problem statement in business language. Credential-stuffing, form-abuse, scraper costs. Before/after narrative. "Zero false-positives by design" without jargon |
| `DEPLOYMENT_OPTIONS.md` | Cloud / on-prem / managed-service summary. Time-to-deploy. Integration prerequisites. Who operates it |
| `FAQ.md` | 12–15 Q&A: cost model, risk of blocking real users, does it work behind Cloudflare/AWS ALB, GDPR posture, uptime impact, how we know it's working |

The existing `docs/operations/FAQ.md` is operator-focused and stays; the new one is
buyer-focused.

### Size

**M** — 4 new docs, prose-heavy, source material largely exists in brochure.

---

## 105c. Security-architect track

### Problem

Architect content exists but is scattered: threat model in `docs/security/`,
control mapping in `docs/compliance/`, architecture in `docs/architecture/`,
enterprise security in `docs/enterprise/`. No single entry point. Two real
gaps: (1) no "what this is NOT" scope doc; (2) no SIEM/SOAR integration
runbooks (Splunk, QRadar, Sentinel, Wazuh) despite log schema being published.

### Fix

Create `README.md` as a curated index (not a duplicate) of:

- Threat model (`docs/security/threat-model.md`)
- Control coverage matrix (`docs/compliance/SECURITY_CONTROLS_MAPPING.md`)
- Data flow & trust boundaries (`docs/security/DEPLOYMENT_SECURITY_MODEL.md`)
- Enterprise deployment topology (`docs/enterprise/deployment.md`)
- Enterprise security architecture (`docs/enterprise/security-architecture.md`)

New content to write:

| File | Content |
|------|---------|
| `SCOPE_AND_LIMITATIONS.md` | What JA4proxy does NOT do. Not a WAF, does not decrypt, does not inspect HTTP bodies, does not prevent SQLi/XSS, does not re-encrypt, does not detect insider threats. Explicit non-goals |
| `SIEM_INTEGRATION.md` | Log schema recap (ECS 8.x, pointer to `docs/api/ecs_extension.md`) + Splunk / QRadar / Sentinel / Wazuh ingestion recipes (forwarder config, index/parser snippets, sample correlation rules) |
| `EVALUATION_CHECKLIST.md` | Short checklist for architects running a POC: what to monitor, what "good" looks like after 7/30 days, how to raise the dial safely |

Retire / restamp the following as historical:

| File | Action |
|------|--------|
| `docs/reports/ENTERPRISE_REVIEW.md` | Move to `docs/reports/archive/ENTERPRISE_REVIEW_2026-02-15.md`, add banner "Snapshot pre-Phase 200 hardening. Current posture: see ``" |
| `docs/GEMINI_CRITIQUE.md` | Move to `docs/reports/archive/GEMINI_CRITIQUE_2026-03-21.md`, add banner listing which findings are remediated (Phase 13/51/52 Management UI; Phase 200-series hardening) |
| `docs/security/DMZ_READINESS.md` | Re-date and re-scope against Phase 200-series controls, or archive and supersede with a fresh readiness doc |

### Size

**L** — three new docs of substance (SCOPE, SIEM integration, eval checklist)
plus archival/restamp work on three existing reports.

---

## 105d. Operator track

### Problem

Operator docs are numerous but overlapping. Four blocking docs, three testing
docs (which leak into dev territory), sparse capacity-planning coverage.
`docs/operator/` sits alongside top-level operator docs (`OPERATIONS.md`,
`INCIDENT_RESPONSE.md`, `MONITORING_SETUP.md`, `SCALING_GUIDE.md`) with no
clear hierarchy.

### Fix

Create `README.md` as the single entry point. Keep existing
runbooks in `docs/runbooks/` — they are well-organised and referenced by alert
rules. Consolidate:

| Action | Files |
|--------|-------|
| **Merge** into `docs/operator/BLOCKING_OPERATIONS.md` | `docs/operator/blocking-guide.md` + `BLOCKING_ANALYSIS.md` + `blocking-test-analysis.md` + `FINAL_BLOCKING_TEST_SUMMARY.md` |
| **Promote** to top-level operator entry | `docs/OPERATIONS.md`, `docs/operations/INCIDENT_RESPONSE.md`, `docs/QUICK_REFERENCE.md`, `docs/MONITORING_SETUP.md` (link, don't move) |
| **Expand** | `docs/operations/SCALING_GUIDE.md` — add worked capacity-planning examples (3 scenarios: small site / enterprise / high-volume API) |
| **Add** | `UPGRADE_PATH.md` summarising the already-existing `docs/runbooks/rolling_upgrade.md` + version compatibility matrix |

### Size

**M** — one big merge (blocking docs), one expansion (scaling), one new
operator entry + summary doc.

---

## 105e. Compliance track

### Problem

Compliance docs exist (`GDPR_COMPLIANCE.md`, `SECURITY_CONTROLS_MAPPING.md`,
`soc2-control-narrative.md`, `iso27001-annex-a-mapping.md`) but no single
entry and no dedicated audit-trail schema doc. Change-management procedure
is implicit in policy-audit key (`management:policy_audit`) but not
documented for auditors.

### Fix

| File | Action |
|------|--------|
| `README.md` | New — role router linking the four existing compliance docs |
| `AUDIT_TRAIL.md` | New — what gets logged, where, for how long; policy-change audit (`management:policy_audit` LIST); operator action log; Redis key retention summary; cross-reference `docs/reference/REDIS_SCHEMA.md` |
| `CHANGE_MANAGEMENT.md` | New — how config changes are proposed, reviewed, applied, reverted (SIGHUP + UI + pub/sub). Maps to auditor-expected CM evidence |

### Size

**S** — three new focused docs, content largely exists and needs to be
extracted and reframed.

---

## 105f. Developer / contributor track

### Problem

`CONTRIBUTING.md` (232 lines) is Day-1-setup-plus-phase-protocol. It does not
explain **how the team actually works**: TDD discipline, keep-main-green rule,
CI gate expectations, how to read phase docs, how to land a PR, how to close a
phase. `CLAUDE.md` and `AGENTS.md` contain this information but are written
for AI agents and are over-dense for a human contributor on day one. The
audit surfaced that new human contributors have no equivalent onboarding
track.

### Fix — establish `` as the human-contributor home

| File | Content |
|------|---------|
| `README.md` | Role router: pick your path — first-time contributor, returning contributor, maintainer |
| `GETTING_STARTED.md` | Local dev in 30 min. Go and Python prereqs. Build, test, run. Points at `CONTRIBUTING.md` for deeper reference (do not duplicate) |
| `HOW_WE_WORK.md` | **The team process doc.** Trunk-based development with short-lived `claude/phase-NN-*` and `feat/*` branches. Never commit direct to `main`. Keep-main-green rule: any red CI on `main` is treated as an incident; fix or revert within 1 hour. Phase protocol summary (link to `CLAUDE.md` + `AGENTS.md` for agent-specific rules). Commit message convention. PR size expectations. Review etiquette |
| `TESTING_STRATEGY.md` | TDD loop the team uses: write the failing test first, smallest change to green, refactor, ratio target ~1.3× test-to-code. Test category matrix (unit / integration / chaos / adversarial / FP corpus / performance / E2E) with "when to write each". Link to `docs/developer/TESTING_STRATEGY.md` as the deep reference. Explain mocks-in-`tests/mocks` rule, no-real-API rule, phase-gate-must-pass rule |
| `QUALITY_PLAN.md` | What `.github/workflows/ci.yml` enforces: test-go, test-python, lint, secrets-scan, SAST, dep audits (Py + Go), dependency review, SHA-pinned-actions check. Weekly CVE sweep cron. What a green PR looks like. How to reproduce a CI failure locally (`make quality`, `make test`, `make lint-all`). SBOM + Cosign signing in `go-proxy-image.yml`. Policy-bundle CI in `ja4proxy-policy.yml`. Release gate in `release-cli.yml` |
| `PHASE_LIFECYCLE.md` | How to run a phase end-to-end, human edition. Mandatory planning protocol (phase doc before code). Branch naming. Commit cadence. `make sync` to regenerate TODO/PROJECT_STATUS. Manifest update + CHANGELOG entry. Phase-close checklist. Link to `AGENTS.md` for the agent-orchestration variant |
| `SIGNAL_DEVELOPMENT.md` | Already exists at `docs/developer/SIGNAL_DEVELOPMENT.md` — move or link |

Content source: much of this already exists in `CLAUDE.md`, `AGENTS.md`,
`CONTRIBUTING.md`, `docs/developer/TESTING_STRATEGY.md`, and the workflow YAML headers
themselves. Job is to extract, reframe for humans, and ensure each doc has
one clear audience.

### Size

**L** — 6 new/moved docs. HOW_WE_WORK, TDD_AND_TESTING, and
CI_AND_QUALITY_GATES are the load-bearing ones; the others can cross-reference
existing material.

---

## 105g. Consolidate overlapping TESTING docs

### Problem

Six docs on testing with heavy overlap: `docs/TESTING.md` (Phase 0 baseline),
`docs/developer/TESTING_STRATEGY.md` (Phase 21 canonical), `docs/TESTING_GO.md` (Go
specific), `docs/developer/TESTING_STRATEGY.md` (file layout), `docs/TEST_SUITE.md`
(categories), `docs/developer/SECURITY_TESTING.md` (JA4 validation, unique scope).

### Fix

Make `docs/developer/TESTING_STRATEGY.md` the single canonical reference. Merge:

- `docs/developer/TESTING_STRATEGY.md` → appendix "Test File Organisation" in
  TESTING_STRATEGY
- `docs/TEST_SUITE.md` → appendix "Test Categories" in TESTING_STRATEGY
- `docs/TESTING.md` → delete; replace with a stub that redirects
- `docs/TESTING_GO.md` → appendix "Go-Specific Testing" in TESTING_STRATEGY

Keep `docs/developer/SECURITY_TESTING.md` — unique JA4-fingerprint scope.

Ensure `TESTING_STRATEGY.md` links to the consolidated doc.

### Size

**M** — mechanical merge, but must preserve every unique paragraph and
rewrite nothing substantive.

---

## 105h. PDF brochure / user guide / reference manual refresh

### Problem

The PDF artefacts in `docs/pdf/` are unique assets: brochure (business), user
guide (operator-facing long-form), reference manual (architect-facing deep
reference). LaTeX source is in-repo and well-structured (chapters by topic).
Issues:

1. **Not discoverable** from README.
2. **Phase drift** — user guide and reference manual were written around
   Phase 15 and have not been systematically re-synchronised through Phases
   20–104. At minimum: coverage metrics stale, Management UI (Phase 13/51/52)
   under-documented, Phase 200-series hardening (Redis TLS, PROXY protocol v2,
   default-credential removal, missing signals) absent.
3. **No build-and-publish path** — PDFs are checked-in artefacts; no CI step
   to rebuild on source change; no release attaches them.

### Fix

Refresh pass on each PDF source tree:

| Artefact | Action |
|----------|--------|
| `docs/pdf/brochure/brochure-body.tex` | Light refresh — update "current state" claims, add Phase-200-series security posture line, link to `README.md`. Verify numbers in brochure match `docs/performance/BENCHMARK_HISTORY.md` |
| `docs/pdf/user-guide/chapters/ch01-introduction.tex` | Remove "Phase 15 introduction" framing; position as current Go-production guide |
| `docs/pdf/user-guide/chapters/ch02-installation.tex` | Update to reflect current Dockerfile.go-proxy non-root + USER directive, env-var credential requirements (Phase 202) |
| `docs/pdf/user-guide/chapters/ch04-configuration.tex` | Reconcile against current `config/proxy.yml` |
| `docs/pdf/user-guide/chapters/ch05-operations.tex` | Reconcile against `docs/OPERATIONS.md` |
| `docs/pdf/user-guide/chapters/ch07-incident-response.tex` | Reconcile against `docs/operations/INCIDENT_RESPONSE.md` |
| `docs/pdf/reference-manual/chapters/ch01-architecture.tex` | Refresh with current Go runtime as primary, Python as prototyping |
| `docs/pdf/reference-manual/chapters/ch04-signals.tex` | Add Phase 203 signals: TAP OS-mismatch, JA4 TLS-version mismatch, expanded weak-cipher set, DGA parity, deep-health |
| `docs/pdf/reference-manual/chapters/ch06-redis-schema.tex` | Reconcile against `docs/reference/REDIS_SCHEMA.md` current state |
| `docs/pdf/reference-manual/chapters/ch09-security-ref.tex` | Add Phase 200-series hardening (Redis TLS, PROXY v2, default-credential removal) |
| `docs/pdf/reference-manual/chapters/ch10-compliance.tex` | Reconcile against `docs/compliance/` current state |
| `docs/pdf/Makefile` | Verify `make` builds all three PDFs reproducibly; document `latexmk` / `tectonic` prerequisite in `GETTING_STARTED.md` |

Add a CI job (new workflow or extension of `ci.yml`) that rebuilds the three
PDFs on every change under `docs/pdf/**` and publishes them as workflow
artifacts. Release workflow should attach the three PDFs to the GitHub release.

### Size

**L** — content refresh is substantial (12 chapters), but mostly reconciliation
against existing living docs rather than original writing.

---

## 105i. Fix stale phase references and Python-vs-Go ambiguity

### Problem

The following docs reference Phase 14/19/21-era state as if current:

- `docs/security/DMZ_READINESS.md` — "Phase 14 gap analysis" (Phase 14 is 90
  phases ago)
- `docs/security/DEPLOYMENT_SECURITY_MODEL.md` — "Phase 19 backup" references
- `docs/README.md` — header says `last_reviewed: 2026-03-27, phase: 21`
- `docs/README.md` — last reviewed Phase 21
- `docs/GEMINI_CRITIQUE.md` — "Phase 13 Management UI deferred" (Phase 13/51/52
  now complete)

Python-vs-Go confusion in README lines 16–25 (badges + buried warning) and
`CONTRIBUTING.md` line 54 (lists `proxy.py` first without prototyping callout).

### Fix

- `docs/README.md` and `docs/README.md`: update frontmatter to current date +
  `phase: 104` (or whatever is latest at close time) and re-audit every table
  row for stale entries
- `docs/security/DMZ_READINESS.md`: either rewrite against current Phase
  200-series controls, or archive with supersede banner (decide in 105c)
- `docs/security/DEPLOYMENT_SECURITY_MODEL.md`: re-date; remove Phase-19-specific
  hedging; reference current backup runbook
- `README.md`: runtime banner fix (see 105a)
- `CONTRIBUTING.md`: reorder project-structure block so Go (`cmd/proxy/`,
  `internal/`) appears first with a "production runtime" header, and
  `proxy.py` under "Python prototyping surface" header

### Size

**S** — find-and-replace, re-date, verify.

---

## 105j. Retire / archive dead docs

### Problem

Some docs have no forward value and mislead new readers.

### Fix

Create `docs/reports/archive/` and move:

| From | To | Reason |
|------|----|--------|
| `docs/GEMINI_CRITIQUE.md` | `docs/reports/archive/GEMINI_CRITIQUE_2026-03-21.md` | Pre-Phase 200 critique, findings largely remediated |
| `docs/reports/ENTERPRISE_REVIEW.md` | `docs/reports/archive/ENTERPRISE_REVIEW_2026-02-15.md` | Pre-Phase 200 hardening snapshot |
| `docs/reports/CYBER_RISK_REVIEW_2026-04-09.md` | Decide: retain if current, archive if pre-200 | Date-check |
| `docs/reports/strategic_security_architecture_review.md` | Decide: date it, then retain or archive | Undated report |

Each archived doc gets a two-line banner at the top identifying the snapshot
date and pointing to the current equivalent. Do not delete — they are an
audit trail of how the project was reviewed.

### Size

**XS** — mechanical moves + banner text.

---

## 105k. Keep-main-green policy doc + enforcement check

### Problem

The team rule "main must never stay red" is operational folklore. It's implied
by CI running on `push: main` but not written down. The user's follow-up flagged
this explicitly.

### Fix

Anchor the policy in `HOW_WE_WORK.md` (see 105f) with:

- Definition of "red main" (any `ci.yml` job failure on the default branch)
- Response SLA (acknowledge within 15 min during working hours, fix or revert
  within 1 hour)
- Revert-first-debug-later preference for PR regressions
- Responsible party (PR author; maintainer as backstop)
- Weekly CVE sweep failure handling (dependency-update PR within 24 h)

Add (optional, decide during implementation) a `docs/runbooks/main_is_red.md`
runbook for the operational response, so the dev doc stays policy-level and
the runbook is the step-by-step.

### Size

**S** — one policy section plus optional runbook.

---

## Acceptance Criteria

**Top-level**
- [ ] `README.md` is ≤ 150 lines and opens with a "Start by role" table linking to the five `docs/for-*/README.md` entry points
- [ ] `README.md` contains an unambiguous "Production runtime is the Go proxy" banner above the fold
- [ ] `README.md` has a PDF-downloads row linking brochure, user guide, reference manual
- [ ] `docs/README.md` frontmatter `last_reviewed` and `phase` fields match the phase in `docs/phases/manifest.yaml` at close time

**Audience entry points**
- [ ] `README.md` exists with 3 sub-docs (WHY_JA4PROXY, DEPLOYMENT_OPTIONS, FAQ)
- [ ] `README.md` exists with SCOPE_AND_LIMITATIONS, SIEM_INTEGRATION, EVALUATION_CHECKLIST
- [ ] `README.md` exists and links (not copies) existing operator docs and runbooks
- [ ] `README.md` exists with AUDIT_TRAIL and CHANGE_MANAGEMENT
- [ ] `README.md` exists with GETTING_STARTED, HOW_WE_WORK, TDD_AND_TESTING, CI_AND_QUALITY_GATES, PHASE_LIFECYCLE

**Developer track specifics**
- [ ] `HOW_WE_WORK.md` documents trunk-based flow, branch naming, keep-main-green rule, PR size expectations, review etiquette
- [ ] `TESTING_STRATEGY.md` documents the TDD loop and references `docs/developer/TESTING_STRATEGY.md` as canonical
- [ ] `QUALITY_PLAN.md` describes every job in `.github/workflows/ci.yml`, `go-proxy-image.yml`, `ja4proxy-policy.yml`, `release-cli.yml`

**Consolidation**
- [ ] Blocking operations merged into `docs/operator/BLOCKING_OPERATIONS.md`; the 4 old blocking docs redirect or are archived
- [ ] `docs/developer/TESTING_STRATEGY.md` absorbs TEST_ORGANIZATION, TEST_SUITE, TESTING_GO as appendices; `docs/TESTING.md` is a redirect stub

**Staleness repair**
- [ ] `docs/security/DMZ_READINESS.md` is either rewritten against Phase 200-series controls or archived with a supersede banner
- [ ] `docs/GEMINI_CRITIQUE.md` and `docs/reports/ENTERPRISE_REVIEW.md` are under `docs/reports/archive/` with snapshot-date banners
- [ ] No doc under `docs/` claims "Phase N" as current where N < latest-complete-phase in manifest

**PDFs**
- [ ] `docs/pdf/brochure/brochure.pdf` rebuilds from refreshed `.tex` source and references current (Phase 200-series) security posture
- [ ] `docs/pdf/user-guide/user-guide.pdf` rebuilds with chapters 1, 2, 4, 5, 7 reconciled against their living-doc equivalents
- [ ] `docs/pdf/reference-manual/reference-manual.pdf` rebuilds with chapters 1, 4, 6, 9, 10 reconciled; Phase 203 signals and Phase 200-series hardening are present
- [ ] `docs/pdf/Makefile` builds all three PDFs in one `make` invocation with zero warnings
- [ ] CI rebuilds the three PDFs on any change under `docs/pdf/**` and publishes them as workflow artifacts

**Cross-cutting**
- [ ] No README / top-level doc refers to `proxy.py` without a "prototyping surface" qualifier
- [ ] Every `docs/for-*/README.md` is the audience's canonical entry point and is linked from the root `README.md` and `docs/README.md`
- [ ] `make sync` has been run; `docs/phases/TODO.md` and `docs/reference/PROJECT_STATUS.md` regenerated
- [ ] `docs/phases/manifest.yaml` has Phase 105 marked COMPLETE
- [ ] `CHANGELOG.md` has a Phase 105 entry

---

## Files to Modify

| File | Change |
|------|--------|
| `README.md` | Rewrite as role-router (≤150 lines) |
| `docs/README.md` | Add links to five `for-*` entry points; update frontmatter |
| `docs/README.md` | Re-audit every row; update frontmatter |
| `CONTRIBUTING.md` | Re-order project structure; link `` |
| `README.md` | New |
| `WHY_JA4PROXY.md` | New |
| `DEPLOYMENT_OPTIONS.md` | New |
| `FAQ.md` | New |
| `README.md` | New |
| `SCOPE_AND_LIMITATIONS.md` | New |
| `SIEM_INTEGRATION.md` | New |
| `EVALUATION_CHECKLIST.md` | New |
| `README.md` | New |
| `UPGRADE_PATH.md` | New |
| `README.md` | New |
| `AUDIT_TRAIL.md` | New |
| `CHANGE_MANAGEMENT.md` | New |
| `README.md` | New |
| `GETTING_STARTED.md` | New |
| `HOW_WE_WORK.md` | New |
| `TESTING_STRATEGY.md` | New |
| `QUALITY_PLAN.md` | New |
| `PHASE_LIFECYCLE.md` | New |
| `docs/operator/BLOCKING_OPERATIONS.md` | New (merge of 4 existing) |
| `docs/operator/blocking-guide.md` | Redirect stub or delete |
| `docs/operator/BLOCKING_ANALYSIS.md` | Redirect stub or delete |
| `docs/operator/blocking-test-analysis.md` | Redirect stub or delete |
| `docs/operator/FINAL_BLOCKING_TEST_SUMMARY.md` | Redirect stub or delete |
| `docs/developer/TESTING_STRATEGY.md` | Absorb TEST_ORGANIZATION, TEST_SUITE, TESTING_GO |
| `docs/TESTING.md` | Redirect stub |
| `docs/developer/TESTING_STRATEGY.md` | Redirect stub or delete |
| `docs/TEST_SUITE.md` | Redirect stub or delete |
| `docs/TESTING_GO.md` | Redirect stub or delete |
| `docs/operations/SCALING_GUIDE.md` | Expand with three worked examples |
| `docs/security/DMZ_READINESS.md` | Rewrite against Phase 200-series **or** archive |
| `docs/security/DEPLOYMENT_SECURITY_MODEL.md` | Re-date; drop Phase-19 hedging |
| `docs/GEMINI_CRITIQUE.md` | Move to `docs/reports/archive/GEMINI_CRITIQUE_2026-03-21.md` with banner |
| `docs/reports/ENTERPRISE_REVIEW.md` | Move to `docs/reports/archive/ENTERPRISE_REVIEW_2026-02-15.md` with banner |
| `docs/reports/CYBER_RISK_REVIEW_2026-04-09.md` | Date-check; retain or archive |
| `docs/reports/strategic_security_architecture_review.md` | Date; retain or archive |
| `docs/pdf/brochure/brochure-body.tex` | Refresh to Phase 200-series |
| `docs/pdf/user-guide/chapters/ch01-introduction.tex` | Rewrite as current Go-production guide |
| `docs/pdf/user-guide/chapters/ch02-installation.tex` | Reconcile against Dockerfile.go-proxy |
| `docs/pdf/user-guide/chapters/ch04-configuration.tex` | Reconcile against `config/proxy.yml` |
| `docs/pdf/user-guide/chapters/ch05-operations.tex` | Reconcile against SECOPS_OPERATIONS |
| `docs/pdf/user-guide/chapters/ch07-incident-response.tex` | Reconcile against INCIDENT_RESPONSE |
| `docs/pdf/reference-manual/chapters/ch01-architecture.tex` | Refresh |
| `docs/pdf/reference-manual/chapters/ch04-signals.tex` | Add Phase 203 signals |
| `docs/pdf/reference-manual/chapters/ch06-redis-schema.tex` | Reconcile against REDIS_SCHEMA |
| `docs/pdf/reference-manual/chapters/ch09-security-ref.tex` | Add Phase 200-series hardening |
| `docs/pdf/reference-manual/chapters/ch10-compliance.tex` | Reconcile against `docs/compliance/` |
| `docs/pdf/Makefile` | Verify reproducible build |
| `.github/workflows/ci.yml` | Add PDF-rebuild-and-artifact step triggered by `docs/pdf/**` path |
| `.github/workflows/release-cli.yml` | Attach three PDFs to release artifacts |
| `docs/phases/manifest.yaml` | Add Phase 105 entry; mark COMPLETE on close |
| `docs/phases/TODO.md` | Regenerated by `make sync` |
| `docs/reference/PROJECT_STATUS.md` | Regenerated by `make sync` |
| `CHANGELOG.md` | Phase 105 entry |

---

## Sizing Summary

| Sub-phase | Size | Notes |
|-----------|------|-------|
| 105a — README as role-router | M | |
| 105b — Website-owner track | M | 4 new docs, source material in brochure |
| 105c — Architect track | L | SCOPE, SIEM, EVAL are all new writing |
| 105d — Operator track | M | Blocking merge + scaling expansion |
| 105e — Compliance track | S | 3 new docs, extracted content |
| 105f — Developer track | L | 6 docs; HOW_WE_WORK + TDD + CI are load-bearing |
| 105g — TESTING consolidation | M | Mechanical merge, preserve everything |
| 105h — PDF refresh | L | 12 chapters, mostly reconciliation |
| 105i — Staleness repair | S | Find-replace + re-date |
| 105j — Archive dead docs | XS | Mechanical moves + banners |
| 105k — Keep-main-green policy | S | One section + optional runbook |

**Total effort:** LARGE. Independently parallelisable across tracks: 105b, 105c,
105d, 105e, 105f, 105h can each run as a separate agent branch. 105a depends
on 105b–105f existing (so it can link them). 105g and 105i can run any time.
105j and 105k are XS/S housekeeping.

Suggested execution order:
1. **Wave 1 (parallel):** 105b, 105c, 105d, 105e, 105f, 105g, 105h, 105i, 105j, 105k
2. **Wave 2 (sequential after Wave 1):** 105a — retitle README once the
   audience entry points exist to link to

---

## Notes for Implementer

- **Never delete unique content.** Every consolidation must preserve every
  unique paragraph from the source docs. When in doubt, keep it as an appendix.
- **Do not duplicate content between `docs/for-*/` and the existing topical
  docs.** The `for-*` docs are **role-curated indexes** with short framing
  prose; the canonical content lives in its topical home (architecture,
  compliance, runbooks, etc.). One source of truth per fact.
- **Archive, don't delete.** Stale reports are audit trail. Move to
  `docs/reports/archive/` with a banner; never `rm`.
- **PDFs:** `docs/pdf/Makefile` already uses `pdflatex` + `makeindex`. Stick
  with `pdflatex` for this phase — switching toolchains is scope creep. A
  future ADR may reconsider `tectonic` for reproducible single-binary CI.
- **CI for PDFs:** the PDF build should be a **non-blocking** CI job initially.
  Promote to blocking only after it has been green for 14 days. The goal is
  discoverability of drift, not making docs a release blocker.
- **Link hygiene:** once all audience entry points exist, grep the docs tree
  for `](docs/` and `](./` and fix broken relative links in one final pass.
- **Python warning:** keep `proxy.py` runnable for prototyping. This phase
  does not deprecate it, only re-frames its documentation. Go-production is
  already the Phase-15-established reality.
- **Do not expand this phase.** New audiences, new PDF formats, new translated
  docs — those are Phase 106+. This phase is about coherence of what exists.
