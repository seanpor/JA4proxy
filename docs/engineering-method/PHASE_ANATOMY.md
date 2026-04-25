<!--
title: "Phase Anatomy — Annotated Walk-through"
audience: architects, contributors, new maintainers
last_reviewed: 2026-04-25
phase: 106g
-->

# Phase Anatomy — Annotated Walk-through

> Worked example: **Phase 104 — Code Health & Coverage Gap Closure**.
> Phase 104 was picked because it is the cleanest end-to-end specimen we
> currently have: short plan, full six-lens review, 13 chronological
> wave-style commits, and a real merge-to-`main` close — and it sits in the
> bracket of phases (104/105/106) the engineering-method README explicitly
> nominated as candidates.

Companion to [`METHOD.md`](METHOD.md) (the rules) and
[`CASE_STUDIES.md`](CASE_STUDIES.md) (long-arc decisions). PHASE_ANATOMY
zooms in on the four ritual stages of one small-to-medium phase:
plan → review → implementation → close.

---

## Why this phase

Phase 104 is small enough to fit in this document and large enough to
exercise every stage of the method: written plan, separate-agent review,
fan-out into many independent sub-tasks, a real test/coverage gate, and a
merge commit on `main`. It touches both Python and Go, showing how the same
method bridges both production languages. Bigger phases (15, 82, 200-series)
follow the same shape but add conflict-resolution and architectural debate
that obscure the ritual.

---

## Stage 1 — Plan: `docs/phases/PHASE_104.md`

The plan is **mandatory before any code** — see
[`AGENTS.md` §Mandatory Planning Protocol](../../AGENTS.md) and
[`CLAUDE.md`](../../CLAUDE.md) §How to Run a Phase. It is short on purpose:
the contract between the phase and the project, not a detailed design.

The plan opens with a status header that forward-links to the review:

```text
> **Status:** PROPOSED
> **Size:** LARGE (15 sub-tasks, all XS/S, all parallel)
> **Dependencies:** None (standalone)
> **Triggered by:** Code health audit 2026-04-16
> **Review:** `docs/phases/PHASE_104_review.md`
```

What this teaches: every plan declares dependencies, sizing (LARGE in
total, but every leaf is XS or S), and points at its review. No "draft /
final" — only PROPOSED → COMPLETE on the manifest.

The **Goal** is one paragraph, the load-bearing contract:

```text
Close all quality gaps across Python and Go: fix `make lint-all`, bring all
Python files to ≥80% coverage, raise Go coverage from 52% to ≥65%, fix the
stale README badge, and add a single `make quality` target that runs everything.
```

What this teaches: a reviewer can mechanically check whether it landed.
"Coverage went up" is unfalsifiable; "≥80% per file, ≥65% Go total" is
testable.

The **Sub-phases** table groups by ownership boundary, not by agent. Each
row is a candidate parallel task:

```text
### Python — Tier 1 Critical (<50%)

| ID | File(s) | Current | Size |
|----|---------|---------|------|
| 104.3a | `src/cli/main.py` | 0% | XS |
| 104.3b | `src/management/redis_client.py` | 30% | XS |
| 104.3c | `src/analytics/main.py` | 36% | S |
```

What this teaches: the IDs (`104.3a`, `104.3b`, …) become the fan-out
unit for Stage 3. Every leaf is XS or S by deliberate choice — Mediums grow
into weeks. If it is Medium, split it.

**Acceptance Criteria** is a literal checklist:

```text
- [ ] `make lint-all` passes with 0 errors
- [ ] `make quality` target exists and runs lint-all + coverage checks
- [ ] `make test` passes with 0 warnings
- [ ] All 14 Python files reach ≥80% line coverage
- [ ] Python total coverage ≥95%
- [ ] Go `internal/redis`, `internal/security`, `internal/metrics` reach ≥70%
- [ ] Go total coverage ≥65%
- [ ] All Go `cmd/` packages have test files
- [ ] README badge matches measured reality
```

What this teaches: criteria are commands, percentages, file existence —
each is a script away from green/red. Vague criteria make the close
negotiable; numbered criteria do not. The full plan is 88 lines: shorter
is a sketch, longer is doing the review's job.

---

## Stage 2 — Review: `docs/phases/PHASE_104_review.md`

The review is produced by a separate agent invocation (`/review-phase`) —
**not** an approval rubber-stamp but a structured critique through six
lenses. PHASE_104_review.md is 487 lines, over five times the plan, because
the review is where the plan's hand-waving gets pinned down.

The six lenses are explicit headings — `2a. Security`, `2b. DevOps`,
`2c. SRE`, `2d. Architecture`, `2e. Testing`, `2f. Documentation`. One
reviewer switches hats six times. Skipping a lens is not allowed; if a
lens has nothing to say, the reviewer writes "no new attack surface —
tests only" rather than dropping the heading. That negative finding is
itself information.

The review's most useful artefact is the **Risk Summary** table:

```text
| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| 1 | README badge claims ≥99%, actual is 92.76% / 52.3% | HIGH | Docs | Update badge |
| 2 | `make lint-all` fails on semgrep | MEDIUM | DevOps | Fix invocation |
| 3 | CI doesn't run mypy/bandit/golangci-lint/coverage | MEDIUM | DevOps | Note for future CI phase |
| 4 | Go `internal/redis` + `internal/security` under 80% | MEDIUM | SRE | Production hot-path |
| 5 | Two Go CLI tools have zero test files | LOW | Testing | Lower risk |
| 6 | No `make quality` aggregate target | LOW | DevOps | Convenience |
```

Two findings (#1 stale README badge, #2 broken `lint-all`) were **not**
in the original plan. The reviewer added them; they appear in the first
wave commit (`809a3ae`). A rubber-stamp review would have shipped both
broken.

The review also **decomposes every Medium task into XS/S leaves**. The plan
said "104.4: TI Feeds Cluster (S)"; the review broke it into `104.4a` …
`104.4e` with explicit files, line ranges, mocks, and "watch out for"
notes:

```text
### Sub-task 104.4d: TI feeds — rest_generic.py + crowdstrike.py
**Size:** S (1.5 hours)   **Depends on:** none   **Parallel with:** all
**Files to touch:** test_ti_feeds_rest_generic.py, test_ti_feeds_crowdstrike.py
**What to do:**
- rest_generic.py (54%): mock aiohttp — jsonpath errors, HTTP non-200,
  unsupported body type, auth warning, invalid IP/TTL, state.mark() paths
- crowdstrike.py (55%): mock token_fetcher — missing creds, token refresh,
  pagination meta, indicator apply
**Done when:** both files reach ≥80%
**Watch out for:** both use aiohttp sessions — use `aiohttp.test_utils` or
`unittest.mock.AsyncMock`
```

What this teaches: this detail lets the implementation agent be a smaller
model than the planner. The review is what makes parallel fan-out safe.

---

## Stage 3 — Implementation: waves

The reviewed sub-task list becomes a wave plan. Phase 104's commits in
chronological order (`git log --reverse | grep phase-104`):

```text
809a3ae  scaffolding — fix lint, badge, markers, add quality target
c22e25a  coverage tests for cli/main, management/redis_client, analytics/main
1e546be  coverage tests for security seccomp_transition + validation
005cb5c  coverage tests for ti_feeds state, contribution, ja4_safety, ...
2456206  coverage tests for ti_feeds rest_generic + crowdstrike
65c8069  coverage tests for ti_feeds runner + seed_file
ea2e330  suppress DeprecationWarning in redis_client close test
2809fc7  Go coverage tests for internal/security
4040e89  Go coverage tests for internal/redis
e47cad4  Go coverage tests for metrics, cli/*, cmd/*
b1cc237  gofmt internal/security/coverage_gap_test.go
f37f2c5  fix ruff import sorting in test files (23 auto-fixes)
cba5d2e  phase-104: coverage gap closure (#33)   ← merge to main
```

Mapped onto the project's wave model:

- **Wave 1 — Scaffolding & early docs (`809a3ae`).** Fixes `lint-semgrep`,
  registers pytest markers, updates the README badge, adds `make quality`,
  lands the plan + review docs. The wave-1 invariant: anything that must be
  true *before* test work starts. Early docs is deliberate, not an
  afterthought.
- **Wave 2 — Code (`c22e25a` … `e47cad4`).** Eight commits, each targeted
  at a specific sub-task ID. Every body cites before/after coverage
  ("src/cli/main.py: 0% → 98%"), making each independently reviewable.
  Python first then Go; unordered inside each language.
- **Wave 3 — Late docs.** Folded into the merge for a phase this small.
  Larger phases (15, 82) split it out.
- **Wave 4 — QA / cleanup (`b1cc237`, `f37f2c5`, `ea2e330`).** Three small
  commits fixing what the gate caught: `gofmt`, ruff import sorting, a
  `DeprecationWarning` from a wave-2 test. *Forced moves* — the gate said
  no, these are the minimum to pass.
- **Wave 5 — Independent review.** PR #33 review before merge — artefact
  lives on the PR, not in `git log`. Merge commit `cba5d2e` is the boundary.

What this teaches: waves are **dependency layers**, not phases-within-phases.
Wave 1 is "what must be true for the rest to happen." Wave 4 is "what we
owe the gate." Most leaf work lives in wave 2.

---

## Stage 4 — Close: gate + commit + manifest

The close is mechanical — where "looks done" gets adjudicated against
"is done". `scripts/close-phase.sh` runs the gate; red means not done.

The merge-PR commit on `main`:

```text
phase-104: coverage gap closure (#33)

phase-104: code health & coverage gap closure
```

The substantive scaffolding commit (`809a3ae`) that landed the plan and
review docs:

```text
phase-104: scaffolding — fix lint, badge, markers, add quality target

- Fix mypy error in safe_resolver.py (IPv4/IPv6Network type mismatch)
- Register missing pytest markers (unit, chaos, adversarial) → 0 warnings
- Fix lint-semgrep: use direct `semgrep` command instead of deprecated
  `python -m semgrep`, remove --error (findings are advisory, not blocking)
- Update README badge from ≥99% (stale Phase 46 claim) to ≥92% (measured)
- Add `make quality` target: lint-all + lint-coverage + Go coverage check
- Add Phase 104 plan doc and review with 15 XS/S sub-tasks
```

Two-language commits stay in their lane — the Go coverage commit
(`2809fc7`) cites Go-side numbers ("72.8% → 89.0%") and Go-side files,
nothing else.

The closing ritual:

1. `make test` passes with **0 warnings** (hard rule — warnings are how
   stale tests hide).
2. `make quality` (the target this phase added) passes.
3. `bash scripts/close-phase.sh` flips manifest `PROPOSED` → `COMPLETE`.
4. `make sync` regenerates `TODO.md` and `PROJECT_STATUS.md`.
5. CHANGELOG entry prepended.
6. Plan, review, manifest, CHANGELOG, TODO, PROJECT_STATUS go in **one**
   atomic commit so a `git revert` is honest about what was un-closed.
7. Push; PR opens; Wave 5 reviewer approves; merge to `main`.

The manifest is the single source of truth for "done?" — not the README,
not chat, not a ticket. The CHANGELOG is for humans; the manifest is for
the build.

---

## What's missing from this picture

The artefacts make the work look orderly because the artefacts are **the
durable subset of the work**. The repo does not record: the first plan
revision being rejected for scheduling Medium tasks (the "no Medium" rule
shows up in the review's "v2" note but the argument that produced it is
gone); wave-2 commits that failed CI on first push and were fixed up before
merge (Wave 4's three QA commits are the tip of this); the real-time chat
course-corrections from the project lead (the method assumes a human in the
loop); and time-pressure decisions ("ship it, fix the warning next phase").
The [`retrospectives/`](retrospectives/README.md) directory tries to
capture some of this, but quarterly cadence loses context. Read
PHASE_NN.md and PHASE_NN_review.md as the *plan of record*, not the *story
of what happened*.

---

## Reading the artefacts yourself

For Phase 104, the canonical artefacts are:

| Artefact | Path / SHA |
|----------|------------|
| Plan | [`docs/phases/PHASE_104.md`](../phases/PHASE_104.md) |
| Review | [`docs/phases/PHASE_104_review.md`](../phases/PHASE_104_review.md) |
| Wave 1 (scaffolding) | commit `809a3ae` |
| Wave 2 (Python coverage) | commits `c22e25a`, `1e546be`, `005cb5c`, `2456206`, `65c8069` |
| Wave 2 (Go coverage) | commits `2809fc7`, `4040e89`, `e47cad4` |
| Wave 4 (QA fix-ups) | commits `b1cc237`, `f37f2c5`, `ea2e330` |
| Merge to main (Wave 5) | commit `cba5d2e` (PR #33) |
| Manifest entry | `docs/phases/manifest.yaml` (Phase 104, status `COMPLETE`) |

To replay:

```bash
git log --reverse --format='%h %s' | grep phase-104
git show 809a3ae --stat   # wave 1 scaffolding
git show cba5d2e --stat   # merge to main
```

Cross-reference [`METHOD.md`](METHOD.md) for the *why* behind each ritual,
and [`CASE_STUDIES.md`](CASE_STUDIES.md) for phases where it had to bend.
