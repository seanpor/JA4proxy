<!--
title: "Engineering Method"
audience: architects, contributors
last_reviewed: 2026-04-25
phase: 106g
-->

# Engineering Method

This document is the formal statement of how JA4proxy is built. It exists so
that a new contributor — human or AI agent — can read one file and know what
the team's working agreements are, why they exist, and where the rules are
encoded in the repository. It is descriptive, not aspirational: every rule
here is enforced by tooling, gating, or repeated review, and where the method
has failed in practice we say so plainly in the [final section](#when-this-method-fails).

## What this method is

JA4proxy is delivered through **phase-based incremental delivery** by a single
small team — one to three humans plus a fan-out of Claude Code agents working
in parallel — optimised for two properties above all else: **keep-main-green**
(every merge to `main` leaves the trunk releasable) and **reproducibility**
(any phase can be re-run from its planning document and arrives at the same
acceptance criteria). Work proceeds one numbered phase at a time, each with a
written plan reviewed by humans before code is written, a TDD wave that locks
the contract, and a coding wave that satisfies the tests. Phases are sized to
ship in days, not weeks, and they are ordered: the next phase is not started
until the previous one has met its acceptance criteria.

## What it is not

- **Not Scrum.** There is no sprint cadence, no story points, no velocity
  tracking. Phases close when their acceptance criteria pass, not when a
  fixed-length window expires.
- **Not SAFe.** There is no Program Increment planning, no Agile Release
  Train, no portfolio kanban. The team is too small and the trunk too
  central for that overhead.
- **Not XP.** Pairing is permitted but not required; many phases are executed
  solo by a human or by an AI agent under human review. The TDD discipline
  here is XP-flavoured but not the full XP package.
- **Not waterfall.** Each phase ships independently to `main` with its own
  acceptance criteria, tests, docs, and changelog entry; there is no global
  design-then-build-then-test sequence across the project.

## The phase as the unit of work

Every change of meaningful size — new feature, refactor, security hardening,
documentation overhaul — begins as a planning document at
[`docs/phases/PHASE_NN.md`](../phases/). The plan states the goal, the
acceptance criteria (in the standard format from
[`docs/STYLE_GUIDE.md`](../STYLE_GUIDE.md) §§5–6), the deliverables, and the
tests that will demonstrate the criteria are met. The plan is reviewed by a
human **before any code is written**.

This protocol is mandatory and is encoded as the first section of
[`AGENTS.md`](../../AGENTS.md) — "📋 Mandatory Planning Protocol — Read
Before Doing Anything". The reason it is enforced rather than recommended:
agents (human or AI) that skip directly to implementation produce code that
matches their internal model of the problem, not the team's. The plan
exists so that a divergence is caught at the cost of editing markdown, not
at the cost of unwinding a branch.

The lifecycle of a phase — branch off `main`, implement, run `make test`,
update `CHANGELOG.md` and `manifest.yaml`, run `make sync`, push, merge — is
documented in [`CLAUDE.md`](../../CLAUDE.md) §"How to Run a Phase". Walked-
through worked examples live in
[`PHASE_ANATOMY.md`](PHASE_ANATOMY.md)<!-- TODO: link will resolve when 106g sibling docs land -->.

## Multi-agent coordination

Several Claude Code agents frequently work in parallel on the same phase:
one writing tests, one writing code, one writing docs, one updating the
changelog. The rules that prevent this from corrupting the trunk are
collected in [`CLAUDE.md`](../../CLAUDE.md) §"Multi-Agent Coordination":

- **Named branches only.** Every agent works on
  `phase-NN-description`. No agent commits directly to `main`.
- **File-ownership map.** Shared files (`Makefile`, `README.md`,
  `CHANGELOG.md`, `requirements.txt`, `config/proxy.yml`,
  `docs/phases/manifest.yaml`, `docker-compose*.yml`) have explicit rules
  about which sections an agent may edit. New work appends; it does not
  rewrite an unrelated agent's section.
- **Merging is the orchestrator's job, not the worker's.** Workers push
  branches; a coordinating run (human or a coordination subagent) merges.
- **Conflict resolution preserves all work.** When two branches both edit
  a shared file, the merge produces a single file containing both sets of
  changes. Discarding work to "win" the merge is forbidden.

The reason for the formality: at any time three to five agents may be
fanning out across the same phase, and without an ownership map their
commits collide on shared files (most painfully on `Makefile` aggregate
targets and the top of `README.md`). Encoding ownership in
[`CLAUDE.md`](../../CLAUDE.md) puts the rule where every agent reads it
before starting work.

## TDD discipline

Phases that change behaviour follow a **two-wave** pattern:

1. **Wave 1 — TDD writer.** Before any production code is added, a writer
   agent produces the test files that encode the phase's acceptance
   criteria. These tests are expected to fail; that failure is what
   defines the contract.
2. **Wave 2 — Coder.** A coder agent makes the failing tests pass and adds
   the supporting production code. The coder is forbidden from weakening
   the tests; if a test is wrong, the coder raises it back to the
   reviewer rather than editing the assertion.

The full methodology — categories of tests required (unit, integration,
chaos/resilience, adversarial/fuzz, false-positive corpus, performance,
end-to-end), where they live, how mocks are organised, and the
phase-completion gate — is in
[`docs/TESTING_STRATEGY.md`](../TESTING_STRATEGY.md). The repository
maintains a target test-to-code ratio of approximately **1.3×** (lines of
test ≥ 1.3 × lines of production code); the rationale, calculation, and
exceptions are documented there.

## Keep-main-green

`main` must always be releasable. Concretely:

- Every merge to `main` requires `make test` to pass on the merging
  branch. The standard local invocation runs the parallel pytest-xdist
  suite (~120 s on the reference workstation) plus the Go unit tests.
- The phase-completion gate (see [`CLAUDE.md`](../../CLAUDE.md) §"How to
  Run a Phase", steps 8–14) requires `make test` to pass *and* the
  documentation gate from
  [`docs/DOCUMENTATION_STANDARDS.md`](../DOCUMENTATION_STANDARDS.md) to
  pass *and* `manifest.yaml` to be updated *and* `make sync` to have
  regenerated derived files. All four happen in one atomic commit.
- If a hook fails, the commit did not happen. The agent fixes the
  underlying issue and creates a **new** commit; `--amend` is not used to
  paper over a hook failure, because amending modifies the *previous*
  commit and risks destroying earlier work.

The conventions for what counts as green — config syntax, log format,
test acceptance-criteria language, doc tone — are codified in
[`docs/STYLE_GUIDE.md`](../STYLE_GUIDE.md). Style is part of the gate, not
an afterthought.

## Acceptance-criteria tagging (REQ-IDs)

Phases that need a machine-checkable trace from requirement to test opt
in to **REQ-ID tagging** by setting `req_tagged: true` in their
`docs/phases/manifest.yaml` entry. Tagged acceptance criteria use the
form:

```
- [ ] REQ-NNN-MM: <human description>. Verified by: <test path>::<test name>
```

`scripts/traceability.py` walks every tagged phase, parses the criteria,
locates the named tests, and fails CI if a `REQ-NNN-MM:` line is missing
the `Verified by:` clause or names a test that does not exist. Untagged
phases (the historical bulk) are skipped — backfilling is not required.

The full grammar, a worked example, and the rationale (regulators ask for
traceability; informal "see the test file" prose does not survive an
audit) are in [`docs/STYLE_GUIDE.md`](../STYLE_GUIDE.md) §6
"Acceptance-Criteria Tags (REQ-IDs)".

## Process metrics

Process health is measured, not asserted. `scripts/process_metrics.py`
walks `docs/phases/manifest.yaml`, the git log, and the CI run history to
emit four numbers:

| Metric | What it measures |
|--------|------------------|
| Phase throughput | Phases completed per calendar month |
| Average phase duration | Days from branch creation to merge to `main` |
| CI reliability | Percentage of `main` CI runs that pass on first try |
| Mean-time-to-green | Hours from a `main` failure to the next green run |

Output is written to
[`retrospectives/latest-metrics.md`](retrospectives/latest-metrics.md) and
read into the quarterly retrospective. The numbers are informational, not
target-setting; we have explicitly avoided turning them into KPIs because
the team is small enough that gaming the metric is easier than improving
the process.

## Retrospectives

Process retrospectives run on a **quarterly cadence**. Each retro is one
markdown file at `docs/engineering-method/retrospectives/YYYY-QN.md`.
The structure — what went well, what didn't, proposed method changes,
outcomes from the previous quarter's proposals — is fixed by
[`retrospectives/TEMPLATE.md`](retrospectives/TEMPLATE.md).

Past retros are not edited; if a method change later proves wrong, that
is recorded in the next retro under "Outcomes from previous quarter".
The first retro covers 2026-Q2 and lives at
[`retrospectives/2026-Q2.md`](retrospectives/2026-Q2.md). The directory
README ([`retrospectives/README.md`](retrospectives/README.md)) explains
how to write one and what inputs to draw from.

## When this method fails

The method is not a guarantee, and treating it as one would be dishonest.
Three classes of failure recur and we name them here so future
contributors recognise them:

1. **Plans that survive review but break on first contact with reality.**
   Phase 101 is the canonical example: the plan was approved, branch
   work began, and a structural assumption about a shared subsystem
   turned out to be wrong only once the implementation was halfway
   built. The branch was stranded. See
   [`docs/phases/PHASE_101_review.md`](../phases/PHASE_101_review.md)
   for the post-mortem. The remedy is **revise the phase doc
   mid-flight** — explicitly, with a commit that updates the plan
   before more code is written. Pretending the original plan was right
   would compound the cost.

2. **Sub-task estimates that drift.** A phase planned as "two days, six
   sub-tasks" routinely lands at five days and ten sub-tasks. The
   estimates are sub-tasks of work the planner could see; the slippage
   is sub-tasks they could not. We have stopped treating these
   estimates as commitments and now treat them as a planning artefact
   only — the acceptance criteria are the commitment.

3. **Retrospectives that surface the same issue twice.** When a 2026-Q2
   retro names an issue that 2026-Q3 names again with the same root
   cause, the proposed remedy in Q2 was wrong or never landed. The
   protocol is to escalate: the Q3 retro must propose a *different*
   remedy and the maintainer schedules a focused phase to enact it,
   rather than allowing the issue to recur into Q4.

The corrective action common to all three is the same: **edit the
artefact, do not paper over it.** Update the phase plan when reality
diverges. Update the retro template if the categories are wrong. Update
[`AGENTS.md`](../../AGENTS.md) if a class of mistake keeps slipping
through the planning protocol. The method is a living set of documents,
not a contract.

## References

| Document | Purpose |
|----------|---------|
| [`CLAUDE.md`](../../CLAUDE.md) | Master plan; multi-agent coordination; how to run a phase |
| [`AGENTS.md`](../../AGENTS.md) | Mandatory Planning Protocol; agent operating rules |
| [`docs/STYLE_GUIDE.md`](../STYLE_GUIDE.md) | Naming, config, log, test, REQ-ID, doc-language conventions |
| [`docs/TESTING_STRATEGY.md`](../TESTING_STRATEGY.md) | Test categories, fixtures, phase-completion gate, 1.3× ratio |
| [`docs/QUALITY_PLAN.md`](../QUALITY_PLAN.md) | Project-wide quality plan; gates and review responsibilities |
| [`docs/engineering-method/CASE_STUDIES.md`](CASE_STUDIES.md) | Worked examples of the method on Phases 15, 82, 200-series<!-- TODO: link will resolve when 106g sibling docs land --> |
| [`docs/engineering-method/PHASE_ANATOMY.md`](PHASE_ANATOMY.md) | Annotated walk-through of one representative phase<!-- TODO: link will resolve when 106g sibling docs land --> |
| [`docs/engineering-method/retrospectives/README.md`](retrospectives/README.md) | Quarterly retrospective cadence and inputs |
