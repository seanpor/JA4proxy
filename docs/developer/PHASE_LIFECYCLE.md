<!--
title: "Phase Lifecycle — Human Edition"
audience: developer
last_reviewed: 2026-04-25
phase: 105
-->

# Phase Lifecycle

This page is the **human-contributor** version of the phase protocol. It
covers running a phase end-to-end: planning, branching, committing,
syncing the manifest, and closing. The agent-orchestration variant — same
content, more enforcement detail — is in
[`../../AGENTS.md`](../../../AGENTS.md). Where this page summarises a rule,
that file is the source of truth.

> **Production runtime is the Go proxy daemon (`ja4pd`).** A phase that adds a signal
> lands implementations in Go, and the configuration wizard (`make init`) or Go CLI (`ja4p`)
> handles configuration and verification.

---

## Mandatory planning protocol

**Write the plan before writing code.** Every phase starts with a
`docs/phases/PHASE_NN.md` document that the user reviews and approves.
The full protocol is in [`../../AGENTS.md`](../../../AGENTS.md) §Mandatory
Planning Protocol; the summary:

1. Pick the next available phase number from
   `docs/phases/manifest.yaml`.
2. Create `docs/phases/PHASE_NN.md` with these sections:
   - **Goal** — one paragraph: what is being built and why.
   - **Scope** — exact list of files to be created or modified.
   - **Implementation plan** — numbered steps in execution order.
   - **Test strategy** — categories required and what they verify.
   - **Acceptance criteria** — explicit, checkable conditions for "done".
   - **Out of scope** — what this phase will not touch.
3. Present the plan and **wait for explicit approval** before opening a
   branch. Code without a reviewed plan tends to drift and require rewrites;
   the plan is the contract.

If the user explicitly waives the plan ("just do it"), record the waiver in
the phase notes.

---

## Branch naming

```
phase-NN-short-description
```

Examples in this repo: `phase-105-docs-restructure`,
`phase-202-supply-chain`. The number matches the manifest entry; the
description is two to four kebab-case words.

Non-phase work uses `feat/`, `fix/`, or `chore/` prefixes — see
[`HOW_WE_WORK.md`](HOW_WE_WORK.md) §Branching.

```bash
git checkout main
git pull
git checkout -b phase-NN-description
```

---

## Commit cadence

- Commit after each meaningful chunk (a function, a test, a doc section).
- Commit message format `phase-NN: description`, with a `Co-Authored-By:`
  trailer. See [`HOW_WE_WORK.md`](HOW_WE_WORK.md) §Commits.
- Stage only files you own per the file-ownership table in
  [`../../CLAUDE.md`](../../../CLAUDE.md) §File Ownership. Do not edit shared
  files outside the rules in that table.

A phase commit history with 10–30 atomic commits is normal. A 1-commit
phase with 800 lines of diff is a smell: rebase to split it before review.

---

## Implementing

Follow the acceptance criteria in `docs/phases/PHASE_NN.md`. Run
`make test` after each meaningful change — every section must be green
([`TESTING_STRATEGY.md`](TESTING_STRATEGY.md) §Phase-gate-must-pass). If the
phase touches scoring or pipeline logic, also run `make check-scores` and
`make parity-check`.

If the work expands beyond the original scope, **update the phase doc
first**, get re-approval, then implement. Do not silently widen the scope.

---

## `make sync` — keep the roadmap consistent

`docs/phases/manifest.yaml` is the single source of truth for phase status.
After editing the manifest:

```bash
make sync
# Or: python3 scripts/sync-roadmap.py
```

`make sync` regenerates `docs/phases/TODO.md` and
`docs/reference/PROJECT_STATUS.md`. These files are read-only outputs of the manifest
— never hand-edit them, and always commit the regenerated versions
together with the manifest change.

Run `python3 scripts/lint-phases.py` (or `make lint-phases`) before
committing. It catches broken `action_plan` paths, stale phase numbers in
H1 headings, and invalid status values, and must exit 0.

---

## Phase close-out

**Use the `/close-phase` slash command.** It orchestrates every gate that
agents have historically skipped. Defined in
`.claude/commands/close-phase.md` and backed by `scripts/close-phase.sh`
for the mechanical checks.

If you cannot use the slash command, run `bash scripts/close-phase.sh`
manually and follow every step in `.claude/commands/close-phase.md` by
hand. The script runs ruff, gofmt, go vet, go test, `make test`, and
`make sync` — and must exit 0.

### Close-out checklist (≤10 items)

- [ ] On a feature branch, working tree clean.
- [ ] All acceptance criteria in `docs/phases/PHASE_NN.md` satisfied.
- [ ] `make test` is fully green locally (paste tail into PR description).
- [ ] `CHANGELOG.md` has a Phase NN entry in the standard format
      (see [`DOCUMENTATION_STANDARDS.md`](DOCUMENTATION_STANDARDS.md)).
- [ ] `docs/reference/REDIS_SCHEMA.md` updated for every new Redis key.
- [ ] If scoring/pipeline affected: `make check-scores` and
      `make parity-check` exit 0.
- [ ] `docs/phases/manifest.yaml` has `status: COMPLETE`,
      `completed: YYYY-MM-DD`, and resolved gaps removed.
- [ ] `make sync` run as a generation check (TODO.md / PROJECT_STATUS.md are
      gitignored build artifacts — Phase 332 — not staged).
- [ ] Atomic commit: code + CHANGELOG fragment + manifest in one commit.
- [ ] PR opened, every required CI check green, merged, post-merge CI on
      `main` confirmed green.

The full close-out narrative — pre-flight, local gate, independent
critical review, post-merge verification — is in
[`../../AGENTS.md`](../../../AGENTS.md) §Phase Close-Out.

---

## Cross-references

- Architectural rules and decision log:
  [`../CLAUDE.md`](../../CLAUDE.md)
- Agent-orchestration variant of this protocol:
  [`../AGENTS.md`](../../AGENTS.md)
- Branch flow, commit conventions, keep-main-green policy:
  [`HOW_WE_WORK.md`](HOW_WE_WORK.md)
- Test discipline and the phase gate:
  [`TESTING_STRATEGY.md`](TESTING_STRATEGY.md)
- CI workflows and quality gates:
  [`QUALITY_PLAN.md`](QUALITY_PLAN.md)
- Documentation standards (CHANGELOG, REDIS_SCHEMA, ADR formats):
  [`DOCUMENTATION_STANDARDS.md`](DOCUMENTATION_STANDARDS.md)
