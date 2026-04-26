<!--
title: "Developer & Contributor — Audience Entry Point"
audience: developers
last_reviewed: 2026-04-25
phase: 105
-->

# Developer & Contributor

> **Audience entry point.** This page is the curated index for human
> contributors landing on the repo. **Topical developer content lives in
> `docs/developer/`** (per-signal recipes, architectural patterns, etc.); this
> directory describes **how the team works** and how a new contributor goes
> from clone to first merged PR.

If you are an AI agent, read `CLAUDE.md` and `AGENTS.md` instead — they are the
agent-orchestration variant of the same protocol.

## Production runtime

The Go proxy (`cmd/proxy/`, `internal/`, built to `bin/proxy`) is the
production runtime. The Python proxy (`proxy.py`, `src/security/`) is a
**prototyping surface** — use it to prove a new signal idea, then port to Go
before it touches real traffic. Default to the Go side unless your task is
explicitly Python prototyping or fixing the Python prototype itself.

## Pick your path

### First-time contributor

1. [`GETTING_STARTED.md`](GETTING_STARTED.md) — clone, build, test, run, in
   ~30 minutes.
2. [`HOW_WE_WORK.md`](HOW_WE_WORK.md) — branch flow, commit conventions, the
   keep-main-green policy, PR etiquette.
3. [`TDD_AND_TESTING.md`](TDD_AND_TESTING.md) — the red→green→refactor loop and
   what tests every change must include.

### Returning contributor

- [`CI_AND_QUALITY_GATES.md`](CI_AND_QUALITY_GATES.md) — what every CI workflow
  enforces and how to reproduce a CI failure locally.
- [`PHASE_LIFECYCLE.md`](PHASE_LIFECYCLE.md) — running a phase end-to-end,
  human edition: planning protocol, branch naming, close-out checklist.
- [`../runbooks/main_is_red.md`](../runbooks/main_is_red.md) — operational
  response when CI on `main` goes red.

### Maintainer

- [`HOW_WE_WORK.md`](HOW_WE_WORK.md) §Keep-main-green policy — your SLA.
- [`PHASE_LIFECYCLE.md`](PHASE_LIFECYCLE.md) §Phase close-out checklist — what
  must be true before a phase can be marked COMPLETE in
  `docs/phases/manifest.yaml`.
- [`CI_AND_QUALITY_GATES.md`](CI_AND_QUALITY_GATES.md) §SHA-pinning rule — how
  Dependabot bumps are reviewed and reflected in `tests/test_workflow_pinning.py`.

## Track index

| Doc | Purpose |
|-----|---------|
| [`GETTING_STARTED.md`](GETTING_STARTED.md) | Local dev environment, prereqs, first build and test run |
| [`HOW_WE_WORK.md`](HOW_WE_WORK.md) | Trunk-based dev, branch naming, commit format, keep-main-green policy |
| [`TDD_AND_TESTING.md`](TDD_AND_TESTING.md) | TDD loop, test categories, mock rules, phase-gate rule |
| [`CI_AND_QUALITY_GATES.md`](CI_AND_QUALITY_GATES.md) | What every CI workflow enforces; reproduce-locally commands |
| [`PHASE_LIFECYCLE.md`](PHASE_LIFECYCLE.md) | Running a phase end-to-end; close-out checklist |
| [`../runbooks/main_is_red.md`](../runbooks/main_is_red.md) | Operational response when CI on `main` goes red |

## Authoritative references (do not duplicate)

These are the source-of-truth documents the track docs above cite rather than
copy:

- [`../../CLAUDE.md`](../../CLAUDE.md) — architecture, cross-cutting requirements,
  decision log
- [`../../AGENTS.md`](../../AGENTS.md) — mandatory planning protocol, agent rules
- [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) — Day-1 setup, project
  structure, code style, completing-a-phase mechanics
- [`../STYLE_GUIDE.md`](../STYLE_GUIDE.md) — naming conventions, log format,
  config syntax, Prometheus naming
- [`../TESTING_STRATEGY.md`](../TESTING_STRATEGY.md) — canonical test methodology
- [`../DOCUMENTATION_STANDARDS.md`](../DOCUMENTATION_STANDARDS.md) — CHANGELOG,
  REDIS_SCHEMA, runbook, ADR formats
- [`../REDIS_SCHEMA.md`](../REDIS_SCHEMA.md) — every Redis key pattern in use
- [`../developer/`](../developer/) — topical developer recipes (per-signal,
  per-subsystem)

If a fact appears here that contradicts one of the canonical references above,
the canonical reference wins. Open a PR to fix this index, not the source.
