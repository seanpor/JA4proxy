<!--
title: "Engineering Method"
audience: architects, contributors
last_reviewed: 2026-04-25
phase: 106
-->

# Engineering Method

How JA4proxy is built: phase-based incremental delivery, multi-agent
coordination, mandatory planning, and quarterly retrospectives. This
directory is the entry point for anyone trying to understand *how* the
project is run, separate from *what* the project does.

The canonical operational rules — branch naming, file ownership, push
discipline — live in [`CLAUDE.md`](../../CLAUDE.md) §Multi-Agent
Coordination, §How to Run a Phase, and §Cross-Cutting Requirements. The
documents in this directory explain the reasoning, show worked examples,
and surface the lessons learned in retrospectives.

## What lives here

- [`METHOD.md`](METHOD.md) — Formal statement of the engineering method:
  why phase-based delivery, what the planning protocol requires, how TDD
  and keep-main-green interact with multi-agent work, and what the method
  is *not* (not Scrum, not SAFe, not XP). Read this first if you are
  evaluating the project's process or onboarding as an architect.

- [`CASE_STUDIES.md`](CASE_STUDIES.md) — Three worked examples drawn from
  real phases: the Phase 15 Go rewrite (architecture evolution), Phase 82
  policy-as-code (feature design), and the Phase 200-series security
  hardening (incident-to-improvement). Each shows what was planned, what
  was delivered, and what had to be revised. Read this if you want to see
  the method applied, not just described.

- [`PHASE_ANATOMY.md`](PHASE_ANATOMY.md) — Annotated walk-through of one
  representative phase from plan → review → implementation → close. Use
  this as the template when authoring a new `PHASE_XX.md`.

- [`retrospectives/`](retrospectives/README.md) — Quarterly process
  retrospectives. Includes the inaugural 2026-Q2 retro, the template,
  and the rolling `latest-metrics.md` snapshot consumed by the quality
  plan. Read this if you want to know what is currently broken about the
  process and what is being fixed.
