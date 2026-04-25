<!--
title: "Engineering-Method Retrospectives"
audience: maintainers, contributors
last_reviewed: 2026-04-24
phase: 106e
-->

# Retrospectives

This directory holds the project's quarterly process retrospectives: short
docs that record what went well, what didn't, what method changes the team
proposes for the next quarter, and what came of the previous quarter's
proposals. Per-phase notes (`docs/phases/PHASE_NN_notes.md`) capture
phase-specific lessons; **these retros are the rollup**.

The cadence is **quarterly**. The first retro covers 2026-Q2 (April–June
2026). Each retro is one markdown file named `YYYY-QN.md`. Past retros are
not edited; if a method change later turns out to have been wrong, that goes
in the next retro under "Outcomes from previous quarter".

## How to write one

1. Copy [`TEMPLATE.md`](TEMPLATE.md) to `YYYY-QN.md`.
2. Read the `PHASE_NN_notes.md` and `PHASE_NN_review.md` files for the
   quarter's phases.
3. Skim `git log --oneline` for the quarter; flag commits whose messages
   reveal friction (revert, fix-up, "stranded", "abandon", "rework").
4. Fill in the four sections — keep it specific. Cite phase numbers and
   commit SHAs where they help.
5. Link the auto-generated metrics file
   ([`latest-metrics.md`](latest-metrics.md), produced by
   `scripts/process_metrics.py` — sibling Phase 106e tooling) at the end.

## Past retros

- [2026-Q2](2026-Q2.md) — inaugural retrospective; covers Phases 100–106.

## Generated metrics

[`latest-metrics.md`](latest-metrics.md) is auto-generated monthly by
`scripts/process_metrics.py`. It captures phase throughput, average phase
duration, CI-reliability percentage, and mean-time-to-green after main
breaks. It is informational, not target-setting; see the script header
for the data sources and refresh cadence.
