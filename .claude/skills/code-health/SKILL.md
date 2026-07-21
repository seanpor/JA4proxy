---
name: code-health
description: Iterative code-health loop — run the lint/scan/test gates via the Phase 800 gate-runner, fix failures with judgment, verify every fix by re-running the failed gate, commit explicitly named files, max 5 cycles, then report honestly. Use for "make the repo clean", "fix lint/scan/test", or periodic health checks.
---

# Code Health Loop (Phase 800)

Bring the repo's lint / scan / test gates green **honestly**. The gate-runner
(`scripts/phase-800-code-health.sh`) detects and reports; **you** fix with
judgment; the human reviews the commits. Never blur those roles: the script
must not fix, and you must not claim a fix the gate has not confirmed.

Design rationale and report contract: `docs/phases/PHASE_800.md`.

## Preconditions — stop and resolve before any gate runs

1. **Work branch, never `main`.** If on `main`: `git checkout -b phase-800-code-health-<yyyymmdd>`.
2. **Clean working tree.** If there are uncommitted changes you did not make in
   this loop, stop and ask the user — never sweep someone's WIP into your work.

## The loop (max 5 cycles)

1. **Baseline** — run all gates: `scripts/phase-800-code-health.sh --fast`
   (use the no-flag full tier when the user asked for a CI-equivalent run; say
   which tier you ran in the report). Exit 0 → emit the report, done.
2. **Diagnose** — for each FAIL gate, read its log under
   `.local/code-health/run-*/`. Identify root causes, not symptoms.
3. **Fix with judgment** — smallest correct change:
   - mechanical style → targeted fixer on the named files only
     (e.g. `ruff check --fix <file>`), never repo-wide sweeps;
   - CVEs → pin/bump per repo pattern (bottom of `requirements.txt`, comment,
     see the `mcp`/`protobuf` precedents); check the parent's constraints on
     PyPI first — an impossible pin blows up pip resolution;
   - code/test defects → fix the code. A wrong *test expectation* is a finding
     for the user, not something you silently edit.
4. **Verify before claiming** — re-run just that gate:
   `scripts/phase-800-code-health.sh --fast --gate lint|scan|test`.
   A fix that was not re-verified is not a fix and must not be counted.
5. **Commit each verified fix** — explicitly named files only. `git add -A`,
   `git add .`, and `git commit -a` are forbidden. The message states what,
   why, and lists every file.
6. **Re-run all gates** (needs the clean tree from step 5). Exit 2 (STUCK) on
   two consecutive runs, or cycle 5 reached → stop; report what remains.

## Hard guardrails

- Never weaken a check to pass it: no `--no-verify`, `# noqa`, `//nolint`,
  `.trivyignore`, `--ignore-vuln`, threshold edits or test-expectation changes
  without the user's explicit approval of that specific suppression — and any
  approved suppression gets a dated comment naming what unblocks its removal.
- Never commit a file you did not deliberately change for a stated reason.
- CLAUDE.md invariants (fail-open, ALPN bypass, IPv6 handling) outrank lint.

## Final report (mandatory)

Emit the gate-runner's last report (≤33 lines × ≤170 chars — it enforces
this), then, in prose: what was fixed (counts from `git diff --stat`, never
from attempts), what remains with file:line, and residuals ticketed or listed
for the user. **An accurate RESIDUAL report is success; a fabricated CLEAN is
failure.**
