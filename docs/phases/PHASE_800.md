# Phase 800 — Code Health Loop: Gate-Runner, Fixing Skill & Honest Reporting

> **Run the real validation gates (`make lint` → `make scan` → `make test`) in a
> loop of at most 5 cycles, fix what fails, verify every fix, and report the
> truth in ≤33 lines × ≤170 chars.** Detection, fixing, and committing are
> deliberately separate concerns with different owners.

## Status: IN_PROGRESS

Reworked 2026-07-18 after a critical review and live verification found the
original implementation unsafe (see *History* below). The tooling is rebuilt;
the phase completes after one audited run whose report is demonstrably accurate.

## The Architecture — detect / fix / commit are different jobs

| Role | Owner | Rules |
|---|---|---|
| **Detect + report** | `scripts/phase-800-code-health.sh` | Deterministic. Runs gates, extracts failures, renders the report, sets the exit code. Never fixes, never touches git. |
| **Fix** | `/code-health` skill (`.claude/skills/code-health/SKILL.md`) — an agent, or a human | Judgment work: read logs, fix root causes, re-run the failed gate to verify **before** claiming anything. |
| **Commit + review** | Human (via the agent's explicit, per-fix commits) | Named files only — `git add -A` is forbidden. Every commit message says what, why, and lists its files. |

Why the split: a script can only fix trivia, so a script that promises to "fix
all the issues" ends up either lying about what it fixed or committing things
nobody reviewed. The original Phase 800 script did both (verified live —
`PHASE_800_notes.md`). Fixing needs judgment; judgment needs verification;
commits need review.

## Gate-runner contract

```
scripts/phase-800-code-health.sh              # all gates, full tier (CI-equivalent)
scripts/phase-800-code-health.sh --fast       # all gates, fast tier
scripts/phase-800-code-health.sh --gate lint  # single gate (mid-fix verification)
```

| Gate | Full tier (default) | Fast tier (`--fast`) |
|---|---|---|
| lint | `make lint` | `make lint-static` |
| scan | `make scan` | `make scan-js` |
| test | `make test` (incl. Go race + integration) | `make test-unit` |

The report always names the tier — a fast-tier CLEAN is never presented as
CI-equivalent.

**Exit codes** — 0 `CLEAN` (every gate passed) · 1 `RESIDUAL` (failures, but
different from the previous all-gates run) · 2 `STUCK` (identical failure
fingerprint to the previous all-gates run — no progress) · 64 `REFUSED`
(on `main`, dirty tree on an all-gates run, or bad usage).

**Guards** — refuses to run on `main`; an all-gates run refuses a dirty tree so
its report describes one reproducible commit; `--gate` runs allow a dirty tree
(that is how an in-flight fix is verified before being committed).

**Report** — ≤33 lines × ≤170 chars, enforced in the generator (truncation +
elision), not merely asserted: status, tier, branch@commit, per-gate
result/duration, `REMAINING ISSUES` (salient failure lines, elided with a
count when over budget), full-log paths, fingerprint, exit-code legend. Full
logs: `.local/code-health/run-<timestamp>-<pid>/` (gitignored; the pid suffix
prevents same-second and concurrent-run collisions).

## Scope

**In scope:** running the gates; fixing lint/style/type findings on named
files; CVE remediation by dependency pin/bump (checking parent constraints
first); fixing genuine code or test *defects*; documenting acknowledged
residuals.

**Out of scope:** architectural changes; feature work; editing test
expectations or thresholds to make failures pass; disabling or weakening any
check (`--no-verify`, `# noqa`, ignore-lists, `.trivyignore`) without explicit
user approval of that specific suppression; committing anything not
deliberately changed for a stated reason.

## Acceptance Criteria

Accuracy is the bar; green is the goal. A run that ends RESIDUAL with an
accurate report and ticketed residuals **passes** this phase; a fabricated
CLEAN fails it.

- [ ] Gate-runner refuses `main` and dirty all-gates runs (exit 64); is
      shellcheck-clean; never invokes a fixer or git write.
- [ ] Exit codes 0/1/2/64 demonstrably match observed gate results.
- [ ] Report provably ≤33×170 (`wc -l` / `wc -L`), names its tier, and lists
      remaining issues + full-log paths.
- [ ] Every fix claimed in a loop report is verified by a gate re-run and
      countable in `git diff --stat`; fix counts match reality.
- [ ] All commits name their files explicitly; none contain unrelated changes.
- [ ] One audited loop run completed; residuals (if any) ticketed or
      acknowledged with dated comments naming their removal condition.
- [ ] `docs/phases/manifest.yaml` updated to COMPLETE only after all of the
      above hold.

## Termination semantics

| Condition | Meaning | Action |
|---|---|---|
| exit 0 | all gates green | emit report; done |
| exit 1 | failures changed | next cycle (≤5) |
| exit 2 twice in a row | no progress | stop; report honestly; ticket |
| cycle 5 reached | budget exhausted | stop; report honestly; ticket |

## History — why this phase was reworked

The original implementation (one bash script that "fixed" and auto-committed)
was reviewed and then verified live in isolated clones on 2026-07-18. Verified
defects: fix counts fabricated in both directions ("3" for 18 changed files,
"3" for zero); `git add -A` committed a planted "DO NOT COMMIT" file and, on a
`main` checkout, committed straight to `main`; every path exited 0, including
`--cycles 0`/garbage args which printed "✅ CLEAN" having run nothing; gates
were never re-run after fixes (tree still red after "FIXED"); it ran weaker
gates than documented; the phase was marked COMPLETE while its own criteria
failed. Full detail and evidence: `PHASE_800_notes.md`.

## Related Phases

- Phase 311/312 — pip-audit resilient wrapper (CVE gate this loop drives)
- Phase 146 — `make lint` / `scan` / `test` aggregate gates
- Phase 524 — documentation-audit model for doc-health fixes
