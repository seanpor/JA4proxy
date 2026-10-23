<!--
title: Dead_Waiver_Detection_Pip_Surface
audience: developer
last_reviewed: 2026-10-23
phase: 848
-->

# Phase 848 — Dead-waiver detection (the pip surface)

> **Status:** IN_PROGRESS (2026-10-23)
> **Size:** SMALL
> **Dependencies:** 847a, 847c, 847e
> **Branch:** `phase-848-dead-pip-waiver-detection`
> **Follows:** Phase 847 (closed 2026-10-23) — issue #642

---

## Goal

Make a **dead waiver** impossible to keep silently, on the one surface where it
is currently invisible: `.pip-audit-ignores`.

A dead waiver is an `--ignore-vuln <ID>` for a finding that no longer exists. It
looks harmless and is not: the ignore outlives the finding, so if a later change
regresses the pinned dependency back into the vulnerable range, the audit reports
the CVE and the ignore **suppresses it**. That is the "zero silent findings"
property Phase 847 exists to enforce, defeated by the one artifact that property
does not watch.

## Why this is not covered today

Two independent reasons, and both have to be fixed together:

1. **The monitor runs pip-audit *with* the ignore list** (`scan_baseline.pip_audit_cmd`
   hard-codes `--ignore-vuln` args from `.pip-audit-ignores`). It therefore never
   learns that a waived id has stopped being reported — the id is filtered before
   it sees the output.
2. **The only dead-waiver check is Trivy-only** (`scripts/check_trivyignore_drift.py
   --fail-on-dead`, which reads a directory of Trivy JSON). Nothing reads
   `.pip-audit-ignores` against a pip-audit result.

Found while closing 847: an audit with the ignore list disabled reported **two**
findings while `.pip-audit-ignores` held **nine** ids. Seven waivers had been dead
for some time (four urllib3, pygments, protobuf, click) — each one a live
suppression waiting for a regression. They were removed by hand (registry 28 →
21); this phase makes the next one impossible to miss.

## Scope

### 1. One audit, both answers (the core change)

The monitor's pip surface stops querying pip-audit with the ignores and does the
filtering **in process**, from the registry:

```text
audit without ignores  ->  all findings      (one network call, full picture)
        |
        +-- id/alias in .pip-audit-ignores  -> waived (not "unwaived", not filed)
        +-- not waived                      -> unwaived (today's behaviour)
        +-- ignored id reported by nobody   -> DEAD
```

Why in-process rather than a second audit: the audit is the expensive, networked
part, and a second run is a second thing to drift. Why not leave the ignore flags
and diff afterwards: the flags are what hide the answer.

**Alias-aware.** pip-audit reports one primary id per finding plus `aliases`
(e.g. `GHSA-…`). A waiver naming an alias must count as *live*, not dead, or the
fix would file false dead-waiver issues for correctly-waived findings.

### 2. Report it, and make it self-healing

- `render_report()` grows a **Dead waivers** section: the ids, and the exact
  command that removes them (the validated `render_waivers.remove_entries`
  splice — never a hand edit).
- The monitor files **one deduplicated issue per dead id**, titled
  `[cve-waiver] <ID>`, and **reopens** it if it comes back — the same
  one-issue-per-thing rule `plan_issues` already follows for findings.
- When the id is no longer dead (removed or genuinely live again), an open
  `[cve-waiver] <ID>` issue is **closed automatically**, so the loop does not
  leave stale alarms behind. That closure is what makes this a control loop
  rather than a growing list.

### 3. Keep the gate's behaviour identical

`pip_audit_cmd()` keeps its ignore flags — the required `scan-regression` and
`lint-static` paths are unchanged. Only the monitor's *measurement* audit omits
them, then subtracts in process, which is provably the same set as before plus
the dead ids. A test pins that equivalence so a future refactor cannot quietly
change what the required gate ignores.

## Implementation plan

| Step | Change | File |
|---|---|---|
| 1 | `run_pip_audit()` / `pip_audit_cmd()` accept "no ignores" without changing the default | `scripts/scan_baseline.py` |
| 2 | `split_waived(findings, waived)` → `(unwaived, dead)`; alias-aware; pure | `scripts/scan_baseline.py` |
| 3 | `ignored_ids(path)` parses both rendered formats (bare id, `--ignore-vuln ID`) | `scripts/render_waivers.py` |
| 4 | Monitor: one unignored audit; subtract; carry `dead` into report + issue plan | `scripts/scan_baseline_monitor.py` |
| 5 | `plan_dead_waiver_issues()` / `plan_waiver_closures()` (pure, deduplicated) | `scripts/scan_baseline_monitor.py` |
| 6 | `render_report(..., dead=…)` section + headline count | `scripts/scan_baseline_monitor.py` |
| 7 | Docs: `SCRIPTS.md`, `MAINTENANCE_CALENDAR.md`; fragment; note in 847's limits | `docs/` |

## Test strategy

Every test asserts the **fixed** behaviour, and each was chosen so that reverting
the fix makes it fail:

1. `split_waived` direct: waived-and-present → not unwaived, not dead; waived-and-
   absent → **dead**; unwaived-and-present → unwaived; **alias-only match → not
   dead** (this is the case a naive `set - set` gets wrong).
2. `ignored_ids` reads the **real** `.pip-audit-ignores` (not a fixture): the set
   must equal the registry's pip-sourced ids. A hard-coded list in the script
   fails this.
3. Monitor end-to-end with a fake audit payload: `current["pypi"]` carries the same
   findings as the old `--ignore-vuln` run **and** the dead id surfaces in the
   report; revert the in-process filter and the finding reappears as unwaived.
4. Issue planning: one issue per dead id, no duplicate when one is already open,
   reopen when closed, and an open issue whose id is live again is planned for
   **closure**.
5. `pip_audit_cmd()` default still contains `--ignore-vuln` (the required gates
   are untouched).

## Acceptance criteria

- [ ] A dead pip waiver appears in the monitor report and as an issue on the next
      run, without any human remembering to look.
- [ ] Removing that waiver closes its issue on the following run.
- [ ] A live waiver (present finding) produces neither a report line nor an issue.
- [ ] Alias-named waivers are never reported dead.
- [ ] The required `scan-regression` pip path is byte-identical in behaviour.
- [ ] `make preflight` green.

## Out of scope

- The Trivy surface — already covered by `check_trivyignore_drift --fail-on-dead`
  and the daily re-affirmation job.
- Automatically *deleting* the waiver: removal stays a reviewed registry edit
  because narrowing a live exemption is the one action that must not be automatic.
- Expired waivers (847d's renewal path).

---

## Close-out

See the bottom of this document after the work lands.
