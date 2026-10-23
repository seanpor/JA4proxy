<!--
title: Medium_CVE_Gating_Measure_Then_Extend
audience: developer
last_reviewed: 2026-10-17
phase: 847e
-->

# Phase 847e — MEDIUM-CVE gating (measure, then extend)

> **Status:** COMPLETE (2026-10-22)
> **Size:** MEDIUM
> **Dependencies:** [847c]
> **Branch:** `phase-847e-medium-gating`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/complete/PHASE_847.md`

---

## Goal

Extend the 847 machinery to **MEDIUM** findings, honouring the programme's stated
aim of zero Medium/High/Critical hanging over us — but do so **evidence-first**,
because gating MEDIUM at full-baseline scope is likely unaffordable and promising
literal zero-MEDIUM would be a lie.

This phase is deliberately **measure-then-extend**: it refuses to commit to a
gating scope until the size of the MEDIUM surface is known.

---

## Scope

**In:**

1. Measure the MEDIUM surface across every deployed surface (third-party images,
   first-party images, the Python dependency surface).
2. Publish the measurement, and the decision it implies, in
   `security/medium-inventory.md`.
3. Implement the scope the measurement supports — one of the three in the
   decision table below, chosen by the data and not by preference.
4. Enforce the ratchet: the MEDIUM baseline may only shrink.
5. Extend the monitor to track MEDIUM, so the ratchet is visible rather than
   asserted.

**Out:**

- Fixing the MEDIUM findings themselves (that is the fix-forward bot's job, and
  the upstream projects' job).
- The reachability *binding* (that is 847f). 847e only applies 847f's
  classification **provisionally**, to size the problem; it does not implement
  the checks.
- Any change to the HIGH/CRITICAL gate's behaviour. 847e adds a severity; it
  must not alter what HIGH/CRITICAL already gate.

---

---

## Why measure first

The current gate scans `HIGH,CRITICAL` only. MEDIUM findings in pinned
third-party images are typically **1–2 orders of magnitude more numerous** than
HIGH (transitive Go/OS package CVEs dominate). Extending a *full-baseline* MEDIUM
gate to required-check status would very likely redden every PR permanently —
recreating defect #1 at a larger scale, which is precisely what 847c exists to
prevent.

So the honest position: **zero-MEDIUM is a direction, gated on data.** This phase
produces the data and then extends the machinery in the way the data supports.

---

## The measurement, and the decision it implies

**Measured on 2026-10-21 by `scripts/medium_inventory.py`**; the full report is
`security/medium-inventory.md`, and every number below is that script's output:

| | |
|---|---|
| Unwaived MEDIUM findings | **152**, across 17 image surfaces |
| With a published fix for the same package | **119** (78%) |
| In third-party images / in ours | **149** / **3** |
| On a surface that publishes a host port | **51** |
| Go (stdlib or module) / Python (ours) / OS or base package | **74** / **3** / **75** |
| Reachability known | **0** — see below |

The Python dependency surface is **not** in that count, and is not a zero: pip-audit
reports no severity (its JSON carries id, aliases, fix_versions and description
only), so there is no MEDIUM band to measure there. It is recorded as a surface
with no severity dimension rather than counted clean.

**Reachability is unknown for 149 of the 152.** The third-party images' binaries
and packages have no static reachability signal available to us — their source is
not ours to analyse, and their OS packages are not linked against anything we can
call. The three findings in *our* images are classified **not-imported** by a
source grep (`mcp` is pinned in `requirements.txt` for semgrep and imported by no
first-party module; `pip` is the installer the image upgrades at build time) —
but that is a hand-checked fact, not an assertion the CI makes. Phase 847f is
what turns a reachability claim into an automated assertion, so until then the
honest answer for every finding in the inventory is *unknown*. Nothing here is
recorded as unreachable.

### Decision: the **diff-only MEDIUM gate**

Of the three scopes in the table below, the measurement selects the middle one:

- **Not the full-baseline scope.** It would require all 152 findings to be fixed
  or waived before any PR could pass. 152 hand-written waivers is not a small
  number, and each would need a reachability justification that does not exist
  yet — which means the justifications would be invented. Waiving them in bulk
  without evidence is exactly the dishonesty this programme exists to prevent.
- **Not monitor-only.** The surface is 152 findings, not "very large"; 78% of them
  have a published fix; and the gate only ever scans surfaces the PR *touches*,
  so upstream churn on an untouched surface cannot redden an unrelated PR — the
  defect 847c exists to prevent is structurally impossible here.
- **So: diff-only.** A touched surface fails the PR when it carries a MEDIUM
  finding that is neither recorded in `security/baseline-medium.json` nor waived.
  The same rule HIGH follows, applied to the band the measurement chose.

### What the scope means, concretely

1. **The recorded MEDIUM set is a backlog, not a truth.** It records what we
   carry today. It may only **shrink**.
2. **A new MEDIUM finding is never added to the record.** It is fixed, or waived
   with a justification and an expiry like every other finding. This is the
   ratchet: accretion has to be paid for deliberately, not absorbed by a file
   that grows on its own.
3. **The HIGH/CRITICAL verdict is unchanged.** The two bands are judged against
   two different records, and neither can make the other look dirty.
4. **The honest cost:** a MEDIUM CVE disclosed upstream for a pinned third-party
   image is "new" against the record, so the next PR that touches that image is
   blocked until the finding is fixed or waived. That is the same trade-off the
   HIGH band makes today, and it is the trade the programme asks for: an untriaged
   finding blocks, because "untriaged" is the thing we are trying to get to zero.

---

## Implementation plan

### 847e.1 — The measurement (`scripts/medium_inventory.py`)

A new script that enumerates every surface the same way the baseline does
(third-party refs from the compose files, first-party refs from the Makefile's
`FIRST_PARTY_IMAGES`, and the Python dependency surface) and scans each one at
**MEDIUM** severity, reporting per surface:

- the MEDIUM finding count;
- how many have a **fixed version available** for the package that carries them
  (a fix exists in the same package — the cheapest possible class of fix);
- the packages that contribute the most findings;
- the scan's own severity, so a surface scanned at the wrong severity is
  visible rather than silently empty.

The severity has to become a **parameter** of the scanner
(`scripts/trivy_image_report.py` currently hard-codes `GATING_SEVERITIES`), or
the inventory cannot ask a different question than the gate. That
parameterisation is the one change this phase makes to shared scanning code, and
it must not change the gate's default.

Reachability is recorded **provisionally** and only where a real signal exists:
`govulncheck` gives a called / not-called verdict for the Go findings in our own
code, and nothing else. OS-package findings and findings inside third-party
images are recorded as **unknown**, not as unreachable — a static reachability
signal does not exist for them today, and guessing "unreachable" would be the
one thing this programme is not allowed to do.

### 847e.2 — The decision (`security/medium-inventory.md`)

The decision table below is applied to the measured numbers, and the numbers are
published next to the decision so the reasoning can be audited:

| If the inventory shows… | Then extend MEDIUM as… |
|---|---|
| Small, mostly-fixable surface | Full-baseline MEDIUM gate (same as HIGH), plus auto-fix PRs for the fixable set. |
| Large surface, mostly third-party/unfixable | **Diff-only MEDIUM gate**: fail a PR only if it *introduces* a new unwaived MEDIUM (same rule as HIGH, but never gate the pre-existing baseline). Baseline MEDIUM tracked by the monitor, ratcheted down over time. |
| Very large, largely unreachable | Track MEDIUM in the monitor + registry only (no required gate), with a documented ratchet target. Revisit when 847f's reachability data matures. |

### 847e.3 — The implementation of the chosen scope

Whatever the decision, two things are true of every scope:

- **The MEDIUM baseline is recorded, not assumed.** `security/baseline-medium.json`
  records the MEDIUM findings per surface at the moment of the decision, so the
  pre-existing surface is *known* rather than *inferred*. A finding that is in
  the file is pre-existing; one that is not is new, and the new ones are what
  the gate judges.
- **The gate partitions by severity.** The scan runs once per touched surface
  and the findings are split into the HIGH/CRITICAL set (judged against
  `security/baseline.json`, exactly as today) and the MEDIUM set (judged against
  `security/baseline-medium.json`). A MEDIUM finding must not be able to make a
  HIGH/CRITICAL comparison look dirty, and vice versa.

For the **diff-only** scope, a new unwaived MEDIUM finding on a touched surface
fails the PR, exactly as a new unwaived HIGH does. For the **full-baseline**
scope, every unwaived MEDIUM finding on a touched surface fails the PR — which
is only affordable if the measurement says the count is small enough to waive
honestly, one waiver at a time, with a justification each.

For the **monitor-only** scope, the gate is unchanged and the monitor does the
work; the phase would then be measurement plus reporting, and the phase doc
would say so plainly.

### 847e.4 — The ratchet, not a cliff

The recorded MEDIUM baseline may only **shrink**:

- `security/baseline-medium.json` carries the recorded findings and a
  **ceiling** — the count at the moment of the decision.
- A unit test asserts the recorded count never exceeds the ceiling, and that the
  ceiling never exceeds the value committed by this phase. Lowering the ceiling
  is the only way it moves, and lowering it is an explicit, reviewed edit.
- A **new** MEDIUM finding is therefore never added to the recorded baseline:
  it is either fixed, or waived with a justification like any other finding.
  That is the whole point of a ratchet — accretion has to be paid for
  deliberately, not absorbed by a file that grows on its own.

The ceiling is not compared against a live scan, and that is deliberate: the
Trivy database churns daily, so a live comparison would make the ratchet a
coin-flip. The ratchet is about the *committed record*, which is the thing a
reviewer can actually argue with.

**Ceiling re-measured: 152 → 79 (Phase 847g, 2026-10-23).** The
CVE-2026-111943 image bumps were measured for MEDIUM as well as HIGH/CRITICAL,
and three of the four replacement tags carry no MEDIUM findings at all. The
record and `MEDIUM_CEILING_MAX` were both lowered to the new measurement in the
same commit; a ratchet that is not lowered when the surface genuinely shrinks is
just a number, and leaving it at 152 would have re-permitted 73 findings of
accretion silently.

### 847e.5 — The monitor tracks it

The 847c monitor already diffs every surface against the baseline and files an
issue per new unwaived finding. It is extended to count MEDIUM as well, so the
ratchet is visible: how many MEDIUM findings remain, and whether the number is
going down. A ratchet nobody can see is a ratchet nobody maintains.

### 847e.6 — What the implementation actually did (deltas from the plan)

The plan above was written before the measurement. Four things turned out
differently, and each is recorded here rather than left implicit in the diff.

1. **The severity parameterisation had to reach the shared parser, not just the
   scanner.** `scripts/check_trivyignore_drift.py::vuln_rows` filtered to
   HIGH/CRITICAL unconditionally, so a MEDIUM scan parsed as *no findings at
   all* — the exact silent-wrongness that parser exists to prevent. It now takes
   the band it was asked for, and normalises a comma-separated string: a bare
   `set("MEDIUM")` is the *characters* `{'M','E','D','I','U'}`, which matches
   nothing and reads as "this image is clean". Both faults were found by the
   measurement disagreeing with a hand-checked scan, not by inspection.
2. **One scan pass, two partitions.** The gate and the monitor both scan each
   touched surface once, at `MEDIUM,HIGH,CRITICAL`, and split the findings. Two
   passes would be easier to write and wrong: the vulnerability database moves
   under us, and the two bands have to describe the same moment or their totals
   cannot be compared with anything.
3. **The reachability signal is thinner than planned.** The plan expected
   `govulncheck` to give a called / not-called verdict for our own Go findings.
   Our own images carry **no** Go MEDIUM findings at all — the three are `pip`
   and `mcp`, both Python — so there is nothing for it to say. The three are
   classified *not-imported* by a source grep, and the inventory records the
   reachability of everything else as **unknown**.
4. **The ratchet's maximum is held by the test, not by the record.** A record
   that could raise its own ceiling would be a record that can grow without
   anybody deciding that it may. `tests/unit/test_medium_ratchet.py` holds the
   committed maximum, so raising it means editing a test — a reviewed diff.

The gate's MEDIUM scope is a module constant (`MEDIUM_SCOPE` in
`scripts/scan_regression.py`), not a runtime flag: a flag would make "is MEDIUM
gated?" a question with more than one answer, and the answer has to be the same
for every caller, in CI and on a laptop, forever. `MEDIUM_SCOPE = "off"` restores
the pre-847e behaviour exactly, and a test pins that.

---

## Test strategy

- **The inventory is a measurement, not a decoration:** the script runs against
  the real surfaces, and the numbers in `security/medium-inventory.md` are the
  script's output, not a hand-written summary. The same scan re-run produces
  the same numbers for the same images and the same database — so a change in
  the inventory means the surface moved, not that the prose drifted.
- **The severity parameterisation is regression-checked:** the scanner's default
  severity set is unchanged, so the HIGH/CRITICAL gate cannot have been altered
  by the MEDIUM work; a test asserts the default is still `HIGH,CRITICAL`.
- **Ratchet:** the recorded MEDIUM baseline count never exceeds the recorded
  ceiling, and the ceiling never exceeds the value this phase committed;
  lowering it is an explicit, reviewed edit.
- **Gate correctness:** a PR that introduces a new unwaived MEDIUM finding on a
  touched surface fails; a PR that does not touch the surface passes; a PR that
  touches a surface whose MEDIUM findings are all in the recorded baseline
  passes. And — the negative that matters — the HIGH/CRITICAL verdict is
  unchanged by the presence of MEDIUM findings, and vice versa.
- **The monitor:** the MEDIUM count is reported, and a surface whose MEDIUM
  count *rose* is visible.
- Run `make preflight`.

---

## Acceptance criteria

- [ ] `security/medium-inventory.md` exists with per-image/dep MEDIUM counts,
      fixability, and reachability breakdown — and the numbers in it are the
      script's output.
- [ ] A documented decision selects one of the three gating scopes, justified by
      the inventory numbers, and the decision says plainly which position is
      being taken.
- [ ] The chosen scope is implemented and the ratchet test is in place.
- [ ] The HIGH/CRITICAL gate's behaviour is unchanged (regression-checked).
- [ ] MEDIUM waivers (if any) live in `security/waivers.yaml` like all others.
- [ ] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `scripts/medium_inventory.py` | New — the measurement |
| `security/medium-inventory.md` | New — the data (generated) |
| `security/baseline-medium.json` | New — the recorded MEDIUM baseline + ratchet ceiling (generated) |
| `scripts/trivy_image_report.py` | The scanner's severity set becomes a parameter (default unchanged) |
| `scripts/check_trivyignore_drift.py` | The shared parser takes the band it was asked for (it hard-coded HIGH/CRITICAL, which silently emptied a MEDIUM scan) |
| `scripts/scan_baseline.py` | `scan_image` / `record_findings` take the band; the MEDIUM record's path |
| `scripts/scan_regression.py` | The gate judges both bands, each against its own record |
| `scripts/scan_baseline_monitor.py` | Measures MEDIUM in the same scan pass and reports it against the record |
| `tests/unit/test_medium_ratchet.py` | New — the ratchet, and that the two bands do not bleed |
| `tests/unit/test_scan_regression.py` | Extend — MEDIUM gate correctness |
| `tests/unit/test_scan_baseline_monitor.py` | Extend — the monitor's MEDIUM measurement |
| `docs/fragments/phase-847e-medium-gating.md` | Changelog fragment |

---

## Close-out (2026-10-22)

Landed as designed: diff-only MEDIUM gate + ratchet, ceiling 152.

One defect was found **after** the merge, by Phase 847f's reachability checks: the
inventory's exposure classifier split a port mapping on the first `:`, which
mangles the interpolated form the monitoring stack actually ships
(`"${AGENT_BIND_IP:-127.0.0.1}:${HOST_PORT_GRAFANA:-3000}:3000"` → host read as
`"${AGENT_BIND_IP"`). Grafana, Prometheus and Alertmanager were therefore reported
as **published** when the committed configuration binds them to loopback — the
opposite of what the function's own docstring promised. The parsing now lives in
`scripts/compose_exposure.py`, shared with the 847f checks, and the inventory was
re-measured against live Trivy: **152 findings, unchanged**, `published` corrected
from 51 to **1**. The ceiling was not touched — a measurement correction is not a
re-baseline.

---

## Notes for implementer

- **Do not skip 847e.1.** Extending MEDIUM to a required full-baseline gate
  without the inventory is the single most likely way this programme recreates the
  problem it is meant to solve.
- If the diff-only scope is chosen, say so plainly in the fragment and the
  inventory — "we gate MEDIUM on new findings only, and ratchet the baseline" is
  an honest, defensible position. Pretending to full-baseline MEDIUM while
  waiving most of it is not.
