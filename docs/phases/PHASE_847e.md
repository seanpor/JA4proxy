<!--
title: Medium_CVE_Gating_Measure_Then_Extend
audience: developer
last_reviewed: 2026-10-17
phase: 847e
-->

# Phase 847e — MEDIUM-CVE gating (measure, then extend)

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** [847c]
> **Branch:** `phase-847e-medium-gating`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Extend the 847 machinery to **MEDIUM** findings, honouring the programme's stated
aim of zero Medium/High/Critical hanging over us — but do so **evidence-first**,
because gating MEDIUM at full-baseline scope is likely unaffordable and promising
literal zero-MEDIUM would be a lie.

This phase is deliberately **measure-then-extend**: it refuses to commit to a
gating scope until the size of the MEDIUM surface is known.

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

## 847e.1 Inventory (the gate on the decision)

Run a full MEDIUM scan across every deployed image/dep and record:

- total MEDIUM count per image/dep;
- how many have an **available fix** (bumpable now);
- how many are **reachable** vs present-but-unreachable (847f's classification,
  applied provisionally);
- how many would be **newly introduced** by a typical dep/image bump.

Produce `security/medium-inventory.md` with the numbers and a recommendation.

## 847e.2 The decision (data-driven)

| If the inventory shows… | Then extend MEDIUM as… |
|---|---|
| Small, mostly-fixable surface | Full-baseline MEDIUM gate (same as HIGH), plus auto-fix PRs for the fixable set. |
| Large surface, mostly third-party/unfixable | **Diff-only MEDIUM gate**: fail a PR only if it *introduces* a new unwaived MEDIUM (same rule as HIGH, but never gate the pre-existing baseline). Baseline MEDIUM tracked by the monitor, ratcheted down over time. |
| Very large, largely unreachable | Track MEDIUM in the monitor + registry only (no required gate), with a documented ratchet target. Revisit when 847f's reachability data matures. |

The registry schema from 847a already carries `severity`, so MEDIUM entries fit
without change — only the *gating threshold* differs per the decision.

## 847e.3 Ratchet, don't cliff

Whichever scope is chosen, enforce a **ratchet**: the MEDIUM baseline may only
shrink. A test asserts the current MEDIUM baseline count ≤ the committed ceiling,
and lowering the ceiling is the only way it moves. This prevents silent
accretion without demanding an unachievable big-bang cleanup.

---

## Test strategy

- **Inventory reproducibility:** the inventory script regenerates the same numbers
  from the same images (deterministic).
- **Ratchet:** assert the MEDIUM baseline count never exceeds the committed
  ceiling; lowering the ceiling is explicit and reviewed.
- **Diff-gate correctness (if chosen):** a PR introducing a new unwaived MEDIUM
  fails; a PR that does not touch the surface passes.
- Run `make preflight`.

---

## Acceptance criteria

- [ ] `security/medium-inventory.md` exists with per-image/dep MEDIUM counts,
      fixability, and reachability breakdown.
- [ ] A documented decision selects one of the three gating scopes, justified by
      the inventory numbers.
- [ ] The chosen scope is implemented and the ratchet test is in place.
- [ ] MEDIUM waivers (if any) live in `security/waivers.yaml` like all others.
- [ ] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `scripts/medium_inventory.py` | New — the measurement |
| `security/medium-inventory.md` | New — the data + decision |
| `security/baseline-medium.json` | New — ratchet ceiling (scope-dependent) |
| `scripts/scan_regression.py` | Extend for MEDIUM (scope-dependent) |
| `tests/unit/test_medium_ratchet.py` | New |
| `docs/fragments/phase-847e-medium-gating.md` | Changelog fragment |

---

## Notes for implementer

- **Do not skip 847e.1.** Extending MEDIUM to a required full-baseline gate
  without the inventory is the single most likely way this programme recreates the
  problem it is meant to solve.
- If the diff-only scope is chosen, say so plainly in the fragment and the
  inventory — "we gate MEDIUM on new findings only, and ratchet the baseline" is
  an honest, defensible position. Pretending to full-baseline MEDIUM while
  waiving most of it is not.
