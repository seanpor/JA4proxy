<!--
title: Fix_Forward_Bot_And_Expiry_Reaffirmation
audience: developer
last_reviewed: 2026-10-17
phase: 847d
-->

# Phase 847d — Fix-forward bot + expiry re-affirmation

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** [847c]
> **Branch:** `phase-847d-fix-forward-bot`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Make **fixing cheaper than waiving**, and make waiver **expiry mean something**.
Today waiving is a one-line edit and fixing is a PR + validation, so pressure
always produces waivers; and `exp:` dates are auto-renewed forever, so they
provide false assurance. This phase inverts both.

---

## 847d.1 The fix-forward bot

Extends the 847c baseline monitor. On a new unwaived finding it does not merely
file an issue — it checks whether a fix exists and, if so, **opens the fix PR**:

1. **Fix-availability check.** For an image: query the registry for newer tags
   (patch/minor), and for each candidate, scan it and compare the finding set.
   For a dep: query PyPI/OSV for a version that clears the CVE while satisfying
   the existing constraints (the `mcp`/semgrep case — where the answer was "no
   version clears it without breaking semgrep" — is exactly the outcome this
   check must be able to report).
2. **If a clearing version exists** → open a PR bumping the pin/tag, carrying:
   the **before/after CVE table** (the diff that proves the fix), the compose
   validation, and the smoke test. A human reviews a green-or-explained PR.
3. **If no clearing version exists** → set `fix_available: false` on the registry
   entry with the evidence ("latest semgrep 1.181.0 still pins `mcp==1.29.0`"),
   and the finding becomes an eligible, honest waiver.

This directly addresses the kin-openapi failure mode: the bot would have reported
*"13.2.4 still bundles kin-openapi v0.144.0; no fixed tag exists in any release"*
— the exact fact that was initially got wrong by hand, because the authoritative
check was expensive. Making that check automatic and cheap is the point.

The repo already has most of the raw material: `scripts/check_upstream_image_updates.py`
(discovers newer tags) and `scripts/check_trivyignore_drift.py` (reads Trivy JSON).
This phase composes them; it does not reinvent them.

## 847d.2 Expiry re-affirmation (replaces blind re-dating)

Rework `scripts/renew_trivyignore.py`'s role. An entry approaching `expires` is
**not** auto-extended. Instead, re-affirm its **premise**:

| Premise question | If false |
|---|---|
| Does the carrier still carry the finding? | Remove the entry (it is DEAD — already modelled by the drift checker). |
| Has a fix shipped since `created`? | Open the fix PR (847d.1) and remove the waiver on merge. |
| Does the reachability claim still hold? (847f) | Invalidate the waiver; require re-justification. |
| None of the above | Human re-affirms with a fresh `expires` **and** a re-stated rationale. Escalates if unattended. |

The renewal workflow keeps its scheduling but its *action* changes from "bump the
date" to "run the re-affirmation checks and report/act." The 90-day ceiling stays;
it just stops being a rubber stamp.

---

## Test strategy

- **Fix-found path:** point the bot at a synthetic finding with a known clearing
  version; assert it opens a PR with a before/after table and does **not** create
  a waiver.
- **No-fix path:** use the real `mcp`/semgrep case (semgrep hard-pins
  `mcp==1.29.0`); assert the bot reports "no clearing version" and sets
  `fix_available: false` with the evidence, rather than opening a broken bump.
- **Re-affirmation:** run it on (a) a DEAD entry → removed; (b) a now-fixable
  entry → fix PR opened + waiver removed; (c) a genuinely-blocked entry → escalated
  for human re-affirmation, **not** silently extended.
- **No blind renewal:** assert the reworked script never emits a date change
  without one of the three outcomes above.
- Run `make preflight`.

---

## Acceptance criteria

- [ ] The bot opens a fix PR (with before/after CVE table + validation) whenever a
      clearing upstream version exists.
- [ ] When no clearing version exists, it records `fix_available: false` with
      evidence — proven on the real `mcp`/semgrep constraint.
- [ ] Expiry handling re-affirms the premise; blind `exp:` re-dating is gone.
- [ ] The fixable-queue metric is emitted and demonstrated ~0 in steady state.
- [ ] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `scripts/fix_forward.py` | New — fix-availability check + PR authoring |
| `scripts/renew_trivyignore.py` | Rework: re-affirmation, not re-dating |
| `.github/workflows/scan-baseline-monitor.yml` | Invoke the bot on new findings |
| `tests/unit/test_fix_forward.py` | New |
| `tests/unit/test_renew_trivyignore.py` | Update for re-affirmation semantics |
| `docs/fragments/phase-847d-fix-forward.md` | Changelog fragment |

---

## Notes for implementer

- The bot must **never auto-merge** its own fix PRs. It authors; a human merges.
  Auto-merging an image bump with only machine validation is exactly the risk this
  programme is meant to reduce.
- Registry edits by the bot (`fix_available`, `expires`) should be committed as a
  normal PR so they are reviewable, not applied by the workflow directly to `main`.
- Be careful with the fix-availability scan cost: cache candidate scans, and only
  rescan when a new tag is published, not on every cron tick.
