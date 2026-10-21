<!--
title: Fix_Forward_Bot_And_Expiry_Reaffirmation
audience: developer
last_reviewed: 2026-10-21
phase: 847d
-->

# Phase 847d — Fix-forward bot + expiry re-affirmation

> **Status:** COMPLETE (2026-10-21)
> **Size:** MEDIUM
> **Dependencies:** [847c]
> **Branch:** `phase-847d-fix-forward-bot`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Make **fixing cheaper than waiving**, and make waiver **expiry mean something**.
Waiving was a one-line edit and fixing was a PR plus validation, so pressure
always produced waivers; and `exp:` dates were auto-renewed forever, so they
provided false assurance. This phase inverts both.

**As delivered:** a fix-availability engine that decides — with evidence —
whether a newer upstream version clears a finding, a bot that turns a "fixable"
verdict into a reviewable bump branch, and a re-affirmation pass that replaces
blind date renewal with an explicit per-entry decision.

---

## 847d.1 The fix-forward bot

`scripts/fix_forward.py` (new). On a new unwaived finding it does not merely
file an issue — it checks whether a fix exists and, if so, **opens the fix PR**:

1. **Fix-availability check.** For an image: query the registry for newer tags
   (patch/minor), and for each candidate, scan it and compare the finding set.
   For a dep: query PyPI/OSV for a version that clears the CVE while satisfying
   the existing constraints — including the `mcp`/semgrep case, where the
   answer is "no version clears it without breaking semgrep", which is exactly
   the outcome the check must be able to report.
2. **If a clearing version exists** → open a PR bumping the pin/tag, carrying
   the **before/after CVE table** (the diff that proves the fix), the compose
   validation, and the smoke test. A human reviews a green-or-explained PR.
3. **If no clearing version exists** → set `fix_available: false` on the
   registry entry with the evidence ("latest semgrep 1.182.0 still pins
   `mcp==1.29.0`"), and the finding becomes an eligible, honest waiver.

This directly addresses the kin-openapi failure mode: the bot reports
*"13.2.4 still bundles kin-openapi v0.144.0; no fixed tag exists in any
release"* — the exact fact that was initially got wrong by hand, because the
authoritative check was expensive. Making that check automatic and cheap is the
point.

The repo already had most of the raw material: `scripts/check_upstream_image_updates.py`
(discovers newer tags) and `scripts/check_trivyignore_drift.py` (reads Trivy JSON).
This phase composes them; it does not reinvent them.

### The three outcomes, and their precedence

| Outcome | Means | Registry effect |
|---|---|---|
| `fixable` | a clearing version exists and was **proven** (candidate scanned, introduces no new unwaived finding) | `fix_available: true`, recheck trigger dropped |
| `blocked` | proven **not** fixable within this repo's constraints | `fix_available: false` + `recheck_trigger` naming the concrete upstream change that would unblock it, plus the evidence |
| `unknown` | the question could not be answered (indeterminate spec, digest-pinned ref, unreachable registry, every candidate scan failed) | **nothing** — `unknown` never claims either way |

Precedence is **blocked > unknown > fixable**: a single proven blocker decides
the unit, and `unknown` is only reached when nothing is proven.

The distinction is load-bearing and was corrected during implementation. A
**failed scan proves nothing**: when every candidate scan fails, the verdict is
`unknown`, never `blocked`. But when some candidates scanned and *introduce new
findings*, that is positive evidence of no usable candidate — `blocked`.

### Deliberate boundaries

- `BUMPABLE_OPS = ("==", ">=")` only. `~=`, `<`, `<=`, `!=` are **human bounds**
  and yield `unknown` — a bot that silently rewrites them would change the
  meaning of the constraint.
- Digest-pinned refs, first-party images, and non-semver tags are `unknown`.
- The bot **never creates a waiver** and **never merges**. It authors a branch
  and an issue; a human merges.
- `bump_requirements()` is the single decide-and-edit function and raises
  `ValueError` rather than silently editing nothing.

## 847d.2 Expiry re-affirmation (replaces blind re-dating)

`scripts/renew_trivyignore.py` was reworked. An entry approaching `expires` is
**not** auto-extended. Instead, its **premise** is re-affirmed:

| Premise question | If false |
|---|---|
| Does the carrier still carry the finding? | Remove the entry (it is DEAD) |
| Is there exactly one carrier, and does a newer tag clear it? | Propose the fix (847d.1); the window is **not** extended |
| Did the scan actually cover the declared carriers? | `unmeasured` — escalate; a missing report is not evidence of absence |
| None of the above | Human re-affirms with a fresh `expires` **and** a re-stated rationale |

**There is no longer any code path that extends an expiry.** `renew_expiring()`
and the `--renew` / `--within-days` / `--days` flags of `render_waivers.py`
were deleted outright, not deprecated.

The 90-day ceiling stays; it just stops being a rubber stamp.

---

## Deviations from the plan (as-built)

| Planned | As built | Why |
|---|---|---|
| The bot "opens the fix PR" | It pushes a `bot/fix-forward-*` branch and files an issue carrying a one-click compare link | Repo policy **#396** disables "Allow GitHub Actions to create and approve pull requests", so `gh pr create` exits 1. The same pattern the renewal workflow already uses. A human opens the PR, which preserves the deliberate no-blanket-review stance. |
| Registry edits "committed as a normal PR" | Same branch-plus-issue route, for the same reason | — |
| Re-affirmation: "has a fix shipped since `created`?" | Checked via `fix_forward`'s image check, restricted to a **unique** carrier | A bump to one image says nothing about a second, so a multi-carrier entry is escalated rather than reported as fixable. Overclaiming here would be worse than escalating. |
| (not planned) | `DEAD` requires the scan to have **covered** the entry's declared carriers | Found during implementation: the renewal workflow writes no report for an image whose Trivy run fails (`|| echo warning`). Treating "absent from the results" as "gone" would delete a **live** waiver — silently narrowing an exemption. This is the exact failure class the programme exists to remove, so it is a first-class verdict (`unmeasured`), not a detail. |
| (not planned) | The registry may be **empty** | `validate()` previously rejected an empty `waivers:` list, so deleting the last dead waiver made the registry unvalidatable — a repo that fixed everything could not record that fact. Zero waivers is the goal, not a schema error. A *missing* key still fails. |

### The HTTP cap, and why it is 32 MiB for PyPI

The first live end-to-end run returned `unknown` where the plan expected
`blocked` — the whole mcp/semgrep sweep was silently skipped. The cause was the
256 KiB response cap: PyPI's metadata for `aiohttp` alone is 9.5 MB, so the
fetch failed and the engine, correctly refusing to claim anything, degraded to
`unknown`.

The cap was split: `HTTP_LIMIT` (256 KiB) stays for OSV and the default, and
`PYPI_METADATA_LIMIT` (32 MiB) applies to `/pypi/…/json` metadata only. The
value is justified by a **measured** high-water mark, not a guess, and
`--bytes-out` records the observed response sizes of every fetch so the
justification is reproducible. Measured on 2026-10-21: aiohttp 9,472,099 B;
hypothesis 6,223,827 B; cryptography 3,283,477 B; semgrep 1,379,268 B.

**This is the phase's central lesson and is recorded here deliberately:** the
injected-fetch unit tests passed while the feature was broken. Only the live
run against real PyPI/OSV caught it. Live end-to-end verification is not
optional for this kind of change.

---

## Test strategy

- **Fix-found path:** a synthetic finding with a known clearing version;
  assert a bump branch is authored with a before/after table and no waiver is
  created.
- **No-fix path:** the real `mcp`/semgrep case (semgrep hard-pins
  `mcp==1.29.0`); assert `blocked` with the evidence and
  `fix_available: false`, rather than a broken bump.
- **Unknown path:** an indeterminate spec, a digest-pinned ref, an unreachable
  registry, and an all-candidates-failed scan — each must produce `unknown`,
  never a claim.
- **Re-affirmation:** (a) a DEAD entry → removed; (b) a now-fixable entry →
  the fix is proposed and the dates are untouched; (c) a blocked entry →
  escalated, **not** silently extended; (d) a partial scan → `unmeasured`,
  **not** removed.
- **No blind renewal:** the renewal primitive is asserted *absent*
  (`assert not hasattr(render_waivers, "renew_expiring")`), and the reworked
  script is asserted never to move a date.
- **Live end-to-end:** the mcp/semgrep verdict against real PyPI/OSV, and the
  DEAD/`unmeasured` distinction against the real registry with a deliberately
  partial scan dir.
- `make preflight`.

---

## Acceptance criteria

- [x] The bot opens a fix PR (with before/after CVE table + validation) whenever
      a clearing upstream version exists. — *Delivered as a branch + one-click
      compare link, per repo policy #396; the PR itself is opened by a human.*
- [x] When no clearing version exists, it records `fix_available: false` with
      evidence — proven on the real `mcp`/semgrep constraint.
- [x] Expiry handling re-affirms the premise; blind `exp:` re-dating is gone.
- [x] The fixable-queue metric is emitted and demonstrated ~0 in steady state.
- [x] `make preflight` passes.

---

## Files

| File | Change |
|------|--------|
| `scripts/fix_forward.py` | New — fix-availability engine + proposal authoring + registry recording |
| `scripts/renew_trivyignore.py` | Reworked: re-affirmation (dead / fixable / unmeasured / escalate), never a date bump |
| `scripts/render_waivers.py` | `renew_expiring` deleted; `remove_entries` added; fix-metadata splice; empty registry valid |
| `scripts/scan_baseline_monitor.py` | `--state-out` — the hand-off to the bot |
| `.github/workflows/scan-baseline-monitor.yml` | `contents: write`; the fix-forward step; scan-cache; `--bytes-out` artifact |
| `.github/workflows/trivyignore-renewal.yml` | Re-affirmation semantics: `--scan-dir`, exit-1 tolerated, deletions only |
| `Makefile` | `scan-monitor STATE_OUT=…` passthrough |
| `tests/unit/test_fix_forward.py` | New |
| `tests/unit/test_renew_trivyignore.py` | Reworked for re-affirmation semantics |
| `tests/unit/test_waivers_registry.py` | Splice + empty-registry tests |
| `tests/unit/test_scan_baseline_monitor.py` | `--state-out` tests |
| `docs/fragments/phase-847d-fix-forward.md` | Changelog fragment |

---

## Notes for implementer

- The bot must **never auto-merge** its own fix PRs. It authors; a human
  merges. Auto-merging an image bump with only machine validation is exactly
  the risk this programme is meant to reduce.
- Registry edits by the bot (`fix_available`, `recheck_trigger`) are committed as
  a normal branch so they are reviewable, not applied by the workflow directly
  to `main`.
- Be careful with the fix-availability scan cost: candidate scans are cached
  (keyed on the ignorefile content, 7-day cap) and persisted across workflow
  runs, so a new tag is rescanned but an unchanged one is not.
- A verdict of `unknown` is a legitimate outcome. Do not "improve" it into a
  claim — the point of the engine is that it never states something it did not
  prove.
