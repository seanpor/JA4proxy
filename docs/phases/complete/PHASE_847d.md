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
| (not planned) | Coverage means "Trivy **analysed** the image", not "a report exists" | Found in review: Trivy writes `"Results": null` when it could not analyse the image (no detectable OS, an unreadable layer). The report still names the image, so it counted as scanned — and a carrier with no findings read as DEAD. See "The review pass" below. |
| (not planned) | Entry boundaries honour the **indent** of the first entry | Found in review: `_ENTRY_RE` matches prose inside a rationale's folded block scalar, so `remove_entries` deleted only an entry's *head* and left its tail behind — the registry stopped being valid YAML. See "The review pass" below. |
| (not planned) | The re-affirmation **workflow** was fixed, not just the script | Found in review: the workflow had been measuring nothing since 2026-08-19 (missing PyYAML on the runner) and reporting success for 63 days. 847d's re-affirmation reads the scan dir that was never populated, so the feature would have been inert. See "The workflow had been measuring nothing for 63 days" below. |

### The review pass

After the implementation was complete, an adversarial read of the branch found
four more defects. Three of them are the failure class this phase exists to
remove — something that looks like "the exemption can go" and is not — so they
are recorded here rather than folded away:

1. **`load_registry()` coerced a missing `waivers:` key to `[]`.** An empty
   registry is the goal state; a file that *lost* the key is a truncated edit
   or a bad merge. Coercing it to `[]` meant the derived ignorefiles would be
   regenerated **empty** — every live exemption dropped, silently — and
   `validate()` could no longer catch it, because the value had already been
   normalised away. The key's absence is now refused at load time.
2. **A rationale could masquerade as an entry.** `rationale: >-` followed by an
   indented `- id: parser` is prose, but it matches the same regex an entry
   does. `remove_entries` therefore computed the wrong span, deleted the
   target's head, left its tail behind, and produced a registry that no longer
   parsed. Entry boundaries now honour the indent of the first entry.
3. **`remove_entries()` could write an unparseable registry.** The text is
   spliced, not re-serialised. It now verifies before writing — the result
   must parse, and must hold exactly the entries the registry says it should.
   Fail closed, no partial write.
4. **A report that analysed nothing counted as coverage.** See the table
   above. Coverage now requires `Results` to be a list, which is the repo's
   established "scanned and clean" shape — `trivy_image_report.py` treats
   `Results: []` as a genuine clean pass, and the two must not disagree about
   what "scanned" means.

The fourth finding is the one that generalises: **every "is this exemption
still needed?" check is only as good as the evidence it rests on**, and
"the file exists" is weaker evidence than it looks. A missing report, a
report that analysed nothing, and a scan that never covered the image are
three different things, and the first two are not evidence of absence.

The gate also caught a fifth: preflight's semgrep step blocks SHA-1 in the
scan-cache fingerprint. It is a content fingerprint and never a signature,
but there is no reason to reach for a broken digest when SHA-256 costs the
same. `ignore_sha` is now `ignore_digest`.

### The workflow had been measuring nothing for 63 days

The sixth finding is the largest, and it was not in the branch at all — it was
in the workflow the branch rewires.

Phase 829a (2026-08-19) added
`images="$(python3 scripts/check_image_versions.py --list-third-party)"` to
`trivyignore-renewal.yml` without installing PyYAML. `actions/setup-python`
installs a **clean** interpreter, so the PyYAML the runner image happens to
carry was not there; `check_image_versions.py` imports it at module level and
exits 2. The chain that followed was silent at every link:

| Step | What actually happened | What it looked like |
|---|---|---|
| `images="$(… --list-third-party)"` | exits 2, prints to stderr | an empty list |
| the Trivy loop | iterates over nothing | a successful scan |
| `check_trivyignore_drift.py --scan-dir …` | runs against an empty directory | a clean drift report |
| `renew_trivyignore.py` | dies with `ModuleNotFoundError: No module named 'yaml'` | — |
| `… \| tee renewal_summary.txt` | the pipeline's status is `tee`'s — **0** | a successful run |
| the job | — | **success, every day** |

63 consecutive daily runs, 2026-08-19 to 2026-10-21, all green. The
`.trivyignore` renewal safety net had been dead the whole time, and the
"measured" drift report was measuring an empty directory.

This is the programme's own failure class, one level up from the code: **a
check that measures nothing and reports success is worse than no check**,
because it looks like coverage while providing none. And it had a second,
sharper edge — 847d's re-affirmation reads `/tmp/trivy-scans` to decide
whether a waiver is DEAD. With the scan dir empty, every entry would have
escalated. Safe, correct, and inert: the feature would never have fired.

Four fixes, each aimed at a different link in that chain:

1. **Install PyYAML** on the runner, in both workflows that run these scripts
   there. `ci.yml` already hit this exact trap and says so at its own install
   step.
2. **An empty image list is an error**, not a clean scan. The step now says
   how many images it scanned, so "nothing" is visible in the log.
3. **The exit codes are no longer confused.** The runner invokes `bash -e`,
   so `-e` is already on: an unguarded pipeline aborts the step the moment
   the script exits 1 — which is the *expected* "a human needs to look" case
   — and `| tee` reports 0 regardless, because the pipeline's status is
   `tee`'s. `PIPESTATUS` carries the script's own code, so exit 1 now means
   "needs a human" and exit 2+ fails the step loudly.
4. **An escalation reaches a human.** A pure ESCALATION changes nothing on
   disk, and the issue was gated on "did a file change?" — so the one verdict
   that most needs a person was the one that produced no artifact. The issue
   is now filed whenever `needs_human` is true, with or without a branch.

The monitor workflow had the same missing dependency, introduced by *this*
phase: adding `setup-python` without `pip install pyyaml` would have taken
the drift monitor down entirely (`check_image_versions.py` is imported by the
monitor, at module level, and exits 2 without it). Found before it could ship.

`tests/unit/test_waiver_workflow_guards.py` now asserts each of these guards,
so the shape cannot come back silently. The assertions include one that
checks the *requirement* is real — that the scripts really do import `yaml` —
so the install step cannot become spurious and the real breakage return.

The generalisation, one level above the code-level lesson above: the same
rule applies to the harness, not just to the evidence. "The file exists" is
weak evidence; so is "the job went green".

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

### The regression gate could not pass, and widened for the wrong reasons

The sixth finding above was in the workflow 847d rewires. The seventh and
eighth were in the *gate* — the 847c instrument that 847d's waiver lifecycle
depends on. Neither was caused by 847d; both were exposed by it, and both
would have kept the gate from doing its job.

**The trigger compared file bytes.** `waiver_inputs_changed()` asked "is one of
the four waiver files in the diff?" — which cannot tell a waiver edit from a
documentation edit. The generated ignorefiles carry a header above their
entries, so rewording that header widened the gate from "the surfaces this PR
touches" to *every* surface. On this branch that is a one-line header change,
and it put 19 surfaces in scope — which then failed on CVE-2026-111943, an
upstream Go stdlib CVE published 2026-10-21, on images this branch never
touched. That is precisely the failure 847c was built to prevent: *an upstream
CVE disclosed overnight cannot redden an unrelated PR*.

The comparison is now on the applied **entries** — the lines Trivy and pip-audit
actually apply — so a comment is not a waiver change and a deleted entry still
is. `security/waivers.yaml` is deliberately *not* compared: the bot records its
own metadata there (`fix_available`, `recheck_trigger`) without changing a
single applied waiver, so byte comparison widened the gate on every bot PR, and
an unrelated upstream CVE would have reddened automated work that had nothing
to do with it. A registry edit that really does change the waiver set changes
the generated files with it — `make lint` runs `render_waivers.py --check` and
refuses a registry and its generated files that disagree — so the generated
files are the complete record of what is waived. Fail closed: a file that
cannot be read at one end counts as changed, and one that cannot be read at
*either* end is an error, not "unchanged".

**A surface that never existed.** `dockerfile_image_map()` parsed the
Makefile's rebuild loop — `-f "$$df" -t "$$tag"` — as a build rule, producing
a Dockerfile path and an image name that cannot exist. The gate then tried to
scan `image:"$$tag"` and failed closed, on a surface that was never real. So
the gate could not pass at all, on any PR that widened its scope, which is
every waiver change. `$$` is make's escape for a literal `$` and is by
definition a shell variable, so captures containing it are now skipped.

**Two definitions in one repository.** The same over-broad trigger still stood
in CI, in the `scan-scope` plumbing job that decides whether the full scan
runs on a PR: a byte-level `paths-filter` over the four waiver files. Two
definitions of "the waiver set changed" is a divergent list — the programme's
own fifth property — so the plumbing job now asks the gate
(`scan_regression.py --waiver-set-changed`) and the two cannot drift apart.
The question has three answers, not two: changed, unchanged, and
could-not-tell, with a distinct exit code for the last so the caller can fail
closed. The `scan` job's condition changed from `== 'true'` to `!= 'false'` for
the same reason: a trigger that silently stops firing is the one failure mode a
safety trigger must not have. If the detector fails, is skipped, or never sets
its output, the full scan now runs anyway.

All of it verified live, in both directions, against the real repository and
the real ignorefiles — not only in unit tests:

| State | The gate | The CI trigger |
|---|---|---|
| this branch (header-only change) | scans nothing | "unchanged" → the full scan is not triggered |
| a real waiver entry deleted | widens to every surface, and catches the un-waived CVE-2026-100349 reappearing in grafana/grafana | "changed" → the full scan runs |

### CVE-2026-111943, and what this phase did about it

A Go standard-library CVE, published 2026-10-21, affects `crypto/x509` in Go
1.27.2 (fixed in 1.26.10 / 1.27.3). It lands on this repository's first-party
images *and* on six pinned third-party images (grafana, prometheus,
alertmanager, redis_exporter) whose Go version is not ours to choose.

It is recorded here because the honest position matters more than the optics:
**847d did not fix it, and did not triage it by hand.** The 847c monitor did,
within nine hours of publication — nine issues, one per affected surface, filed
by `scan_baseline_monitor.py` with the evidence attached. That is the
programme's designed channel, and it worked. What is left for a human is the
decision the monitor cannot make: bump our own base images to Go 1.27.3, and
either wait for upstream releases of the third-party images or waive them with
a dated justification.

The gate fix above is what made that separation possible. Before it, the CVE
could not be triaged *at all* in this PR: the header change had widened the
gate to every surface, so the branch was red on a finding it had no
relationship to, and the honest options were both bad — land a red required
gate, or ship a knowingly-false header in a security artifact.

---

### The live run, and the two defects only it could find

The unit suite was green. The renewal workflow, however, had never actually
re-affirmed an entry — it had been measuring nothing for 63 days, and the
re-affirmation it now performs had therefore never been executed. So it was
run **for real**: nine third-party images scanned with Trivy, and the
re-affirmation pointed at the resulting scan directory.

It crashed on the first entry it tried to re-affirm:

```
  File "scripts/renew_trivyignore.py", line 159, in fix_proposal
    from scripts import fix_forward as ff
ModuleNotFoundError: No module named 'scripts'
```

**The script was only ever correct when imported.** Every test called
`main()` in-process, where pytest has the repository root on `sys.path` and
`from scripts import fix_forward` resolves. The workflow runs
`python3 scripts/renew_trivyignore.py …`, which puts `scripts/` on `sys.path`
and *not* the repository root — so the same import raises there. It was the
only bare sibling import in the repository; every other one already carried
the `try: from scripts import X / except ImportError: import X` fallback.
Fixed the same way, and the workflow's invocation is now a test.

**The crash would have worn the exit code of a legitimate escalation.** Python
exits 1 on an uncaught exception, and the workflow reads 1 as "a human needs
to look" — it files an issue and stays green. So the first time a waiver
entered the five-day window, the re-affirmation would have died, filed a
perfectly legitimate-looking issue, and never run again. That is this phase's
own failure class in a new costume: a tool that measures nothing and reports
success. A crash is now exit code 2 — an error, and loudly so.

**A contested removal aborted the whole run.** `remove_entries` refuses to
delete an entry whose carrier another surviving waiver still claims. That
refusal raised, and the run died with exit 2 — turning a policy question into
a red daily job. It is now a per-entry escalation with the exact reason, and
entries are removed one at a time, so one contested waiver no longer holds an
unrelated dead waiver hostage. The refusal itself is kept: it is conservative,
it fails safe, and changing what a carrier claim *means* is a decision for a
follow-up phase, not a side effect of a bug fix.

The output no longer claims a removal that did not happen either. It used to
print `✓ dead: … — removing the waiver.` and then, in the contested case, not
remove it.

Both defects were invisible to the unit suite and obvious the moment the code
ran against real data. That is the argument for the live run, and it is why
the live run is part of this phase's test strategy rather than an extra.

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
  partial scan dir — and, in both directions, proving the guard is not a
  blanket refusal (a complete scan does delete).
- **The workflow's own invocation:** the re-affirmation run as
  `python3 scripts/renew_trivyignore.py …` — a subprocess, with only
  `scripts/` on `sys.path` — against a real scan directory. Two defects were
  invisible to the in-process tests and found here; see the live-run section
  above.
- **Evidence quality:** a report that analysed nothing (`Results: null`) is
  not coverage; a rationale that looks like an entry does not move an entry
  boundary; a missing `waivers:` key is not an empty registry; a deletion that
  would produce an unparseable file is refused before it is written.
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
| `scripts/render_waivers.py` | `renew_expiring` deleted; `remove_entries` added; fix-metadata splice; empty registry valid; indent-based entry boundaries; fail-closed registry writes |
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
