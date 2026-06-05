---
phase: 224
title: Makefile Target Integrity — Reconcile Help Text with Real Targets
status: IN_PROGRESS
size: LARGE
created: 2026-06-05
audience: [developer, operator]
---

# Makefile Target Integrity

## Goal

Make the Makefile honest: **every target name printed by `make help*` must be a
real, runnable target, and every aggregate must actually run all of its
members.** Then guarantee the user's headline workflow works —

```bash
make lint scan test     # full lint + full scan + full test, excluding only the heaviest benchmarks
```

— and add a meta-lint guard so this class of drift can never silently return.

This phase is a critical-review-and-repair of the Makefile as it currently
stands. The help screens read well, but a large fraction of the advertised
targets do not exist; some aggregates depend on missing prerequisites and fail
hard, and one headline target (`scan`) is declared `.PHONY` with no recipe, so
it *silently does nothing* and reports success.

## Audit — Current Breakage (verified 2026-06-05)

Measured by extracting every `make X` reference and every `@echo "  name  - …"`
advertisement from the Makefile and diffing against the set of real target
declarations (`^name:`).

### Class 1 — Hard failures (target errors out on invocation)

| Command | Fails because | Effect |
|---|---|---|
| `make lint` | `lint` → `lint-all` → `lint-docs-all` → **`doc-health`**, plus `lint-sast` → **`lint-semgrep`** and `lint-infra` → **`lint-ansible`** (all missing `$(MAKE)` sub-calls) | `make lint` is **completely broken** |
| `make lint-deps` | depends on **`scan-container`** (missing) | errors: *No rule to make target 'scan-container'* |
| `make check-updates` | depends on **`check-updates-container`** (missing) | errors out |
| `make init` | depends on **`setup-build`** (missing) | guided setup wizard errors out |

### Class 2 — Silent false success (looks fine, does nothing)

| Command | Problem | Effect |
|---|---|---|
| `make scan` | listed in `.PHONY` (line 5) and advertised in `make help` (line 68) but **has no recipe** | prints *"Nothing to be done for 'scan'"* — the headline security command runs **zero scans** while appearing to succeed |

This is the most dangerous failure: an operator believes a full security scan
ran when nothing happened.

### Class 3 — Advertised in help text but no such target

Names printed by `make help`, `make help-scan`, `make help-ops`, `make help-dev`
that have no target behind them:

| Advertised name | Advertised in | Disposition |
|---|---|---|
| `scan` | `help`, `help-scan` | **Repair** (`\n` corruption, line 850) — headline full scan |
| `scan-all` | `help-scan` | **Repair** (line 853) — aggregate; alias kept for `make scan` |
| `scan-container` | `help-scan` (prereq of `lint-deps`) | **Repair** (line 843) |
| `scan-local` | `help-scan` | **Repair** (line 847) |
| `doc-health` | `help`/`lint-docs-all` | **Create** — doc structure/health check |
| `link-check` | help text | **Create / alias** of markdown link check (`.mlc.json`) |
| `lint-docs` | help text | **Alias** → `lint-docs-all` |
| `lint-phases` | help text (also cited in PHASE_221 acceptance) | **Create** — phase-doc validator |
| `lint-semgrep` | `$(MAKE)` call in `lint-sast` | **Create** — semgrep run (`.semgrep-phase122.yml`) |
| `lint-ansible` | `$(MAKE)` call in `lint-infra` | **Create** — ansible-lint (or drop the call) |
| `tunnel` | `help-ops` (`make tunnel NAME=… HOST=…`) | **Create** canonical; alias `ssh-tunnels` |
| `management-up` / `-down` / `-logs` / `-shell` | `help-ops`, `help-dev` | **Create** — compose wrappers (decision locked) |
| `test-component-suites` | `help-dev` | **Create** — aggregate (decision locked) |
| `test-ratio` | `help-dev` | **Create** — wrap `scripts/test_ratio.py` (decision locked) |
| `check-updates-container` | prereq of `check-updates` | **Repair** (`\n` corruption, line 857) |

> Note: the `ssh -L …` line in `help-ops` (line 797) is a literal example SSH
> command, **not** a make target — out of scope.

### Class 4 — Stale `.PHONY` entries

`sync-build` is declared `.PHONY` (line 9) but no such target exists and nothing
needs it. Reconcile `.PHONY` against real targets.

### Root cause #1 — corrupted newlines (the `\n` dedup bug)

The headline mechanical cause, found by the guard in sub-phase A: a botched
"deduplicate phony lines" pass (commit `30f28c2`, *"resolve Makefile warnings"*)
replaced real newlines with the **literal two characters `\n`** in 21 places.
Where the corruption landed as `# deduplicated phony line\nTARGET:`, the entire
line becomes a **comment** to `make`, so the target definition — *recipe and all*
— silently disappears, and its tab-indented recipe lines dangle onto an unrelated
earlier target.

Six real targets are disabled this way (they exist in the file, fully written,
but `make` never sees them):

| Line | Target (commented-out) | Real recipe present |
|---|---|---|
| 843 | `scan-container` | `docker build … security-scan` |
| 847 | `scan-local` | `gosec …` |
| 850 | `scan` | `$(MAKE) scan-all` |
| 853 | `scan-all` | aggregates the 4 container/dep scans |
| 857 | `check-updates-container` | `docker build … update-checker` |
| 862 | `check-updates-local` | `$(PYTHON) scripts/check_updates.py` |

This single corruption explains the recipe-less `scan` (Class 2), the dangling
`scan-container` / `check-updates-container` prereqs (Class 1), and four of the
"missing" scan-family targets (Class 3). The fix for these is **repair the
newlines**, not author new targets. Line 25 also collapsed a `.PHONY` comment
banner into one giant `\n`-joined comment; lines 60/185 put literal `\n` inside
`@echo` output (cosmetic — `dash`'s `echo` happens to re-expand them on this
host); lines 962–1072 are junk `# deduplicated phony line\n` comment residue.

### Root cause #2 — the guard is blind to itself

`make lint-meta` runs `scripts/meta_lint.py`, whose job is to *"Verify Makefile
and automation script health"* (Phase 147). It checks two things:
1. `make -n help` exits 0,
2. `make X` commands **inside `docs/`** point at real targets.

It does **not** parse the Makefile's own `@echo` help bodies, so phantom targets
advertised in `help`/`help-scan`/etc. are invisible to it. That blind spot is why
this drift accumulated. Closing it is the durable fix.

## Design Principles

1. **Help is a contract.** Anything `make help*` prints as a target name is a
   real, runnable target. Enforced by the meta-lint guard, not by vigilance.
2. **No phantom `.PHONY`.** A name in `.PHONY` with no recipe is a bug (it turns
   "no rule" errors into silent no-ops). `.PHONY` and real-target sets are
   reconciled.
3. **Aggregates run their members.** `lint`, `scan`, `test` are thin umbrellas
   whose only job is to invoke real sub-targets; each sub-target is independently
   runnable.
4. **One heavy/light boundary, documented once.** `lint`, `scan`, `test` cover
   everything *except* the heaviest benchmarks. The heavy work lives under a
   separate, explicitly-named umbrella so `make lint scan test` is the "full but
   not punishing" command.
5. **Prefer aliases over renames** where a name is already documented elsewhere
   (e.g. `ssh-tunnels`), to avoid breaking existing muscle memory and docs.

## The Heavy/Light Boundary

`make lint scan test` must run the full quality gate but skip the heaviest
benchmarks. Targets classified as **heavy** (excluded from the three umbrellas,
kept runnable on their own and grouped under a `bench` / `perf` umbrella):

`bench`, `bench-macro`, `bench-micro`, `perf-test`, `perf-test-basic`,
`load-test`, `load-test-baseline`, `load-test-report`, `test-go-perf`,
`measure-mttr`.

`make test` today already excludes these (it runs Go unit + Python unit +
integration smoke), so the boundary is mostly a documentation + guard task; this
phase makes it explicit and asserts it.

## Sub-Phases

Each sub-phase is an atomic commit. After each, `make lint-meta` (extended in A)
and the relevant umbrella are run to confirm no regression. A handover note is
appended to `## Handover Log`.

### A — Meta-lint guard (do this FIRST, so the rest is verifiable)

**Scope:** `scripts/meta_lint.py`, `tests/unit/test_makefile_integrity.py` (new).

Extend `meta_lint.py` to, in addition to its current checks:
1. Parse every `@echo` line in the Makefile, extract advertised target names
   (both `make <name>` forms and `  <name>  - <desc>` help-row forms), and assert
   each is a declared target. Maintain a small explicit allow-list for literal
   non-targets (e.g. the `ssh -L` example).
2. Assert every prerequisite of every target is itself a declared target or a
   file that exists (catches `doc-health`, `scan-container`, `setup-build`,
   `check-updates-container`).
3. Assert every name in `.PHONY` has a recipe **or** is a real aggregate
   (catches the recipe-less `scan` and stale `sync-build`).
4. Assert the three umbrellas (`lint`, `scan`, `test`) transitively reference
   **none** of the heavy targets listed above.

Add `tests/unit/test_makefile_integrity.py` invoking the same logic so the
guard runs in `make test` (not only `make lint-meta`).

**Acceptance for A:** the new guard *fails* against the current Makefile (proving
it detects every Class 1–4 issue). Capture that failing output in the handover
note; it becomes the to-do list for B–E.

### B — Repair the `\n` corruption + Class 1/4 fixes

**Scope:** `Makefile`.
- **Repair every literal `\n`** (21 sites, `grep -nF '\n' Makefile`): convert to
  real newlines. This alone restores `scan`, `scan-all`, `scan-container`,
  `scan-local`, `check-updates-container`, `check-updates-local` (lines
  843–862), un-collapses the line-25 `.PHONY` banner, and clears the junk
  `# deduplicated phony line\n` residue (lines 962–1072). Verify after with
  `grep -cF '\n' Makefile` → 0, and confirm the recovered recipes attach to the
  right targets (no recipe dangling onto an unrelated earlier target).
- Create `setup-build` (the build-prep step `init` expects) or remove the
  dependency if `init` already does its own setup. Default: thin real target.
- Remove `sync-build` from `.PHONY` (or implement it if `build`/`sync` needs it).
- Verify: `make lint-deps`, `make check-updates`, `make -n init` resolve; the
  scan family is now real (continues in D for the `scan` umbrella shape).

> Guardrail: this is search-and-replace on a 1100-line generated-ish file. Do it
> in small, reviewed hunks; re-run `make lint-meta` after each so a bad edit
> surfaces immediately. Do **not** re-run any "deduplicate" script.

### C — Doc-lint family

**Scope:** `Makefile` (+ `scripts/` if a helper is needed).
- `doc-health` — markdown/structure health (reuse existing tooling: `.mlc.json`
  markdown-link-check, `test-doc-links`).
- `link-check` — alias or thin wrapper over the markdown link checker.
- `lint-docs` — alias → `lint-docs-all`.
- `lint-phases` — validate phase docs (front-matter present, `phase:` matches
  filename, `status` is a known value, referenced in `manifest.yaml`). This also
  satisfies PHASE_221's acceptance criterion 9, which currently references a
  non-existent target.

### D — The `scan` family (Class 2 + Class 3)

**Scope:** `Makefile`.
- `scan` — **the headline full scan**: aggregates `scan-images`,
  `scan-dockerfiles`, `scan-first-party`, `check-image-versions`, plus the SAST
  / secrets checks (`lint-sast`, `lint-secrets`) and the Go vuln scan. Excludes
  heavy benchmarks (none of these are heavy). This is what `make scan` in
  `make lint scan test` runs.
- `scan-container` (from B) — govulncheck/gosec in a container.
- `scan-local` — govulncheck/gosec locally.
- `scan-all` — alias → `scan` (decision locked: `scan` is the full scan).
- Reword `help-scan` so each row matches the real behaviour (front-door
  `make help` already calls `scan` "all security and container scans").

### E — Ops/dev help reconciliation (Class 3 remainder)

**Scope:** `Makefile`.
- `tunnel` — make canonical (wraps current `ssh-tunnels` logic); keep
  `ssh-tunnels` as an alias so existing docs/scripts keep working.
- `management-up` / `-down` / `-logs` / `-shell` — **create** (decision locked).
  Thin wrappers over the `management` service in
  `deploy/docker/docker-compose.poc.yml` (line 378): `up -d management`,
  `stop management`, `logs -f management`, `exec management sh`.
- `test-component-suites` — **create** (decision locked). Aggregate of the
  existing component `test-*` targets (`test-unit`, `test-chaos`,
  `test-adversarial`, `test-compliance`, `test-attack-mapping`, …), excluding the
  heavy `test-go-perf`.
- `test-ratio` — **create** (decision locked). Thin wrapper over the existing
  `scripts/test_ratio.py`.

After E, help text and the target set agree (guard A enforces this).

### F — Headline workflow + easy heavy-benchmark trigger

**Scope:** `Makefile`, `tests/unit/test_makefile_integrity.py`, `CHANGELOG.md`,
`docs/phases/manifest.yaml`.
- Run `make lint scan test` end-to-end; it must complete a full lint, full scan,
  and full test with **no** heavy benchmark running.
- **Heavy-benchmark UX** (your ask: "easy to trigger the heavy benchmarks"):
  - `bench-all` — one umbrella that runs every heavy target (`bench`,
    `perf-test`, `load-test`, `test-go-perf`, `measure-mttr`, …). Advertised in
    `make help` next to the light gate.
  - `verify-all` — `lint scan test bench-all` (the everything gate, for a
    release candidate). Documented as "slow".
  - Fix the bare-`python` calls in `load-test`/`test-go-perf` → `$(PYTHON)`
    while here (3.10-vs-3.14 robustness; see Phase 225 note).
- Remove the `xfail` on `test_real_makefile_has_no_integrity_violations` (strict
  xfail means it would otherwise XPASS-fail) — the gate is now a positive test.
- Run the extended `make lint-meta` — now green.
- `make sync`, CHANGELOG entry, manifest `status: COMPLETE`.

## Test Strategy

- **Guard (primary):** `scripts/meta_lint.py` + `tests/unit/test_makefile_integrity.py`
  must (a) be **red** before B–E, (b) be **green** after F.
- **Resolution checks:** `make -n lint`, `make -n scan`, `make -n test`,
  `make -n lint-deps`, `make -n check-updates`, `make -n init`,
  `make -n lint-docs-all` all resolve with zero "No rule to make target" errors.
- **No-op check:** `make scan` must execute ≥1 real scanner (assert non-empty
  scanner output / non-zero work), never "Nothing to be done".
- **Boundary check:** assert `make -n lint scan test` does **not** contain any of
  the heavy benchmark target recipes.
- **Existing suites:** `make test` stays green.

## Acceptance Criteria

1. `make lint scan test` runs a full lint, full scan, and full test to
   completion, invoking **none** of the heavy benchmark targets.
2. `make scan` executes real scanners (no "Nothing to be done"); `scan-all`,
   `scan-container`, `scan-local` all resolve and run.
3. `make lint`, `make lint-deps`, `make check-updates`, `make -n init`,
   `make lint-docs-all` all resolve with no missing-target errors.
4. Every target name advertised in `make help`, `help-ops`, `help-lint`,
   `help-scan`, `help-dev`, `help-legacy` is a real, runnable target.
5. Every prerequisite of every target is a real target or an existing file.
6. `.PHONY` contains no recipe-less phantom (`scan` has a recipe; `sync-build`
   resolved); no real aggregate is missing from `.PHONY`.
7. `make lint-phases` exists and validates phase docs (unblocks PHASE_221 AC #9).
8. Extended `scripts/meta_lint.py` detects all Class 1–4 issues (demonstrated red
   on the pre-fix Makefile) and is green at phase close; `make lint-meta` passes.
9. `tests/unit/test_makefile_integrity.py` runs inside `make test` and passes.
10. `make test` exits 0.

## Out of Scope

- Rewriting the Makefile structure or splitting it into includes.
- Changing what any *working* target actually does (only fixing broken/missing
  ones and reconciling help text).
- New CI workflows (the guard runs via existing `make test` / `make lint-meta`).
- Performance tuning of the benchmarks themselves.
- **Containerizing the toolchain** — deferred to Phase 225 (see below).

## Follow-on: Phase 225 — Hermetic / containerized tooling (proposed)

Local Python is **3.10.12** but the project targets **3.14**
(`pyproject.toml: python_version = "3.14"`), so version-sensitive tools (mypy,
ruff, bandit, trivy, govulncheck) run against the wrong interpreter locally —
the "Python 3.10 complaint" the user observed. The durable fix is to run those
tools inside pinned containers (the repo already has `deploy/docker/security-scan`
and `deploy/docker/update-checker` images — the pattern exists), so `make lint`
/ `make scan` are reproducible regardless of host Python.

Explicitly **not** containerized: `scripts/meta_lint.py` (this phase's guard) is
pure-stdlib and version-agnostic by design, so it must keep running on the bare
host — requiring Docker just to parse the Makefile would make it *less* robust.
That separation (heavy tools → container; the Makefile-honesty guard → host) is
the boundary Phase 225 should formalize.

## Decisions (locked 2026-06-05)

1. **`management-*`, `test-component-suites`, `test-ratio`:** **create all** as
   real targets (building blocks verified to exist — `management` compose
   service, `test-*` suite targets, `scripts/test_ratio.py`).
2. **`scan` semantics:** **`scan` = full security + container scan**; `scan-all`
   is an alias. This is what `make lint scan test` runs.

## Handover Log

*Appended after each sub-phase by the implementing agent.*

### A — Meta-lint guard (COMPLETE, 2026-06-05)

**Files:** `scripts/meta_lint.py` (rewritten — importable, dependency-free model
parser + checks, legacy checks preserved), `tests/unit/test_makefile_integrity.py`
(new — 25 synthetic tests green + 1 strict-xfail real-Makefile gate).

**What the guard checks:** advertised-name↔target (`check_advertised_exist`),
prereq existence (`check_prereqs_exist`), dangling `$(MAKE)` sub-calls
(`check_make_calls_exist`), `.PHONY` phantoms + no-op targets
(`check_phony_sane`), light-umbrella heavy-exclusion
(`check_umbrellas_exclude_heavy`), plus a `make -n` resolution probe
(`resolve_umbrellas`, skipped gracefully if `make` is absent).

**Wired in:** runs in `make lint-meta` (CLI) and `make test` (via the new unit
test in `tests/unit/`). Both are RED now, as intended.

**Findings (the B–E to-do list) — `make lint-meta` reports 26 violations:**
- **Root cause = literal `\n` corruption** (commit 30f28c2). 21 sites; 6 ate real
  targets: `scan`, `scan-all`, `scan-container`, `scan-local`,
  `check-updates-container`, `check-updates-local` (lines 843–862). → repair in B.
- Dangling `$(MAKE)` sub-calls breaking `make lint`: `doc-health` (lint-docs-all),
  `lint-semgrep` (lint-sast), `lint-ansible` (lint-infra). → create in B/C.
- Dangling prereqs: `setup-build` (init). → B.
- `.PHONY` phantoms: `scan` (corruption), `sync-build` (stale). → B.
- Genuinely-missing advertised: `doc-health`, `link-check`, `lint-docs`,
  `lint-phases`, `tunnel`, `management-{up,down,logs,shell}`,
  `test-component-suites`, `test-ratio`. → C/E.

**Robustness notes for the next agent:**
- `$(MAKE)` edges are matched by the canonical `$(MAKE)`/`${MAKE}` form only
  (bare `make` in echo prose like "make sure" was a false-positive source —
  fixed). They ARE extracted from `$(MAKE) X || echo …` fallback lines.
- The parser treats `# …\nTARGET:` lines as comments (correct — that's exactly
  the corruption), so don't be surprised the "missing" scan targets are missing.
- Heavy set + light umbrellas are single-sourced as constants at the top of
  `meta_lint.py` (`HEAVY_TARGETS`, `LIGHT_UMBRELLAS`) — keep them in sync with the
  "Heavy/Light Boundary" section here and add `bench-all`/`verify-all` in F.
- The real-Makefile gate is `xfail(strict=True)` → it becomes a hard failure the
  instant the Makefile is clean, which is the signal to remove the marker in F.
