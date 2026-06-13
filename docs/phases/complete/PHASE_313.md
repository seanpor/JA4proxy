---
phase: 313
title: Fix CI Lint Loop & Scan Failure Handling
status: COMPLETE
created: 2026-06-13
completed: 2026-06-13
audience: [developer]
---

# Fix CI Lint Loop & Scan Failure Handling

> **Goal.** Make `make lint` / `make scan` run against a single pinned toolchain
> and **fail closed** on real findings, with a concise pass/fail verdict capping
> the output. Builds on the resilient-CI work in [[PHASE_311]] and [[PHASE_312]]
> (which hardened the `pip-audit` gate); this phase hardens the surrounding
> lint/scan plumbing.

> **Note on provenance.** This work first accumulated, uncommitted and
> unfinished, on an unrelated feature branch. It was parked onto a clean branch
> (`phase-313-ci-fixes`) and the bugs it carried were fixed there. This document
> was written alongside that landing rather than before it; the acceptance
> criteria below reflect what was implemented and tested on that branch.

## Background

Two long-standing rough edges in the lint/scan targets:

1. **Toolchain drift.** `make lint` / `make scan` invoked whatever versions of
   the linters/scanners happened to be on the host (or CI runner). Results
   differed between a developer's machine and CI, and "works locally" did not
   mean "passes the gate."
2. **Soft-passing gates.** Several `lint-*` sub-targets ended in
   `… || echo "! Warning: … failed"`, so a linter that actually failed still
   left `make lint` green. `scan-images` ran Trivy with `--exit-code 0` and only
   counted `CRITICAL`, so **HIGH** CVEs were advisory and never failed the build.

The output was also a wall of per-tool spew with no summary line, so a human
skimming CI could not quickly see what passed.

## Design

### Pinned tools container

A small `Dockerfile.tools` image carries the lint/scan toolchain (ansible-lint,
semgrep, gitleaks, bandit, ruff, mypy, pip-audit, gosec, golint). A new
`docker-run-tools` helper target builds it and runs an arbitrary `CMD` inside it
against a read-only bind-mount of the repo:

```make
docker-run-tools:
	@docker build -t $(TOOLS_IMG) -f Dockerfile.tools .
	@docker run --rm -v $(PWD):/src:ro -w /src $(TOOLS_IMG) sh -c "$(CMD)"
```

`make lint` and `make scan` route their real work through it
(`docker-run-tools CMD="make lint-all"` / `"make scan-all"`), so local and CI
share one pinned toolchain.

### Fail-closed gates

- `scan-images`: Trivy switched to `--severity HIGH,CRITICAL --exit-code 1`, and
  the per-image tally fails the target on **HIGH or CRITICAL** (was
  CRITICAL-only). Documented exceptions still live in `.trivyignore`.
- The `|| echo "! Warning: …"` soft-passes were removed from `lint-sast`,
  `lint-infra`, `lint-observability`, `lint-supply-chain`, and `lint-docs-all`,
  so a failing sub-linter fails `make lint`.

### Concise verdicts

- `scripts/ci_summary.py` — prints a one-line `✅ CI <STAGE> PASS` after a stage.
- `scripts/pipeline_summary.py` — prints a `=== <Stage> summary — OK ===` verdict
  for `lint` / `scan` / `test`. It runs **after** the stage's real work and only
  when that work succeeded (the recipes use `set -e` / sequential `@`-lines that
  abort on failure first), so it just reports — it never re-runs `make`.

## Bugs fixed while landing

The parked WIP did not work as-is. Three defects were fixed on the branch:

| Bug | Symptom | Fix |
|---|---|---|
| **`pipeline_summary` recursion** | `make test` → `pipeline_summary test` → `make test` → … (infinite); same for `lint`. The scan branch also called `scan_summary.py` with no args (exit 2), breaking `make scan`. | Rewrote all three modes to print a verdict and **never invoke `make`**. The detailed per-image/per-scanner tables remain `scan_summary.py`'s job (`make scan-summary`). |
| **Mangled `lint-docker` recipe** | The new `docker-run-tools` target had been spliced onto the end of `lint-docker`, deleting its trailing `✓ Docker lint passed` echoes and the `lint-shell` comment. | Restored the echoes/comment; promoted `docker-run-tools` to a proper standalone target. `lint-docker` is now byte-identical to `main`. |
| **Self-contradictory CI test** | `tests/integration/test_ci_flow.py` ran real `make lint` / `make scan` (Docker builds, network) and asserted a **clean** repo's scan must **fail**. | Rewrote it to verify the configuration hermetically (no Docker/network): Makefile parses, lint/scan route through `docker-run-tools`, `scan-images` uses `--exit-code 1`, and `pipeline_summary` returns a verdict fast without recursing. |

## Scope (files)

- **New:** `Dockerfile.tools` — pinned lint/scan toolchain image.
- **New:** `scripts/ci_summary.py`, `scripts/pipeline_summary.py` — verdict helpers.
- **New:** `tests/integration/test_ci_flow.py` — hermetic CI-config checks.
- **Edit:** `Makefile` — `TOOLS_IMG`, `docker-run-tools`, route `lint`/`scan`
  through it, harden `scan-images`, drop the soft-pass `|| echo` lines, wire the
  summary calls.
- **Edit:** `CHANGELOG.md` — Phase 313 entry.

## Test strategy

`tests/integration/test_ci_flow.py` (8 tests, ~0.25 s, no Docker/network):

- Makefile parses (`make -n`) and `docker-run-tools` exists.
- `lint` and `scan` route through `docker-run-tools`.
- `scan-images` fails on HIGH+CRITICAL (`--exit-code 1`, no advisory `0`).
- `pipeline_summary` returns `0` with a verdict for each mode, under a short
  timeout (a live guard against the recursion regression), and its source
  contains no `make` invocation (static guard).

## Acceptance criteria

- [x] `make lint` / `make scan` run their work inside the pinned tools container.
- [x] `scan-images` fails the build on **HIGH or CRITICAL** (was CRITICAL-only).
- [x] No `lint-*` sub-target soft-passes via `|| echo "! Warning…"`.
- [x] `make lint` / `make test` / `make scan` do **not** recurse; each ends with
      a concise verdict line.
- [x] `lint-docker` recipe restored (success echoes intact; `docker-run-tools` is
      a standalone target); `make -n` parses cleanly.
- [x] `test_ci_flow.py` is hermetic and passes (8/8); ruff-clean.

## Out of scope

- Changing the `pip-audit` gate behaviour (owned by [[PHASE_311]] / [[PHASE_312]]).
- Adding new linters/scanners or new pinned GitHub Actions.
- The Go build/test targets and the management-UI asset pipeline.

## Risks

- **Container build cost.** Routing through `docker-run-tools` adds a
  `docker build` to local `make lint`/`scan`. Bounded by Docker layer caching;
  the image only rebuilds when `Dockerfile.tools` changes.
- **Stricter gate surfaces existing HIGH CVEs.** Flipping `scan-images` to fail
  on HIGH may turn up previously-advisory findings; each needs a real fix or a
  justified, dated `.trivyignore` entry (loud and intentional, not a regression).
