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

### Every tool runs in a container (no host Python env)

The original idea was to run the whole of `make lint-all` *inside* one tools
container (`docker-run-tools CMD="make lint-all"`). That approach is broken for
this repo: `lint-all` includes sub-targets that themselves `docker run`
(hadolint, shellcheck, trivy, gitleaks, gosec, promtool, amtool) — running them
inside a container means Docker-in-Docker, and the bind-mount paths (`$(PWD)`
inside the container ≠ a path the host daemon can see) don't line up. It also
failed at image-build time because `gitleaks` was in a `pip install` line, and
`gitleaks` is a Go binary, not a PyPI package.

So the design is: **the host `make` orchestrates; each tool runs in its own
container.** No Docker-in-Docker.

- **Python tools + project Python scripts** — one pinned `Dockerfile.tools`
  image (Python 3.14 + the project's pinned requirements so mypy/pytest resolve
  imports, plus `ruff`, `mypy`, `bandit`+`pbr`, `pip-audit`). Run via
  `$(TOOLS_RUN)` (a `docker run … $(TOOLS_IMG)` helper) from `lint-static`,
  `lint-meta`, `doc-health`, `lint-phases`, `test-attack-mapping`. This kills the
  flaky host `pip install` that kept reddening the gate.
- **Tools with their own official images** — run from those directly, as before:
  hadolint, shellcheck, trivy, gitleaks, gosec, promtool, amtool, scorecard,
  lychee. **semgrep** moved to its official image (`semgrep/semgrep`) because it
  does not run on Python 3.14; **ansible-lint** runs from
  `pipelinecomponents/ansible-lint`.
- `make lint` / `make scan` now just call `$(MAKE) lint-all` / `scan-all`
  directly. `scan-all` was already fully containerised.

The CI runner therefore needs only Docker (plus the Go toolchain it already has).

### Deliberate exceptions

- **`lint-go`** keeps using the runner/host Go toolchain (`go fmt`/`go vet`).
  go.mod requires the bleeding-edge **go 1.26**, which lint container images lag;
  the Go toolchain is reliable and is not the breakage this phase targets.
- **`bandit`** runs in the 3.14 image and exits 0, but its plugins emit
  `ast.Num` internal-error noise (removed in Python 3.12+). This is an upstream
  bandit-on-3.14 limitation **also present on `main`** (no regression).
- **Advisory (never gate)**: `ansible-lint` (pre-existing molecule role-path
  syntax-checks), `lychee` link-check (pre-existing link issues; the real gate is
  the `docs-link-check.yml` workflow), and `scorecard-local` (needs a token; the
  gate is `scorecard.yml`). These were advisory on `main` too.

### Fail-closed gates

- `lint-sast` (semgrep) now genuinely gates — it runs from semgrep's official
  image instead of being skipped when semgrep is absent from the host.
- `scan-images` keeps `main`'s posture: scans **HIGH+CRITICAL**, reports both,
  but **gates on CRITICAL only** (HIGH is advisory). The parked WIP tried to gate
  on HIGH too; the first CI run showed the third-party images carry a large
  pre-existing **HIGH** backlog (grafana/tempo, otel, thrift, openssl, gpgv, Go
  stdlib — 13 HIGH, 0 CRITICAL), so HIGH-gating is **deferred** to a dedicated
  CVE-remediation effort rather than blanket-`.trivyignore`-ing real findings.
  (The WIP's HIGH-gate was also buggy — it counted the "CRITICAL: 0" totals line.)

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
| **Mangled `lint-docker` recipe** | The new `docker-run-tools` target had been spliced onto the end of `lint-docker`, deleting its trailing `✓ Docker lint passed` echoes and the `lint-shell` comment. | Restored the echoes/comment. (`docker-run-tools` was later removed entirely — see the row below.) |
| **Self-contradictory CI test** | `tests/integration/test_ci_flow.py` ran real `make lint` / `make scan` (Docker builds, network) and asserted a **clean** repo's scan must **fail**. | Rewrote it to verify the configuration hermetically (no Docker/network): Makefile parses, lint/scan call the aggregate target, the Python linters run via `$(TOOLS_RUN)`, `Dockerfile.tools` has no `pip`-installed gitleaks, `scan-images` uses `--exit-code 1`, and `pipeline_summary` returns a verdict fast without recursing. |
| **`docker-run-tools` broke CI** | First push: required **Full Lint** + **Security Scan** failed — `Dockerfile.tools` couldn't build (`pip install … gitleaks==8.*`), and even fixed it would need Docker-in-Docker for the docker-based sub-linters. | Removed `docker-run-tools`; rebuilt the toolchain as per-tool containers orchestrated by the host (see Design). Verified `make lint` exits 0 locally end-to-end. |

## Scope (files)

- **New:** `Dockerfile.tools` — pinned Python lint toolchain (Python 3.14 +
  project requirements + ruff/mypy/bandit+pbr/pip-audit).
- **New:** `scripts/ci_summary.py`, `scripts/pipeline_summary.py` — verdict helpers.
- **New:** `tests/integration/test_ci_flow.py` — hermetic CI-config checks.
- **Edit:** `Makefile` — `tools-image` + `$(TOOLS_RUN)` helper; route the Python
  linters/scripts through it; semgrep + ansible-lint via official images;
  `lint`/`scan` call `lint-all`/`scan-all` directly; harden `scan-images`;
  `lychee`/`scorecard-local` made advisory; wire the summary calls.
- **Edit:** `CHANGELOG.md` — Phase 313 entry.

## Test strategy

`tests/integration/test_ci_flow.py` (11 tests, ~0.3 s, no Docker/network) plus a
full local `make lint` run (exit 0). The hermetic tests assert:

- Makefile parses (`make -n`) and the `tools-image` target exists.
- `lint`/`scan` call `lint-all`/`scan-all` and do **not** reference the removed
  `docker-run-tools`; no `docker-run-tools:` target exists Makefile-wide.
- The Python linters run via `$(TOOLS_RUN)`; `Dockerfile.tools` has no
  `pip`-installed gitleaks (the original build-breaking bug).
- `scan-images` fails on HIGH+CRITICAL (`--exit-code 1`, no advisory `0`).
- `pipeline_summary` returns `0` with a verdict for each mode under a short
  timeout (a live recursion guard) and its source contains no `make` invocation.

## Acceptance criteria

- [x] Every linter runs in a container; the CI runner needs only Docker (+ Go).
      No host `pip install` of linters.
- [x] `make lint` exits 0 end-to-end (verified locally) and `make scan` runs the
      already-containerised `scan-all` (CRITICAL-gated; HIGH advisory, as on main).
- [x] semgrep gates via its official image (Python-3.14-incompatible on host).
- [ ] **Deferred:** gate `scan-images` on HIGH after the third-party HIGH-CVE
      backlog is remediated (own follow-up).
- [x] `make lint` / `make test` / `make scan` do **not** recurse; each ends with
      a concise verdict line.
- [x] `lint-docker` recipe intact (success echoes); `make -n` parses cleanly.
- [x] `test_ci_flow.py` is hermetic and passes (11/11); ruff-clean.

## Out of scope

- Changing the `pip-audit` gate behaviour (owned by [[PHASE_311]] / [[PHASE_312]]).
- Adding new linters/scanners or new pinned GitHub Actions.
- The Go build/test targets and the management-UI asset pipeline.

## Risks

- **Container build cost.** The first `make lint` builds `Dockerfile.tools`
  (~1.5 min) and pulls the official linter images. Bounded by Docker layer/image
  caching; the tools image only rebuilds when the requirements or
  `Dockerfile.tools` change. In CI this adds a one-off build per lint run unless
  a registry/layer cache is wired up later.
- **Deferred HIGH-gating.** `scan-images` still only gates on CRITICAL. The
  third-party HIGH backlog is real (DoS-class CVEs in tempo/otel/openssl/Go
  stdlib); gating on it now would either block all PRs or require blanket-ignoring
  genuine findings. It needs a focused remediation pass (base-image + dependency
  bumps, with dated `.trivyignore` only where no fix exists) — tracked separately.
