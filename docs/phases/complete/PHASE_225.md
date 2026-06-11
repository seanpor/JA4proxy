---
phase: 225
title: Hermetic Tooling & `make doctor` Accuracy
status: PROPOSED
size: MEDIUM
created: 2026-06-05
audience: [developer, operator]
---

# Hermetic Tooling & `make doctor` Accuracy

## Goal

Stop `make doctor` (and the lint/scan targets) from depending on version-sensitive
tools installed on the host. Run those tools in pinned containers so results are
reproducible regardless of the developer's machine, and make `doctor` report
accurately instead of "muttering" about tools that are *intended* to live in
containers.

## Motivation

On a clean dev host `make doctor` currently warns about:

```
! Warning: Python version is Python 3.10.12. Expected 3.14+ for full compatibility.
! Warning: hadolint not found (some targets will fail)
! Warning: trivy not found (some targets will fail)
! Warning: amtool not found (some targets will fail)
! Warning: gitleaks not found (some targets will fail)
! Warning: codespell not found (some targets will fail)
! Warning: markdownlint not found (some targets will fail)
```

These are the symptom of two problems:

1. **No interpreter pinning.** Local Python is 3.10.12 but the project targets
   3.14 (`pyproject.toml: python_version = "3.14"`). Running mypy/ruff/bandit
   against 3.10 yields version-mismatch noise and can mask or invent findings.
2. **Host-tool assumption.** `hadolint`, `trivy`, `amtool`, `gitleaks`,
   `codespell`, `markdownlint` are expected on `PATH`. They are not present by
   default and *shouldn't have to be* — they belong in containers (the repo
   already has `deploy/docker/security-scan/` and `deploy/docker/update-checker/`
   as the pattern).

This was flagged as a follow-on in PHASE_224 (the Makefile guard there is
deliberately kept host-only and stdlib, and must stay that way).

## Design

1. **One tool-runner image** (or reuse/extend `security-scan`) that bundles the
   pinned toolchain: Python 3.14 + ruff/mypy/bandit, plus trivy, hadolint,
   gitleaks, codespell, markdownlint, amtool. Pin by digest (matches the repo's
   SLSA/Scorecard posture).
2. **Targets run tools via the image**, not the host — e.g. a `TOOL_RUN` wrapper
   (`docker run --rm -v $(PWD):/src <img> <tool> …`) used by `lint-*`/`scan-*`.
   Keep a `LOCAL=1` escape hatch for contributors who do have the tool, and keep
   graceful skip-if-absent for the no-Docker case.
3. **`make doctor` becomes accurate:**
   - Check Docker (the one true host dependency for tooling) and the tool image's
     availability/pullability — not each individual tool on `PATH`.
   - Treat host `python`/`go` as needed only for the fast host-side paths
     (`meta_lint`, unit tests). Report the 3.10-vs-3.14 gap as informational with
     the remediation ("tools run in the 3.14 container").
   - Distinguish **blocking** (Docker missing) from **informational** (a host
     tool absent but containerized).
4. **Keep the PHASE_224 guard host-only.** `scripts/meta_lint.py` must remain
   stdlib and run without Docker — it is the one thing that must work everywhere.

## Out of Scope

- Upgrading the host's system Python (this phase removes the *need* to).
- Changing what any linter/scanner reports (that is PHASE_226).

## Acceptance Criteria

1. On a host with only Docker + Go + Python3 (no trivy/hadolint/gitleaks/etc.),
   `make doctor` reports a healthy environment with **no false "tool not found"
   warnings** — containerized tools are reported as available-via-container.
2. `make lint` and `make scan` run their tools in pinned containers and produce
   identical results on two different host Python versions.
3. `make doctor` clearly separates blocking vs informational checks.
4. `make lint-meta` still runs with no Docker present (host-only guard intact).
5. A `LOCAL=1` (or equivalent) path lets contributors use host tools when present.

## Open Questions

- Single fat tool image vs. a few small ones (security vs. docs vs. python)?
- Pull-on-demand vs. a `make tools-pull` prefetch step in `init`?
