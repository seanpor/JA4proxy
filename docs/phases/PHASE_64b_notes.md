# Phase 64b — Helm + kind smoke test notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** XS
> **Status:** COMPLETE

## Deliverables

1. **`scripts/smoke/test_helm_kind.sh`** — Smoke test that creates a single-node
   kind cluster, installs the Helm chart, validates rollout status, runs an
   in-pod health check, and writes PASS to `test-results/smoke/helm-kind.result`.
   Gracefully skips (exit 0) when `kind` is not on PATH. Fails hard when `helm`
   is missing but `kind` is present.

2. **`tests/test_phase64b_smoke_helm.py`** — TDD validation that checks the
   script's structural correctness (shebang, strict mode, skip logic, cleanup
   trap, chart path, result file path, no docker-compose v1) without requiring
   kind or helm installed.

3. **Makefile target** — `smoke-k8s` appended after the 64a `smoke-docker` target.

4. **CI jobs** — `smoke-docker` and `smoke-k8s` jobs added to
   `.github/workflows/ci.yml` with `continue-on-error: true` and SHA-pinned
   actions.

## Decisions made

- The script uses `wget` instead of `curl` for the in-pod health check since
  minimal container images are more likely to have wget (alpine/busybox based).
- Both smoke CI jobs use `continue-on-error: true` so they don't block PRs
  (kind/helm may not be available in all CI environments).

## Phase 101 entries surfaced

None — script is self-contained and does not require chart modifications.
