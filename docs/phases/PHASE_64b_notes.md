# Phase 64b — Helm + kind smoke test notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** XS
> **Status:** NOT STARTED

## Deliverable
- `scripts/smoke/test_helm_kind.sh`
- `make smoke-k8s` target in Makefile (append to bottom)
- `smoke-k8s` CI job in `.github/workflows/ci.yml` (optional, non-blocking)

## What was done
<!-- Record kind version, helm version, and the pod log on success. -->

## Test results
<!-- Record PASS/SKIP result, any Helm chart issues discovered. If the chart
uses a DaemonSet instead of Deployment, note the correction made. -->

## Decisions made
<!-- Note any deviations from the spec in PHASE_64.md. -->

## Phase 101 entries surfaced
<!-- If the Helm chart needs fixing for the smoke test to pass, file a Phase 101
entry here rather than blocking 64b. -->
