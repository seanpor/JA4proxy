---
phase: 228
title: Human-Readable Scan Summaries
status: IN_PROGRESS
size: SMALL
created: 2026-06-06
audience: [developer, operator]
---

> **Progress — Trivy image summary (DONE 2026-06-09).** `scripts/scan_summary.py`
> (stdlib-only) runs Trivy in JSON mode for each image (reusing the Phase 227
> `TRIVY_CACHE`) and prints a one-row-per-image CRIT/HIGH/MED table with a
> verdict + rollup, via `make scan-summary`. It is reporting-only — `make scan`
> stays the gate — and is unit-tested (`tests/unit/test_scan_summary.py`).
>
> **Remaining.** Fold in the gosec JSON summary and a `make lint` rollup so the
> same at-a-glance view covers the misconfig + SAST + multi-linter output, not
> just third/first-party image CVEs.
---

# Human-Readable Scan Summaries

## Goal

Turn the wall of raw scanner output (`make scan`, `make lint`) into a compact,
human-readable summary so a person can tell at a glance what passed, what
failed, and why — without scrolling through pages of Trivy tables.

## Motivation

Post-Phase-226 the scans are honest but verbose: each of ~6 images prints a full
Trivy table, plus Dockerfile misconfig tables, plus gosec output. The signal
(which image has which CRITICAL) is buried in a blur of repeated tables. The same
applies to `make lint`'s multi-linter output.

## Scope

- A small parser (e.g. `scripts/scan_summary.py`, stdlib-only like
  `meta_lint.py`) that consumes machine-readable scanner output (`trivy
  --format json`, `gosec -fmt json`) and prints:
  - a one-line-per-image table: `image | CRITICAL | HIGH | top CVEs`,
  - a final `PASS/FAIL` verdict with the exact gating reason,
  - a pointer to the full log for detail.
- Keep the raw output available (e.g. behind `VERBOSE=1` or written to a file)
  so nothing is hidden — this summarizes, it does not suppress.
- Apply the same treatment to the `make lint` aggregate where practical.

## Out of Scope

- Changing scan/lint gating behaviour (Phase 226).
- A web dashboard (this is terminal/CI-log output only).

## Acceptance Criteria

1. `make scan` ends with a compact summary table + a clear PASS/FAIL line naming
   the gating finding(s).
2. Full detail remains accessible (file or VERBOSE flag) — no information hidden.
3. The summary's PASS/FAIL exactly matches the real exit code (no divergence
   between what it says and what gates).
