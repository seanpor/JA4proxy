---
phase: 228
title: Human-Readable Scan Summaries
status: COMPLETE
size: SMALL
created: 2026-06-06
completed: 2026-06-09
audience: [developer, operator]
---

> **Outcome (COMPLETE — 2026-06-09).** `scripts/scan_summary.py` (stdlib-only,
> unit-tested) turns the scan blur into compact tables, and `make scan-summary`
> prints two gate-consistent rollups:
> - **Image CVEs (Trivy):** one CRIT/HIGH/MED row per third/first-party image
>   (reuses the Phase 227 `TRIVY_CACHE`).
> - **gosec (Go SAST):** one HIGH/MED/LOW row (built from the pinned
>   `security-scan` image, `gosec -fmt json`).
>
> Both are reporting-only — `make scan` stays the authoritative gate — and their
> verdicts match the gate's severity thresholds.
>
> **Deliberate scope decisions:**
> - A `misconfig` mode exists in the script (and is tested) but is **not**
>   auto-run by `make scan-summary`: a whole-directory Trivy `config` scan is
>   broader than `scan-dockerfiles` (which gates a specific file list), so wiring
>   it would report FAIL for files the gate never checks — contradicting a green
>   `make scan`. It is documented for manual use instead.
> - A `make lint` rollup was **descoped**: unlike the scan tables, `make lint`
>   already prints a short, clear per-target ✓/✗ status, so it is not the "blur"
>   this phase targeted. Revisit only if lint output grows unwieldy.
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
