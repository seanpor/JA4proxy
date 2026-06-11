---
phase: 311
title: Resilient pip-audit — Stop PyPI Outages Reddening the Lint Gate
status: COMPLETE
created: 2026-06-11
completed: 2026-06-11
audience: [developer]
---

# Resilient pip-audit

> **Goal.** Stop transient PyPI/OSV outages from failing the **required** Full
> Lint gate. The flakes produce public red CI on the repo and email maintainers
> on every occurrence — without any actual security finding.

## Problem

`pip-audit` (default `pypi` service) queries PyPI's per-package JSON API once per
dependency. A transient `503`/timeout there raises `ServiceError` and exits
non-zero, so `lint-static` (inside `make lint`) fails. This has reddened the
gate repeatedly (the `scapy/2.7.0/json` 503 on #121; earlier semgrep/PyPI
flakes on #116/#120) — pure upstream availability, not a vulnerability.

Switching to the OSV service was rejected: the existing `--ignore-vuln` entries
are PyPI advisory IDs, and OSV uses different IDs, which would resurface the
acknowledged transitive CVEs as failures.

## Solution

A wrapper `scripts/pip-audit-resilient.sh` that passes all args through to
`pip-audit` but classifies the outcome:

| Outcome | Action |
|---------|--------|
| Clean | exit 0 |
| **Real vulnerability found** | **exit 1 — always blocks** |
| Vulnerability *service* unreachable (5xx / timeout / connection / 429) | retry with linear backoff; if still down after N attempts, emit a CI `::warning::` and **exit 0** |
| Any other non-zero (bad args, parse error) | exit non-zero — **fail safe** |

The soft-pass is deliberately narrow: it triggers **only** when the service is
unreachable, **never** when a finding is reported. Persistent gaps remain
covered by the **weekly scheduled** CI audit, the standalone
`dependency-audit-python` job, and Dependabot — so a one-PR transient miss is an
acceptable trade against a red required gate + maintainer email spam.

Tunables via env: `PIP_AUDIT_RETRIES` (4), `PIP_AUDIT_BACKOFF` (5s), `PIP_AUDIT_TIMEOUT` (30s).

## Scope

- **New:** `scripts/pip-audit-resilient.sh`; `tests/unit/test_pip_audit_resilient.py`.
- **Edit:** `Makefile` `lint-static` → call the wrapper (keeps the 5 `--ignore-vuln`).
- **Edit:** `.github/workflows/ci.yml` standalone `dependency-audit-python` job → wrapper.
- No new GitHub Action (a `run:` step), so the workflow-pinning gate is unaffected.

## Test strategy

`test_pip_audit_resilient.py` stubs `pip-audit` on `PATH` and asserts all four
paths: clean→0, real-vuln→1, transient-outage→0 (with warning), unknown→fail-safe.

## Acceptance criteria

- [x] A simulated transient outage soft-passes (exit 0 + warning), not red.
- [x] A real vulnerability still fails (exit 1).
- [x] Unknown non-zero fails safe.
- [x] shellcheck-clean; both call sites (Makefile + CI job) use the wrapper.
- [x] No new pinned action introduced.

## Out of scope

- Switching the vulnerability service to OSV (breaks the PyPI `--ignore-vuln` IDs).
- Vendoring an offline vuln DB.
- The Go/secrets/semgrep jobs (different tools; address separately if they flake).
