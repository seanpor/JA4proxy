---
phase: 312
title: pip-audit Dual-Service Fallback — Shrink the Soft-Pass Window
status: COMPLETE
created: 2026-06-11
completed: 2026-06-11
audience: [developer]
---

# pip-audit Dual-Service Fallback

> **Goal.** Make the resilient `pip-audit` wrapper from [[PHASE_311]] soft-pass
> *far less often* by trying a **second** vulnerability service (OSV.dev) when
> the primary (PyPI) is unreachable, before falling back to the
> warn-and-proceed soft-pass. PyPI **and** OSV.dev being down at the same instant
> is far rarer than either alone, so the "couldn't check" window shrinks to
> near-zero — while staying live (no offline DB) and keeping the existing
> PyPI `--ignore-vuln` IDs on the primary path.

## Background

Phase 311's `scripts/pip-audit-resilient.sh` runs `pip-audit` against the default
**PyPI** service, retries on a transient/service error, and **soft-passes with a
CI warning** if PyPI stays unreachable. That soft-pass is the only place the gate
stops being fail-closed. We can make it almost never trigger by adding an OSV
fallback — without the staleness risk of an offline DB (rejected after analysis:
a stale local DB silently misses new CVEs, a worse posture than a *loud* soft-pass).

## Design

Extend the existing wrapper (do **not** rewrite it) with one fallback step.

Behaviour matrix:

| Primary (`-s pypi`) result | Action |
|---|---|
| clean | pass |
| **real vulnerability** | **fail** (a finding is authoritative — no fallback) |
| unknown non-zero (bad args, parse error) | fail safe |
| **service unreachable** after retries | → **try OSV fallback** (below) |

OSV fallback (`-s osv`, retried like the primary):

| OSV result | Action |
|---|---|
| clean | **pass** + info note "verified via OSV fallback (PyPI was unreachable)" |
| **real vulnerability** | **fail** |
| service unreachable too | **soft-pass** with the existing CI `::warning::` (the rare double-outage) |

So the soft-pass now requires **both** services down simultaneously.

## The one real nuance — the ignore-list on the OSV path

The 5 acknowledged transitive CVEs (`--ignore-vuln CVE-2025-50181`, …) are PyPI
advisory IDs. On the OSV service, pip-audit identifies the same advisories by
their OSV/GHSA IDs, so the OSV fallback could **re-surface those 5 as "new"** and
wrongly fail.

Resolution (to verify during implementation):
- pip-audit has `--aliases {on,off,auto}`; with alias resolution, a `CVE-…` in
  `--ignore-vuln` **may** still match the OSV/GHSA entry. **First choice:** pass
  the same `--ignore-vuln` CVE IDs with `--aliases on` on the OSV path and
  confirm the 5 are still suppressed.
- **Fallback if aliases don't cover them:** maintain a tiny explicit map of the
  5 CVEs → their OSV/GHSA IDs and pass those on the OSV path. Keep the map next
  to the wrapper with a comment, and a test that asserts the OSV path suppresses
  exactly those 5.

Acceptance below makes this a hard gate: the OSV fallback must **not** fail on the
5 acknowledged CVEs, and **must** still fail on a genuinely new vuln.

## Scope (files)

- **Edit:** `scripts/pip-audit-resilient.sh` — add the OSV fallback step + the
  ignore-list handling for the OSV path. No change to its public behaviour for
  the common (PyPI-up) case.
- **Edit:** `tests/unit/test_pip_audit_resilient.py` — add fallback cases (stub
  keys off the `-s <service>` arg).
- **No change** to the Makefile / CI wiring (both call sites already use the
  wrapper from phase-311). **No new tool, no new pinned action, no offline DB.**

## Test strategy

Extend the stubbed-`pip-audit` test so the stub varies by the `-s` value:
- PyPI unreachable → OSV clean ⇒ exit 0 (+ "OSV fallback" note).
- PyPI unreachable → OSV finds a real vuln ⇒ exit 1.
- PyPI unreachable → OSV unreachable ⇒ exit 0 (soft-pass + warning).
- PyPI clean ⇒ exit 0, OSV never invoked.
- PyPI real vuln ⇒ exit 1, OSV never invoked (finding is authoritative).
- The 5 acknowledged CVEs are suppressed on **both** paths.

## Acceptance criteria

- [x] A simulated PyPI outage with OSV healthy ⇒ the gate **passes by actually
      checking** (no soft-pass), with a visible "OSV fallback" note.
- [x] OSV fallback still **fails on a real vulnerability** and **does not fail**
      on the 5 acknowledged transitive CVEs.
- [x] Soft-pass now requires **both** services unreachable.
- [x] PyPI-up behaviour is byte-for-byte unchanged from phase-311.
- [x] shellcheck-clean; unit test covers every path; no new pinned action.

## Out of scope

- Offline / vendored OSV database (rejected — staleness is a *silent* worse
  posture; this keeps the check live and loud).
- Switching the *primary* service or the tool (stays pip-audit + PyPI primary so
  the existing CVE `--ignore-vuln` IDs keep working).
- The Go/secrets/semgrep CI jobs (different tools).

## Risks

- **Coverage drift on the fallback path:** OSV's advisory set ≠ PyPI's, so a
  fallback run *could* surface a different finding. This only happens during a
  PyPI outage (rare), is **loud** (fails the gate for a maintainer to triage),
  and is defensible — it is a second opinion, not a silent gap. Acceptable.
- **Slightly longer CI on the rare fallback path** (a second retried audit).
  Bounded by the existing retry/backoff envs.
