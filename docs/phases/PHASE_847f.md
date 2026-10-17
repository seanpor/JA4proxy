<!--
title: Reachability_Evidence_Binding
audience: developer
last_reviewed: 2026-10-17
phase: 847f
-->

# Phase 847f — Reachability evidence binding

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** [847a]
> **Branch:** `phase-847f-reachability-binding`
> **Part of:** Phase 847 (umbrella) — see `docs/phases/PHASE_847.md`

---

## Goal

Turn waiver **justifications into automated assertions**, so a waiver's stated
premise is *checked*, not merely *asserted*. If the premise stops being true, CI
says so — instead of the waiver silently outliving its justification.

This is what separates an evidenced waiver from a hand-wave. Today every
`.trivyignore.third-party` entry ends with "Why not exploitable: …" as free text
that nobody verifies and that can silently stop being true.

---

## The idea

Every waiver already carries an implicit claim about **attack surface**. Bind each
`reachability:` value (from 847a's schema) to a machine check:

| `reachability` claim | Automated assertion |
|---|---|
| `internal-monitoring-only` (grafana/loki/prometheus) | The compose file binds the service to an internal network with **no published host port** (`ports:` absent or loopback-only). |
| `not-imported` (e.g. `mcp`, pulled in only by semgrep) | No first-party module imports the package (a source grep / import-linter check). |
| `cli-tooling-only` | The package is only reachable from a CI/dev dependency path, never a runtime image. |
| `input-path-unreachable` | The specific code path is not exercised by any reachable route (best-effort; may be a documented manual attestation where static analysis is infeasible). |

Each waiver's `reachability:` value names one of these checks. A new test runs
**every** bound check and fails if any waiver's premise no longer holds.

---

## 847f.1 Registry → check binding

Extend 847a's schema so `reachability` is an enum naming a registered check, not
free text. The renderer validates that every `reachability:` value has a
registered checker, so an unbound waiver is rejected at authoring time.

## 847f.2 The check library

`scripts/reachability_checks.py` implements each registered check against the live
compose/source files:

- **internal-monitoring-only:** parse the compose files; assert the named service
  has no non-loopback `ports:` and is attached only to internal networks.
- **not-imported:** assert the package appears in no first-party import (reuse the
  discipline of the existing import-hygiene checks; the `mcp` case — imported
  nowhere, pulled in by semgrep — is the reference example).
- **cli-tooling-only:** assert the package is not present in any runtime image's
  dependency set.

## 847f.3 Failure = invalidated premise, not silent pass

When a check fails, the message must name the waiver and the broken premise, and
instruct re-justification — not merely delete the waiver. A waiver whose premise
broke is a **finding**, and re-entering it correctly is the fix. (E.g. if grafana
were later given a public port, the kin-openapi waivers' "internal-only" premise
breaks and they must be re-assessed, not auto-removed.)

---

## Test strategy

- **Binding validity:** every waiver's `reachability:` maps to a registered check;
  an unknown value fails the renderer.
- **Positive:** with the current compose files, all `internal-monitoring-only`
  checks pass (grafana/loki/prometheus are internal-only today).
- **Negative (the whole point):** temporarily add a published port to grafana in a
  scratch compose and assert the kin-openapi waivers' premise check **fails**;
  revert. Record in the PR.
- **not-imported:** assert `mcp` passes (imported by no first-party module).
- Run `make preflight`.

---

## Acceptance criteria

- [ ] `reachability:` is a validated enum bound to registered checks.
- [ ] `scripts/reachability_checks.py` implements every registered check.
- [ ] A CI test runs all bound checks against live compose/source and fails on a
      broken premise (demonstrated with a scratch compose edit).
- [ ] A broken premise produces a "re-justify this waiver" failure, never a
      silent waiver removal.
- [ ] `make preflight` passes.

---

## Files to modify

| File | Change |
|------|--------|
| `scripts/reachability_checks.py` | New — the check library |
| `scripts/render_waivers.py` | Validate `reachability` enum + binding |
| `security/waivers.yaml` | Convert free-text reachability to enum values |
| `tests/unit/test_reachability_checks.py` | New |
| `docs/fragments/phase-847f-reachability-binding.md` | Changelog fragment |

---

## Notes for implementer

- Start with the two checks that are cheap and high-value (`internal-monitoring-only`,
  `not-imported`); `input-path-unreachable` is genuinely hard to automate and may
  legitimately ship as a documented manual attestation — do not block the phase on
  automating it.
- These checks run on the **compose/source state**, so they belong in `make test`
  (fast, static), not in the slow image scan.
- Keep the failure message actionable: name the waiver ID, the premise, the file
  that broke it, and the fix (re-justify or remediate). A bare "check failed" will
  be ignored.
