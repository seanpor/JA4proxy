<!--
title: Customer_Journeys_And_UI_Regression_Gate
audience: developer
last_reviewed: 2026-10-15
phase: 824
-->

# Phase 824 — Customer Journeys & UI Regression Gate (umbrella)

> **Size:** LARGE (umbrella — split into six SMALL/MEDIUM sub-phases)
> **Dependencies:** Phase 816 (COMPLETE), Phase 821a (COMPLETE), Phase 821b (COMPLETE)
> **Branch:** one branch per sub-phase, e.g. `phase-824a-journey-catalogue`
> **Supersedes:** the single-file PHASE_824 plan, split 2026-10-15 after review
> found its coverage numbers came from a stale snapshot.

---

## Goal

The suite proves the parts work. It does not prove **a person can get their job
done** — and it does not notice when the console renders a blank dashboard.

This umbrella is the coordination point for a persona-level regression layer
(the customer journeys) and a UI gate that turns "the console is broken" into a
red check instead of an empty page nobody notices. The work is split so each
piece is independently reviewable and small enough to hand to a junior engineer.

---

## Sub-phases

| Sub-phase | Deliverable | Size | Deps |
|---|---|---|---|
| **824a** | Journey catalogue in `docs/reference/CUSTOMER_JOURNEYS.md` | SMALL | — |
| **824b** | Per-partial auth enforcement + panel landmarks | SMALL | 824c |
| **824c** | Fix the Tier-1 extractor hole; static forward/reverse/mutating target gate; refresh `check_console_journey.sh` | SMALL–MEDIUM | — |
| **824d** | `/api/v1/health/ui` four-state endpoint + tests | MEDIUM | 824c |
| **824e** | T2 journey scripts J1/J2/J4/J8 + `make test-journeys TIER=` | MEDIUM | 824a |
| **824f** | CI tiering + branch protection wiring | SMALL | 824d, 824e |

**824c is the foundation and lands first.** It repairs the extractor hole in the
existing Tier 1 gate, and 824b imports its `hx_targets` helper — so the edge runs
824c → 824b, not the other way round. 824d reuses 824c's target list. 824e needs
only 824a and can proceed in parallel with 824b–824d. 824f is last — it is the
only sub-phase that touches `main`'s branch protection.

---

## The gap, measured (corrected 2026-10-16)

Two successive versions of this table were wrong in different ways, and each was
the plan's whole justification. Re-derive it from the tree; do not trust a
snapshot.

- **20 `hx-get` partial targets** appear across `management/templates/**`, plus
  `/api/v1/tls-health` = **21**.
- **`management/tests/test_ui_regression.py` (Phase 826) already covers 18 of the
  20 partials** — and `tls-health` — with an authenticated GET that fails on a
  404. Tier 1 is parametrised over URLs extracted from the templates, so it is
  self-maintaining.
- **Exactly 2 partials were invisible to it**: `attack-top` and
  `attack-fingerprint-table`. Not because they lacked a test, but because the
  extractor's regex (`hx-get=["']([^"'{}]+)["']`) **drops any URL containing a
  Jinja brace**, and those two are brace-only:
  `hx-get="/api/v1/partials/attack-top{% if attack_mode_active %}…{% endif %}"`.
  Fixing that regex is 824c's first job.
- The earlier "13 tested / 8 untested" table was wrong because it counted only
  tests that name a route **literally**. Tier 1 builds its URLs from `_hx_urls()`,
  so grepping for the string `/api/v1/partials/health-cards` finds nothing even
  though the route is requested on every run. 824b's original "add 16 tests for 8
  uncovered partials" was duplicate work and has been replaced.

| Status | Targets |
|---|---|
| Covered by Tier 1 (live authenticated GET) | 18 partials + `tls-health` |
| **Invisible to Tier 1 (extractor drops braces)** | `attack-top`, `attack-fingerprint-table` |
| No per-partial auth assertion in `make test` | 14 partials — only `panel1-harm`…`panel5-changes` + `alerts-bar` have one |

The earlier claim that Phase 821b *widened* the gap is backwards: 821b *added*
authenticated + unauthenticated tests for the panels it added (`b1e5aa14`,
`management/tests/test_pages.py:252-341`).

Re-derive the target list from the tree — and remember that grepping for a route
name will **not** find the parametrised Tier 1 cases:

```bash
# every hx-* target, with its method — the authoritative re-derivation
grep -rhoE 'hx-(get|post|put|patch|delete)="[^"]*"' management/templates/ | sort -u
```

Two structural facts still hold:

- The console is a shell page plus htmx partials polled from
  `/api/v1/partials/*`. `management/tests/test_pages.py` asserts the shell
  renders, but the shell renders **identically** when every partial behind it is
  broken — htmx fetches them after page load.
- `attack-mode-indicator` is registered in `management/api/routes/attack_mode.py`
  and `tls-health` in `management/api/routes/tls_health.py`, not in `partials.py`.
  Tier 1 catches a rename of either (both have brace-free `hx-get`s), and 824c's
  static gate catches the same rename by method as well as path.

**Mutating targets must never be probed** (they change bans, dials, audit and
triage state). The full set, extracted from the templates:

```
POST   /api/v1/bans
POST   /api/v1/bans/{ip}
DELETE /api/v1/bans/{ip}
DELETE /api/v1/dial/revert
POST   /api/v1/intelligence/dismiss/{id}
POST   /api/v1/intelligence/mark-fp/{id}
POST   /api/v1/lists/ja4/blacklist/{ja4}?source=attack_ui
POST   /api/v1/triage/dismiss/{ip}
```

Check these for **route registration only** (match against `app.routes`); never
send them a request.

---

## Shared design constraints

These apply to every sub-phase. They are here so they are written once.

1. **Assert on outcomes, never on "the command exited 0."** J1 asserts blocked
   *and* allowed counts, not that a `curl` returned.
2. **Every journey with an enforcement action needs a control group.** Legitimate
   traffic must be present and must survive, or "block everything" passes.
3. **Distinguish "no data" from "broken."** Reuse Phase 821a's state vocabulary.
   A panel that is legitimately empty must fail differently from one that is
   broken, or a flaky timing failure and a real regression look identical.
4. **`EMPTY` and `DEGRADED` (Phase 821a's `Unavailable`) must never read RED.** A
   quiet system — or one correctly weathering a Redis outage — must not report
   itself broken, or the flag is ignored within a week. When in doubt, apply
   `CLAUDE.md`'s core asymmetry: a false positive (a real user blocked) is the
   expensive failure.
5. **Do not point the container HEALTHCHECK at the UI health check.** A red
   console must not restart the management container.
6. **Never leak upstream error strings** from a health endpoint. Return stable
   reason codes; log the detail server-side. See `JA4PROXY-2026-0008`, which was
   a real finding about management health/metrics endpoints leaking recon data.

---

## Out of scope

- **Playwright / real-browser tier.** Own phase, after 824c and 824d prove out
  the cheaper tiers.
- **J10 capacity.** Blocked on Phase 819a's benchmark fix — the existing
  benchmark is rate-limited and reports a constant.
- **J3's environment and the console panels themselves.** Phases 816 and
  821a/821b completed those; 824e asserts on them.
- **The `management/api/routes/connections.py` unbounded-read fix.** That is a
  separate security issue (unbounded `xrange(_STREAM_KEY)` at lines 212, 281,
  334). It is *not* on the DSAR path — the DSAR export lives in
  `compliance.py`, whose unbounded read is already fixed (`JA4PROXY-2026-0035`,
  `closed_commit: ce4da33`). Do not conflate the two.

---

## Notes for Implementer

- **Phase 824f touches branch protection.** `tests/test_workflow_pinning.py:318`
  asserts the contexts in `scripts/branch_protection.sh` equal ci.yml's
  non-`continue-on-error` job names plus the declared externals. Any new
  required job must be added to that script in the same change, or the test
  fails. Only the cheap checks should be required; a flaky required check stalls
  every merge.
- **Phase 826 also landed the UI regression gate this umbrella assumed it had to
  build.** `management/tests/test_ui_regression.py` implements Tier 1 (every
  `hx-get` URL resolves, live and authenticated), Tier 2 (a 200 that renders an
  error state still fails) and Tier 3 (fingerprint drill-down content). 824c is an
  **extension** of that file — it fixes the extractor's brace hole and adds the
  mutating/reverse checks — not a new gate. Check the tree for an existing guard
  before writing a new one; the original plan and its first correction both
  missed this file.
- **The journeys are documented once**, in
  `docs/reference/CUSTOMER_JOURNEYS.md` (824a). Phase docs reference it; they do
  not restate it.
