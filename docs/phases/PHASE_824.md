<!--
title: Customer_Journeys_And_UI_Regression_Gate
audience: developer
last_reviewed: 2026-10-15
phase: 824
-->

# Phase 824 — Customer Journeys & UI Regression Gate (umbrella)

> **Status:** PROPOSED
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
| **824b** | Route-contract tests for the 8 uncovered partials | SMALL | — |
| **824c** | T1 gate: every template `hx-*` target resolves; refresh `check_console_journey.sh` | MEDIUM | 824b |
| **824d** | `/api/v1/health/ui` four-state endpoint + tests | MEDIUM | 824c |
| **824e** | T2 journey scripts J1/J2/J4/J8 + `make test-journeys TIER=` | MEDIUM | 824a |
| **824f** | CI tiering + branch protection wiring | SMALL | 824d, 824e |

824a, 824b and 824c have no shared code, so they can be worked in parallel.
824d needs 824c (it reuses the extraction list). 824e needs 824a (the catalogue
names the assertions). 824f is last — it is the only sub-phase that touches
`main`'s branch protection.

---

## The gap, measured (corrected 2026-10-15)

The previous single-file plan said *"20 distinct `hx-get` route targets … 7 have
dedicated route assertions … 13 lack"*. All three numbers were wrong, and they
were the plan's whole justification. The measured numbers:

- **21 `hx-get` targets** appear across `management/templates/**`: **20** under
  `/api/v1/partials/*` plus the `/api/v1/tls-health` page route.
- **13 targets already have a dedicated route test** that GETs the exact path
  (12 partials + `tls-health`).
- **8 partials have no dedicated route test** — this is the real gap.

| Status | Targets |
|---|---|
| Tested | `alerts-bar`, `bans`, `infrastructure`, `list-table`, `panel1-harm`, `panel2-decisions`, `panel3-liveness`, `panel4-reliability`, `panel5-changes`, `situation`, `threat-posture`, `triage-queue`, `tls-health` |
| **Untested** | `attack-fingerprint-table`, `attack-mode-indicator`, `attack-top`, `audit`, `dial`, `health-cards`, `intelligence`, `intelligence-review` |

The earlier claim that Phase 821b *widened* the gap is backwards: 821b added
authenticated + unauthenticated route tests for `panel1-harm`, `panel2-decisions`,
`panel3-liveness`, `panel5-changes` and `alerts-bar` in the same commit that
added the panels (`b1e5aa14`, `management/tests/test_pages.py:252-341`).

Re-derive this table from the tree — do not trust the snapshot:

```bash
grep -rhoE 'hx-get="[^"]*"' management/templates/ \
  | sed -E 's/hx-get="//; s/"$//; s/\?.*//; s/\{%.*//' | sort -u
```

Two structural facts still hold:

- The console is a shell page plus htmx partials polled from
  `/api/v1/partials/*`. `management/tests/test_pages.py` asserts the shell
  renders, but the shell renders **identically** when every partial behind it is
  broken — htmx fetches them after page load.
- `attack-mode-indicator` is registered in `management/api/routes/attack_mode.py`
  and `tls-health` in `management/api/routes/tls_health.py`, not in
  `partials.py`, so a router refactor can blank them with nothing to catch it.

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
- **Phase 826 already landed and mentions Phase 824.** `826` was recorded as
  `dependencies: [824]` while 824 was still PROPOSED — an inversion. The edge was
  removed in this restructure; 826's actual subject (the Intelligence pipeline)
  is now covered by 824e's journeys, so the dependency runs 824 → 826, not the
  other way round.
- **The journeys are documented once**, in
  `docs/reference/CUSTOMER_JOURNEYS.md` (824a). Phase docs reference it; they do
  not restate it.
