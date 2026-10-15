<!--
title: Customer_Journey_Catalogue
audience: developer
last_reviewed: 2026-10-15
phase: 824a
-->

# Phase 824a — Customer Journey Catalogue

> **Status:** COMPLETE (2026-10-15)
> **Size:** SMALL
> **Dependencies:** none
> **Branch:** `phase-824a-journey-catalogue`
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Write down what people actually do with JA4proxy, end to end, from the command
line and the console — and, for each journey, the observable outcome that proves
it worked. This is the reference the other Phase 824 sub-phases test against.

It is documentation only. No code, no tests. The value is that it fixes the
**claims** the later phases assert, and it replaces the phase doc's earlier
coverage numbers, which were wrong.

---

## Scope

**In:** `docs/reference/CUSTOMER_JOURNEYS.md` as the catalogue's permanent home;
the corrected, re-derived UI route-coverage table; a `docs/README.md` index
entry; a changelog fragment.

**Out:** any test or production code (824b–824f); the Playwright/browser tier;
J10 capacity (blocked on Phase 819a).

---

## 824a.1 The catalogue

Eleven journeys, each with **trigger / CLI path / console path / proves it
worked**: J1 stop-the-bots, J2 day-one deploy, J3 demo, J4 false-positive rescue,
J5 dial tuning, J6 retrospective, J7 hot config reload, J8 degraded
dependencies, J9 audit & compliance, J10 capacity, J11 upgrade & rollback.

The "proves it worked" line is the deliverable. It is an outcome, never "the
command exited 0", and where enforcement happens it has two halves — the bad
traffic is actioned **and** a legitimate control group survives.

## 824a.2 Correct the coverage numbers

The earlier single-file plan claimed "20 targets, 7 asserted, 13 unasserted" and
listed `alerts-bar`, `panel1-harm`, `panel2-decisions`, `panel3-liveness` and
`panel5-changes` as unasserted. Re-derived against the tree:

| | Count |
|---|---|
| `hx-get` targets across `management/templates/**` | **21** (20 partials + `tls-health`) |
| Have a dedicated route test | **13** |
| **Do not have one** | **8** |

The 8 uncovered partials are `attack-fingerprint-table`,
`attack-mode-indicator`, `attack-top`, `audit`, `dial`, `health-cards`,
`intelligence`, `intelligence-review`. Phase 821b did not widen the gap: it
*added* tests for the panels it added (`b1e5aa14`,
`management/tests/test_pages.py:252-341`).

The catalogue records the derivation command next to the table so the numbers can
be re-checked rather than trusted.

## 824a.3 Index and changelog

Add `CUSTOMER_JOURNEYS.md` to the `docs/README.md` reference index, and add a
news fragment under `docs/fragments/`.

---

## Acceptance Criteria

- [x] `docs/reference/CUSTOMER_JOURNEYS.md` exists with valid frontmatter
      (`title`, `audience`, `last_reviewed`, `phase`).
- [x] All eleven journeys are documented with trigger, CLI path, console path,
      and an explicit "proves it worked" outcome.
- [x] The UI route-coverage table matches a fresh run of the derivation command
      (21 targets / 13 tested / 8 untested).
- [x] The catalogue's claims about `connections.py` vs `compliance.py` match
      `docs/phases/PHASE_824.md` (the DSAR path is `compliance.py`).
- [x] `docs/README.md` links to the catalogue.
- [x] A fragment exists at `docs/fragments/phase-824a-customer-journey-catalogue.md`.
- [x] `make lint` passes (`lint-phases`, `check-manifest`, `doc-health` included).

---

## Files to Modify

| File | Change |
|------|--------|
| `docs/reference/CUSTOMER_JOURNEYS.md` | New file — the journey catalogue |
| `docs/README.md` | Add the catalogue to the reference index |
| `docs/phases/PHASE_824a.md` | New file — this plan (moved to `complete/`) |
| `docs/phases/PHASE_824.md` | Rewrite as the umbrella/index |
| `docs/phases/manifest.yaml` | Add 824a–824f; fix the 826 dependency inversion |
| `docs/fragments/phase-824a-customer-journey-catalogue.md` | New file — changelog fragment |

---

## Notes for Implementer

- The catalogue is the **single source** for the journeys. If a later sub-phase
  needs a journey changed, change it here, not in the phase doc.
- codespell skips `docs/reference/`, and the markdown/spelling checks are
  advisory, so doc prose will not fail `make lint` — review it by eye anyway.
