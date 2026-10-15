<!--
title: Journey_Scripts_T2
audience: developer
last_reviewed: 2026-10-15
phase: 824e
-->

# Phase 824e — T2 Journey Scripts (J1, J4, J8) and Tier Selection

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** Phase 824a
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Turn the highest-value journeys from
`docs/reference/CUSTOMER_JOURNEYS.md` into executable checks that run against a
live stack, and give `make test-journeys` a tier selector so the cheap checks can
run often and the expensive ones can run less often.

`make test-journeys` and the J2 harness already exist
(`tests/integration/journeys/check_console_journey.sh`). This phase adds the
scripts and the tiering; it does not rebuild the harness.

---

## Scope

**In:** J1 (stop-the-bots), J4 (false-positive rescue) and J8 (degraded
dependencies) scripts; tier selection in `make test-journeys`.

**Out:** J2 (exists — refreshed in 824c); J3, J5–J7, J9–J11 (T3/planned); J10
(blocked on Phase 819a); the health endpoint (824d); CI wiring (824f).

---

## 824e.1 Tier definitions

| Tier | What it is | Cost | Frequency |
|---|---|---|---|
| **T1** | static: route resolution, endpoint contract (824b, 824c, 824d tests) | seconds, no stack | every PR |
| **T2** | journeys against a live stack, no fault injection | minutes, one stack | nightly / on demand |
| **T3** | journeys against a live stack with fault injection, restart, upgrade | tens of minutes | weekly / pre-release |
| **T4** | capacity under saturation | long, noisy machine | manual (blocked) |

`make test-journeys` gains a `TIER=` argument (`TIER=2` default). Each script
declares its tier in a header comment and the target selects by that declaration
— do **not** hardcode the list in the Makefile, or it drifts from the scripts.

## 824e.2 J1 — stop the bots

Against a live stack with generated traffic:

1. Baseline: record `allow` and `block` counts from
   `ja4proxy_connections_total` (or `/api/v1/health` + the metrics endpoint).
2. Raise the dial into enforcement (`ja4-admin.sh dial 40`).
3. Assert offered bot traffic is blocked **and** the legitimate control group is
   still served.

**The second half is the test.** A script that only asserts \"bad traffic
blocked\" passes a proxy that blocks everything. Use `make demo-bot` for the
non-browser client and ordinary browser-shaped requests for the control group.

## 824e.3 J4 — false-positive rescue

Against a live stack with a known-blocked IP:

1. Confirm the IP is actioned (`ja4-admin.sh blocked`).
2. Release it (`ja4-admin.sh unblock-ip <IP>`).
3. Assert the client is served again **within one propagation interval**, and a
   repeat of the same fingerprint is not re-blocked.

Time-bound the assertion. \"Eventually\" without a bound is not a regression test.

## 824e.4 J8 — degraded dependencies

Against a live stack (`TIER=3`, because it stops Redis):

1. Stop Redis.
2. Assert traffic still flows and the proxy **fails open**
   (`allow` count still moving).
3. Assert the console shows the panels as unavailable/degraded, **not** stale
   numbers presented as current.
4. Restart Redis and assert recovery.

**This is the one journey that tests the Phase 821a doctrine split** — *the proxy
fails open, the console fails visibly* — end to end. If Redis cannot be stopped
safely, guard the whole check behind the tier so it only runs where it is
expected.

## 824e.5 Budget honestly

The tier argument is a promise about cost. If the 824f CI opt-in budget claims
\"T2 nightly ~5 min\", the scripts must fit that or the budget must change. Each
script prints its own wall-clock at the end so the number is observable rather
than asserted. A journey that quietly takes twenty minutes will be disabled
within a month.

---

## Acceptance Criteria

- [ ] `check_j1_stop_the_bots.sh`, `check_j4_false_positive_rescue.sh` and
      `check_j8_degraded_dependencies.sh` exist, are executable, and follow the
      `ok`/`bad`/`FAIL` convention of the existing J2 script.
- [ ] J1 asserts the **control group survives**, not only that bots are blocked.
- [ ] J4 bounds the recovery assertion in time.
- [ ] J8 asserts fail-open **and** visible degradation, then recovery.
- [ ] `make test-journeys TIER=2` runs the T2 scripts only; `TIER=3` includes J8.
- [ ] Each script prints its wall-clock time.
- [ ] Each script is **demonstrated** to fail when the behaviour it checks is
      broken.
- [ ] `make lint` passes.
- [ ] A fragment exists at `docs/fragments/phase-824e-*.md`.

---

## Files to Modify

| File | Change |
|------|--------|
| `tests/integration/journeys/check_j1_stop_the_bots.sh` | New file |
| `tests/integration/journeys/check_j4_false_positive_rescue.sh` | New file |
| `tests/integration/journeys/check_j8_degraded_dependencies.sh` | New file |
| `Makefile` | `TIER=` selection in `test-journeys` |
| `docs/fragments/phase-824e-journey-scripts.md` | New file — changelog fragment |

---

## Notes for Implementer

- Each journey must state its \"proves it worked\" assertion in a header comment,
  copied from `docs/reference/CUSTOMER_JOURNEYS.md`. That comment is the contract.
- J1 and J4 need a running stack; J8 additionally mutates Redis state. Do not let
  a failed cleanup leave the stack unenforceable — restore the dial to 0 and
  restart Redis in a `trap`.
- Do not add a background refresher or a Prometheus gauge here. See 824d's scope.
