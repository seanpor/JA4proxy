---
phase: 807
title: "management/tests/ — fix schema-drifted test fixtures"
status: PROPOSED
created: 2026-07-22
audience: [developer]
dependencies: [806]
---

# management/tests/ — fix schema-drifted test fixtures

> **STATUS: PROPOSED — small, mechanical. Second of three phases (806/807/808)
> closing the [[PHASE_801]]-adjacent CI gap. Depends on [[PHASE_806]] landing
> first (removes the 8 dead-module failures so this phase's diff is only the
> real fixture fixes).

## Goal

Fix the remaining 27 failures in `management/tests/` (35 total minus
[[PHASE_806]]'s 8). Investigated during scoping — these are **test-fixture
drift, not application regressions**:

| Root cause | Files | Evidence |
|---|---|---|
| Stale stream key `ja4proxy:events` + flat-field schema | `test_connections_pagination.py`, `test_dsar_correctness.py`, `test_pentest_dsar_bounded_xrange_regression.py`, `test_compliance_routes.py`, part of `test_new_endpoints.py` | `management/api/routes/connections.py` reads `events:connection` with ECS-dotted JSON under an `"event"` field (documented in its own docstring as "the Go proxy writes...") — the tests seed a different key with flat fields entirely, so every query returns empty. |
| Response fields the route no longer returns | `test_attack.py` (`current_status`, `block_count`) | `grep` confirms neither field exists anywhere in `management/api/routes/attack.py` today. |
| Test bug: reused/non-monotonic XADD id | `test_attack_fingerprints.py` | `redis.exceptions.ResponseError: The ID specified in XADD is equal or smaller than the target stream top item` — a hardcoded `id=entry_id` reused across multiple `xadd()` calls. |

## Plan

1. **Stream-key/schema fixes**: update the affected files' seed helpers to
   write to `events:connection` with the ECS-dotted `{"event": json.dumps(...)}`
   wrapper `connections.py` actually reads — mirror the pattern already
   correct in `test_attack.py`/`test_attack_fingerprints.py`.
2. **`test_attack.py`**: either restore `current_status`/`block_count` to the
   route response (if the fields are still meaningful — check
   `docs/security/findings.yaml`/git blame for why they were dropped, if
   they were) or update the test's expectations to match current behavior.
   Do not restore fields just to make a test pass — confirm which side is
   "correct" first.
3. **`test_attack_fingerprints.py`**: fix the XADD helper to let Redis
   auto-assign IDs (`id="*"`) instead of a hand-rolled, colliding id.
4. Re-run `management/tests/` in full — 0 failures.

## Acceptance criteria

- [ ] `management/tests/` passes in full (0 failures, matching whatever
      skip count is legitimate).
- [ ] Every fixture that seeds connection events uses the real
      `events:connection` / ECS-dotted schema — no test writes to the
      retired `ja4proxy:events` key.
- [ ] `test_attack.py`'s field expectations are verified correct (not just
      silenced) — a one-line note in the PR description on which side moved
      and why.
