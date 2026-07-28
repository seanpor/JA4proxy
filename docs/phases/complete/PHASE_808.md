---
phase: 808
title: "management/tests/ — wire into CI, stop the silent gap recurring"
status: PROPOSED
created: 2026-07-22
audience: [developer]
dependencies: [807]
---

# management/tests/ — wire into CI

> **STATUS: PROPOSED — small. Third of three phases (806/807/808) closing
> the [[PHASE_801]]-adjacent CI gap. Depends on [[PHASE_807]] being green
> first — this phase only wires in what's already passing, it doesn't fix
> anything itself.

## Goal

`management/tests/` (760 tests, including the real SAML/WebAuthn/TOTP/OIDC/
RBAC/pentest-regression coverage) has been excluded from `make test` this
whole time because `pyproject.toml`'s `testpaths = ["tests"]` never looks
there. Make it run, and make sure it can't silently drop out again.

## Plan

1. Add `management/tests` to `pyproject.toml`'s `testpaths`, **or** add an
   explicit `pytest management/tests/ ...` line to the `Makefile`'s `test:`
   target (matching the existing `tests/unit/` / `tests/integration/` /
   `tests/test_workflow_pinning.py` pattern) — pick whichever keeps
   `management/tests/`'s existing `conftest.py`/fixture isolation intact;
   confirm no test-ID collisions with `tests/unit/management/` (same
   service, different directory — check for duplicate test names before
   merging the collection).
2. Confirm `make test` runs all ~760 additional tests and the full suite
   stays green.
3. Add a guardrail test (small, in `tests/`) asserting `management/tests/`'s
   test count is non-zero when collected via whatever mechanism step 1
   used — so a future refactor of `testpaths`/Makefile that silently
   re-excludes it fails loud instead of just going quiet again.
4. Note the fix in `docs/developer/TESTING_STRATEGY.md` if it documents
   `testpaths`/test layout (update if stale).

## Acceptance criteria

- [ ] `make test` runs `management/tests/` — confirmed by a deliberately
      broken test locally (in a throwaway commit, not merged) actually
      failing the CI job, then reverted.
- [ ] No test-ID collisions between `tests/unit/management/` and
      `management/tests/`.
- [ ] A guardrail test exists preventing silent re-exclusion.
- [ ] Full CI green with the larger test count.
