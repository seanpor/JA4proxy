<!--
title: Partial_Route_Contract_Tests
audience: developer
last_reviewed: 2026-10-15
phase: 824b
-->

# Phase 824b — Partial Route Contract Tests

> **Status:** PROPOSED
> **Size:** SMALL
> **Dependencies:** none
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Eight of the console's twenty htmx partials have no test that requests their
route. If one is renamed or deleted, the console silently renders a blank panel
and no test notices — the shell page still returns 200, because htmx fetches the
partials *after* page load.

This phase closes that gap by adding a route-contract test for each of the eight,
using the pattern already in `management/tests/test_pages.py`.

---

## Scope

**In:** eight routes in `management/tests/test_pages.py`.

**Out:** the template-extraction gate (824c); the health endpoint (824d);
journeys (824e); the panels themselves.

---

## 824b.1 The eight routes

| Route | Recommended landmark |
|---|---|
| `/api/v1/partials/health-cards` | a card/status container (check `health_cards.html`) |
| `/api/v1/partials/dial` | `aria-label="Dial slider"` |
| `/api/v1/partials/audit` | `id="audit-tbody"` or `No audit events found` |
| `/api/v1/partials/intelligence` | `Intelligence` |
| `/api/v1/partials/intelligence-review` | `id="review-content-inner"` |
| `/api/v1/partials/attack-top` | `IP Address` (table header) |
| `/api/v1/partials/attack-fingerprint-table` | `Fingerprint` (table header) |
| `/api/v1/partials/attack-mode-indicator` | **none** — see 824b.3 |

## 824b.2 The test shape

For each route, add two tests to `management/tests/test_pages.py`, copying the
`test_panel4_reliability_partial_*` pair exactly:

```python
@pytest.mark.asyncio
async def test_dial_partial_authenticated(authenticated_client: AsyncClient) -> None:
    """GET /api/v1/partials/dial returns 200 with HTML when authenticated."""
    response = await authenticated_client.get("/api/v1/partials/dial")
    assert response.status_code == 200
    assert _is_html(response)
    assert 'aria-label="Dial slider"' in response.text


@pytest.mark.asyncio
async def test_dial_partial_unauthenticated(test_client: AsyncClient) -> None:
    """GET /api/v1/partials/dial without auth returns 401, not 500."""
    response = await test_client.get("/api/v1/partials/dial")
    assert response.status_code == 401
```

The unauthenticated half matters: a 500 means the handler crashed *before* auth
ran, which is a different (worse) bug than a 401.

## 824b.3 Pick a landmark that survives the empty state

Choose a landmark string that is present **both** when the panel has data and
when it legitimately has none — a container `id` or a table header, not a data
row. `audit_table.html` renders `No audit events found` when empty, so
`id="audit-tbody"` alone will fail the empty case; assert the landmark **or** the
empty-state string.

`attack-mode-indicator` is a special case: the route returns an **empty string**
when attack mode is inactive (`management/api/routes/attack_mode.py:212`), which
is the normal state. For that route, assert only `status_code == 200` and
`_is_html` — do **not** assert on content.

Verify each landmark by reading the template under
`management/templates/partials/`. Do not guess; a wrong landmark is a test that
fails for the wrong reason.

## 824b.4 Prove it can fail

After the tests pass, rename one route handler's decorator path (e.g. change
`/api/v1/partials/dial` to `/api/v1/partials/dial-x`), run the suite, confirm
the new test fails, then revert. A test never seen to fail is not yet a test.
Do this for at least one route and record it in the PR description.

---

## Acceptance Criteria

- [ ] 16 new tests exist (8 routes × authenticated/unauthenticated).
- [ ] Each authenticated test asserts `200`, `text/html`, and a landmark that is
      correct for the empty state.
- [ ] Each unauthenticated test asserts `401` (not `500`).
- [ ] Renaming one route was **demonstrated** to fail its test.
- [ ] `make test` passes; `make lint` passes.
- [ ] A fragment exists at `docs/fragments/phase-824b-*.md`.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/tests/test_pages.py` | Add 16 route-contract tests |
| `docs/fragments/phase-824b-partial-route-contract-tests.md` | New file — changelog fragment |

---

## Notes for Implementer

- Use the existing `authenticated_client` and `test_client` fixtures in
  `management/tests/conftest.py`. Do not create new ones.
- `_is_html()` already exists at the top of `test_pages.py`; reuse it.
- Keep all eight routes in one file. 824c replaces this hand-maintained list with
  one extracted from the templates, so this phase's value is the *rendering*
  assertions (200 + real content), which 824c's route-resolution check does not
  cover.
