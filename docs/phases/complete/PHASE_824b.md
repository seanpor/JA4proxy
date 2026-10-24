<!--
title: Partial_Auth_And_Panel_Landmarks
audience: developer
last_reviewed: 2026-10-16
phase: 824b
-->

# Phase 824b — Partial Auth Enforcement & Panel Landmarks

> **Size:** SMALL
> **Dependencies:** Phase 824c (for the shared `hx_targets` extractor)
> **Branch:** `phase-824b-partial-auth-landmarks`
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Assert the two things about the console partials that **no existing test does**.

This phase was originally written as "add route-contract tests for the 8
uncovered partials, because a rename would blank a panel unnoticed". A review on
2026-10-16 found that premise to be **false**:

- `management/tests/test_ui_regression.py` (Phase 826) Tier 1 **already** GETs
  every partial URL extracted from the templates, authenticated, and fails on a
  404 — so a renamed or deleted partial already fails CI.
- Of the eight partials the old plan called "uncovered", **six are covered** by
  Tier 1 (`attack-mode-indicator`, `audit`, `dial`, `health-cards`,
  `intelligence`, `intelligence-review`). Only two were genuinely invisible, and
  that was due to an extractor bug in the *existing* gate — now fixed by **824c**.

So the "add 16 route tests" deliverable is dropped as duplicate. What remains is
genuinely missing:

1. **Auth enforcement is asserted per-partial for only 6 of 20 partials.** Only
   `panel1-harm`…`panel5-changes` and `alerts-bar` have an unauthenticated test in
   `make test` (`management/tests/test_pages.py:252-344`). The other 14 partials
   render bans, audit events and intelligence findings, and nothing asserts they
   reject an unauthenticated caller. The live shell script checks 13 of them, but
   only in the integration tier, against a running stack.
2. **Nothing asserts a partial renders the *right* panel.** Tier 2 asserts that
   error markers are **absent**; it does not assert that correct content is
   **present**. A route wired to the wrong template — or one returning an empty
   body — passes every gate that exists today.

---

## Scope

**In:** a new `management/tests/test_partial_contract.py` with two parametrised
tests.

**Out:** the static registration gate (824c); the health endpoint (824d);
journeys (824e); the panels themselves. Do **not** delete or rewrite the existing
`panel1-harm`…`alerts-bar` tests in `test_pages.py` — they are subsumed but
harmless, and removing them is a separate cleanup.

---

## 824b.1 Auth enforcement, parametrised

One test over every `GET` target from the shared extractor, so a new panel is
covered the moment its template lands:

```python
from .hx_targets import hx_targets

GET_TARGETS = sorted({url for method, url, _ in hx_targets() if method == "GET"})

@pytest.mark.asyncio
@pytest.mark.parametrize("url", GET_TARGETS)
async def test_partial_requires_auth(test_client: AsyncClient, url: str) -> None:
    """An unauthenticated GET must be 401, not 500 and not 200.

    A 500 means the handler crashed *before* auth ran. A 200 means customer data
    — bans, audit trail, intelligence findings — is readable without a session.
    """
    response = await test_client.get(url)
    assert response.status_code == 401, (
        f"{url} returned {response.status_code} unauthenticated"
    )
```

All 20 partials and `/api/v1/tls-health` require auth (`get_current_user`, or
`require_role`, which depends on it), so **401 is uniform** — no per-route
exceptions are needed. `_is_html` is irrelevant here.

## 824b.2 Positive content, with landmarks that survive the empty state

Tier 2 proves a panel is not rendering an *error*; this proves it is rendering
*itself*. Use an explicit map, because a guessed landmark is a test that fails for
the wrong reason:

```python
LANDMARKS = {
    "/api/v1/partials/health-cards": "Active Bans",
    "/api/v1/partials/dial": 'aria-label="Dial slider"',
    "/api/v1/partials/audit": 'id="audit-tbody"',
    "/api/v1/partials/intelligence": 'id="intelligence-row"',
    "/api/v1/partials/intelligence-review": 'id="review-content-inner"',
    "/api/v1/partials/attack-top": "No high-activity IPs",
    "/api/v1/partials/attack-fingerprint-table": "No fingerprint data",
    # attack-mode-indicator intentionally absent — see 824b.3
}

@pytest.mark.asyncio
@pytest.mark.parametrize("path,landmark", sorted(LANDMARKS.items()))
async def test_partial_renders_its_panel(
    authenticated_client: AsyncClient, path: str, landmark: str
) -> None:
    response = await authenticated_client.get(path)
    assert response.status_code == 200
    assert _is_html(response)
    assert landmark in response.text, f"{path} did not render its own panel"
```

Each landmark was verified against the template and is correct **in the empty
state**, which is the only state a fake-Redis test reaches:

| Target | Landmark | Why it is safe |
|---|---|---|
| `health-cards` | `Active Bans` | one of four always-rendered default cards (`health_cards.html`) |
| `dial` | `aria-label="Dial slider"` | static markup (`dial_widget.html`) |
| `audit` | `id="audit-tbody"` | rendered in **both** branches (`audit_table.html:11` and `:92`) |
| `intelligence` | `id="intelligence-row"` | unconditional wrapper (`intelligence.html:1`) |
| `intelligence-review` | `id="review-content-inner"` | unconditional wrapper (`intelligence_review_content.html`) |
| `attack-top` | `No high-activity IPs` | the empty branch — the populated branch is unreachable under fake Redis |
| `attack-fingerprint-table` | `No fingerprint data` | same |

**Two corrections to the original plan, both verified:**

- `attack-top`'s and `attack-fingerprint-table`'s recommended landmarks were the
  table headers `IP Address` and `Fingerprint`. Those appear **only in the
  populated branch** (`attack_table.html:15-21`, `attack_fingerprint_table.html`),
  which a fake-Redis test never reaches — so the original landmarks would have
  failed. Use the empty-state strings above, or a container present in both.
- The claim that `id="audit-tbody"` "will fail the empty case" is wrong:
  `audit_table.html` renders `<tbody id="audit-tbody">` in its empty branch too.

## 824b.3 `attack-mode-indicator` is the one exception

The route returns `HTMLResponse("")` when attack mode is inactive
(`management/api/routes/attack_mode.py:212-229`) — the normal state. The content
type is still `text/html`, so assert status and type, and nothing else:

```python
async def test_attack_mode_indicator_is_empty_when_inactive(
    authenticated_client: AsyncClient,
) -> None:
    response = await authenticated_client.get("/api/v1/partials/attack-mode-indicator")
    assert response.status_code == 200
    assert _is_html(response)
    # Body is empty when attack mode is off — asserted above for every other
    # panel, deliberately not here.
```

## 824b.4 Prove each test can fail

A test never seen to fail is not yet a test. Do both, then revert:

- **Landmark:** point one entry at a string the template does not contain (e.g.
  change `attack-top`'s landmark to `IP Address`) and confirm the test fails.
- **Auth:** temporarily change one partial's dependency from `get_current_user` to
  nothing and confirm `test_partial_requires_auth` fails.

Record both in the PR description.

---

## Test Strategy

- Run `make test`. The new file adds roughly `len(GET_TARGETS)` cases per test —
  around 40 fast in-process requests, no live stack.
- Keep the file free of external processes: `authenticated_client` and
  `test_client` already inject `fakeredis` (`management/tests/conftest.py`). Do not
  add new fixtures.
- `make lint` (ruff + mypy) must pass.

---

## Acceptance Criteria

- [x] `management/tests/test_partial_contract.py` exists with the two parametrised
      tests.
- [x] `test_partial_requires_auth` covers **every** extracted `GET` target and
      asserts 401 — including the 14 partials that had no such test before.
- [x] Every entry in `LANDMARKS` is verified against its template and is present
      in the **empty** state.
- [x] `attack-mode-indicator` is excluded from `LANDMARKS` and has its own
      explicit test documenting why.
- [x] Both failure modes were **demonstrated** (landmark and auth) and reverted.
- [x] The new file imports the extractor from 824c — no second copy of the regex.
- [x] `make test` passes; `make lint` passes.
- [x] A fragment exists at `docs/fragments/phase-824b-*.md`.

---

## Close-out

**Status:** COMPLETE (2026-10-24).

### Outcome

| Property | Before | After |
|---|---|---|
| Unauthenticated partial testing | 6 of 20 partials tested (`test_pages.py`) | All 26 extracted GET targets tested in `test_partial_contract.py` |
| Negative test assertion | None for 14 partials | 401 status verified on all targets |
| Positive panel landmark assertion | Tier 2 checks error absence only | `test_partial_renders_its_panel` asserts structural landmarks in empty state |
| Inactive attack mode contract | Implicit | Explicitly verified as 200 text/html with empty string body |

### Evidence

- `management/tests/test_partial_contract.py` — 34 test cases (26 auth + 7 landmark + 1 empty-indicator).
- Demonstrated landmark failure: changing `attack-top`'s landmark to `IP Address` failed with `AssertionError: /api/v1/partials/attack-top did not render its own panel`.
- Demonstrated auth failure: removing `Depends(get_current_user)` from `health_cards_partial` failed `test_partial_requires_auth` with 500 error (`TypeError`).
- `make test` and `make lint` pass 100%.

### Honest limits
- Landmarks verify that the correct template structure renders in the baseline empty state; end-to-end data population remains covered by integration journey tiers.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/tests/test_partial_contract.py` | New — auth + landmark assertions |
| `docs/fragments/phase-824b-partial-auth-landmarks.md` | New file — changelog fragment |

---

## Notes for Implementer

- **Ordering matters:** this phase imports `hx_targets` from 824c. Land 824c first,
  or the two in one branch, or the import fails.
- Reuse `_is_html` — it already exists in `management/tests/test_pages.py`
  (`"text/html" in response.headers.get("content-type", "")`). Import it or
  re-declare the two-line helper; do not invent a third.
- The existing `authenticated_client` issues a token with role `admin`, which
  satisfies `require_role(Role.auditor)` on `attack-mode-indicator`.
- Do **not** assert a 401 versus 403 distinction: `require_role` raises 403 only
  *after* `get_current_user` succeeds, so an unauthenticated caller is always 401.
