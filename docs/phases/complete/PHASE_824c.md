<!--
title: Template_Route_Target_Gate
audience: developer
last_reviewed: 2026-10-16
phase: 824c
-->

# Phase 824c — Template Route Target Gate

> **Status:** COMPLETE (2026-10-23)
> **Size:** SMALL–MEDIUM
> **Dependencies:** none
> **Branch:** `phase-824c-template-route-gate`
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Close the **last** route-coverage hole in the console and add the two target
checks that no test performs today.

This phase was originally written as "build a self-maintaining gate". A review on
2026-10-16 found that gate **already exists** — `management/tests/test_ui_regression.py`
(Phase 826) parametrises Tier 1 over every `hx-get` URL it extracts from the
templates, so a renamed partial already fails CI. Building a second gate would be
duplicate work.

What that gate does **not** do, and this phase adds:

1. It **silently drops** any `hx-get` whose URL contains a Jinja brace — its regex
   is `hx-get=["']([^"'{}]+)["']`. Exactly two template URLs are brace-only, so
   exactly two partials are invisible to it: `attack-top` and
   `attack-fingerprint-table`. That is a real hole in an existing guard.
2. It never checks **mutating** targets (`hx-post`/`hx-delete`) against the route
   table.
3. It never checks the **reverse** direction (a registered partial route that no
   template references, which rots unseen).

---

## Scope

**In:** a shared `hx-*` extractor; repairing `_hx_urls()` so Tier 1 sees the two
dropped partials; a new static registration gate for forward + reverse + mutating
targets; refreshing the stale partial list in
`tests/integration/journeys/check_console_journey.sh`.

**Out:** sending any request (that is the existing Tier 1 and Phase 824e);
positive content assertions and per-partial auth enforcement (Phase 824b);
`/api/v1/health/ui` (Phase 824d); the panels themselves.

---

## 824c.1 One extractor, shared

Add `management/tests/hx_targets.py` exposing a single function used by both this
gate and Tier 1:

```python
ATTR = re.compile(r"""hx-(get|post|put|patch|delete)=["']([^"']*)["']""")
JINJA_TAG = re.compile(r"\{%.*?%\}", re.S)      # {% if ... %} / {% endif %}
JINJA_EXPR = re.compile(r"\{\{.*?\}\}", re.S)   # {{ window }}

def hx_targets() -> list[tuple[str, str, str]]:
    """(method, request_url, path) for every hx-* target in the templates."""
    out = []
    for tpl in TEMPLATES.rglob("*.html"):
        for m in ATTR.finditer(tpl.read_text(encoding="utf-8")):
            url = JINJA_EXPR.sub("sample", JINJA_TAG.sub("", m.group(2).strip()))
            if url.startswith("/"):
                out.append((m.group(1).upper(), url, url.split("?", 1)[0]))
    return out
```

Normalisation rules, and why each exists:

1. **Remove `{% ... %}` tags.** `attack-top{% if attack_mode_active %}?attack_mode=true{% endif %}`
   becomes `attack-top?attack_mode=true`. Stripping only the tags (not the block
   body) is correct and keeps the query.
2. **Replace `{{ ... }}` with the sample token `sample`.** Handles `?window={{ window }}`
   and `?filter={{ key }}`.
3. **Keep the query in `request_url`; drop it for `path`.** Do not drop it from
   `request_url` — `list-table` is `?list=`-driven and may not render without it.
4. **Never match a URL containing `{` or `}` after normalisation.** If one
   survives, the normaliser is incomplete; fail loudly rather than pass silently.

Unit-test the normaliser against all four real cases plus the JS one in 824c.4.

## 824c.2 Repair Tier 1 so it sees the two dropped partials

Change `_hx_urls()` in `management/tests/test_ui_regression.py` to build its list
from the shared extractor:

```python
from .hx_targets import hx_targets

def _hx_urls() -> list[str]:
    return sorted({url for method, url, _ in hx_targets() if method == "GET"})
```

This is the whole fix for the hole — after it, `attack-top?attack_mode=true` and
`attack-fingerprint-table?attack_mode=true` are requested by Tier 1 like every
other panel. Verify both newly appear, and that the existing "guard the guard"
test (`len(_hx_urls()) >= 5`) still passes and its count **rose** from 22.

## 824c.3 The static registration gate

New file `management/tests/test_template_route_targets.py`. It sends **no
requests** — it matches the extracted target against the declared route table.

**Discover routes by parsing decorators, not by calling `create_app()`.** An
existing test already learned this the hard way and documented it —
`management/tests/test_pages.py:349` (`test_no_template_links_to_a_route_that_does_not_exist`):
the app registers a different route set per environment, and a `create_app()`-based
version *"passed on a dev host and failed in the CI container"*. Reuse that test's
approach; do not reintroduce the flaky one.

Capture the **method** so mutating targets can be checked, tolerate a multi-line
decorator, and tolerate an `f` prefix:

```python
DECORATOR = re.compile(
    r'@router\.(get|post|put|patch|delete)\(\s*f?[\'"]([^\'"]+)[\'"]'
)
```

- **Forward.** For each `(method, _, path)`, assert some registered route matches
  `path` **and** declares `method`. Match by **prefix** — strip each declared route
  at its first `{` — exactly as `test_pages.py:375` does. This is required because
  real routes are parameterised in ways a literal comparison would miss:
  `/api/v1/bans/{ip:path}`, `/api/v1/lists/{list_type}/{list_name}/{entry:path}`,
  `/api/v1/intelligence/dismiss/{finding_id}`.
- **Never send the mutating ones.** `hx-post` and `hx-delete` targets change bans,
  dials, audit and triage state. The gate is static for all targets; the full set
  is listed in `docs/phases/PHASE_824.md`.
- **Guard the guard.** Assert the extractor found ≥ 20 targets and ≥ 6 mutating
  targets, so a broken regex fails instead of passing vacuously.
- **Reverse.** Enumerate registered `GET` routes under `/api/v1/partials/`,
  subtract the referenced paths, and assert the remainder is **exactly**
  `{"/api/v1/partials/attack-table"}`. Assert the set equals that value (not merely
  `⊆`), so a future allowance cannot be added without someone choosing to.
- **Justify the alias.** A second test asserts `/api/v1/partials/attack-table` is
  referenced by **no** template `hx-get` — that is precisely why it is allowed. It
  is a second decorator on the `attack-top` handler
  (`management/api/routes/partials.py:1605-1606`), and the only mention in a
  template is an HTML comment (`management/templates/partials/attack_table.html:3`),
  which is not an `hx-get`.

## 824c.4 Record the two blind spots (do not try to fix them here)

A static `hx-*` attribute scan cannot see every target. Both known gaps are
acceptable **and must be written down in the test docstring**, because a future
reader will otherwise assume the gate is exhaustive:

- **JS-assembled URLs.** `management/templates/partials/threat_posture.html`
  builds its `hx-get` in JavaScript (`setThreatWindow()` calls
  `container.setAttribute('hx-get', '/api/v1/partials/threat-posture?window=' + …)`).
  The same path also appears as a static literal
  (`hx-get="/api/v1/partials/threat-posture?window=15m"`), so the **path** is
  covered. Assert that invariant — the JS-built path is covered by a static
  target — rather than scraping `<script>` blocks.
- **Python-generated attributes.** `management/api/routes/events.py` emits
  `hx-post` attributes from server-side f-strings (the live-feed row buttons). The
  scan is templates-only by design; those targets duplicate template ones. Do not
  extend the scan to `*.py` in this phase.

## 824c.5 No exclusion for `/api/v1/health/ui`

The earlier draft required excluding `/api/v1/health/ui` from "probing". That
requirement is **dropped**: this gate sends no requests, and `/api/v1/health/ui` is
not under `/api/v1/partials/` so it is outside the reverse check anyway. When
Phase 824d adds that route *and* its template `hx-get` in the same change, the
forward check covers it for free — and if the template lands first, the forward
check fails until the route exists, which is the desired behaviour. Do not add a
special case.

## 824c.6 Refresh the hand-rolled live check

`tests/integration/journeys/check_console_journey.sh:59` lists 13 partials and
expects **401** from each against a live unauthenticated stack. It is stale: it
omits **seven** — `alerts-bar`, `list-table`, `panel1-harm`, `panel2-decisions`,
`panel3-liveness`, `panel4-reliability`, `panel5-changes`.

Complete the list to all 20, and add a comment pointing at
`management/tests/test_template_route_targets.py` as the authoritative coverage
map. Keep the script — it is the only check that runs against a live stack and
asserts real unauthenticated behaviour (401, no 5xx), which a static gate cannot.

---

## Test Strategy

- Unit-test the normaliser (`hx_targets`) against: `?window={{ window }}`,
  `?filter={{ key }}`, `attack-top{% if … %}…{% endif %}`, a plain literal, and the
  JS-built URL from `threat_posture.html`.
- Prove the gate **can fail**: temporarily rename one partial decorator (e.g.
  `dial` → `dial-x`) and confirm the gate reports it; temporarily delete
  `ALLOWED_UNREFERENCED`'s entry and confirm the reverse check fails. Revert both.
  Record in the PR description.
- **Demonstrate the hole being closed.** Before 824c.2, assert
  `/api/v1/partials/attack-top` is absent from `_hx_urls()`; after, present. Put
  this in the PR description — it is the phase's actual value.
- Run `make test` and `make lint`.

---

## Findings during close-out

Three defects surfaced while verifying the phase rather than while writing it.
Each is recorded here because each one is the *class* of failure the phase
exists to prevent, found inside the gate itself.

### 1. The forward check could not fail

`_route_prefix_matches()` split the declared route at its first `{` and treated
the remainder as a path prefix. Two declared routes then matched **every**
target:

* `GET /` — prefix `"/"` ends with `/`, so "starts with the prefix" is always true;
* `GET /api/v1/{list_name}` (the f-string-registered canonical list route) —
  prefix `"/api/v1/"`, so every `/api/v1/...` target matched a route that only
  accepts one segment.

The gate was therefore green for the wrong reason on all 48 targets: a template
could reference a route that does not exist and the forward check would still
pass. Found by *actually performing the demonstration the acceptance criteria
ask for* — renaming `/api/v1/partials/attack-mode-indicator` failed the reverse
check and the journey parity check, but the forward check stayed green.

Fixed by matching segment-wise: a literal segment must be equal, `{name}`
matches exactly one segment, `{name:path}` consumes the rest, and the segment
counts must otherwise agree. This is deliberately **stricter** than
`test_pages.py`'s prefix rule — a gate that accepts a catch-all as proof of a
specific route is worse than useless.

### 2. The journey's partial list drifted immediately

`check_console_journey.sh` cannot import the route table (it is a shell script
asserting real 401s against a running stack), so its `PARTIALS=(...)` list is a
hand-maintained copy — and the first draft of the refresh dropped
`attack-mode-indicator` while claiming completeness. A parity test now parses
`PARTIALS=(...)` and fails when it differs from the registered partials (minus
the justified alias).

### 3. The repaired extractor exposed a real panel bug

`/api/v1/partials/attack-top` calls the JSON handler `top_attackers()` directly,
bypassing FastAPI's dependency injection. Its `window: int = Query(...)` default
therefore reached `time.time() - window` (`TypeError`) and the response's
`window_seconds` field (not JSON serialisable). The attack table had **never**
rendered its content path; htmx's failure branch hid it exactly the way the
Intelligence panel was hidden before Phase 826. Fixed at the call site (the
partial has no window parameter of its own, so the handler's default is what
belongs there) and pinned by a partial-level test.

---

## Acceptance Criteria

- [x] `management/tests/hx_targets.py` exists and is unit-tested against the four
      Jinja/JS cases.
- [x] `_hx_urls()` now includes `attack-top` and `attack-fingerprint-table`, and
      Tier 1's URL count rose accordingly (48 targets, 19 partials referenced).
- [x] Every extracted target resolves to a route by **path + method**, matched
      segment-wise (see finding 1 — the first implementation could not fail),
      with routes parsed from decorators (not `create_app()`).
- [x] No request is sent for any mutating target (the gate is static).
- [x] The reverse check passes and asserts the allowance set is **exactly**
      `{"/api/v1/partials/attack-table"}`, with a test proving it is unreferenced.
- [x] Renaming a partial route, and removing the allowance, were each
      **demonstrated** to fail the gate (3 failed / 51 passed and 2 failed / 52
      passed respectively — see finding 1).
- [x] The two blind spots (JS-assembled, Python-generated) are documented in the
      test docstring.
- [x] `check_console_journey.sh` lists all 20 non-alias partials, and a parity
      test fails when the list drifts (finding 2).
- [x] `make test` passes; `make lint` passes.
- [x] A fragment exists at `docs/fragments/phase-824c-template-route-gate.md`.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/tests/hx_targets.py` | New — the shared `hx-*` extractor/normaliser |
| `management/tests/test_template_route_targets.py` | New — forward + reverse + mutating gate, journey parity |
| `management/tests/test_ui_regression.py` | `_hx_urls()` delegates to the extractor |
| `management/api/routes/partials.py` | Resolves the handler's `Query` default at the direct call site (finding 3) |
| `management/tests/test_attack.py` | Pins the attack-table partial contract |
| `tests/integration/journeys/check_console_journey.sh` | Complete the stale partial list (20 non-alias partials) |
| `docs/fragments/phase-824c-template-route-gate.md` | New file — changelog fragment |

---

## Notes for Implementer

- **The gate is static by design.** It proves a route is *registered*; the
  existing Tier 1 proves the route *renders*. Both are needed and both are cheap.
  Do not merge them.
- The decorator parser cannot see routes registered from an **f-string** — e.g.
  `management/api/routes/canonical_lists.py:320-392` registers
  `f"/api/v1/{list_name}"`. That is acceptable here: no partial route is registered
  that way, so the reverse check is sound. Document it, and do **not** loosen the
  matcher to "fix" a failure it causes — a loose matcher would hide the real
  breakage this gate exists to catch.
- `attack-top` and `attack-table` are the **same handler** with two decorators.
  `attack-table` is the alias; `attack-top` is what templates reference.
- A discovered, **out-of-scope** defect worth reporting separately (not fixing
  here): `management/static/confirm-modal.js:26` builds
  `/api/v1/actions/${target}/tarpit`, and no route under `/api/v1/actions/` exists
  anywhere in `management/api/`. The modal's "Tarpit IP" action therefore 404s.
  This is a JS-built URL, so this gate would not have caught it either.

---

## Close-out

**Landed in PR** on branch `phase-847f-reachability-binding` (bundled with 847f
rather than given its own PR: the change is a test-only gate plus one call-site
fix, and it was completed while 847f was in flight).

| Gate | Result |
|---|---|
| `management/tests/test_template_route_targets.py` | 54 passed (48 parametrised forward cases, 5 behavioural) |
| `management/tests/test_ui_regression.py` + `test_attack.py` | 79 passed (Tier 1/2/3 green, including the two targets the old extractor dropped) |
| Machine demonstrations | route rename → 3 failed / 51 passed; allowance removed → 2 failed / 52 passed |
| `make lint`, `make test` | green |

The journey script itself was **not** executed: `check_console_journey.sh` needs a
running POC stack. Its list is now parity-checked against the route table, so the
part it can get wrong statically is covered by CI.

### Residual (documented, deliberately not fixed here)

`management/static/confirm-modal.js:26` assembles
`/api/v1/actions/${target}/tarpit`, and no route under `/api/v1/actions/` exists —
the modal's "Tarpit IP" action 404s. It is a JS-assembled URL, so this gate would
not catch it either (one of the two documented blind spots). Out of scope: it
needs a product decision (wire the action to the ban/tarpit endpoint, or remove
the control), not a test repair.
