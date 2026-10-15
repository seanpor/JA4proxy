<!--
title: Template_Route_Target_Gate
audience: developer
last_reviewed: 2026-10-15
phase: 824c
-->

# Phase 824c — Template Route Target Gate

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** Phase 824b
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Make the route contract **self-maintaining**: extract every `hx-*` target from
the templates and assert it resolves to a registered route. Adding a panel to a
template then adds its own coverage, with no hand-maintained list to forget.

This is the cheapest check with the highest yield: it catches the class of bug
where a router refactor blanks a panel and nothing notices.

---

## Scope

**In:** a new test that scans `management/templates/**`; a refresh of the stale
hardcoded partial list in `tests/integration/journeys/check_console_journey.sh`.

**Out:** issuing live HTTP requests in the gate (that is 824b for the eight
routes and 824e for journeys); the health endpoint (824d).

---

## 824c.1 Extract the targets

Scan `management/templates/**/*.html` for `hx-get`, `hx-post`, `hx-put`,
`hx-patch`, `hx-delete` attributes. The extractor must handle three things a
naive regex gets wrong:

1. **Jinja in the URL.** `?window={{ window }}`, `?filter={{ key }}` and
   `attack-top{% if attack_mode_active %}?attack_mode=true{% endif %}` are not
   literal paths. Strip `{% ... %}` blocks, and for `{{ ... }}` substitute a
   sample value from a small per-parameter fixture table.
2. **JS-assembled URLs.** `management/templates/partials/threat_posture.html:258`
   builds an `hx-get` in JavaScript and calls `setAttribute`. A static scan
   cannot see it. Either (a) also scan `<script>` blocks and
   `management/static/*.js` for `hx-get` strings, or (b) forbid JS-assembled
   `hx-get` and change that widget to issue a plain htmx request. Pick one and
   state it in the test docstring. (Option (a) is less invasive; today the JS URL
   duplicates the static one, so a scan of the literal string in the script is
   enough.)
3. **Query strings do not affect route resolution.** Resolve on the path only;
   keep the query only for the sample fixture.

Write the extractor as a small helper in the test file, and unit-test the helper
against the three Jinja cases and the JS-assembled one.

## 824c.2 Assert the forward direction

For every extracted target:

- **`hx-get`** → a route matching the path with method `GET` **must** exist in
  `app.routes`. Do not send a request; matching the routing table is enough and
  is free.
- **`hx-post` / `hx-put` / `hx-patch` / `hx-delete`** → a route matching the path
  with the corresponding method **must** exist. **Never send a request to these.**
  They change bans, dials, audit and triage state. The full mutating set is
  listed in `docs/phases/PHASE_824.md`.

A target that matches no route fails the test with the template file and the
target in the message.

## 824c.3 Assert the reverse direction

Build the set of registered `GET` routes under `/api/v1/partials/`, subtract the
set of template targets, and assert the remainder is empty — **except** for an
explicit `ALLOWED_UNREFERENCED` set for deliberate aliases. Today that set
contains one entry: `/api/v1/partials/attack-table`, which is a compatibility
alias of `attack-top` registered as a second decorator
(`management/api/routes/partials.py:1605-1606`).

This catches the opposite failure: a route nobody links to, which rots unseen.

## 824c.4 Exclude the UI health endpoint

The extraction must exclude `/api/v1/health/ui` (added in 824d). It is polled by
the console and would otherwise be probed recursively. Add it to the exclude set
now, even though it does not exist yet, so 824d does not have to remember.

## 824c.5 Refresh the existing hand-rolled check

`tests/integration/journeys/check_console_journey.sh` has a hardcoded partial
list that predates Phase 821b and is stale — it omits `alerts-bar` and
`panel1-harm`…`panel5-changes`. Update the list to be complete, and add a comment
pointing at the new automated test as the authoritative coverage. Do not delete
the script: it runs against a live stack and checks unauthenticated behaviour
(401, no 5xx), which the static gate cannot.

---

## Acceptance Criteria

- [ ] A new test file extracts targets from `management/templates/**`.
- [ ] Every `hx-get` target resolves to a registered `GET` route.
- [ ] Every mutating target resolves by method, and **no** mutating request is
      sent (demonstrate: ban count unchanged after a run — see 824.md).
- [ ] The extractor is tested against `?window={{ window }}`,
      `?filter={{ key }}`, `attack-top{% if … %}` and the JS-assembled URL at
      `threat_posture.html:258`.
- [ ] The reverse check passes and explicitly verifies the `attack-table` alias.
- [ ] Renaming a partial route is **demonstrated** to fail the gate.
- [ ] `check_console_journey.sh`'s partial list is complete.
- [ ] `make test` passes; `make lint` passes.
- [ ] A fragment exists at `docs/fragments/phase-824c-*.md`.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/tests/test_template_route_targets.py` | New file — the extraction gate |
| `tests/integration/journeys/check_console_journey.sh` | Complete the stale partial list |
| `docs/fragments/phase-824c-template-route-gate.md` | New file — changelog fragment |

---

## Notes for Implementer

- The app object is importable the same way `management/tests/test_new_endpoints.py`
  imports it; iterate `app.routes` and match `route.path` + `route.methods`.
- Resolve routes by **path pattern**, not by calling them. Starlette stores
  `/api/v1/bans/{ip}` literally, so match its pattern, not a concrete IP.
- Keep the fixture table of sample query values small and near the extractor.
  One entry per parameter name is enough.
- This gate is deliberately **static**. It proves the route is registered; 824b
  proves the route renders. Both are needed.
