<!--
title: UI_Health_Endpoint
audience: developer
last_reviewed: 2026-10-15
phase: 824d
-->

# Phase 824d — `/api/v1/health/ui` Four-State Endpoint

> **Status:** PROPOSED
> **Size:** MEDIUM
> **Dependencies:** Phase 824c
> **Part of:** Phase 824 (umbrella) — see `docs/phases/PHASE_824.md`

---

## Goal

Give the console a single red flag. One endpoint fetches every partial the
dashboard polls and reports, per panel, whether it is OK, legitimately empty,
degraded by a dependency, or **broken**. The operator, Prometheus and CI then
share one definition of "the console is broken".

The design rule that matters most: `EMPTY` and `DEGRADED` must **never** read
RED, or a quiet system — or one correctly weathering a Redis outage — reports
itself broken, and the flag is ignored within a week.

---

## Scope

**In:** a new authenticated endpoint and its tests.

**Out:** the Prometheus gauge and any background refresher. The endpoint alone
gives the operator and CI everything they need; a periodic fan-out poller is the
fragilest part of this design and is deliberately deferred. Wire the metric later
only if a consumer actually needs it.

---

## 824d.1 The four states

Reuse Phase 821a's vocabulary (`Ok`/`Empty`/`Unavailable` — see
`docs/phases/complete/PHASE_821a.md`), exposed here in upper case. **`DEGRADED`
is Phase 821a's `Unavailable`, renamed only for the wire format.** Do not invent a
third meaning for it.

| State | Meaning | RED? |
|---|---|---|
| `OK` | rendered with data | no |
| `EMPTY` | rendered, legitimately no data in window | **no** |
| `DEGRADED` | a dependency is down; the proxy is failing open by design | **no** |
| `BROKEN` | route missing, 5xx, non-HTML, or timeout | **yes** |

The console shows a panel as "unavailable" when its dependency is down
(Phase 821a). That is `DEGRADED`. Criterion 6 below (Redis stopped) depends on
this mapping being exact.

## 824d.2 Response shape

```
GET /api/v1/health/ui
{
  "status": "RED",
  "degraded": 1,
  "panels": [
    {"id": "infrastructure", "state": "OK",      "ms": 41},
    {"id": "threat-posture", "state": "EMPTY",   "ms": 12, "reason": "empty"},
    {"id": "health-cards",   "state": "DEGRADED","ms": 5,  "reason": "dependency_unavailable"},
    {"id": "panel5-changes", "state": "BROKEN",  "ms": 5,  "reason": "http_500"}
  ]
}
```

**Aggregate rule:** `status` is `RED` if any panel is `BROKEN`, otherwise
`GREEN`. `DEGRADED` and `EMPTY` never make the aggregate RED; they are reported
in the `degraded` count and per-panel. This rule is load-bearing — CI asserts
"not RED".

**Reason codes** (stable, never upstream text): `route_missing`, `http_5xx`,
`non_html`, `timeout`, `empty`, `dependency_unavailable`. Never return
`str(exc)` — see `JA4PROXY-2026-0008` (management health/metrics endpoints
leaking recon data) and the existing pattern in
`management/api/routes/health.py` where detail is logged server-side only.

## 824d.3 Fetch in-process

Do **not** HTTP-request the app's own address. `deploy/docker/Dockerfile.management:47`
runs `--workers 1`, so a synchronous client inside an `async def` blocks the only
event loop and the self-request can never be served. Use
`httpx.AsyncClient(transport=ASGITransport(app=request.app))` — the pattern in
`management/tests/test_infrastructure_partial.py`.

Two consequences to handle explicitly:

- **Forward the caller's credentials.** Every partial requires
  `get_current_user`. Pass the incoming `Cookie` header on each probe, so the
  probe authenticates as the same user. The endpoint's role floor
  (`require_role(Role.auditor)`, the lowest role) must stay **≥** every probed
  panel's floor. All twenty partials currently use `get_current_user` (any
  authenticated user), so this holds today — if a partial raises its floor above
  the endpoint's, this breaks. Note it in the docstring.
- **Exclude the endpoint itself.** It is polled by a template; probing it would
  recurse. 824c already excludes `/api/v1/health/ui` from the extracted set.

Do **not** point the container HEALTHCHECK at this endpoint: a RED console must
not restart the management container.

## 824d.4 Status is not enough — apply the content check

A 200 is not success: a panel can return 200 containing "unavailable". So
classify by **content**, not by status alone:

1. Route not in `app.routes`, or response `>= 500`, or content-type is not HTML,
   or the probe times out → `BROKEN`.
2. Else, match the body against a small per-panel marker table:
   - body contains an `unavailable` marker → `DEGRADED`
   - else body contains an `empty` marker → `EMPTY`
   - else → `OK`

The marker table is the same knowledge 824b encodes as "landmarks", extended with
the unavailable/empty markers the panels already render (`alerts_bar`,
`health_cards`, `live_feed` and `panel1`–`panel5` carry them today). Panels not
in the table default to `OK` on 200 + HTML — state that limitation in the
docstring rather than pretending coverage the endpoint does not have.

**Do not let it become self-fulfillingly green.** If it only checked HTTP status
it would report `OK` for a panel rendering "unavailable" — exactly the failure it
exists to catch.

## 824d.5 Auth and amplification

`/api/v1/health` is unauthenticated (it is the container HEALTHCHECK). This
endpoint is **not**: left open it becomes an anonymous amplifier — one request
fans out to twenty authenticated, Redis-touching renders. Require at least
`auditor` (`require_role(Role.auditor)`), return reason codes only, and keep it
off any scrape-triggered path.

---

## Acceptance Criteria

- [ ] `GET /api/v1/health/ui` exists and requires authentication (401 when
      anonymous).
- [ ] A healthy stack returns `GREEN` with every panel `OK`.
- [ ] Redis stopped yields `DEGRADED`, **not** RED (the J8 mapping).
- [ ] A deliberately broken panel returns `BROKEN` and makes `status` RED —
      **demonstrated**, not assumed.
- [ ] A legitimately empty panel returns `EMPTY` and does **not** make `status`
      RED.
- [ ] The endpoint never returns an upstream error string.
- [ ] The endpoint excludes itself from the probed set (no recursion).
- [ ] The HEALTHCHECK is unchanged.
- [ ] `make test` passes; `make lint` passes; `make scan` passes.
- [ ] A fragment exists at `docs/fragments/phase-824d-*.md`.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/api/routes/ui_health.py` | New file — the endpoint |
| `management/api/main.py` | Register the router |
| `management/tests/test_ui_health.py` | New file — endpoint tests |
| `docs/fragments/phase-824d-ui-health-endpoint.md` | New file — changelog fragment |

---

## Notes for Implementer

- Reuse the target extractor built in 824c. Do not hand-list the panels.
- The in-process ASGI call re-enters the middleware stack, so each probe also
  increments the request-metrics middleware (`management/api/main.py:328`). With
  ~20 bounded probes this is acceptable; do not build a background poller on top
  of it in this phase.
- Keep the marker table beside the endpoint, one entry per panel, with a comment
  saying which template each marker comes from.
- Test the four states directly. A health check never proven to fail is not a
  health check.
