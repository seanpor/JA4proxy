---
phase: 232b
title: Threat Posture Situation Bar & Heartbeat Alerting
status: PROPOSED
size: SMALL
created: 2026-06-14
audience: [developer, operator]
dependencies: [232a]
---

# Threat Posture Situation Bar & Heartbeat Alerting

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Part 2 of 4 of the split Phase 232. Adds ambient security posture awareness to the Management Console.

## Goal

Provide operators with immediate awareness of the proxy security posture. Implement a `/api/v1/partials/situation` endpoint that queries Redis (the last 5 minutes of the events stream and proxy heartbeats) and returns an HTML situation bar polled every 10 seconds. When the proxy is active, it displays threat posture status (NOMINAL / ELEVATED / ACTIVE); if the proxy goes down, the situation bar is replaced by a prominent red alerting banner. Update operational documentation to guide operators on interpreting these states.

## Scope

### Files to create/modify:
- [management/api/routes/partials.py](file:///home/sean/LLM/JA4proxy3/management/api/routes/partials.py)
- [management/templates/partials/situation_bar.html](file:///home/sean/LLM/JA4proxy3/management/templates/partials/situation_bar.html)
- [management/templates/dashboard.html](file:///home/sean/LLM/JA4proxy3/management/templates/dashboard.html)
- [docs/OPERATIONS_GUIDE.md](file:///home/sean/LLM/JA4proxy3/docs/OPERATIONS_GUIDE.md)

### Out of scope:
- Compiling static Tailwind CSS or vendoring JS files (covered by 232a).
- Any modifications to compose networking or ports (covered by 232c).
- Any modifications to first-party Go proxy code.

## Implementation Plan

1. **Implement Situation Endpoint**:
   - Add `situation_partial()` to `/management/api/routes/partials.py`.
   - Read from `proxy:heartbeat:*` to detect proxy down events (if missing > 60s).
     **Prerequisite:** nothing writes `proxy:heartbeat:*` on `main` today — this
     program must add the Go producer (see PHASE_234 §5.0). Standardise on
     `proxy:heartbeat:{instance_id}`.
   - Read the last 5 minutes of the `events:connection` stream using `xrevrange`
     (NOT `ja4proxy:events` — that's the legacy analytics stream). Each entry has
     one `event` field of flat dot-keyed ECS JSON: parse it and read
     `event.action`, `event.risk_score`, `source.ip`, `ja4proxy.fingerprint.ja4`.
     Count blocks/tarpits, identify the top attacking IP and highest score.
   - Read the connection rate from `stats:events_per_min`.
   - Classify state as: `PROXY_DOWN`, `NOMINAL` (0 blocks), `ELEVATED` (1-9 blocks), or `ACTIVE` (10+ blocks).
2. **Create Situation Bar Template**:
   - Create `management/templates/partials/situation_bar.html` with explicit styling and colors for all 4 states.
   - Include color + shape (emojis) for accessibility.
   - Return a full-width red alert banner in `PROXY_DOWN` mode containing a link to the recovery runbook.
3. **Wire into Dashboard**:
   - Insert an HTMX polling slot (polled every 10s via `load, every 10s`) at the top of `management/templates/dashboard.html`.
   - Use negative margins (`-mx-6 -mt-6`) to stretch the situation bar edge-to-edge.
4. **Update Operations Guide**:
   - Document the new Threat Posture states in `docs/OPERATIONS_GUIDE.md`. Explain the thresholds and what actions operators should take during `ELEVATED`, `ACTIVE`, and `PROXY_DOWN` incidents.

## Test Strategy

- **Mocked Redis Unit Tests**: Create `tests/unit/test_situation_partial.py` asserting that the situation partial returns the correct HTML output and CSS colors for all 4 states under mocked Redis conditions (testing stream events count, heartbeat keys, and connection rates).
- **Manual Verification**: Add dummy stream logs using `redis-cli XADD` and delete `proxy:heartbeat:*` keys to verify that the UI updates reactively within 10 seconds.

## Acceptance Criteria

- [ ] `/api/v1/partials/situation` endpoint is implemented and passes formatting/lint gates.
- [ ] `situation_bar.html` template handles `NOMINAL`, `ELEVATED`, `ACTIVE`, and `PROXY_DOWN` states correctly.
- [ ] The dashboard template includes the situation bar in a polling slot.
- [ ] [docs/OPERATIONS_GUIDE.md](file:///home/sean/LLM/JA4proxy3/docs/OPERATIONS_GUIDE.md) is updated with threat posture monitoring instructions.
- [ ] Unit tests cover all 4 states with 100% test pass rate and no warning flags.
