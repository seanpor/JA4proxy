# Phase 64d -- GameDay scenarios notes

> **Sub-phase of:** Phase 64 (Deployment Validation & Disaster Recovery)
> **Size:** XS
> **Status:** COMPLETE

## Deliverable
- `docs/runbooks/gameday_scenarios.md` -- four exercises with RTO targets
- Dated entry template for `docs/runbooks/disaster_recovery.md` "Runbook Exercise History"

## Coordination
64c has not yet merged, so the "Runbook Exercise History" append to
`disaster_recovery.md` is deferred. A template entry is included in
`gameday_scenarios.md` (Post-Exercise Debrief Template section) and should
be appended to `disaster_recovery.md` after 64c lands and the first Redis
outage GameDay is executed against a live stack.

## What was done
- Created `docs/runbooks/gameday_scenarios.md` with four GameDay exercises:
  1. Redis outage (RTO: detect < 2 min, recover < 5 min)
  2. Single node failure (RTO: detect < 1 min, recover < 2 min)
  3. Total fleet failure (RTO: root cause < 5 min, fleet up < 15 min)
  4. Dial corruption (RTO: detect < 3 min, dial=0 < 3 min, correct < 5 min)
- Each exercise includes: Objective, Environment, Duration, Trigger,
  Team actions (before opening runbook), Success criteria, Related runbook link.
- All commands use `docker compose` (v2), no Python proxy references.

## Test results
First GameDay (Redis outage) has NOT been executed against a live stack.
The exercise log entry is provided as a template with `[DATE]` placeholder
in the Post-Exercise Debrief Template section. This should be filled in
when executed against a live Docker Compose stack.

## Decisions made
- Debrief template included directly in the gameday file rather than a
  separate document, to keep all exercise materials co-located.
- Linked to `disaster_recovery.md` scenarios 1-4 by reference rather than
  duplicating recovery procedures.

## Phase 101 entries surfaced
- Automated GameDay scheduling (cron-triggered fault injection) not in scope.
- Fleet-down Alertmanager rule referenced in Exercise 3 may not exist yet;
  verify during Phase 64f (TLS alerts sub-phase) or file as Phase 101 gap.
