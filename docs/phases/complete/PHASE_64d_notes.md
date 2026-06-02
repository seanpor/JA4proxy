# Phase 64d — GameDay Scenarios Notes

## Artifacts Created

| File | Purpose |
|------|---------|
| `docs/runbooks/gameday_scenarios.md` | 4 GameDay exercise definitions |

## Acceptance Checklist

- [x] File exists with all four exercises
- [x] Each exercise links back to matching scenario in `disaster_recovery.md`
- [x] Each exercise has: environment, duration, trigger, pre-runbook actions, success criteria, RTO target
- [x] Runbook Exercise History section present (empty, for GameDay logging)
- [x] Post-Exercise Checklist present
- [x] First GameDay (Redis outage) NOT yet exercised locally — will be done during live validation

## Decoupling from 64c

- Exercise history is written to `gameday_scenarios.md` (this file's own section)
- After 64c merges, a follow-up commit will copy the exercise history entry
  to `disaster_recovery.md`'s "Runbook Exercise History" section
- This is tracked as a Phase 64 close-out checklist item, not a blocking dependency

## Out of Scope

- Exercise execution (done during live validation, not during doc creation)
- K8s and systemd GameDay variants (deferred until those deployment targets validated)
- MTTR measurement (Phase 64h)
