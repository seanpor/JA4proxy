# Phase 19 — Junior Implementation Handoff (TDD)

## Status: READY TO START

This is the single document you should follow to implement Phase 19.

---

## Read Order (Do Not Skip)

Before writing code, read these in order:

1. `CLAUDE.md`
2. `docs/phases/PHASE_19.md`
3. `docs/phases/PHASE_19b.md`
4. `docs/phases/PHASE_19_EXECUTION_PLAN.md` (implementation source of truth)
5. `docs/TESTING_STRATEGY.md`
6. `docs/DOCUMENTATION_STANDARDS.md`
7. `docs/REDIS_SCHEMA.md`
8. `config/proxy.yml`

---

## What You Are Building

Implement a backup and restore framework for JA4proxy Redis state with:
- deterministic backup artifacts
- manifest + checksum validation
- non-destructive restore by default
- explicit destructive restore path
- retention (by count and age)
- observability (metrics, logs, alerts)
- operator documentation and runbooks

Out of scope for this phase:
- encryption at rest
- cloud/off-host backup replication
- Management UI controls

---

## Non-Negotiable Engineering Rules

### 1) Strict TDD for every task

Use this cycle only:
1. Write failing tests first (Red)
2. Write minimum code to pass tests (Green)
3. Refactor safely (Refactor)
4. Update docs for that task in the same PR

If tests were not written first, the task is not complete.

### 2) Small PR batches

- Implement only 1-3 atomic tasks per PR.
- Each PR must map to task IDs from `PHASE_19_EXECUTION_PLAN.md`.

### 3) No milestone skipping

Complete milestones in order. Do not start later milestones early.

### 4) Do not mark done without evidence

Each task must include:
- passing tests
- code diff
- doc diff
- short note describing failure mode coverage

---

## Implementation Order (Mandatory)

Follow the milestones in `docs/phases/PHASE_19_EXECUTION_PLAN.md` in this exact order:

1. `19.1` Foundation: contracts and config schema
2. `19.2` Backup worker core
3. `19.3` Retention and cleanup
4. `19.4` Restore engine
5. `19.5` CLI integration
6. `19.6` Observability
7. `19.7` Security hardening
8. `19.8` Integration, chaos, adversarial
9. `19.9` Performance and non-regression
10. `19.10` Documentation completion

---

## Expected Files to Create/Update

### New code files
- `src/backup/policy.py`
- `src/backup/worker.py`
- `src/backup/restorer.py`

### CLI integration
- Existing CLI entrypoint module(s): add backup/restore/list/validate commands

### Config
- `config/proxy.yml`: add `backup:` section with inline comments

### New test files (minimum)
- `tests/unit/backup/test_policy.py`
- `tests/unit/backup/test_worker_enumeration.py`
- `tests/unit/backup/test_worker_artifact.py`
- `tests/unit/backup/test_worker_control_keys.py`
- `tests/unit/backup/test_restore_manifest.py`
- integration/chaos/adversarial/perf files as defined in execution plan

### Docs to update
- `docs/REDIS_SCHEMA.md`
- `docs/OBSERVABILITY_STANDARDS.md`
- `docs/SECOPS_OPERATIONS.md`
- `docs/INCIDENT_RESPONSE.md`
- `docs/QUICK_REFERENCE.md`
- `docs/decisions/ADR-019.md` (new)
- `docs/security/BACKUP_THREAT_MODEL.md` (new)
- `CHANGELOG.md` (when phase gate passes)

---

## Per-Task Definition of Done

A task is complete only when all are true:

- [ ] Red tests written first and failing for the intended reason
- [ ] Minimal implementation passes tests
- [ ] Refactor completed with no behavior change
- [ ] Type hints and docstrings added
- [ ] Relevant docs updated in same PR
- [ ] No regressions in existing tests

---

## PR Template (Use Every Time)

Title format:
- `feat(phase-19): <task id> <short description>`
- Example: `feat(phase-19): 19.2.2 artifact packaging and manifest`

PR body must include:

1. **Task IDs:** e.g. `19.2.1, 19.2.2`
2. **TDD evidence:** list tests added first, and initial failing assertion
3. **Implementation summary:** key modules/functions changed
4. **Failure modes covered:** what can break and test proving behavior
5. **Docs updated:** exact files
6. **Commands run + results:** test/lint/bench commands

---

## Final Phase Completion Gate

Do not mark Phase 19 complete until all are true:

- [ ] `make test-unit`
- [ ] `make test-integration`
- [ ] `make test-chaos`
- [ ] `make test-adversarial`
- [ ] benchmark suite passes and results recorded
- [ ] `docs/REDIS_SCHEMA.md` updated
- [ ] `docs/OBSERVABILITY_STANDARDS.md` updated
- [ ] runbooks updated (`SECOPS_OPERATIONS`, `INCIDENT_RESPONSE`, `QUICK_REFERENCE`)
- [ ] `ADR-019` present and linked
- [ ] `BACKUP_THREAT_MODEL` present and linked
- [ ] `CHANGELOG.md` updated after all tests/docs pass

---

## Escalation Rule

If you hit ambiguity, stop and ask with:
- task ID
- exact blocker
- proposed option A and B
- impact/tradeoff of each

Do not invent behavior that conflicts with `PHASE_19_EXECUTION_PLAN.md`.

