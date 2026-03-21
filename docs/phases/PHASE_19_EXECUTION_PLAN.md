# Phase 19 — Backup & Restore Execution Plan (TDD-First)

## Status: READY FOR IMPLEMENTATION

This document is the implementation source of truth for Phase 19 execution order,
task granularity, and verification gates.

Read in order:
1. `docs/phases/PHASE_19.md` (functional intent and background)
2. `docs/phases/PHASE_19b.md` (security supplement and risk posture)
3. `docs/phases/PHASE_19_EXECUTION_PLAN.md` (this file; build order)

---

## Goal

Deliver a production-safe backup and restore framework for Redis-backed JA4proxy
state with:
- deterministic artifact creation
- non-destructive restore by default
- explicit destructive restore path
- integrity validation
- complete observability
- runbook-grade operator documentation

This phase must be implemented using strict TDD (red -> green -> refactor) and
must pass both testing and documentation gates before completion.

---

## Resolved Decisions

- **Encryption in Phase 19:** not implemented. Phase 19 stores plaintext archives
  with filesystem hardening and explicit risk acceptance (as documented in Phase 19b).
- **Restore default:** non-destructive.
- **Destructive restore:** explicit opt-in only (`--force` equivalent path).
- **Backup scope v1:** security-critical and operational keys only; transient
  per-connection/rate-window keys excluded.
- **Single source for implementation order:** this document.

---

## Scope

### In Scope (Phase 19)
- Backup worker module and scheduler integration
- Restore module with validation
- Backup metadata/control keys in Redis
- Manifest format and checksum validation
- Retention management (age and count)
- CLI entry points for backup/restore/list/validate
- Prometheus metrics, logs, and alert rules
- Unit/integration/chaos/adversarial/performance tests
- Docs updates required by standards

### Out of Scope (Phase 19)
- At-rest encryption of backup artifacts
- Off-host replication workflows (S3/GCS/etc.)
- Differential/replication-stream backup
- Management UI controls for backup/restore

---

## TDD Workflow Standard (Applies to Every Task)

For each task below:
1. **Red:** write failing tests first.
2. **Green:** write minimal implementation to pass tests.
3. **Refactor:** clean up while keeping tests green.
4. **Document:** update required docs in the same task batch.

No task is complete unless all four steps are done.

---

## Implementation Plan (Atomic Tasks)

## 19.1 Foundation: Contracts and Scaffolding

### Task 19.1.1 — Define backup key-policy contract
- **Deliverable:** canonical include/exclude/never-backup key policy.
- **Files:**
  - `src/backup/policy.py` (new)
  - `tests/unit/backup/test_policy.py` (new)
- **TDD:**
  - Red: tests for include/exclude precedence and forbidden key exclusion.
  - Green: implement pure-policy matcher functions.
  - Refactor: ensure deterministic ordering and docstrings.
- **Docs:** add policy summary to `docs/REDIS_SCHEMA.md` phase section draft notes.

### Task 19.1.2 — Add backup config schema
- **Deliverable:** validated `backup:` config block with safe defaults.
- **Files:**
  - `config/proxy.yml`
  - config loader validation module(s)
  - `tests/unit/...` config validation tests
- **Required keys:** `enabled`, `destination`, `retention_days`, `retain_count`,
  `schedule`, `max_keys_per_run`, `max_size_bytes`, `include_audit_log`.
- **TDD:** invalid config cases first (missing keys, invalid ranges, bad types).
- **Docs:** inline YAML comments required for all new keys.

## 19.2 Backup Worker (Core)

### Task 19.2.1 — Implement deterministic key enumeration
- **Deliverable:** `SCAN`-based key enumeration with stable ordering.
- **Files:**
  - `src/backup/worker.py` (new)
  - `tests/unit/backup/test_worker_enumeration.py` (new)
- **TDD:** ordering, dedup, exclude filters, max key cap.

### Task 19.2.2 — Implement artifact packaging + manifest
- **Deliverable:** backup archive creation and sidecar manifest JSON.
- **Files:**
  - `src/backup/worker.py`
  - `tests/unit/backup/test_worker_artifact.py`
- **Manifest minimum fields:** filename, created_at, backup_type, keys_count,
  checksum_sha256, size_bytes, included_patterns, excluded_patterns.
- **TDD:** failing tests for schema, checksum generation, timestamp format.

### Task 19.2.3 — Redis control key updates
- **Deliverable:** writes `backup:latest`, `backup:last_success`, `backup:last_failure`,
  history list, retention control behavior.
- **Files:**
  - `src/backup/worker.py`
  - `tests/unit/backup/test_worker_control_keys.py`
- **TDD:** success path and failure path both asserted.

## 19.3 Retention and Cleanup

### Task 19.3.1 — Count-based retention
- **Deliverable:** keep only most recent N artifacts.
- **Files:** worker/cleanup module + unit tests.
- **TDD:** over-limit deletion order tests first.

### Task 19.3.2 — Age-based retention
- **Deliverable:** delete artifacts older than `retention_days`.
- **TDD:** boundary cases (exact age threshold, clock skew tolerance).

### Task 19.3.3 — Combined retention policy
- **Deliverable:** both rules apply deterministically.
- **TDD:** mixed scenarios with explicit expected survivors.

## 19.4 Restore Engine

### Task 19.4.1 — Manifest loader + validator
- **Deliverable:** strict manifest parsing and required-field validation.
- **Files:**
  - `src/backup/restorer.py` (new)
  - `tests/unit/backup/test_restore_manifest.py`
- **TDD:** invalid JSON, missing fields, mismatched filename, corrupted schema.

### Task 19.4.2 — Checksum verification
- **Deliverable:** reject tampered archive/manifest mismatch.
- **TDD:** corruption tests before implementation.

### Task 19.4.3 — Non-destructive restore
- **Deliverable:** restore into existing Redis without full wipe.
- **TDD:** assert pre-existing keys remain.

### Task 19.4.4 — Destructive restore path
- **Deliverable:** explicit wipe-first behavior only when destructive flag set.
- **TDD:** ensure wipe never happens without explicit destructive flag.

## 19.5 CLI Integration

### Task 19.5.1 — `backup` command
- **Deliverable:** CLI subcommand executes backup and returns non-zero on failure.
- **Files:** CLI command wiring + unit tests.

### Task 19.5.2 — `restore` command
- **Deliverable:** CLI restore with safe defaults and explicit force behavior.
- **TDD:** argument-parsing failures, validation failures, force path.

### Task 19.5.3 — `backup list` and `backup validate`
- **Deliverable:** operator visibility and pre-restore checks.
- **TDD:** missing directory, missing manifest, corrupted manifest.

## 19.6 Observability

### Task 19.6.1 — Metrics
- **Deliverable:** `ja4proxy_backup_*` and `ja4proxy_restore_*` metrics.
- **Files:** metrics module + unit tests + observability docs.
- **TDD:** each metric updated in success and failure paths.

### Task 19.6.2 — Structured logs
- **Deliverable:** parseable logs for completed/failed/skipped/cleanup events.
- **TDD:** snapshot-style log tests for required fields.

### Task 19.6.3 — Alerts
- **Deliverable:** stale backup and failure-rate alert rules.
- **Files:** alert rule files + rule tests.

## 19.7 Security Hardening (Phase 19b Items)

### Task 19.7.1 — Never-backup key guard
- **Deliverable:** hard exclusion list always enforced.
- **TDD:** adversarial tests for forbidden key presence.

### Task 19.7.2 — Audit logging of backup/restore operations
- **Deliverable:** write audit events for backup, restore, delete, failure.
- **TDD:** assert event schema and required fields.

### Task 19.7.3 — Filesystem permission validation hooks
- **Deliverable:** startup/runtime checks for unsafe backup directory permissions.
- **TDD:** simulate unsafe permission modes.

## 19.8 Integration and Chaos

### Task 19.8.1 — Real Redis backup/restore integration tests
- **Deliverable:** end-to-end happy-path for backup then restore.

### Task 19.8.2 — Chaos tests
- **Deliverable:** Redis timeout, network interruption, disk-full, corrupted artifact.

### Task 19.8.3 — Adversarial tests
- **Deliverable:** tampered manifest/archive rejection, symlink/path-traversal defense.

## 19.9 Performance and Non-Regression

### Task 19.9.1 — Backup runtime benchmark
- **Deliverable:** dataset-size thresholds with recorded measurements.

### Task 19.9.2 — Hot-path non-regression
- **Deliverable:** prove backup system does not block connection hot path.

## 19.10 Documentation Completion

### Task 19.10.1 — Redis schema updates
- `docs/REDIS_SCHEMA.md`

### Task 19.10.2 — Observability docs
- `docs/OBSERVABILITY_STANDARDS.md`
- runbook/alerts references

### Task 19.10.3 — Operations runbooks
- `docs/SECOPS_OPERATIONS.md`
- `docs/INCIDENT_RESPONSE.md`
- `docs/QUICK_REFERENCE.md`

### Task 19.10.4 — ADR and threat model artifacts
- `docs/decisions/ADR-019.md` (new)
- `docs/security/BACKUP_THREAT_MODEL.md` (new)

### Task 19.10.5 — Changelog
- Add Phase 19 entry in `CHANGELOG.md` only when gate passes.

---

## Milestone Sequence

1. Foundation (`19.1`)
2. Backup core (`19.2`)
3. Retention (`19.3`)
4. Restore core (`19.4`)
5. CLI (`19.5`)
6. Observability (`19.6`)
7. Security hardening (`19.7`)
8. Integration/chaos/adversarial (`19.8`)
9. Performance (`19.9`)
10. Documentation completion (`19.10`)

No skipping forward: each milestone must pass its test set before moving on.

---

## Per-Task Definition of Done

- [ ] Red tests created and fail for the intended reason
- [ ] Implementation makes tests pass
- [ ] Refactor completed; code is typed and documented
- [ ] New failure mode has a chaos or adversarial test
- [ ] Relevant docs updated in same task
- [ ] No regression in existing test suites

---

## Phase Completion Gate (Must All Pass)

- [ ] `make test-unit`
- [ ] `make test-integration`
- [ ] `make test-chaos`
- [ ] `make test-adversarial`
- [ ] `make benchmark` (or project equivalent benchmark command)
- [ ] Backup performance thresholds recorded in benchmark history
- [ ] `docs/REDIS_SCHEMA.md` updated
- [ ] `docs/OBSERVABILITY_STANDARDS.md` updated
- [ ] Runbooks updated (`SECOPS_OPERATIONS`, `INCIDENT_RESPONSE`, `QUICK_REFERENCE`)
- [ ] `ADR-019` present and linked
- [ ] `BACKUP_THREAT_MODEL` present and linked
- [ ] `CHANGELOG.md` updated after all tests/docs pass

---

## Suggested Work Cadence

- Implement in small PR-sized batches: one milestone or 1-3 tasks per batch.
- Keep each batch independently testable and reviewable.
- Do not merge implementation tasks that have placeholder tests.

