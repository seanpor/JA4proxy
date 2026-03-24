# Phase 19 — Backup & Restore Execution Plan (TDD-First)

## Status: IN PROGRESS — core complete; gap closure in progress

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

## Completion Status by Task

Legend: ✅ DONE | ⚠️ PARTIAL | ❌ MISSING | 🔄 IN PROGRESS

## 19.1 Foundation: Contracts and Scaffolding

### Task 19.1.1 — Define backup key-policy contract ✅
- `src/backup/policy.py` — include/exclude/never-backup patterns, `should_backup()`, `order_keys()`
- `tests/unit/backup/test_policy.py` — 14+ tests covering all pattern precedence cases

### Task 19.1.2 — Add backup config schema ✅
- `config/proxy.yml` — `backup:` block with `enabled`, `destination`, `retention_days`,
  `retain_count`, `schedule`, `max_keys_per_run`, `max_size_bytes`, `include_audit_log`
- `tests/unit/test_config_validation.py` — validates all config keys load correctly
- ⚠️ Config defaults mismatch spec: max_keys_per_run=1000 (should be 5M), max_size_bytes=1GB
  (should be 10GB), include_audit_log=true (should be false) — corrected in gap-closure pass

## 19.2 Backup Worker (Core)

### Task 19.2.1 — Implement deterministic key enumeration ✅
- `src/backup/worker.py` — SCAN-based enumeration, stable ordering, exclude filters, max key cap
- `tests/unit/backup/test_worker_enumeration.py` — ordering, dedup, exclude filters, max key cap

### Task 19.2.2 — Implement artifact packaging + manifest ✅
- `src/backup/worker.py` — `.bin` artifact + `.manifest.json` sidecar, SHA256 checksum
- `tests/unit/backup/test_worker_artifact.py` — schema, checksum generation, timestamp format
- ⚠️ Manifest missing `encryption` block (required for Phase 21 extensibility) — added in gap-closure

### Task 19.2.3 — Redis control key updates ✅
- `src/backup/worker.py` — writes `backup:latest`, `backup:last_success`, `backup:last_failure`
- `tests/unit/backup/test_worker_control_keys.py` — success path and failure path asserted

## 19.3 Retention and Cleanup

### Task 19.3.1 — Count-based retention ✅
### Task 19.3.2 — Age-based retention ✅
### Task 19.3.3 — Combined retention policy ✅
- `src/backup/worker.py` `apply_retention()` — dual policy (age + count)
- `tests/unit/backup/test_retention.py` — boundary cases and mixed scenarios

## 19.4 Restore Engine

### Task 19.4.1 — Manifest loader + validator ✅
### Task 19.4.2 — Checksum verification ✅
### Task 19.4.3 — Non-destructive restore ✅
### Task 19.4.4 — Destructive restore path ✅
- `src/backup/restorer.py` — `BackupRestorer` with all four paths
- `tests/unit/backup/test_restore_manifest.py`
- `tests/unit/backup/test_restore_checksum.py`
- `tests/unit/backup/test_restore_nondestructive.py`
- `tests/unit/backup/test_restore_destructive.py`

## 19.5 CLI Integration

### Task 19.5.1 — `backup` command ✅
### Task 19.5.2 — `restore` command ✅
### Task 19.5.3 — `backup list` and `backup validate` ✅
- `src/cli/backup_cli.py` — `BackupCLI` with backup/restore/list/validate subcommands
- `tests/unit/backup/test_cli_backup.py`
- `tests/unit/backup/test_cli_restore.py`
- `tests/unit/backup/test_cli_list_validate.py`

## 19.6 Observability

### Task 19.6.1 — Metrics ✅
- `src/backup/worker.py` and `src/backup/restorer.py` — 13 Prometheus metrics registered
- `docs/OBSERVABILITY_STANDARDS.md` — `ja4proxy_backup_*` and `ja4proxy_restore_*` metrics
- `tests/unit/backup/test_metrics.py`

### Task 19.6.2 — Structured logs ✅
- JSON structured logs for backup_started, backup_succeeded, backup_failed, restore_started,
  restore_succeeded, restore_failed, sensitive_key_detected
- `tests/unit/backup/test_logging.py`

### Task 19.6.3 — Alerts ✅
- `monitoring/alertmanager/rules/backup.rules.yml` — 6 alert rules
  (BackupFailureDetected, BackupStale, RestoreFailureDetected, RestoreOperationInProgress,
  BackupOperationInProgress, BackupDurationHigh)

## 19.7 Security Hardening (Phase 19b Items)

### Task 19.7.1 — Never-backup key guard ✅
- `src/backup/worker.py` `_is_never_backup_key()` — `_KEY_PATTERNS_NEVER_BACKUP` enforced
- `tests/unit/backup/test_never_backup_guard.py`
- `tests/integration/backup/test_adversarial_scenarios.py` — 9 adversarial tests

### Task 19.7.2 — Audit logging of backup/restore operations ✅
- `src/backup/worker.py` and `src/backup/restorer.py` — write to `management:audit_log`
- `tests/unit/backup/test_audit_logging.py`

### Task 19.7.3 — Filesystem permission validation hooks ✅
- `src/backup/worker.py` `_validate_backup_directory()` — world/group-writable checks, ownership
- `tests/unit/backup/test_filesystem_validation.py`

## 19.8 Integration and Chaos

### Task 19.8.1 — Real Redis backup/restore integration tests ⚠️
- `tests/integration/backup/test_real_redis_integration.py` — 1 end-to-end test (skipped without Redis)
- `tests/integration/backup/test_integration_mock_redis.py` — 19 mock-Redis integration tests ✅

### Task 19.8.2 — Chaos tests ✅
- `tests/integration/backup/test_chaos_scenarios.py` — Redis timeout, network interruption,
  disk-full, corrupted artifact

### Task 19.8.3 — Adversarial tests ✅
- `tests/integration/backup/test_adversarial_scenarios.py` — tampered manifest/archive rejection,
  symlink defense, max_keys cap, never-backup guard

## 19.9 Performance and Non-Regression

### Task 19.9.1 — Backup runtime benchmark ✅
- `tests/performance/backup/test_runtime_benchmark.py` — 12 tests with size thresholds

### Task 19.9.2 — Hot-path non-regression ✅
- `tests/performance/backup/test_hot_path_non_regression.py` — 11 tests proving isolation from proxy

## 19.10 Documentation Completion

### Task 19.10.1 — Redis schema updates ✅
- `docs/REDIS_SCHEMA.md` Phase 19 section: backup:latest, backup:last_success,
  backup:last_failure, backup:last_restore, backup:restored_from

### Task 19.10.2 — Observability docs ✅
- `docs/OBSERVABILITY_STANDARDS.md` — all 13 backup/restore metrics registered

### Task 19.10.3 — Operations runbooks ⚠️
- `docs/SECOPS_OPERATIONS.md` — backup section present ✅
- `docs/QUICK_REFERENCE.md` — backup commands present ✅
- `docs/INCIDENT_RESPONSE.md` — backup/restore recovery section MISSING ❌ (added in gap-closure)

### Task 19.10.4 — ADR and threat model artifacts ✅
- `docs/decisions/ADR-019.md` — backup & restore framework decision with encryption deferral
- `docs/security/BACKUP_THREAT_MODEL.md` — attacker table, mitigation analysis

### Task 19.10.5 — Changelog ✅
- `CHANGELOG.md` Phase 19 entry present

---

## Gap Closure Items (Added After Initial Implementation Review)

These items were identified in the post-implementation gap analysis on 2026-03-24.
All must be closed before the Phase Completion Gate is marked PASS.

| # | Item | File(s) | Status |
|---|------|---------|--------|
| G1 | Config defaults: max_keys_per_run 1000→5M, max_size_bytes 1GB→10GB, include_audit_log true→false | `config/proxy.yml`, `tests/unit/test_config_validation.py` | ❌ |
| G2 | Manifest encryption block for Phase 21 extensibility | `src/backup/worker.py` | ❌ |
| G3 | FP corpus tests: verify critical keys included, transient excluded | `tests/fp_corpus/test_backup_fp.py` | ❌ |
| G4 | DEPLOYMENT_SECURITY_MODEL.md with backup security section | `docs/DEPLOYMENT_SECURITY_MODEL.md` | ❌ |
| G5 | INCIDENT_RESPONSE.md backup/restore recovery procedures | `docs/INCIDENT_RESPONSE.md` | ❌ |
| G6 | CHANGELOG.md Phase 19b entry | `CHANGELOG.md` | ❌ |

---

## Milestone Sequence

1. Foundation (`19.1`) ✅
2. Backup core (`19.2`) ✅
3. Retention (`19.3`) ✅
4. Restore core (`19.4`) ✅
5. CLI (`19.5`) ✅
6. Observability (`19.6`) ✅
7. Security hardening (`19.7`) ✅
8. Integration/chaos/adversarial (`19.8`) ✅ (live-Redis test skipped without Redis)
9. Performance (`19.9`) ✅
10. Documentation completion (`19.10`) ⚠️ gap closure in progress

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

- [x] `make test-unit` — 2233 pass (2026-03-24)
- [x] `make test-integration` — all mock-Redis tests pass; live-Redis test requires `make start`
- [x] `make test-chaos` — chaos scenarios pass
- [x] `make test-adversarial` — 9 adversarial tests pass
- [x] `make benchmark` — 23 performance tests pass
- [x] Backup performance thresholds recorded in benchmark history
- [x] `docs/REDIS_SCHEMA.md` updated
- [x] `docs/OBSERVABILITY_STANDARDS.md` updated
- [ ] Runbooks updated (`SECOPS_OPERATIONS` ✅, `INCIDENT_RESPONSE` ❌, `QUICK_REFERENCE` ✅)
- [x] `ADR-019` present and linked
- [x] `BACKUP_THREAT_MODEL` present and linked
- [x] `CHANGELOG.md` updated after all tests/docs pass
- [ ] Gap closure items G1–G6 all closed

---

## Suggested Work Cadence

- Implement in small PR-sized batches: one milestone or 1-3 tasks per batch.
- Keep each batch independently testable and reviewable.
- Do not merge implementation tasks that have placeholder tests.
