# Phase 22 — Backup System Enhancements Execution Plan (TDD-First)

## Status: PROPOSED

This document outlines the implementation plan for Phase 22 backup system enhancements, following the same strict TDD approach as Phase 19.

**Prerequisite**: Phase 19 must be complete and stable before starting Phase 22.

---

## Goal

Enhance the Phase 19 backup framework with enterprise-grade features:
- **Encryption at rest** (AES-256)
- **Cloud storage integration** (S3, GCS, Azure)
- **Incremental backups** (differential strategy)
- **Compression optimization** (gzip, zstd)
- **Concurrency controls** (distributed locking)
- **Health monitoring** (automated verification)

All enhancements maintain **full backward compatibility** with Phase 19.

---

## Scope

### In Scope (Phase 22)
- Encryption module with multiple key sources
- Cloud storage adapters (S3, GCS, Azure)
- Incremental backup strategy and tracking
- Configurable compression algorithms
- Redis-based distributed locking
- Automated backup health checks
- Enhanced metrics and observability
- Comprehensive test suite (unit, integration, chaos, adversarial, performance)
- Full documentation updates

### Out of Scope (Phase 22)
- Multi-region replication
- Automated scheduling (remains external)
- Tape backup integration
- Database-level backups (RDB/AOF)

---

## TDD Workflow Standard

**Every task follows this workflow:**
1. **Red**: Write failing tests first
2. **Green**: Minimal implementation to pass tests
3. **Refactor**: Clean up while keeping tests green
4. **Document**: Update required docs in same task batch

**No task is complete without all four steps.**

---

## Implementation Plan (Atomic Tasks)

## 22.1 Encryption Foundation

### Task 22.1.1 — Encryption Interface Design
- **Deliverable**: Encryption interface contract
- **Files**:
  - `src/backup/encryption.py` (new)
  - `tests/unit/backup/test_encryption_interface.py` (new)
- **TDD**: Tests for interface methods before implementation
- **Docs**: Interface specification in ADR-022 draft

### Task 22.1.2 — File-Based Key Management
- **Deliverable**: Secure key file handling
- **Files**:
  - `src/backup/key_manager.py` (new)
  - `tests/unit/backup/test_key_manager.py` (new)
- **TDD**: Invalid key paths, permission tests, rotation scenarios
- **Security**: Key files must be 600 permissions, owned by proxy user

### Task 22.1.3 — AES-256-GCM Implementation
- **Deliverable**: Production-ready encryption
- **Files**:
  - `src/backup/encryption.py` (implementation)
  - `tests/unit/backup/test_aes_encryption.py` (new)
- **TDD**: Encryption/decryption round-trip, invalid key handling
- **Performance**: Must not increase backup time >20%

### Task 22.1.4 — Backward Compatibility Layer
- **Deliverable**: Read Phase 19 unencrypted backups
- **Files**:
  - `src/backup/encryption.py` (compatibility)
  - `tests/unit/backup/test_backward_compat.py` (new)
- **TDD**: Detect and handle unencrypted backups
- **Docs**: Migration guide in SECOPS_OPERATIONS.md

## 22.2 Cloud Storage Integration

### Task 22.2.1 — Unified Storage Interface
- **Deliverable**: Abstract storage interface
- **Files**:
  - `src/backup/storage.py` (new)
  - `tests/unit/backup/test_storage_interface.py` (new)
- **TDD**: Interface validation, error handling contract

### Task 22.2.2 — S3 Adapter Implementation
- **Deliverable**: AWS S3 storage adapter
- **Files**:
  - `src/backup/storage_s3.py` (new)
  - `tests/unit/backup/test_storage_s3.py` (new)
- **TDD**: Mock-based tests for all S3 operations
- **Security**: Credential handling, IAM role support

### Task 22.2.3 — GCS Adapter Implementation
- **Deliverable**: Google Cloud Storage adapter
- **Files**:
  - `src/backup/storage_gcs.py` (new)
  - `tests/unit/backup/test_storage_gcs.py` (new)
- **TDD**: Mock-based tests, error scenarios

### Task 22.2.4 — Azure Blob Storage Adapter
- **Deliverable**: Azure Blob Storage adapter
- **Files**:
  - `src/backup/storage_azure.py` (new)
  - `tests/unit/backup/test_storage_azure.py` (new)
- **TDD**: Mock-based tests, retry logic

## 22.3 Incremental Backups

### Task 22.3.1 — Change Tracking Mechanism
- **Deliverable**: Track changed keys since last backup
- **Files**:
  - `src/backup/change_tracker.py` (new)
  - `tests/unit/backup/test_change_tracker.py` (new)
- **TDD**: Key addition/removal tracking, Redis set operations
- **Redis**: Uses `backup:keys_since_last_full` set

### Task 22.3.2 — Incremental Backup Creation
- **Deliverable**: Create incremental backup files
- **Files**:
  - `src/backup/worker.py` (enhanced)
  - `tests/unit/backup/test_incremental_backup.py` (new)
- **TDD**: Incremental vs full backup comparison
- **Manifest**: Extended with incremental metadata

### Task 22.3.3 — Multi-Part Restore Logic
- **Deliverable**: Restore from full + incremental chain
- **Files**:
  - `src/backup/restorer.py` (enhanced)
  - `tests/unit/backup/test_incremental_restore.py` (new)
- **TDD**: Chain validation, missing part detection
- **Ordering**: Enforce chronological restore order

### Task 22.3.4 — Automatic Full Backup Trigger
- **Deliverable**: Trigger full backup after N incrementals
- **Files**:
  - `src/backup/worker.py` (trigger logic)
  - `tests/unit/backup/test_full_trigger.py` (new)
- **Config**: `backup.incremental.max_incrementals_before_full`

## 22.4 Compression & Optimization

### Task 22.4.1 — gzip Compression Implementation
- **Deliverable**: gzip compression support
- **Files**:
  - `src/backup/compression.py` (new)
  - `tests/unit/backup/test_gzip_compression.py` (new)
- **TDD**: Compression/decompression, ratio measurement

### Task 22.4.2 — zstd Compression Implementation
- **Deliverable**: zstd compression support
- **Files**:
  - `src/backup/compression.py` (zstd)
  - `tests/unit/backup/test_zstd_compression.py` (new)
- **TDD**: Performance vs ratio tradeoff tests

### Task 22.4.3 — Compression Ratio Metrics
- **Deliverable**: Track and report compression ratios
- **Files**:
  - `src/backup/metrics.py` (enhanced)
  - `tests/unit/backup/test_compression_metrics.py` (new)
- **Metric**: `ja4proxy_backup_compression_ratio`

### Task 22.4.4 — CPU Usage Monitoring
- **Deliverable**: Monitor compression CPU impact
- **Files**:
  - `src/backup/compression.py` (monitoring)
  - `tests/unit/backup/test_cpu_monitoring.py` (new)
- **Fallback**: Auto-disable if CPU > threshold

## 22.5 Concurrency Controls

### Task 22.5.1 — Redis-Based Locking
- **Deliverable**: Distributed lock mechanism
- **Files**:
  - `src/backup/lock_manager.py` (new)
  - `tests/unit/backup/test_lock_manager.py` (new)
- **TDD**: Lock acquisition, release, timeout scenarios
- **Redis**: Uses `backup:operation_lock` with TTL

### Task 22.5.2 — Lock Timeout Handling
- **Deliverable**: Graceful timeout handling
- **Files**:
  - `src/backup/lock_manager.py` (timeouts)
  - `tests/unit/backup/test_lock_timeout.py` (new)
- **Config**: `backup.concurrency.lock_timeout_seconds`

### Task 22.5.3 — Deadlock Detection
- **Deliverable**: Detect and recover from deadlocks
- **Files**:
  - `src/backup/lock_manager.py` (detection)
  - `tests/unit/backup/test_deadlock.py` (new)
- **Metric**: `ja4proxy_backup_lock_contention_total`

### Task 22.5.4 — Concurrent Operation Tests
- **Deliverable**: Test concurrent backup/restore
- **Files**:
  - `tests/integration/backup/test_concurrent_ops.py` (new)
- **TDD**: Multiple workers, lock contention scenarios

## 22.6 Health Monitoring

### Task 22.6.1 — Scheduled Health Checks
- **Deliverable**: Automated backup verification
- **Files**:
  - `src/backup/health_checker.py` (new)
  - `tests/unit/backup/test_health_checker.py` (new)
- **TDD**: Checksum verification, manifest validation
- **Schedule**: Configurable cron expression

### Task 22.6.2 — Checksum Verification
- **Deliverable**: Verify all backup checksums
- **Files**:
  - `src/backup/health_checker.py` (checksum)
  - `tests/unit/backup/test_checksum_verification.py` (new)
- **Alert**: `BackupHealthCheckFailure` on mismatch

### Task 22.6.3 — Alert Generation
- **Deliverable**: Alert on health check failures
- **Files**:
  - `src/backup/health_checker.py` (alerts)
  - `tests/unit/backup/test_health_alerts.py` (new)
- **Metrics**: `ja4proxy_backup_health_check_status`

### Task 22.6.4 — Auto-Cleanup Logic
- **Deliverable**: Cleanup corrupted backups
- **Files**:
  - `src/backup/health_checker.py` (cleanup)
  - `tests/unit/backup/test_auto_cleanup.py` (new)
- **Config**: `backup.health_check.auto_cleanup_enabled`

## 22.7 Integration & Testing

### Task 22.7.1 — End-to-End Encrypted Cloud Backup
- **Deliverable**: Full workflow test
- **Files**:
  - `tests/integration/backup/test_encrypted_cloud.py` (new)
- **TDD**: Encryption → Cloud upload → Download → Decryption → Restore

### Task 22.7.2 — Incremental Backup Chain Restore
- **Deliverable**: Complex restore scenario
- **Files**:
  - `tests/integration/backup/test_incremental_chain.py` (new)
- **TDD**: Full + 3 incrementals → successful restore

### Task 22.7.3 — Concurrent Operation Scenarios
- **Deliverable**: Stress test concurrency
- **Files**:
  - `tests/integration/backup/test_concurrency_stress.py` (new)
- **TDD**: 5 concurrent backups, lock contention

### Task 22.7.4 — Performance Benchmarking
- **Deliverable**: Baseline measurements
- **Files**:
  - `tests/performance/backup/test_encryption_perf.py` (new)
  - `tests/performance/backup/test_compression_perf.py` (new)
  - `tests/performance/backup/test_cloud_upload_perf.py` (new)
- **Baseline**: Record encryption speed, compression ratios

## 22.8 Documentation

### Task 22.8.1 — Updated Redis Schema
- **Deliverable**: New backup-related keys
- **Files**:
  - `docs/REDIS_SCHEMA.md` (updated)
- **Keys**: `backup:operation_lock`, `backup:keys_since_last_full`

### Task 22.8.2 — Observability Standards
- **Deliverable**: New metrics and alerts
- **Files**:
  - `docs/OBSERVABILITY_STANDARDS.md` (updated)
- **Metrics**: 6 new backup metrics

### Task 22.8.3 — Operations Guide Updates
- **Deliverable**: Enhanced operations documentation
- **Files**:
  - `docs/SECOPS_OPERATIONS.md` (updated)
- **Sections**: Encryption setup, cloud configuration, incremental backup management

### Task 22.8.4 — Security Threat Model
- **Deliverable**: Comprehensive threat analysis
- **Files**:
  - `docs/security/BACKUP_ENHANCEMENTS_THREAT_MODEL.md` (new)
- **Content**: STRIDE analysis for new features

### Task 22.8.5 — Changelog Entry
- **Deliverable**: Phase 22 changelog
- **Files**:
  - `CHANGELOG.md` (updated)
- **Content**: All new features, breaking changes (none), migration notes

---

## Milestone Sequence

1. Encryption Foundation (`22.1`)
2. Cloud Storage Integration (`22.2`)
3. Incremental Backups (`22.3`)
4. Compression & Optimization (`22.4`)
5. Concurrency Controls (`22.5`)
6. Health Monitoring (`22.6`)
7. Integration & Testing (`22.7`)
8. Documentation (`22.8`)

**No skipping forward**: Each milestone must pass its test set before moving on.

---

## Per-Task Definition of Done

- [ ] Red tests created and fail for intended reason
- [ ] Implementation makes tests pass
- [ ] Refactor completed (typed, documented)
- [ ] New failure modes have chaos/adversarial tests
- [ ] Relevant docs updated in same task
- [ ] No regression in existing test suites

---

## Phase Completion Gate

### Testing Requirements
- [ ] `make test-unit` — All unit tests passing
- [ ] `make test-integration` — All integration tests passing
- [ ] `make test-chaos` — All chaos tests passing
- [ ] `make test-adversarial` — All adversarial tests passing
- [ ] `make benchmark` — Performance baselines recorded

### Documentation Requirements
- [ ] `docs/REDIS_SCHEMA.md` updated with new keys
- [ ] `docs/OBSERVABILITY_STANDARDS.md` updated with new metrics
- [ ] `docs/SECOPS_OPERATIONS.md` updated with new procedures
- [ ] `docs/QUICK_REFERENCE.md` updated with new commands
- [ ] `docs/decisions/ADR-022.md` created
- [ ] `docs/security/BACKUP_ENHANCEMENTS_THREAT_MODEL.md` created
- [ ] `CHANGELOG.md` updated

### Quality Requirements
- [ ] 95%+ unit test coverage on new code
- [ ] 85%+ integration test coverage
- [ ] All TDD workflows followed
- [ ] Backward compatibility verified
- [ ] No breaking changes introduced
- [ ] All security requirements met

---

## Suggested Work Cadence

- **Small PR batches**: 1-2 milestones per PR
- **Independent testing**: Each batch independently testable
- **Documentation first**: Update docs before implementation
- **Security review**: Each milestone includes threat analysis
- **Performance baseline**: Record before/after metrics

---

## Implementation Notes

### Backward Compatibility
- Phase 19 backups must remain readable
- All Phase 19 config options supported
- New features disabled by default

### Security Considerations
- Encryption keys never stored in backups
- Cloud credentials from secure sources only
- All operations audited in `management:audit_log`
- Lock operations include timeout protection

### Performance Targets
- Encryption overhead < 20%
- Compression ratio > 50%
- Cloud upload retry logic robust
- Lock contention minimal

---

## Next Steps

1. **Review**: Team review of Phase 22 proposal
2. **Prioritize**: Select initial milestone order
3. **Plan**: Create detailed task breakdown
4. **Implement**: Follow TDD workflow strictly
5. **Test**: Comprehensive test coverage
6. **Document**: Update all documentation
7. **Deploy**: Gradual rollout with monitoring

---

*Phase 22 builds on Phase 19's solid foundation, adding enterprise features while maintaining stability and security.*