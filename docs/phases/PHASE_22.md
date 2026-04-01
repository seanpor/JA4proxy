# PHASE 22 — Backup System Enhancements - Phase 1: Core Features

Status: PROPOSED

> **Prerequisite**: Phase 19 (Backup & Restore Framework) must be complete and stable.
> **Type**: Feature enhancement phase (builds on Phase 19 foundation)
> **TDD Approach**: Strict TDD required for all new functionality

---

## 1. Overview

Phase 22 enhances the Phase 19 backup system with **encryption at rest**, **cloud storage integration**, **incremental backups**, and **performance optimizations**. This phase maintains full backward compatibility with Phase 19 backups while adding enterprise-grade features.

### 1a. Goals

| Goal | Description | Success Criteria |
|------|-------------|------------------|
| **Encryption** | AES-256 encryption for backup files | Backups encrypted with configurable key management |
| **Cloud Storage** | S3/GCS/Azure Blob Storage support | Backups can be stored in cloud object storage |
| **Incremental** | Differential backup strategy | 70%+ reduction in backup size for incremental runs |
| **Compression** | gzip/zstd compression options | 50-80% reduction in backup file size |
| **Concurrency** | Distributed locking mechanism | Safe concurrent backup/restore operations |
| **Monitoring** | Enhanced backup health checks | Automated integrity verification and alerts |

### 1b. Non-Goals (Out of Scope)

- **Backup scheduling**: Still handled externally (cron/systemd)
- **Multi-region replication**: Future phase consideration
- **Backup rotation to tape**: Not applicable for this system
- **Database-level backups**: Redis RDB/AOF remain separate

---

## 2. Functional Requirements

### 2a. Encryption at Rest

**Requirement**: All backup files must support optional encryption

**Implementation**:
- AES-256-GCM encryption algorithm
- Configurable encryption key management:
  - File-based key storage (default)
  - AWS KMS integration
  - HashiCorp Vault integration
  - Environment variable key provisioning
- Encryption enabled via config flag: `backup.encryption.enabled: true`
- Backward compatibility: Can read unencrypted Phase 19 backups

**TDD Requirements**:
- Test encryption/decryption round-trip
- Test with invalid keys (must fail safely)
- Test key rotation scenarios
- Test backward compatibility with Phase 19 backups

### 2b. Cloud Storage Integration

**Requirement**: Support major cloud object storage providers

**Implementation**:
- **AWS S3**: Standard and IA storage classes
- **Google Cloud Storage**: Standard and Nearline
- **Azure Blob Storage**: Hot and Cool tiers
- Unified interface: `backup.storage.provider: s3|gcs|azure|local`
- Configuration per provider (credentials, bucket names, regions)
- Automatic retry logic for transient failures
- Bandwidth throttling configuration

**TDD Requirements**:
- Mock-based tests for each provider
- Error handling tests (network failures, auth failures)
- Large file upload/resume tests
- Cost estimation metrics

### 2c. Incremental Backups

**Requirement**: Implement differential backup strategy

**Implementation**:
- **Full backup**: Baseline (same as Phase 19)
- **Incremental backup**: Only changed keys since last backup
- **Differential backup**: Changed keys since last full backup
- Tracking via Redis set: `backup:keys_since_last_full`
- Configurable incremental window: `backup.incremental.window_hours`
- Automatic full backup trigger after N incrementals

**TDD Requirements**:
- Test incremental backup accuracy
- Test restore from full + incremental chain
- Test window boundary conditions
- Test key deletion handling

### 2d. Compression Optimization

**Requirement**: Configurable compression for backup files

**Implementation**:
- **Compression algorithms**: gzip (default), zstd, none
- **Compression levels**: 1-9 (tradeoff between speed/size)
- Configurable per backup type: `backup.compression.algorithm: zstd`
- Compression metrics: ratio, duration, CPU usage
- Automatic fallback to no compression on failure

**TDD Requirements**:
- Test each compression algorithm
- Test compression ratio measurements
- Test CPU usage limits
- Test fallback behavior

### 2e. Concurrency Controls

**Requirement**: Safe concurrent backup/restore operations

**Implementation**:
- Redis-based distributed locking
- Lock key: `backup:operation_lock` with TTL
- Lock timeout: `backup.lock_timeout_seconds: 300`
- Automatic lock renewal for long operations
- Deadlock detection and recovery

**TDD Requirements**:
- Test concurrent backup attempts
- Test lock timeout scenarios
- Test deadlock recovery
- Test lock renewal logic

### 2f. Backup Health Monitoring

**Requirement**: Automated backup integrity verification

**Implementation**:
- Scheduled health checks: `backup.health_check_schedule`
- Checksum verification for all backups
- Manifest validation
- Age-based alerts for stale backups
- Automatic cleanup of corrupted backups (configurable)
- Health status metric: `ja4proxy_backup_health_status`

**TDD Requirements**:
- Test corrupted backup detection
- Test health check scheduling
- Test alert generation
- Test auto-cleanup behavior

---

## 3. Security Requirements

### 3a. Encryption Security

- **Key management**: Keys never stored in backup files
- **Key rotation**: Support for periodic key rotation
- **Key destruction**: Secure key deletion procedures
- **Audit logging**: All encryption operations logged
- **Performance**: Encryption must not increase backup time by >20%

### 3b. Cloud Storage Security

- **Credentials**: Never hardcoded, always from secure sources
- **IAM roles**: Preferred over static credentials
- **Network**: TLS 1.2+ for all cloud communications
- **Bucket policies**: Least privilege access only
- **Object encryption**: SSE-S3/SSE-KMS for additional layer

### 3c. Concurrency Security

- **Lock security**: Prevent lock bypass attacks
- **Timeout security**: Prevent infinite locks
- **Audit trail**: All lock operations logged
- **Rate limiting**: Prevent lock flooding attacks

---

## 4. Observability Requirements

### 4a. New Metrics

```
ja4proxy_backup_encryption_operations_total{status}  # encryption success/failure
ja4proxy_backup_compression_ratio                       # achieved compression ratio
ja4proxy_backup_cloud_upload_duration_seconds           # cloud upload time
ja4proxy_backup_incremental_keys_saved_total            # keys saved via incremental
ja4proxy_backup_lock_contention_total                   # lock wait events
ja4proxy_backup_health_check_status{status}            # health check results
```

### 4b. New Log Events

```json
{
  "ts": "2026-03-22T10:00:00Z",
  "type": "system", 
  "level": "INFO",
  "subsystem": "backup",
  "event": "encryption_completed",
  "algorithm": "AES-256-GCM",
  "duration_ms": 42,
  "key_count": 1000
}
```

### 4c. Alert Rules

- `BackupEncryptionFailure`: Encryption failure rate > 5% over 1h
- `BackupCloudUploadFailure`: Cloud upload failure rate > 10% over 30m
- `BackupHealthCheckFailure`: Health check failure detected
- `BackupLockContentionHigh`: Lock contention > 5 events per minute

---

## 5. Configuration Requirements

### 5a. New Config Sections

```yaml
backup:
  # Encryption
  encryption:
    enabled: false
    algorithm: "AES-256-GCM"
    key_source: "file"  # file|env|aws_kms|vault
    key_path: "/app/secrets/backup_key.txt"
    rotation_days: 90
  
  # Cloud Storage
  cloud:
    provider: "local"  # local|s3|gcs|azure
    s3:
      bucket: "ja4proxy-backups"
      region: "us-east-1"
      endpoint: null  # null for AWS, or custom endpoint
    gcs:
      bucket: "ja4proxy-backups"
      project_id: "my-project"
    azure:
      container: "backups"
      account_name: "myaccount"
    upload_timeout_seconds: 300
    retry_attempts: 3
  
  # Incremental Backups
  incremental:
    enabled: false
    strategy: "differential"  # differential|incremental
    window_hours: 24
    max_incrementals_before_full: 6
  
  # Compression
  compression:
    algorithm: "zstd"  # none|gzip|zstd
    level: 3
    min_size_bytes: 1048576  # Only compress files > 1MB
  
  # Concurrency
  concurrency:
    lock_enabled: true
    lock_timeout_seconds: 300
    max_concurrent_backups: 1
  
  # Health Monitoring
  health_check:
    enabled: true
    schedule: "0 4 * * *"  # Daily at 4 AM
    check_all_backups: false
    max_check_age_days: 7
```

---

## 6. Backward Compatibility

### 6a. Phase 19 Backup Compatibility

- **Read**: Phase 22 must be able to read Phase 19 backups
- **Write**: Phase 22 backups include version marker
- **Restore**: Phase 22 can restore Phase 19 backups
- **Migration**: Automatic detection of backup format version

### 6b. Configuration Compatibility

- All Phase 19 config options remain supported
- New options are additive only
- Default values maintain Phase 19 behavior

---

## 7. Testing Strategy

### 7a. TDD Approach

1. **Red**: Write failing tests first for each feature
2. **Green**: Implement minimal code to pass tests
3. **Refactor**: Clean up while keeping tests green
4. **Document**: Update docs in same task batch

### 7b. Test Coverage Requirements

| Test Type | Minimum Coverage | Notes |
|-----------|-------------------|-------|
| Unit tests | 95% | All new code paths |
| Integration tests | 85% | Real cloud provider mocks |
| Chaos tests | 7 scenarios | Network failures, timeouts |
| Adversarial tests | 5 scenarios | Tampering, lock bypass attempts |
| Performance tests | 8 benchmarks | Encryption speed, compression ratios |

### 7c. Test Categories

**Unit Tests**:
- Encryption/decryption algorithms
- Cloud storage adapters
- Incremental backup logic
- Compression implementations
- Locking mechanisms

**Integration Tests**:
- End-to-end encrypted backup/restore
- Cloud storage upload/download
- Incremental backup chains
- Concurrent operation handling

**Chaos Tests**:
- Cloud provider timeout scenarios
- Network interruption during upload
- Disk full during encryption
- Lock timeout scenarios

**Adversarial Tests**:
- Tampered encrypted backups
- Invalid cloud credentials
- Lock bypass attempts
- Compression bomb attacks

**Performance Tests**:
- Encryption speed benchmarks
- Compression ratio measurements
- Cloud upload bandwidth
- Concurrent operation scaling

---

## 8. Implementation Plan

### 8a. Milestone Breakdown

**Milestone 22.1: Encryption Foundation**
- Task 22.1.1: Encryption interface design
- Task 22.1.2: File-based key management
- Task 22.1.3: AES-256-GCM implementation
- Task 22.1.4: Backward compatibility layer

**Milestone 22.2: Cloud Storage Integration**
- Task 22.2.1: Unified storage interface
- Task 22.2.2: S3 adapter implementation
- Task 22.2.3: GCS adapter implementation
- Task 22.2.4: Azure Blob Storage adapter

**Milestone 22.3: Incremental Backups**
- Task 22.3.1: Change tracking mechanism
- Task 22.3.2: Incremental backup creation
- Task 22.3.3: Multi-part restore logic
- Task 22.3.4: Automatic full backup triggering

**Milestone 22.4: Compression & Optimization**
- Task 22.4.1: gzip compression implementation
- Task 22.4.2: zstd compression implementation
- Task 22.4.3: Compression ratio metrics
- Task 22.4.4: CPU usage monitoring

**Milestone 22.5: Concurrency Controls**
- Task 22.5.1: Redis-based locking
- Task 22.5.2: Lock timeout handling
- Task 22.5.3: Deadlock detection
- Task 22.5.4: Concurrent operation tests

**Milestone 22.6: Health Monitoring**
- Task 22.6.1: Scheduled health checks
- Task 22.6.2: Checksum verification
- Task 22.6.3: Alert generation
- Task 22.6.4: Auto-cleanup logic

**Milestone 22.7: Integration & Testing**
- Task 22.7.1: End-to-end encrypted cloud backup
- Task 22.7.2: Incremental backup chain restore
- Task 22.7.3: Concurrent operation scenarios
- Task 22.7.4: Performance benchmarking

**Milestone 22.8: Documentation**
- Task 22.8.1: Updated Redis schema
- Task 22.8.2: Observability standards
- Task 22.8.3: Operations guide updates
- Task 22.8.4: Security threat model
- Task 22.8.5: Changelog entry

---

## 9. Phase Completion Gate

- [ ] All unit tests passing (95%+ coverage)
- [ ] All integration tests passing (85%+ coverage)
- [ ] All chaos tests implemented and passing
- [ ] All adversarial tests implemented and passing
- [ ] All performance benchmarks recorded
- [ ] Backward compatibility verified with Phase 19
- [ ] docs/REDIS_SCHEMA.md updated
- [ ] docs/OBSERVABILITY_STANDARDS.md updated
- [ ] docs/SECOPS_OPERATIONS.md updated
- [ ] docs/QUICK_REFERENCE.md updated
- [ ] docs/decisions/ADR-022.md created
- [ ] docs/security/BACKUP_ENHANCEMENTS_THREAT_MODEL.md created
- [ ] CHANGELOG.md updated
- [ ] No regression in existing test suites

---

## 10. Risks & Mitigations

### 10a. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Encryption performance overhead | Medium | Low | Benchmark and optimize, provide compression level tuning |
| Cloud provider API changes | High | Low | Versioned API usage, comprehensive error handling |
| Incremental backup corruption | High | Medium | Checksum verification, health monitoring, automatic fallbacks |
| Key management complexity | Medium | Medium | Multiple key source options, clear documentation |
| Lock contention issues | Low | Medium | Configurable timeouts, deadlock detection, monitoring |

### 10b. Security Considerations

- **Encryption keys**: Never stored in code or backups
- **Cloud credentials**: Short-lived tokens preferred
- **Network security**: All cloud communications over TLS 1.2+
- **Audit logging**: All sensitive operations logged
- **Failure mode**: Fail securely (no data loss on encryption failure)

---

## 11. Future Considerations

### 11a. Potential Phase 23 Features

- Multi-region backup replication
- Automated backup scheduling
- Backup lifecycle management
- Cost optimization for cloud storage
- Cross-account backup sharing

### 11b. Deprecation Plan

- Phase 19 features remain fully supported
- No breaking changes planned
- Gradual migration path provided

---

## 12. References

- `docs/phases/PHASE_19.md` — Phase 19 foundation
- `docs/phases/PHASE_19b.md` — Phase 19 security
- `src/backup/` — Phase 19 implementation
- `tests/unit/backup/` — Phase 19 unit tests
- `tests/integration/backup/` — Phase 19 integration tests

---

*Last updated: 2026-03-22 (Proposed)*