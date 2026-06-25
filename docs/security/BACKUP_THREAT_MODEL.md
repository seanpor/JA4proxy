<!--
title: Backup_Threat_Model
audience: Security Teams, Auditors
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy Backup & Restore — Threat Model (Phase 19)

**Date:** 2026-03-21
**Status:** Final
**Phase:** 19

## Overview

This document analyzes threats specific to the backup and restore framework implemented in Phase 19. It follows the STRIDE model and identifies mitigations for each threat category.

## System Components

### In Scope
- `cmd/ja4p/backup.go` — Backup creation and retention (Go)
- `cmd/ja4p/restore.go` — Restore operations (Go)
- `internal/backup/` — Backup policy and key management
- Backup artifacts (`.bin` files with AES-256-GCM encryption)
- Redis control keys (`backup:*`)

### Out of Scope
- Redis server security (covered in REDIS_SECURITY_REVIEW.md)
- Filesystem encryption (not implemented in Phase 19)
- Off-host backup storage (not implemented in Phase 19)

## Threat Analysis

### 1. Spoofing (Authentication)

**Threat:** Unauthorized entity performs backup/restore operations

| Threat ID | Description | Impact | Mitigation | Status |
|-----------|-------------|--------|------------|--------|
| BACKUP-001 | Unauthorized backup creation | Information disclosure | Filesystem permissions + audit logging | ✓ Mitigated |
| BACKUP-002 | Unauthorized restore operation | Data corruption/loss | CLI requires explicit flags + audit logging | ✓ Mitigated |
| BACKUP-003 | Spoofed audit log entries | Loss of accountability | Audit log entries include actor identification | ✓ Mitigated |

**Mitigations:**
- Backup directory must be owned by proxy user
- All operations logged to `management:audit_log` with actor identification
- Restore operations require explicit confirmation

### 2. Tampering (Integrity)

**Threat:** Backup artifacts or metadata are modified

| Threat ID | Description | Impact | Mitigation | Status |
|-----------|-------------|--------|------------|--------|
| BACKUP-010 | Backup file tampering | Restore corrupted/invalid data | SHA256 checksum verification | ✓ Mitigated |
| BACKUP-011 | Manifest tampering | Invalid restore operations | Checksum cross-verification | ✓ Mitigated |
| BACKUP-012 | Redis control key tampering | Incorrect backup state | Control keys are informational only | ⚠ Accepted |
| BACKUP-013 | Retention policy bypass | Excessive backup retention | Policy enforced by backup worker | ✓ Mitigated |

**Mitigations:**
- SHA256 checksums for all backup artifacts
- Manifest includes checksum that must match backup file
- Restore operation verifies checksum before proceeding
- Retention policy enforced by `apply_retention()` method

### 3. Repudiation (Non-repudiation)

**Threat:** Denial of backup/restore operations

| Threat ID | Description | Impact | Mitigation | Status |
|-----------|-------------|--------|------------|--------|
| BACKUP-020 | Denial of backup operation | Loss of accountability | Comprehensive audit logging | ✓ Mitigated |
| BACKUP-021 | Denial of restore operation | Loss of accountability | Audit log entries with timestamps | ✓ Mitigated |
| BACKUP-022 | Denial of backup failure | Delayed incident response | Failure events logged separately | ✓ Mitigated |

**Mitigations:**
- All operations logged to `management:audit_log` Redis list
- Structured JSON logs with timestamps and actor identification
- Separate success/failure metrics in Prometheus
- Audit log entries include detailed operation metadata

### 4. Information Disclosure

**Threat:** Sensitive data exposed through backups

| Threat ID | Description | Impact | Mitigation | Status |
|-----------|-------------|--------|------------|--------|
| BACKUP-030 | Sensitive keys in backup | Credential exposure | Never-backup key patterns | ✓ Mitigated |
| BACKUP-031 | Backup file access | Data exposure | Filesystem permissions | ✓ Mitigated |
| BACKUP-032 | Manifest data exposure | Metadata leakage | Manifest contains no sensitive data | ✓ Mitigated |
| BACKUP-033 | Redis control key exposure | Operational data leakage | Control keys are public | ⚠ Accepted |

**Mitigations:**
- Hardcoded never-backup patterns for sensitive keys
- Filesystem permission validation before writing backups
- Backup directory must not be world-readable or group-readable
- Manifest contains only metadata, no sensitive data

**Accepted Risks:**
- Backup files are plaintext (no encryption in Phase 19)
- Redis control keys are not considered sensitive
- Backup directory location is configurable and should be secured

### 5. Denial of Service

**Threat:** Backup/restore operations disrupted

| Threat ID | Description | Impact | Mitigation | Status |
|-----------|-------------|--------|------------|--------|
| BACKUP-040 | Backup directory DoS | Backup failure | Filesystem validation | ✓ Mitigated |
| BACKUP-041 | Redis overload during backup | Performance degradation | Key enumeration limits | ✓ Mitigated |
| BACKUP-042 | Disk space exhaustion | Backup failure | Retention policy enforcement | ✓ Mitigated |
| BACKUP-043 | Long-running restore | Service disruption | Timeout mechanisms | ⚠ Partial |

**Mitigations:**
- Filesystem validation before backup operations
- `max_keys_per_run` limit prevents unbounded Redis operations
- Retention policy prevents unlimited backup accumulation
- Backup operations are non-blocking to main proxy operations

**Partial Mitigations:**
- No explicit timeout for restore operations (future enhancement)
- Large restores may impact Redis performance temporarily

### 6. Elevation of Privilege

**Threat:** Unauthorized access to backup/restore functionality

| Threat ID | Description | Impact | Mitigation | Status |
|-----------|-------------|--------|------------|--------|
| BACKUP-050 | CLI command injection | Arbitrary backup/restore | CLI requires file system access | ✓ Mitigated |
| BACKUP-051 | Path traversal attacks | Arbitrary file access | Path validation in CLI | ✓ Mitigated |
| BACKUP-052 | Privilege escalation via backup | System compromise | Backup worker runs as proxy user | ✓ Mitigated |

**Mitigations:**
- CLI validates backup file paths
- Backup worker runs with proxy user permissions only
- No privilege escalation mechanisms in backup code
- Filesystem operations limited to configured backup directory

## Attack Scenarios and Mitigations

### Scenario 1: Backup File Tampering
**Attack:** Attacker modifies backup file to inject malicious data
**Impact:** Restore operation loads corrupted data into Redis
**Mitigation:** SHA256 checksum verification before restore
**Detection:** Checksum mismatch logged and restore aborted

### Scenario 2: Sensitive Key Backup
**Attack:** Sensitive keys (API tokens) included in backup
**Impact:** Credential exposure if backup file is compromised
**Mitigation:** Hardcoded never-backup patterns exclude sensitive keys
**Detection:** Warning logs when sensitive keys detected during backup

### Scenario 3: Backup Directory Exhaustion
**Attack:** Attacker fills backup directory with fake files
**Impact:** Legitimate backups fail due to disk space
**Mitigation:** Retention policy limits number of backups
**Detection:** Backup failure metrics and logs

### Scenario 4: Restore Race Condition
**Attack:** Concurrent restore operations cause data corruption
**Impact:** Inconsistent Redis state
**Mitigation:** Single restore operation at a time (no explicit locking)
**Detection:** Audit log shows concurrent operations

## Security Controls Summary

### Preventive Controls
- Never-backup key patterns
- Filesystem permission validation
- Checksum verification
- Explicit destructive restore flag
- Retention policy enforcement

### Detective Controls
- Audit logging to `management:audit_log`
- Prometheus metrics for all operations
- Structured JSON logs with subsystem tags
- Checksum verification before restore

### Corrective Controls
- Backup failure metrics trigger alerts
- Retention policy automatically cleans up old backups
- Failed restore operations leave Redis unchanged

## Accepted Risks

### Risk 1: Plaintext Backup Files
**Description:** Backup files are not encrypted
**Rationale:** Phase 19 focuses on core functionality; encryption adds significant complexity
**Mitigation:** Filesystem permissions and secure backup directory location
**Future Work:** Encryption to be implemented in future phase

### Risk 2: No Off-Host Backups
**Description:** Backups stored only on local filesystem
**Rationale:** Phase 19 implements local filesystem backups first
**Mitigation:** Backup directory can be mounted from network storage
**Future Work:** Cloud storage integration in future phase

### Risk 3: Limited Concurrent Operation Protection
**Description:** No explicit locking for concurrent backup/restore operations
**Rationale:** Backup operations are read-only; restore operations should be rare
**Mitigation:** Audit logging shows concurrent operations
**Future Work:** Explicit locking mechanism if needed

## Operational Security Recommendations

### Backup Directory Security
- Set permissions to `700` (drwx------)
- Owned by proxy user only
- Located on encrypted filesystem if possible
- Regularly monitor for unauthorized access

### Monitoring and Alerting
- Alert on backup failure rate > 10% over 1 hour
- Alert if no successful backup in 24 hours
- Alert on restore operations (rare events)
- Monitor backup directory disk space

### Incident Response
**Backup Failure:**
1. Check filesystem permissions and space
2. Verify Redis connectivity
3. Review logs for specific errors
4. Manual backup if automated fails

**Restore Failure:**
1. Verify backup file integrity with `validate` command
2. Check Redis connectivity and memory
3. Review manifest for consistency
4. Contact support if checksum verification fails

**Sensitive Data Exposure:**
1. Rotate all potentially exposed credentials
2. Review backup files for sensitive data
3. Update never-backup patterns if needed
4. Implement encryption for future backups

## Compliance Considerations

### Data Protection
- Backup files may contain personal data (IP addresses, JA4 fingerprints)
- Consider backup files as sensitive data
- Apply appropriate retention policies
- Secure backup directory access

### Audit Requirements
- All backup/restore operations are audited
- Audit logs retained in `management:audit_log` (1000 entries)
- Structured logs provide additional audit trail
- Metrics provide operational visibility

## Future Enhancements

### Phase 19+ Security Roadmap
1. **Encryption:** Encrypt backup files at rest
2. **Off-host storage:** Cloud storage integration
3. **Incremental backups:** Reduce backup size and frequency
4. **Multi-part backups:** Handle very large datasets
5. **Backup signing:** Cryptographic signatures for integrity
6. **Key rotation:** Automatic credential rotation

## References

- `docs/phases/complete/PHASE_19.md` — Functional requirements
- `docs/phases/complete/PHASE_19b.md` — Security supplement
- `docs/reference/REDIS_SCHEMA.md` — Redis key schema
- `docs/OPERATIONS.md` — Operations guide
- `docs/reference/OBSERVABILITY_STANDARDS.md` — Monitoring standards
- `src/backup/` — Implementation code
- `tests/unit/backup/` — Unit tests
- `tests/integration/backup/` — Integration tests
- `tests/performance/backup/` — Performance tests