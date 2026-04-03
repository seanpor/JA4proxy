# Phase 57: Backup System Enhancements - Phase 3: Cloud & Incrementals

Status: PROPOSED
Priority: MEDIUM (Post-Phase 40)

## Goal
Implement offsite cloud storage support and incremental backup strategies to minimize the backup window for large datasets.

## Sub-Tasks

### 57a — Cloud Storage Adapters
- [ ] **Interface:** Define a `StorageAdapter` interface for handling backup artifact uploads/downloads.
- [ ] **S3 Provider:** Implement AWS S3 support (using `aiobotocore`).
- [ ] **GCS Provider:** Implement Google Cloud Storage support.
- [ ] **Retention:** Implement cloud-side retention policies (e.g., auto-delete old objects).

### 57b — Incremental Backup Strategy
- [ ] **Change Tracking:** Implement a Redis-based "Dirty Set" that tracks keys modified since the last full backup.
- [ ] **Partial Artifacts:** Create a new artifact format for incremental changes.
- [ ] **Restore Logic:** Implement a multi-part restorer that applies the latest full backup and all subsequent incrementals.

### 57c — Concurrency & Locking
- [ ] **Operation Locking:** Use Redis-based distributed locking to prevent multiple workers from initiating a backup simultaneously.
- [ ] **Integrity Checks:** Verify the checksum of cloud-stored artifacts after upload.

## Acceptance Criteria
- [ ] Successful backup and restore using an S3-compatible backend.
- [ ] Incremental backups reduce the data transfer size by >80% for typical daily traffic.
- [ ] Distributed locking prevents "Backup Storms" across multiple proxy instances.
- [ ] Zero data loss verified during a full round-trip restore from cloud storage.
