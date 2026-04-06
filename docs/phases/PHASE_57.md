# Phase 57 — Backup Enhancements: Cloud Storage & Incrementals

Priority: MEDIUM (Post-Phase 40)
Replaces: Original single-phase plan (superseded after 4-agent review, 2026-04-06)

---

## Mandatory Pre-Start Decisions

Answer these before writing any code. Agents must not start until the operator
has confirmed answers and updated this section.

| # | Question | Why it matters |
|---|----------|----------------|
| 1 | Is Phase 15 Go rewrite in production before Phase 57 ships? | If yes, build Go equivalents, not Python ones |
| 2 | What is the actual backup window duration in production today? | "80% reduction" only matters if the window is a problem |
| 3 | What is the RTO/RPO SLA for this deployment? | Drives backup interval and incremental cadence |
| 4 | Will cloud-uploaded artifacts require pre-upload DSAR redaction? | Determines if Phase 57e must precede 57b/57c |
| 5 | Which cloud provider is actually used in production? | Prioritise the one that ships first |

---

## Known Bugs to Fix Before Phase 57 (Phase 19/40 defects, unblocked by 57)

These were uncovered during the Phase 57 review and should be fixed on a
separate branch before Phase 57 work begins, as they affect backup correctness:

- **Policy contradiction**: `abuseipdb:*` appears in both `policy.py`
  `include_patterns` (line 19) and `worker.py` `_KEY_PATTERNS_NEVER_BACKUP`
  (line 30). The never-backup guard wins silently. Decide: remove from
  include_patterns OR from never-backup list.

- **Attribution data not backed up**: `attribution:profile:{fp}` (90d TTL)
  and `attribution:ips:{fp}` (30d TTL) are long-lived and genuinely durable
  but absent from `KeyPolicy.include_patterns`. These represent weeks of
  attacker correlation work. Add them or document the intentional omission.

- **DSAR redactor only checks key names**: `redactor.py` filters entries where
  the IP appears in the *key name* only. Audit log entries and RDAP enrichment
  values that contain the IP string are silently included. Fix before any cloud
  upload feature ships — otherwise uploading a backup to S3/GCS while having
  an unredacted copy of a GDPR subject's IP in a value is a compliance gap.
  This is addressed in Phase 57e below.

---

## Phase 57a — Format Header & StorageAdapter Foundation

**Size: SMALL**
**Depends on: nothing (pure internal refactor)**
**Blocks: 57b, 57c, 57d (all need the header to distinguish full vs. incremental)**

### Goal

Add a backward-compatible version header to `format.py` so full and incremental
artifacts are self-describing. Define the `StorageAdapter` abstract base class
and a `LocalStorageAdapter` no-op that the scheduler already satisfies. No
external dependencies added.

### Deliverables

- [ ] `src/backup/format.py` — add 9-byte header: `[4B magic "JA4B"][1B version][4B flags]`
  - Flags bitmask: `FULL=0x01`, `INCREMENTAL=0x02`, `ENCRYPTED=0x04`
  - `encode_header(backup_type, flags) -> bytes`
  - `decode_header(data) -> (backup_type, flags)`
  - `is_legacy_format(data) -> bool` — detects old format (no magic bytes)
  - `decode_entries()` updated to skip header if present; handles legacy format
- [ ] `src/backup/storage_adapter.py` — `StorageAdapter` ABC with methods:
  `upload(local_path, manifest)`, `download(remote_uri, local_path)`,
  `list_backups(prefix)`, `delete(remote_uri)`, `verify_checksum(remote_uri, expected)`
- [ ] `LocalStorageAdapter` — no-op implementation (returns metadata from existing file)
- [ ] `src/backup/worker.py` — update manifest dict to include `format_version: 1`
  and `format_flags`; prepend header to `backup_data` before write
- [ ] `src/backup/restorer.py` — detect header; handle both legacy and v1 format

### Acceptance Criteria

- [ ] All existing backup round-trip tests (`test_backup_roundtrip.py`) still pass
  with zero changes — legacy format detection must be transparent
- [ ] New `test_format_header.py`: encode→decode round-trip for each backup type
  (full, incremental); legacy-format detection for pre-header artifacts
- [ ] New `test_storage_adapter_interface.py`: `LocalStorageAdapter` satisfies the
  ABC contract; parametrised tests over the interface that 57b/57c will reuse
- [ ] Zero new external dependencies

---

## Phase 57b — S3 Cloud Adapter

**Size: SMALL**
**Depends on: 57a (StorageAdapter ABC)**
**Blocks: nothing (57c is parallel)**

### Goal

Upload completed backup artifacts to AWS S3 (or any S3-compatible store, e.g.
MinIO). The scheduler calls the adapter asynchronously after `create_backup()`
returns; the backup local path is written first (unchanged behaviour).

### Architecture Decision

Keep `BackupWorker.create_backup()` synchronous (no refactor). Extend
`BackupScheduler._fire()` to call `await storage_adapter.upload(path, manifest)`
after the sync worker completes. The scheduler already uses `asyncio.to_thread()`
for the worker; the upload runs in the async context above it.

Do NOT use `aiobotocore` directly — use `aioboto3` (the async wrapper) which
handles session management cleanly. Credentials sourced from environment
variables only — never from `config/proxy.yml` values.

### Deliverables

- [ ] `src/backup/cloud/s3_adapter.py` — `S3StorageAdapter(StorageAdapter)`:
  - `upload()`: `put_object` + verify ETag matches SHA256 after upload
  - `download()`: `get_object` + stream to local path
  - `list_backups()`: `list_objects_v2` with prefix, returns `[StorageMetadata]`
  - `delete()`: `delete_object`
  - `verify_checksum()`: `head_object` → compare stored metadata checksum
  - Retry: 3 attempts with exponential backoff on `ClientError`; fail open
    (log + Prometheus error counter) — never block local backup on cloud failure
- [ ] `src/backup/scheduler.py` — accept optional `storage_adapter: StorageAdapter`;
  call `await storage_adapter.upload(path, manifest)` after successful local backup
- [ ] `config/proxy.yml` — new section `backup.cloud_storage.s3`:
  ```yaml
  backup:
    cloud_storage:
      enabled: false          # phase-57b
      provider: "s3"          # phase-57b
      s3:
        bucket: "${BACKUP_S3_BUCKET}"        # phase-57b
        region: "${BACKUP_S3_REGION:-us-east-1}"  # phase-57b
        prefix: "backups/"                   # phase-57b
        storage_class: "STANDARD"            # phase-57b: STANDARD | GLACIER
        retention_days: 90                   # phase-57b
  ```
- [ ] `requirements.txt` — add `aioboto3>=13.0  # phase-57b`

### Acceptance Criteria

- [ ] `tests/unit/backup/test_s3_adapter.py` — uses `moto.mock_s3`:
  upload → list → download → checksum match; upload failure → logs + counter,
  local backup path unchanged
- [ ] `tests/integration/backup/test_cloud_roundtrip_s3.py` — moto-backed full
  round-trip: create local backup → upload to fake S3 → download → restore →
  verify Redis state identical
- [ ] Cloud upload failure does NOT fail the local backup (fail-open verified)
- [ ] `ja4proxy_backup_cloud_upload_total{result="success|failure"}` counter exists
- [ ] `moto` added to `requirements.txt` under test dependencies

---

## Phase 57c — GCS Cloud Adapter

**Size: SMALL**
**Depends on: 57a (StorageAdapter ABC)**
**Blocks: nothing (parallel to 57b)**

### Goal

Same as 57b but for Google Cloud Storage. `google-cloud-storage` client is
synchronous; wrap with `asyncio.to_thread()` in the adapter to keep the
scheduler's async context clean.

### Deliverables

- [ ] `src/backup/cloud/gcs_adapter.py` — `GCSStorageAdapter(StorageAdapter)`:
  same interface as S3Adapter; uses `asyncio.to_thread()` to wrap sync GCS calls
- [ ] `config/proxy.yml` — new section `backup.cloud_storage.gcs`:
  ```yaml
  backup:
    cloud_storage:
      gcs:
        bucket: "${BACKUP_GCS_BUCKET}"           # phase-57c
        project_id: "${BACKUP_GCS_PROJECT_ID}"   # phase-57c
        credentials_path: "${BACKUP_GCS_CREDENTIALS_PATH}"  # phase-57c
        prefix: "backups/"                        # phase-57c
        storage_class: "STANDARD"                 # phase-57c
        retention_days: 90                        # phase-57c
  ```
- [ ] `requirements.txt` — add `google-cloud-storage>=2.0  # phase-57c` as optional

### Acceptance Criteria

- [ ] `tests/unit/backup/test_gcs_adapter.py` — uses `unittest.mock` to patch
  `google.cloud.storage.Client`; same test matrix as S3 adapter
- [ ] Cloud upload failure does NOT fail local backup (same fail-open contract)
- [ ] `ja4proxy_backup_cloud_upload_total{provider="gcs", result="success|failure"}` counter

---

## Phase 57d — Dirty Tracking & Incremental Engine

**Size: SMALL–MEDIUM**
**Depends on: 57a (format header)**
**Blocks: 57f (multi-part restore)**

### Goal

Track which Redis keys have been modified since the last full backup using an
explicit `backup:dirty_keys` Sorted Set (score = modification timestamp). Use
this set to produce incremental backup artifacts — containing only changed keys —
that are much smaller than a full backup.

### Architecture Decision: SADD-based tracking (not keyspace notifications)

Keyspace notifications require `CONFIG SET notify-keyspace-events` which is
not available on all managed Redis services and is unsupported by `fakeredis`.
Instead, every proxy write that affects a backed-up key calls
`DirtySetTracker.mark_dirty(redis_client, key)` — a single `ZADD` with the
current timestamp. This is simple, testable with fakeredis, and requires no
Redis configuration changes.

**Integration points** (all in `src/security/` write paths):
- Every `redis_client.set(key, ...)` for `config:*`, `ban:*`, `ja4:*`
- Every `redis_client.sadd("ja4:whitelist", ...)` / `sadd("ja4:blacklist", ...)`
- Batched writes in `analytics/` node

Wrap common write operations in a thin helper to avoid scatter:
```python
# src/backup/dirty_set_tracker.py
async def tracked_set(redis_client, key: str, value, **kwargs):
    await redis_client.set(key, value, **kwargs)
    await redis_client.zadd("backup:dirty_keys", {key: time.time()})
```

### Deliverables

- [ ] `src/backup/dirty_set_tracker.py` — `DirtySetTracker`:
  - `mark_dirty(redis_client, key)` — `ZADD backup:dirty_keys {ts} {key}`
  - `get_dirty_keys(redis_client) -> set[str]` — `ZRANGE` all members
  - `clear_dirty(redis_client)` — `DEL backup:dirty_keys`
  - `tracked_set()` / `tracked_hset()` / `tracked_sadd()` helpers
- [ ] `src/backup/worker.py` — new `create_incremental_backup(destination, dirty_keys)`
  method: same pipeline as `create_backup()` but filters to `dirty_keys` only;
  writes `backup_type: "incremental"` and `base_backup_filename` to manifest
- [ ] `src/backup/scheduler.py` — add `incremental_schedule` cron support; on
  incremental tick, read dirty keys, call `create_incremental_backup()`, clear
  dirty set only on success
- [ ] `config/proxy.yml` — new section:
  ```yaml
  backup:
    incremental:
      enabled: false                    # phase-57d
      schedule: "0 */6 * * *"           # phase-57d: every 6h
      full_backup_schedule: "0 2 * * 0" # phase-57d: full every Sunday 02:00
      max_chain_length: 20              # phase-57d: force full after N incrementals
      dirty_key_tracking:
        enabled: true                   # phase-57d
        max_tracked_keys: 100000        # phase-57d
  ```
- [ ] `docs/REDIS_SCHEMA.md` — document `backup:dirty_keys` (Sorted Set, score=timestamp,
  no TTL, owned by DirtySetTracker)

### Acceptance Criteria

- [ ] `tests/unit/backup/test_dirty_set_tracker.py` — fakeredis: mark → get →
  clear; concurrent marks; cap enforcement
- [ ] `tests/unit/backup/test_incremental_backup.py` — fakeredis with 1000-key
  stable state: full backup → modify 5% of keys → incremental size < 20% of full
  (verifies the ">80% reduction" claim with explicit data)
- [ ] `tests/integration/backup/test_incremental_e2e.py` — full → incremental →
  second incremental; manifest chain recorded correctly
- [ ] Incremental artifact has `backup_type: "incremental"` and `base_backup_filename`
  in manifest
- [ ] Dirty set cleared only after successful backup (failure leaves it intact)

---

## Phase 57e — DSAR Redactor Hardening

**Size: SMALL**
**Depends on: nothing (standalone fix)**
**Blocks: 57b and 57c (cloud upload with PII gap is a GDPR regression)**

### Goal

Fix the DSAR redactor to scan key *values* for IP addresses, not just key names.
The current implementation in `redactor.py` silently passes through audit log
entries and enrichment values that contain the target IP as a string within the
JSON value. This must be fixed before any cloud upload feature ships.

### Known gaps to fix

- `management:audit_log` entries — JSON values contain `actor_ip` fields
- `rdap:ip:{ip}` values — JSON contains the IP in nested fields
- `management:policy_audit` entries — may contain actor IPs

### Deliverables

- [ ] `src/backup/redactor.py` — extend to deep-scan JSON values:
  for each entry, attempt JSON decode of the value bytes; recursively walk
  the structure looking for string fields matching any target IP; if found,
  either redact the field or exclude the entire entry (configurable)
- [ ] New config option: `backup.dsar.redact_values: true` (default) /
  `redact_entire_entry: false` (default — redact field, keep entry)
- [ ] Pre-upload check in `StorageAdapter.upload()`: if DSAR redaction is enabled
  globally, refuse to upload an artifact that has not been scanned since
  last modification (flag in manifest: `dsar_scanned: true/false`)

### Acceptance Criteria

- [ ] `tests/unit/backup/test_redactor.py` updated: add cases where IP appears
  in JSON value but not key name — verify it is redacted
- [ ] Audit log entry with `actor_ip: "192.0.2.1"` is redacted when that IP
  is the DSAR subject
- [ ] `test_storage_adapter_interface.py` — upload of unscanned artifact raises
  `DSARComplianceError` when redaction is enabled (fail-closed for cloud)

---

## Phase 57f — Multi-Part Restore

**Size: SMALL**
**Depends on: 57a (format header), 57d (incremental artifacts exist)**
**Blocks: nothing**

### Goal

Extend `BackupRestorer` to apply a full backup and a chain of incrementals in
sequence. The restore chain is derived from manifest `base_backup_filename` links.
Failure in any incremental is recoverable — restore from the full alone if the
chain is broken.

### Deliverables

- [ ] `src/backup/restorer.py` — new `restore_incremental_chain(full_manifest_path,
  incremental_manifests: list[str], ...)` method:
  1. Restore full backup (existing logic)
  2. For each incremental in timestamp order: apply `_restore_backup_data()`
     (RESTORE with `replace=True` merges over existing state)
  3. If any incremental artifact fails checksum: log warning, skip that
     artifact, continue (not fail-stop — a missing incremental is recoverable)
  4. Record `backup:restored_from_chain: [full, incr1, incr2, ...]`
- [ ] CLI: `ja4proxy_admin.py backup restore --apply-incrementals` flag
- [ ] Manifest schema updated: `base_backup_filename` (incremental → full link),
  `sequence_number` (int, 0 = full)

### Acceptance Criteria

- [ ] `tests/unit/backup/test_incremental_restore_chain.py`:
  full + 3 incrementals → restore → verify final state equals full + all deltas
- [ ] Corrupt incremental → warning logged, chain continues → final state equals
  full + non-corrupt incrementals
- [ ] `--apply-incrementals` flag enumerated and documented in CLI help

---

## Phase 57g — Documentation & CLI

**Size: SMALL**
**Depends on: all above phases complete**
**Blocks: nothing (can be written in parallel with implementation)**

### Goal

Close all documentation gates opened by phases 57a–57f. This is a pure
documentation phase — no new code.

### Deliverables

- [ ] `docs/decisions/ADR-023.md` — Cloud vs. local backup strategy: why hybrid
  (local fast path + cloud durable store), what was rejected
- [ ] `docs/decisions/ADR-024.md` — Incremental cadence: why SADD dirty tracking
  over keyspace notifications; trade-offs
- [ ] `docs/decisions/ADR-025.md` — Format versioning: why 9-byte header, backward
  compat approach, flag bitmask design
- [ ] `docs/runbooks/cloud_backup_operations.md` — operator guide: setup (IAM/service
  account), daily operations, disaster recovery multi-part restore procedure,
  troubleshooting, cost optimisation
- [ ] `docs/REDIS_SCHEMA.md` — add:
  - `backup:dirty_keys` (Sorted Set, score=timestamp)
  - `backup:incremental:manifest:{seq}` (Hash)
  - `backup:artifacts` (Sorted Set, score=timestamp, member=JSON metadata)
  - `backup:restored_from_chain` (String, comma-separated chain)
- [ ] `scripts/ja4proxy_admin.py` — new subcommands:
  - `backup cloud upload <artifact> [--provider s3|gcs]`
  - `backup cloud list [--provider s3|gcs]`
  - `backup cloud download <id> --provider s3|gcs [--dest /path]`
  - `backup incremental status`
  - `backup incremental compact [--force]`
  - `backup restore --apply-incrementals`
- [ ] `CHANGELOG.md` — Phase 57 entry in standard format
- [ ] `docs/SECOPS_OPERATIONS.md` — add "Cloud Backup Operations (Phase 57)" section
- [ ] `docs/phases/manifest.yaml` — mark Phase 57 COMPLETE after all sub-phases done
- [ ] Run `python3 scripts/sync-roadmap.py`

### Acceptance Criteria

- [ ] All links in new docs resolve (`make link-check` passes)
- [ ] All new code has docstrings
- [ ] `make lint-docs` passes with zero warnings

---

## Cancelled Work (do not implement)

The original Phase 57 sub-task **"57c — Concurrency & Locking"** is **dead work**.
Distributed locking (`backup:operation_lock`, TTL 600s, NX semantics) was fully
implemented in Phase 40 (`worker.py` lines 213–214, `restorer.py` lines 226–227,
both `finally` blocks). Do not re-implement.

---

## Sub-Phase Summary

| Sub-Phase | Size | Depends on | Parallel with | Owner |
|-----------|------|-----------|---------------|-------|
| 57a: Format Header & Adapter ABC | SMALL | nothing | — | agent-A |
| 57b: S3 Adapter | SMALL | 57a | 57c, 57e | agent-B |
| 57c: GCS Adapter | SMALL | 57a | 57b, 57e | agent-C |
| 57d: Dirty Tracking & Incremental | SMALL–MED | 57a | 57b, 57c, 57e | agent-D |
| 57e: DSAR Redactor Hardening | SMALL | nothing | 57a, 57b, 57c | agent-E |
| 57f: Multi-Part Restore | SMALL | 57a, 57d | 57b, 57c, 57e | agent-F |
| 57g: Documentation & CLI | SMALL | all above | — | agent-G |

**Execution order:**
1. Parallel: 57a + 57e (no dependencies between them)
2. Parallel: 57b + 57c + 57d (all depend on 57a; 57d also needs format header)
3. Sequential: 57f (needs 57d artifacts to exist)
4. Sequential: 57g (needs all above complete)

**Estimated gate:** Each SMALL is completable by a single agent in one session
with clear acceptance criteria. 57d is SMALL–MEDIUM and may take 1.5 sessions.

---

## Acceptance Criteria (Phase 57 Complete)

All sub-phases complete, AND:

- [ ] S3 round-trip backup/restore verified against moto
- [ ] Incremental backup size < 20% of full for 5%-change workload (fakeredis benchmark)
- [ ] DSAR redactor covers both key names and JSON values
- [ ] Multi-part restore (full + N incrementals) produces correct final state
- [ ] Distributed lock NOT re-implemented (already in Phase 40 — verify no duplicate)
- [ ] Documentation gate (Phase 57g) complete
- [ ] All existing backup tests still pass unchanged
- [ ] `make test-unit` passes with zero warnings
