# Phase 57 — Backup Enhancements: Cloud Storage & Incrementals

Priority: MEDIUM (Post-Phase 40)
Replaces: Original single-phase plan (superseded after 4-agent review, 2026-04-06)
Revised: 2026-04-06 — Phase 57d (Dirty Tracking & Incrementals) cut after "So What?" review

---

## Mandatory Pre-Start Decisions

Answer these before writing any code. Agents must not start until the operator
has confirmed answers and updated this section.

| # | Question | Why it matters |
|---|----------|----------------|
| 1 | Is Phase 15 Go rewrite in production before Phase 57 ships? | If yes, build Go equivalents, not Python ones |
| 2 | What is the actual backup window duration in production today? | Cloud upload adds latency; measure first |
| 3 | What is the RTO/RPO SLA for this deployment? | Drives backup interval |
| 4 | Will cloud-uploaded artifacts require pre-upload DSAR redaction? | Phase 57e is a blocker for 57b/57c if yes |
| 5 | Which cloud provider is actually used in production? | Prioritise the one that ships first |

---

## Known Bugs to Fix Before Phase 57 (Phase 19/40 defects, unblocked by 57)

These were uncovered during the Phase 57 review and should be fixed on a
separate branch before Phase 57 work begins, as they affect backup correctness:

- **Policy contradiction**: `abuseipdb:score:*` appears in both `policy.py`
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

## Phase 57a — Format Header & StorageAdapter Foundation ✅ COMPLETE

**Size: SMALL**
**Depends on: nothing (pure internal refactor)**
**Blocks: 57b, 57c (all need StorageAdapter ABC)**
**Branch: `claude/phase-57a-format-header`**
**Tests: 206 unit tests pass, 8 integration round-trip tests pass, 0 regressions**

### What was delivered

- `src/backup/format.py` — 9-byte header `[4B magic "JA4B"][1B version][4B flags]`
  added. `encode_header()`, `decode_header()`, `is_legacy_format()` implemented.
  `decode_entries()` transparently handles both legacy (no header) and new format.
  Flags bitmask: `FLAG_FULL=0x01`, `FLAG_INCREMENTAL=0x02`, `FLAG_ENCRYPTED=0x04`.
- `src/backup/storage_adapter.py` — `StorageAdapter` ABC with 5 abstract async
  methods: `upload`, `download`, `list_backups`, `delete`, `verify_checksum`.
  `StorageMetadata` dataclass. `LocalStorageAdapter` no-op implementation.
  Zero new external dependencies.
- `src/backup/worker.py` — header prepended to every backup artifact; manifest
  includes `format_version: 1` and `format_flags`; checksum covers header bytes.
- `tests/unit/backup/test_format_header.py` — 34 tests
- `tests/unit/backup/test_storage_adapter_interface.py` — 31 tests

---

## Phase 57b — S3 Cloud Adapter

**Size: SMALL**
**Depends on: 57a (StorageAdapter ABC) ✅**
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

Use `boto3` + `asyncio.to_thread()` — **NOT** `aioboto3`. For a once-per-schedule
operation (upload after backup), `asyncio.to_thread(boto3_call)` is simpler, easier
to debug, and equally performant. `aioboto3`'s session management complexity is not
warranted here. Credentials sourced from environment variables only — never from
`config/proxy.yml` values (boto3 reads standard `AWS_*` env vars automatically).

### Deliverables

- [ ] `src/backup/cloud/s3_adapter.py` — `S3StorageAdapter(StorageAdapter)`:
  - `upload()`: `put_object` via `asyncio.to_thread` + verify ETag matches SHA256
  - `download()`: `get_object` via `asyncio.to_thread` + stream to local path
  - `list_backups()`: `list_objects_v2` with prefix, returns `[StorageMetadata]`
  - `delete()`: `delete_object` via `asyncio.to_thread`
  - `verify_checksum()`: `head_object` → compare stored metadata checksum
  - Retry: 3 attempts with exponential backoff on `ClientError`; fail open
    (log + Prometheus error counter) — never block local backup on cloud failure
- [ ] `src/backup/cloud/__init__.py` — empty init
- [ ] `src/backup/scheduler.py` — accept optional `storage_adapter: StorageAdapter`;
  call `await storage_adapter.upload(path, manifest)` after successful local backup
- [ ] `config/proxy.yml` — new section `backup.cloud_storage.s3`:
  ```yaml
  backup:
    cloud_storage:
      enabled: false          # phase-57b
      provider: "s3"          # phase-57b: s3 | gcs
      s3:
        bucket: "${BACKUP_S3_BUCKET}"             # phase-57b
        region: "${BACKUP_S3_REGION:-us-east-1}"  # phase-57b
        prefix: "backups/"                        # phase-57b
        storage_class: "STANDARD"                 # phase-57b: STANDARD | GLACIER
        retention_days: 90                        # phase-57b
  ```
- [ ] `requirements.txt` — add `boto3>=1.34  # phase-57b` and `moto[s3]>=5.0  # phase-57b (test)`

### Acceptance Criteria

- [ ] `tests/unit/backup/test_s3_adapter.py` — uses `moto.mock_aws`:
  upload → list → download → checksum match; upload failure → logs + counter,
  local backup path unchanged
- [ ] `tests/integration/backup/test_cloud_roundtrip_s3.py` — moto-backed full
  round-trip: create local backup → upload to fake S3 → download → restore →
  verify Redis state identical
- [ ] Cloud upload failure does NOT fail the local backup (fail-open verified)
- [ ] `ja4proxy_backup_cloud_upload_total{provider="s3", result="success|failure"}` counter exists

---

## Phase 57c — GCS Cloud Adapter

**Size: SMALL**
**Depends on: 57a (StorageAdapter ABC) ✅**
**Blocks: nothing (parallel to 57b)**

### Goal

Same as 57b but for Google Cloud Storage. `google-cloud-storage` client is
synchronous; wrap with `asyncio.to_thread()` in the adapter — same pattern as
S3. Credentials from environment variable `BACKUP_GCS_CREDENTIALS_PATH` only.

### Deliverables

- [ ] `src/backup/cloud/gcs_adapter.py` — `GCSStorageAdapter(StorageAdapter)`:
  same interface as `S3StorageAdapter`; uses `asyncio.to_thread()` to wrap all
  synchronous GCS client calls
- [ ] `config/proxy.yml` — new section `backup.cloud_storage.gcs`:
  ```yaml
  backup:
    cloud_storage:
      gcs:
        bucket: "${BACKUP_GCS_BUCKET}"                       # phase-57c
        project_id: "${BACKUP_GCS_PROJECT_ID}"               # phase-57c
        credentials_path: "${BACKUP_GCS_CREDENTIALS_PATH}"   # phase-57c
        prefix: "backups/"                                   # phase-57c
        storage_class: "STANDARD"                            # phase-57c
        retention_days: 90                                   # phase-57c
  ```
- [ ] `requirements.txt` — add `google-cloud-storage>=2.0  # phase-57c (optional)`

### Acceptance Criteria

- [ ] `tests/unit/backup/test_gcs_adapter.py` — uses `unittest.mock` to patch
  `google.cloud.storage.Client`; same test matrix as S3 adapter
- [ ] Cloud upload failure does NOT fail local backup (same fail-open contract)
- [ ] `ja4proxy_backup_cloud_upload_total{provider="gcs", result="success|failure"}` counter

---

## Phase 57d — CANCELLED (Dirty Tracking & Incrementals)

**Status: CANCELLED — deferred to Phase 58 or later**
**Reason:** Cut after "So What?" review on 2026-04-06.

### Why it was cut

1. **Scope inflation**: Instrumenting every write path requires touching ~18 files
   in `src/security/` — a backup sub-phase has no business owning security module
   code. This is a cross-cutting refactor, not a backup feature.

2. **Weak use case**: The "80% reduction in backup size" claim assumes large volumes
   of transient rate-limit keys are being backed up. They are not — they are
   explicitly excluded from `KeyPolicy.include_patterns`. The real long-lived key
   set (bans, JA4 lists, config, attribution) changes at 0.5–2% per 6-hour window,
   not 5–20%.

3. **Premature optimisation**: Backup window duration has not been measured in
   production. There is no confirmed problem to solve. Cloud storage costs can be
   managed with S3/GCS lifecycle policies and compression.

### Deferred scope

If incremental backups are needed after cloud storage is measured in production,
the implementation should:
- Live in its own phase (Phase 58)
- Require a security-subsystem audit of write paths before instrumentation
- Include a production measurement baseline showing the optimisation is needed

---

## Phase 57e — DSAR Redactor Hardening

**Size: SMALL**
**Depends on: 57a ✅ (test file `test_storage_adapter_interface.py` already exists)**
**Blocks: 57b and 57c (cloud upload with PII gap is a GDPR regression)**

### Goal

Fix the DSAR redactor to scan key *values* for IP addresses, not just key names.
The current `redactor.py` silently passes through audit log entries and enrichment
values containing the target IP as a string inside the JSON value. This must be
fixed before any cloud upload feature ships.

### Known gaps to fix

- `management:audit_log` entries — JSON values contain `actor_ip` fields
- `rdap:ip:{ip}` values — JSON contains the IP in nested fields
- `management:policy_audit` entries — may contain actor IPs

### Deliverables

- [ ] `src/backup/redactor.py` — extend `redact()` to deep-scan JSON values:
  for each entry, attempt JSON decode of the value bytes; recursively walk
  the structure looking for string fields matching any target IP; if found,
  either redact the field or exclude the entire entry (configurable via
  `redact_entire_entry: bool`, default `False` — redact field, keep entry)
- [ ] `src/backup/redactor.py` — add `DSARComplianceError` exception class (raised
  when a pre-upload check finds an unscanned artifact and redaction is enabled)
- [ ] New config option in `config/proxy.yml`:
  ```yaml
  backup:
    dsar:
      redact_values: true          # phase-57e: scan JSON values, not just key names
      redact_entire_entry: false   # phase-57e: false=redact field, true=drop entry
  ```
- [ ] Pre-upload check in `StorageAdapter.upload()` base class: if manifest
  `dsar_scanned` flag is `False` and redaction is enabled, raise `DSARComplianceError`
  (fail-closed for cloud — do not upload unscanned PII to S3/GCS)
- [ ] `src/backup/worker.py` — set `dsar_scanned: false` in manifest by default;
  set `dsar_scanned: true` only after `BackupRedactor.redact()` has been called
  on the artifact

### Acceptance Criteria

- [ ] `tests/unit/backup/test_redactor.py` updated: add cases where IP appears
  in JSON value but not key name — verify it is redacted
- [ ] Audit log entry with `actor_ip: "192.0.2.1"` is redacted when that IP
  is the DSAR subject
- [ ] `test_storage_adapter_interface.py` — upload of artifact where
  `dsar_scanned: false` raises `DSARComplianceError` when redaction is enabled
- [ ] `test_storage_adapter_interface.py` — upload of artifact where
  `dsar_scanned: true` proceeds without error

---

## Phase 57f — Restore Verification & Fallback

**Size: SMALL**
**Depends on: 57a ✅**
**Blocks: nothing**

### Goal

Harden `BackupRestorer` with post-restore verification and a fallback restore path.
After a restore completes, verify the restored key count matches the manifest and
record which artifact was used. If the primary artifact fails checksum, try a
fallback artifact automatically. This was previously scoped around incremental chains;
with 57d cut, it focuses on full-backup reliability for disaster recovery.

### Deliverables

- [ ] `src/backup/restorer.py` — post-restore verification:
  1. After restore, count restored keys in Redis (via SCAN) and compare to
     manifest `keys_count`; log a WARNING if count diverges by more than 5%
  2. Record `backup:restored_from` in Redis: `{filename, restored_at, keys_count}`
     (String, no TTL — survives until next restore)
- [ ] `src/backup/restorer.py` — fallback restore:
  - New method `restore_with_fallback(primary_path, fallback_paths: list[Path])`
  - Tries primary first; if checksum verification fails, tries each fallback in
    order; raises `RestoreError` only if all paths fail
  - Logs which artifact was ultimately used
- [ ] CLI: `ja4proxy_admin.py backup restore --fallback <path>` flag (can be
  repeated for multiple fallbacks)
- [ ] Manifest schema updated: `sequence_number: 0` (always 0 for full backups —
  reserved for future incremental use)

### Acceptance Criteria

- [ ] `tests/unit/backup/test_restore_verification.py`:
  - Restore succeeds → `backup:restored_from` key written to Redis
  - Key count within 5% → no warning logged
  - Key count diverges >5% → WARNING logged, restore still succeeds
- [ ] `tests/unit/backup/test_restore_fallback.py`:
  - Primary checksum fails → fallback used → restore succeeds
  - All paths fail checksum → `RestoreError` raised
  - Audit log records which artifact was actually used
- [ ] `--fallback` flag documented in CLI help text

---

## Phase 57g — Documentation & CLI

**Size: SMALL**
**Depends on: 57a ✅, 57b, 57c, 57e, 57f complete**
**Blocks: nothing (can draft in parallel with implementation)**

### Goal

Close all documentation gates for phases 57a–57f. No new code.

### Deliverables

- [ ] `docs/decisions/ADR-023.md` — Cloud vs. local backup strategy: why hybrid
  (local fast path + cloud durable store), why S3 and GCS (not a single provider),
  what was rejected (`aioboto3` in favour of `boto3 + asyncio.to_thread`)
- [ ] `docs/decisions/ADR-025.md` — Format versioning: why 9-byte header, backward
  compat approach, flag bitmask design, why incrementals were deferred
- [ ] `docs/runbooks/cloud_backup_operations.md` — operator guide:
  - Setup: IAM role for S3 (minimum permissions: `s3:PutObject`, `s3:GetObject`,
    `s3:ListBucket`, `s3:DeleteObject`); GCS service account setup
  - Environment variables required (`BACKUP_S3_BUCKET`, `BACKUP_S3_REGION`, etc.)
  - Daily operations: verifying uploads, checking Prometheus counters
  - Disaster recovery: `backup restore --fallback` procedure
  - DSAR compliance: when and how to run redactor before uploads
  - Cost optimisation: S3 lifecycle policies, storage class selection
  - Troubleshooting: credential failures, checksum mismatches, fallback paths
- [ ] `docs/REDIS_SCHEMA.md` — add:
  - `backup:artifacts` (Sorted Set, score=timestamp, member=JSON metadata) — if used
  - `backup:restored_from` (String, no TTL, written after each restore)
- [ ] `scripts/ja4proxy_admin.py` — new subcommands:
  - `backup cloud upload <artifact> [--provider s3|gcs]`
  - `backup cloud list [--provider s3|gcs]`
  - `backup cloud download <id> --provider s3|gcs [--dest /path]`
  - `backup restore --fallback <path>` (repeatable)
  - `backup restore --verify` (post-restore key count check)
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

The following sub-tasks are **cancelled** — do not implement:

1. **Phase 57d (Dirty Tracking & Incrementals)**: Cut 2026-04-06. Requires touching
   ~18 `src/security/` files, solves an unconfirmed performance problem, and the
   "80% size reduction" claim is not valid for this workload. See Phase 57d section
   above for full rationale. Deferred to Phase 58.

2. **Original "57c — Concurrency & Locking"**: Distributed locking
   (`backup:operation_lock`, TTL 600s, NX semantics) was fully implemented in
   Phase 40 (`worker.py` lines 213–214, `restorer.py` lines 226–227). Do not
   re-implement.

---

## Sub-Phase Summary

| Sub-Phase | Size | Depends on | Parallel with | Status |
|-----------|------|-----------|---------------|--------|
| 57a: Format Header & Adapter ABC | SMALL | nothing | — | ✅ COMPLETE |
| 57b: S3 Adapter | SMALL | 57a ✅ | 57c, 57e | TODO |
| 57c: GCS Adapter | SMALL | 57a ✅ | 57b, 57e | TODO |
| 57d: Dirty Tracking & Incrementals | ~~SMALL–MED~~ | — | — | ❌ CANCELLED |
| 57e: DSAR Redactor Hardening | SMALL | 57a ✅ | 57b, 57c | TODO |
| 57f: Restore Verification & Fallback | SMALL | 57a ✅ | 57b, 57c, 57e | TODO |
| 57g: Documentation & CLI | SMALL | all above | — | TODO |

**Execution order:**
1. ✅ Done: 57a (format header + StorageAdapter ABC)
2. Parallel: 57b + 57c + 57e + 57f (all depend only on 57a, which is complete)
3. Sequential: 57g (needs all above complete)

---

## Acceptance Criteria (Phase 57 Complete)

All sub-phases complete, AND:

- [ ] S3 round-trip backup/restore verified against moto
- [ ] GCS round-trip backup/restore verified via mocked google-cloud-storage
- [ ] DSAR redactor covers both key names and JSON values
- [ ] Restore verification records `backup:restored_from` after every restore
- [ ] Fallback restore tries secondary artifacts when primary fails checksum
- [ ] Distributed lock NOT re-implemented (already in Phase 40 — verify no duplicate)
- [ ] Documentation gate (Phase 57g) complete
- [ ] All existing backup tests still pass unchanged
- [ ] `make test-unit` passes with zero warnings
