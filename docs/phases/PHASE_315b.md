# PHASE 315b — Go Redis Restore (selective, GDPR-aware)

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Part 2 of 2. **Depends on PHASE_315a** (it reads the artifact 315a writes).
> Restore is the *dangerous* half — read §3 before anything else.

---

## 1. Goal (plain language)

Take an encrypted snapshot produced by `ja4pd backup` (315a) and load it back
into Redis — **safely**. "Safely" is the whole point of splitting this out:
restoring the wrong things can **re-block real users** and can **resurrect
personal data a user asked us to erase**. This phase builds `ja4pd restore` with
guard-rails that make those two failures impossible by default.

## 2. Background

- Reads the artifact format defined by **315a** (gzip → AES-256-GCM, a manifest +
  per-key `{ttl, dumped_value}`).
- The archived Python restorer is reference-only at
  `git show 5afeba26:archive/python_legacy/src/backup/restorer.py`.
- `deploy/monitoring/alertmanager/rules/backup.rules.yml` already alerts on
  `ja4proxy_restore_operations_total{status}`, `ja4proxy_restore_currently_running`,
  `ja4proxy_restore_duration_seconds_bucket` — **dead until this phase emits them.**

## 3. The two ways restore can hurt people (this drives the whole design)

JA4proxy's governing rule (`CLAUDE.md`, "The Core Asymmetry"): **blocking a real
user is a high-cost error; a missed bad bot is cheap.** Restore can violate this
in two distinct ways:

1. **Re-blocking.** A snapshot captures every ban, the dial value, and the
   block-lists *as they were at backup time*. If an operator has since un-banned
   an IP, or lowered the dial, a naïve "restore everything" silently re-blocks
   those users and re-arms blocking. **Restoring block-state is a mass
   false-positive event by construction.**
2. **Resurrecting erased data (GDPR).** `scripts/gdpr_delete.py` is our Right-to-
   Erasure path — it deletes a subject's per-IP keys and logs the erasure to
   `management:gdpr_erasure_log`. A backup taken *before* an erasure, restored
   *after* it, brings the erased person's data back. That is a GDPR Article 17
   breach.

Everything below exists to make those two outcomes **off by default**.

## 4. Key decisions (and why)

| # | Decision | Why |
|---|---|---|
| D1 | **Restore allow-state by default; block-state only with an explicit `--include-blocks` flag.** "Block-state" = `ban:*`, `ban_cidr:*`, `ip:blacklist`, `ja4:blacklist`, `config:dial`. "Allow-state" = whitelists, allowlists, fingerprints, audit history. | Default restore can never re-block a user. An operator who *wants* the old bans back must consciously ask. (§3 risk 1.) |
| D2 | **GDPR tombstone check.** Before writing any per-IP key, consult `management:gdpr_erasure_log` (and a derived erased-subject set). Skip — and count — any key whose subject was erased after the backup. | A restore must never resurrect erased data. (§3 risk 2.) Emit `ja4proxy_restore_skipped_total{reason="erased"}`. |
| D3 | **Verify integrity before touching Redis.** Decrypt + check the AES-GCM tag + manifest checksum first; abort wholesale on failure. | A truncated/tampered artifact must fail closed, not half-restore. |
| D4 | **Refuse a non-empty target without `--force`.** | Stops an accidental clobber of a live, populated Redis. |
| D5 | **`--dry-run` reports what *would* change and writes nothing.** | Operators can preview a restore (which keys, which skipped-as-erased, which blocks gated) before committing. |
| D6 | **Every restore is audited.** Append to `management:policy_audit` and write `backup:last_restore` / `backup:restored_from` (already in `REDIS_SCHEMA.md`): operator, source file, key counts, timestamp. | The schema requires every policy change be attributed; a restore is a big policy change. |
| D7 | **Take `backup:operation_lock`** (the same `SET NX EX 600` 315a uses). | A restore must not race a live backup or a second restore. |
| D8 | **TTLs re-applied from the artifact** (`RESTORE key ttl value`), not reset. Document the choice. | A ban that had 200s left should not come back with a fresh 3600s. Preserves decay semantics. |
| D9 | **Hybrid GDPR Tombstone Merge via `--tombstone-file`.** | Since `FLUSHDB` destroys Redis state, read tombstones from an external host-mounted `--tombstone-file` AND the backup manifest itself, merging them to ensure erased subjects are never resurrected. |
| D10 | **Paced, Throttled Restore Pipelines.** | Restore keys using paced pipelines (default batch 100, delay 10ms) to prevent saturating the single-threaded Redis engine. |
| D11 | **Configuration Divergence Warning.** | Compare active config hash and build version with the manifest. Warn and block restore unless `--force` is used, preventing config-state misalignment. |
| D12 | **Forward-Compatible Schema Migration Registry.** | Upgrades are a standard lifecycle event. When restoring an older backup (`schema_version = N`) on a newer proxy binary running a newer schema (`current_schema_version = N+1`), pipe each key and binary payload through an in-memory schema migrator function to transform it on the fly. Block downgrades by default. Registry uses a map of source version to transformer functions: `type MigratorFunc func(key string, payload []byte) (string, []byte, error)`. |
| D13 | **Namespace/Prefix Remapping during Restore (`--prefix-map`).** | Allow operators to restore snapshots into safe namespace prefixes (e.g., remapping `ban:->restore:ban:`) to validate, debug, or compare values without overwriting live database state. |
| D14 | **Post-Restore Integrity & Health Validation (Smoke Test).** | Verify restore completeness by running a validation check after writing keys (checking allowlists, audit logs, schema correctness). Fail-safe: raise alerts on failure. |

## 5. Design / flow

```
ja4pd restore <artifact> [--include-blocks] [--force] [--dry-run] [--tombstone-file <path>] [--prefix-map <mapping>]
  │
  ├─ parse unencrypted binary header (magic, ver, salt, iterations, nonce)
  ├─ derive 32-byte key from passphrase + salt (PBKDF2-SHA256, 100k iterations)
  ├─ decrypt & verify GCM tag and unpack gzipped manifest JSON
  ├─ if backup schema_version > current_schema_version: abort (downgrade blocked)
  ├─ compare active config hash & build version; if mismatch, warn and abort unless --force
  ├─ acquire backup:operation_lock                    (abort if held)
  ├─ set ja4proxy_restore_currently_running = 1
  ├─ load tombstones from --tombstone-file AND the backup manifest → merged erased-subject set
  ├─ if target Redis has keys and --force is not set: abort
  ├─ FLUSHDB (only if --force set)                     [unless --dry-run]
  ├─ for each key batch in the artifact (batch size: 100):
  │     • is it block-state and --include-blocks not set?   → skip (gated)
  │     • is its subject in the merged erased set?          → skip (erased), count
  │     • if --prefix-map is set: remap the key name (e.g. prefix change)
  │     • if backup schema_version < current_schema_version:
  │     │    └─ execute in-memory schema migrator function for this key/payload type
  │     • else: RESTORE key ttl value (REPLACE)             [unless --dry-run]
  │     • sleep 10ms (yield Redis CPU to live traffic)
  ├─ run post-restore validation (smoke test core keys)    [unless --dry-run]
  ├─ append management:policy_audit + backup:last_restore / backup:restored_from
  ├─ write restore metrics (.prom): operations_total{status}, duration, running=0
  └─ release lock
```

Any failure: log, `ja4proxy_restore_operations_total{status="failure"}`,
`currently_running 0`, release lock, non-zero exit. Restore is **never automatic**
— always an explicit operator command.

## 6. Metrics (the restore three, completing the set 315a started)

- `ja4proxy_restore_operations_total{status="success|failure"}`
- `ja4proxy_restore_currently_running` (0/1)
- `ja4proxy_restore_duration_seconds` (histogram)
- *(extra)* `ja4proxy_restore_skipped_total{reason="erased|block_gated"}`

## 7. Implementation plan (in order)

1. Add the restore metrics to `internal/metrics` + `OBSERVABILITY_STANDARDS.md §1d`. Add validation failure metric `ja4proxy_restore_validation_failed` (counter).
2. Schema Migration Registry: Define the registry structure and interface in `internal/backup/migration.go`:
   ```go
   type MigratorFunc func(key string, payload []byte) (string, []byte, error)
   type SchemaMigrator struct {
       migrators map[int]MigratorFunc // maps fromVersion -> migration logic
   }
   func (s *SchemaMigrator) Register(fromVersion int, fn MigratorFunc)
   func (s *SchemaMigrator) Migrate(key string, payload []byte, fromVersion, targetVersion int) (string, []byte, error)
   ```
   Write a sample migrator (e.g. from version 1 to 2) to establish the pattern.
3. `internal/backup/restore.go`: parse header → PBKDF2 derive → decrypt/verify → schema compatibility check (reject downgrades) → config check (hash/version) → lock → merge tombstones (file + manifest) → paced per-key classify, prefix remapping, schema migration & restore (batching/delay) → post-restore validation (smoke test) → audit.
4. Classification helpers: a small, well-tested function that labels a key as
   `allow` / `block` / `per-ip` from its prefix, plus a subject-extractor for
   per-IP keys (IPv4 **and** IPv6 canonical forms — never truncate v6).
5. `ja4pd restore` CLI: `--include-blocks`, `--force`, `--dry-run`, `--tombstone-file`, `--key-file`, `--prefix-map`.
6. Restore metric textfile emission (deferred `running 0` even on crash).
7. Docs: extend `docs/runbooks/backup_restore.md` (restore procedure, the two
   risks, the config hash check, prefix remapping, upgrade migrations, the flags); ADR if any non-obvious choice; CHANGELOG; manifest `315b`.

## 8. Test plan

- **Unit (miniredis)** — classification (allow vs block vs per-IP, v4 & v6);
  block-state skipped unless `--include-blocks`; erased subject skipped + counted (via hybrid file + manifest merge);
  `--dry-run` writes nothing; non-empty-target refusal without `--force`;
  audit entry written; metrics toggle.
- **Schema Migration Tests** — verify that backups with older `schema_version` values trigger registered migrator functions that mutate keys/payloads correctly on the fly, while backups with newer schema versions are rejected (blocking downgrades).
- **Prefix Remapping Test** — verify that `--prefix-map` correctly translates key names before writing to Redis (asserting live keys are untouched).
- **Post-Restore Smoke Validation Test** — verify the health check passes on valid keys, and fails (incrementing metric) if core keys are missing.
- **Config Divergence Test** — verify restore warns and aborts when configuration hashes or build versions diverge, and proceeds with `--force`.
- **Integration (real Redis)** — the 315a round-trip: every-type + IPv6 keys
  backed up → flushed → restored → asserted equal incl. TTLs. **Plus the GDPR
  test**: back up an IP's keys → erase that IP via the `gdpr_delete` key set (or by writing to the `--tombstone-file`) →
  restore → assert the erased IP's keys are **not** resurrected.
- **Adversarial** — tampered artifact (flip a byte) → GCM verify fails, nothing
  written; artifact from a different/incompatible schema_version → refused.
- **Safety/asymmetry** — default restore of a snapshot full of bans leaves the
  live ban set **unchanged** (blocks gated); `--include-blocks` restores them and
  the audit log records it.

## 9. Acceptance criteria

- `ja4pd restore` round-trips a 315a artifact exactly (keys + TTLs) for allow-state
  by default; block-state restored **only** with `--include-blocks`.
- A restore **never** resurrects a GDPR-erased subject (test-proven).
- Tampered/incompatible artifacts fail closed; non-empty targets need `--force`;
  `--dry-run` is side-effect-free.
- Every restore appends `management:policy_audit` + `backup:last_restore`.
- The three `ja4proxy_restore_*` alerts can now fire/clear.
- Tests pass; coverage ≥ 80%; runbook/ADR/CHANGELOG/manifest updated.

## Files to Modify

| File | Change |
|------|--------|
| `internal/metrics/metrics.go` | Register restore Prometheus metrics |
| `docs/OBSERVABILITY_STANDARDS.md` | Add restore metrics definitions |
| `internal/backup/migration.go` | New file — Schema migration registry and interfaces |
| `internal/backup/restore.go` | New file — restore orchestration, tombstone merge, classification, and decryption |
| `cmd/ja4pd/main.go` | Wire `restore` CLI subcommand with flags |
| `docs/runbooks/backup_restore.md` | Update restore procedure and scenarios runbook |
| `CHANGELOG.md` | Add Phase 315b changes |

## 10. Out of scope

- The backup engine, artifact format, encryption, textfile-collector wiring — all
  PHASE_315a.
- Automatic / scheduled restore (deliberately impossible — restore is manual).
- Cross-Redis-version restore (a `RESTORE` from a newer Redis can be rejected;
  document "restore onto the same major version").
