# PHASE 313b — Go Redis Restore (selective, GDPR-aware)

> **STATUS: PROPOSED — plan for review. No code until approved.**
> Part 2 of 2. **Depends on PHASE_313a** (it reads the artifact 313a writes).
> Restore is the *dangerous* half — read §3 before anything else.

---

## 1. Goal (plain language)

Take an encrypted snapshot produced by `ja4pd backup` (313a) and load it back
into Redis — **safely**. "Safely" is the whole point of splitting this out:
restoring the wrong things can **re-block real users** and can **resurrect
personal data a user asked us to erase**. This phase builds `ja4pd restore` with
guard-rails that make those two failures impossible by default.

## 2. Background

- Reads the artifact format defined by **313a** (gzip → AES-256-GCM, a manifest +
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
| D7 | **Take `backup:operation_lock`** (the same `SET NX EX 600` 313a uses). | A restore must not race a live backup or a second restore. |
| D8 | **TTLs re-applied from the artifact** (`RESTORE key ttl value`), not reset. Document the choice. | A ban that had 200s left should not come back with a fresh 3600s. Preserves decay semantics. |

## 5. Design / flow

```
ja4pd restore <artifact> [--include-blocks] [--force] [--dry-run]
  │
  ├─ decrypt + verify GCM tag + manifest checksum     (abort on failure)
  ├─ acquire backup:operation_lock                    (abort if held)
  ├─ set ja4proxy_restore_currently_running = 1
  ├─ load management:gdpr_erasure_log → erased-subject set
  ├─ for each key in the artifact:
  │     • is it block-state and --include-blocks not set?   → skip (gated)
  │     • is its subject in the erased set?                 → skip (erased), count
  │     • else: RESTORE key ttl value  (REPLACE)            [unless --dry-run]
  ├─ append management:policy_audit + backup:last_restore / backup:restored_from
  ├─ write restore metrics (.prom): operations_total{status}, duration, running=0
  └─ release lock
```

Any failure: log, `ja4proxy_restore_operations_total{status="failure"}`,
`currently_running 0`, release lock, non-zero exit. Restore is **never automatic**
— always an explicit operator command.

## 6. Metrics (the restore three, completing the set 313a started)

- `ja4proxy_restore_operations_total{status="success|failure"}`
- `ja4proxy_restore_currently_running` (0/1)
- `ja4proxy_restore_duration_seconds` (histogram)
- *(extra)* `ja4proxy_restore_skipped_total{reason="erased|block_gated"}`

## 7. Implementation plan (in order)

1. Add the restore metrics to `internal/metrics` + `OBSERVABILITY_STANDARDS.md §1d`.
2. `internal/backup/restore.go`: decrypt+verify → lock → erased-set load →
   per-key classify (allow/block/erased) → `RestoreReplace` with TTL → audit.
3. Classification helpers: a small, well-tested function that labels a key as
   `allow` / `block` / `per-ip` from its prefix, plus a subject-extractor for
   per-IP keys (IPv4 **and** IPv6 canonical forms — never truncate v6).
4. `ja4pd restore` CLI: `--include-blocks`, `--force`, `--dry-run`.
5. Restore metric textfile emission (deferred `running 0` even on crash).
6. Docs: extend `docs/runbooks/backup_restore.md` (restore procedure, the two
   risks, the flags); ADR if any non-obvious choice; CHANGELOG; manifest `313b`.

## 8. Test plan

- **Unit (miniredis)** — classification (allow vs block vs per-IP, v4 & v6);
  block-state skipped unless `--include-blocks`; erased subject skipped + counted;
  `--dry-run` writes nothing; non-empty-target refusal without `--force`;
  audit entry written; metrics toggle.
- **Integration (real Redis)** — the 313a round-trip: every-type + IPv6 keys
  backed up → flushed → restored → asserted equal incl. TTLs. **Plus the GDPR
  test**: back up an IP's keys → erase that IP via the `gdpr_delete` key set →
  restore → assert the erased IP's keys are **not** resurrected.
- **Adversarial** — tampered artifact (flip a byte) → GCM verify fails, nothing
  written; artifact from a different/incompatible schema_version → refused.
- **Safety/asymmetry** — default restore of a snapshot full of bans leaves the
  live ban set **unchanged** (blocks gated); `--include-blocks` restores them and
  the audit log records it.

## 9. Acceptance criteria

- `ja4pd restore` round-trips a 313a artifact exactly (keys + TTLs) for allow-state
  by default; block-state restored **only** with `--include-blocks`.
- A restore **never** resurrects a GDPR-erased subject (test-proven).
- Tampered/incompatible artifacts fail closed; non-empty targets need `--force`;
  `--dry-run` is side-effect-free.
- Every restore appends `management:policy_audit` + `backup:last_restore`.
- The three `ja4proxy_restore_*` alerts can now fire/clear.
- Tests pass; coverage ≥ 80%; runbook/ADR/CHANGELOG/manifest updated.

## 10. Out of scope

- The backup engine, artifact format, encryption, textfile-collector wiring — all
  PHASE_313a.
- Automatic / scheduled restore (deliberately impossible — restore is manual).
- Cross-Redis-version restore (a `RESTORE` from a newer Redis can be rejected;
  document "restore onto the same major version").
