<!--
title: Go Redis Backup & Restore Runbook
audience: Operators, DevOps
last_reviewed: 2026-06-13
phase: 315b
-->

# Runbook — Go Redis Backup & Restore (`ja4p backup` / `ja4p restore`)

The proxy is stateless; all durable security state lives in Redis. This runbook
covers the **Go** backup engine (Phase 315a) and the **restore** engine (Phase
315b — the *dangerous half*; see the restore section below before using it).

## What gets backed up

The durable security-state prefixes: `ban*`, `config:dial`, `ip:blacklist`,
`ip:whitelist`, `ja4:blacklist`, `ja4:whitelist`, `management:audit_log`,
`management:policy_audit`, `management:gdpr_erasure_log`, `beacon*`, `fp*`,
`blocklist*`. Each key is stored with its remaining TTL.

**Never backed up** (the security boundary): ephemeral/regenerable state
(`ratelimit*`, `concurrent*`) and all credential/session/MFA material
(`mgmt:totp*`, `mgmt:webauthn*`, `mgmt:saml*`, `mgmt:oidc*`, `mgmt:session*`).
These must regenerate, not be restored.

## The passphrase (required)

The artifact is AES-256-GCM encrypted. Supply the passphrase via, in order of
precedence: `--key`, `--key-file <path>`, or `$JA4PROXY_BACKUP_KEY`. **Store it
in your secret manager, never in `config/proxy.yml`.** Losing it means the
artifact cannot be decrypted; leaking it exposes audit logs and bans.

## Run a backup

```bash
export JA4PROXY_BACKUP_KEY=...            # from your secret store
ja4p backup \
  --config config/proxy.yml \
  --dir /var/lib/ja4proxy/backups \
  --retention-count 7 --retention-days 30 \
  --metrics-textfile /var/lib/node_exporter/textfile/ja4proxy_backup.prom
```

Schedule it from a systemd timer or cron. The artifact is written atomically as
`ja4proxy-backup-<unixtime>.bin` (mode `0600`, directory `0700`); older artifacts
beyond the retention window are pruned.

## Inspect an artifact (offline, no Redis)

```bash
ja4p backup inspect /var/lib/ja4proxy/backups/ja4proxy-backup-1750000000.bin \
  --key-file /etc/ja4proxy/backup.key
```

Prints the manifest (created-at, schema version, proxy version, config hash, key
count) and a per-prefix key breakdown — use it to verify an artifact decrypts and
contains what you expect before relying on it.

## Metrics & alerts

The run emits `ja4proxy_backup_operations_total{status}`,
`ja4proxy_backup_last_success_seconds`, `ja4proxy_backup_currently_running`, and
`ja4proxy_backup_duration_seconds`. With `--metrics-textfile` pointed at the
node-exporter textfile directory, these are scraped after the short-lived CLI
exits. They back the `BackupFailed` / `BackupStale` / `BackupRunningTooLong`
alerts in `deploy/monitoring/alertmanager/rules/backup.rules.yml`.

## Failure handling

A backup failure is **fail-safe**: it logs, increments
`ja4proxy_backup_operations_total{status="failure"}`, sets
`ja4proxy_backup_currently_running` back to 0, releases the
`backup:operation_lock`, and exits non-zero. It never touches live traffic. A
held lock (another backup or a restore in progress) aborts the run.

---

# Restore (`ja4p restore`) — the dangerous half

Restoring the wrong things can **re-block real users** (a mass false-positive
event) and can **resurrect personal data a subject asked us to erase** (a GDPR
Article 17 breach). `ja4p restore` makes both **impossible by default**.

## The two guard-rails (on by default)

1. **Block-state is gated.** Bans (`ban:*`, `ban_cidr:*`), the block lists
   (`ip:blacklist`, `ja4:blacklist`) and the dial (`config:dial`) are **not**
   restored unless you pass `--include-blocks`. A default restore can only bring
   back allow-state (whitelists, fingerprints, audit history) — it can never
   re-block a user.
2. **GDPR-erased subjects are never resurrected.** Before writing any per-IP key
   (`ban:{ip}`, `fp:os:ip:{ip}`, `fp:ip:{ip}`, `beacon:{ip}:{ja4}`), the restore
   consults the tombstone set: the live `management:gdpr_erasure_log` (read
   **before** any flush) **merged** with an optional `--tombstone-file`. Any key
   whose subject was erased after the backup is skipped and counted
   (`ja4proxy_restore_skipped_total{reason="erased"}`).

## Safety flags

| Flag | Effect |
|---|---|
| *(none)* | Restore allow-state only, into an **empty** target, real write. |
| `--include-blocks` | Also restore bans/blacklists/dial — **can re-block users**. |
| `--force` | `FLUSHDB` a **non-empty** target before restoring (else the restore refuses to clobber). Tombstones are read *before* the flush. |
| `--dry-run` | Report what *would* happen (counts of restore / block-gated / erased-skipped); **writes nothing**. |
| `--tombstone-file <path>` | A file of IPs (one per line, `#` comments allowed) that must never be resurrected — survives a disaster where the live erasure log is gone. |

## Restore

```bash
export JA4PROXY_BACKUP_KEY=...
# Preview first — always:
ja4p restore /var/lib/ja4proxy/backups/ja4proxy-backup-1750000000.bin --dry-run --include-blocks
# Disaster recovery onto an empty/replaced DB, bans included, erased subjects honoured:
ja4p restore <artifact> --include-blocks --force --tombstone-file /etc/ja4proxy/erased-ips.txt
```

TTLs are re-applied from the artifact (a ban with 200s left comes back with ~200s,
not a fresh hour). Every restore is audited to `management:policy_audit` and writes
`backup:last_restore` / `backup:restored_from`.

## Restore metrics & failure handling

Emits `ja4proxy_restore_operations_total{status}`,
`ja4proxy_restore_currently_running`, `ja4proxy_restore_duration_seconds`, and
`ja4proxy_restore_skipped_total{reason="erased|block_gated"}`. A failure is
fail-safe (logs, `status="failure"`, `currently_running` → 0, lock released,
non-zero exit). A tampered/truncated/wrong-key artifact fails closed **before**
any Redis write; a backup whose `schema_version` is newer than this binary is
refused (downgrade-block).
