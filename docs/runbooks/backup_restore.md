<!--
title: Go Redis Backup Runbook
audience: Operators, DevOps
last_reviewed: 2026-06-13
phase: 315a
-->

# Runbook — Go Redis Backup (`ja4p backup`)

The proxy is stateless; all durable security state lives in Redis. This runbook
covers the **Go** backup engine introduced in Phase 315a. (Restore — `ja4p
restore` — is Phase 315b and not yet available.)

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
held lock (another backup or a future restore in progress) aborts the run.
