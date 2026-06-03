<!--
title: Cloud Backup Operations
audience: Infrastructure operators, SecOps
last_reviewed: 2026-04-06
phase: 57
-->

# Cloud Backup Operations (Phase 57)

> **Audience:** Infrastructure operators, SecOps analysts
> **Prerequisites:** JA4proxy deployed; Phase 57 cloud adapters enabled
> **Related:** [Redis Operations](redis_operations.md) · [SecOps Operations](../OPERATIONS.md)

---

## Overview

Phase 57 extends the Phase 19/40 backup system with optional cloud storage upload.
The local artifact is always written first (unchanged behaviour). Cloud upload is an
async step that runs after `create_backup()` returns. A cloud upload failure is
non-fatal: it logs a WARNING and increments a Prometheus counter, but the local
artifact is always intact.

Supported providers: **AWS S3** (Phase 57b) and **Google Cloud Storage** (Phase 57c).

---

## Setup: AWS S3

### IAM Policy

Create a dedicated IAM user with the minimum required permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:DeleteObject",
        "s3:HeadObject"
      ],
      "Resource": [
        "arn:aws:s3:::YOUR-BUCKET",
        "arn:aws:s3:::YOUR-BUCKET/*"
      ]
    }
  ]
}
```

Do **not** grant `s3:*` or any IAM management permissions to this user.

### Environment Variables

Set these in the proxy container environment (or `.env` file):

```bash
BACKUP_S3_BUCKET=ja4proxy-backups-prod
BACKUP_S3_REGION=eu-west-1
AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Never put credentials in `config/proxy.yml`. They are read from environment only.

### Enable in Config

Edit `config/proxy.yml`:

```yaml
backup:
  cloud_storage:
    enabled: true      # phase-57b
    provider: "s3"     # phase-57b
    s3:
      bucket: "${BACKUP_S3_BUCKET}"
      region: "${BACKUP_S3_REGION:-us-east-1}"
      prefix: "backups/"
      storage_class: "STANDARD"
      retention_days: 90
```

Hot-reload is supported: send `SIGHUP` or use the Management UI to apply changes
without restarting.

---

## Setup: Google Cloud Storage

### Service Account

Create a service account and grant it the `roles/storage.objectAdmin` role scoped
to the target bucket. Download the JSON key file.

### Environment Variables

```bash
BACKUP_GCS_BUCKET=ja4proxy-backups-prod
BACKUP_GCS_PROJECT_ID=my-gcp-project-id
BACKUP_GCS_CREDENTIALS_PATH=/secrets/gcs-service-account.json
```

Mount the credentials file into the container at the path specified by
`BACKUP_GCS_CREDENTIALS_PATH`. Set file permissions to `0400`.

### Enable in Config

```yaml
backup:
  cloud_storage:
    enabled: true      # phase-57c
    provider: "gcs"    # phase-57c
    gcs:
      bucket: "${BACKUP_GCS_BUCKET}"
      project_id: "${BACKUP_GCS_PROJECT_ID}"
      credentials_path: "${BACKUP_GCS_CREDENTIALS_PATH}"
      prefix: "backups/"
      storage_class: "STANDARD"
      retention_days: 90
```

---

## Daily Operations

### Check Upload Health

```bash
# Successful uploads since startup (should be non-zero after each backup window)
ja4proxy_backup_cloud_upload_total{result="success"}

# Upload failures (investigate if non-zero)
ja4proxy_backup_cloud_upload_total{result="failure"}
```

Upload failures do NOT affect local backup health. Check:

```bash
# Local backup health
ja4proxy_backup_operations_total{status="success"}
ja4proxy_backup_last_success_timestamp
```

### List Cloud Artifacts

```bash
# List all backups in S3
python3 scripts/ja4proxy_admin.py backup cloud list --provider s3

# List all backups in GCS
python3 scripts/ja4proxy_admin.py backup cloud list --provider gcs
```

Output columns: `uri`, `filename`, `size_bytes`, `created_at`.

### Manual Upload

To manually upload a local artifact to cloud (e.g. after a connectivity gap):

```bash
python3 scripts/ja4proxy_admin.py backup cloud upload /app/backups/backup_20260406T020000Z.bin --provider s3
```

The command prints the cloud URI on success:
```
Uploaded: s3://ja4proxy-backups-prod/backups/backup_20260406T020000Z.bin
```

---

## Disaster Recovery

### Full Restore from Cloud

```bash
# Step 1: Download the artifact and its manifest
python3 scripts/ja4proxy_admin.py backup cloud download backup_20260406T020000Z.bin \
  --provider s3 --dest /tmp/recovery/

# Step 2: Restore with fallback to an older artifact if the primary fails
python3 scripts/ja4proxy_admin.py backup restore \
  /tmp/recovery/backup_20260406T020000Z.bin \
  /tmp/recovery/backup_20260406T020000Z.bin.manifest.json \
  --fallback /tmp/recovery/backup_20260405T020000Z.bin \
  --confirm

# Step 3: Verify the restore recorded itself
redis-cli get backup:restored_from
# Returns: {"filename":"backup_20260406T020000Z.bin","restored_at":"2026-04-06T...","keys_count":12345}
```

The `--fallback` flag can be repeated to specify a chain of fallbacks in order:
```bash
python3 scripts/ja4proxy_admin.py backup restore primary.bin primary.bin.manifest.json \
  --fallback fallback1.bin --fallback fallback2.bin --confirm
```

`restore_with_fallback()` tries each artifact in sequence and stops at the first
success. If all fail it raises `RestoreError: All N restore artifact(s) failed`.

### Post-Restore Checks

After restore, verify:

1. `redis-cli get backup:restored_from` — confirms restore ran and recorded the source artifact
2. `redis-cli get backup:last_restore` — ISO-8601 timestamp of the restore
3. Check for key count divergence in proxy logs:
   ```
   backup | event=restore_key_count_divergence | ...
   ```
   This is advisory only (logged as WARNING, never blocks restore success). It is
   normal if Redis had additional keys from other sources beyond the backup window.

---

## DSAR Compliance

Before uploading a backup artifact that may contain a GDPR data subject's IP address:

```bash
# Redact the IP from all matching key names AND JSON values in the artifact
python3 scripts/ja4proxy_admin.py backup dsar-redact /app/backups/backup_20260406T020000Z.bin \
  --ip 192.0.2.1 \
  --output /app/backups/backup_20260406T020000Z_redacted.bin
```

The command prints how many entries were redacted:
```
Redacted 3 entries containing 192.0.2.1. Saved to backup_20260406T020000Z_redacted.bin.
```

The redactor scans:
- **Key names**: any entry where the IP appears in the Redis key string
- **JSON values**: audit log entries (`management:audit_log`, `management:policy_audit`)
  and RDAP enrichment values (`rdap:ip:*`) are JSON-decoded and walked recursively for
  string fields matching the target IP

The `dsar_scanned: true` manifest flag is set automatically after redaction. If DSAR
redaction is enabled in config (`backup.dsar.redact_values: true`) and an artifact has
`dsar_scanned: false`, `StorageAdapter.upload()` raises `DSARComplianceError` rather
than uploading unredacted PII to cloud storage.

---

## Cost Optimisation

### S3 Lifecycle Rules

Apply lifecycle rules to auto-transition old artifacts to cheaper storage tiers:

```json
{
  "Rules": [
    {
      "Status": "Enabled",
      "Filter": {"Prefix": "backups/"},
      "Transitions": [
        {"Days": 30, "StorageClass": "STANDARD_IA"},
        {"Days": 90, "StorageClass": "GLACIER"}
      ]
    }
  ]
}
```

Apply via AWS CLI:
```bash
aws s3api put-bucket-lifecycle-configuration \
  --bucket ja4proxy-backups-prod \
  --lifecycle-configuration file://lifecycle.json
```

### GCS Lifecycle Rules

```bash
gsutil lifecycle set lifecycle.json gs://ja4proxy-backups-prod
```

Where `lifecycle.json`:
```json
{
  "rule": [
    {"action": {"type": "SetStorageClass", "storageClass": "NEARLINE"},
     "condition": {"age": 30}},
    {"action": {"type": "SetStorageClass", "storageClass": "COLDLINE"},
     "condition": {"age": 90}}
  ]
}
```

---

## Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `ja4proxy_backup_cloud_upload_total{result="failure"}` increasing | Credentials expired, bucket permissions changed, network unreachable | Check `BACKUP_S3_BUCKET`/`BACKUP_GCS_BUCKET` env vars; verify IAM policy; check proxy container network connectivity |
| `DSARComplianceError` on upload | Artifact has `dsar_scanned: false` and redaction is enabled | Run `backup dsar-redact` before upload, or set `dsar_scanned: true` manually in the manifest if you have verified the artifact contains no PII |
| Restore key count WARNING in logs | Redis had additional keys from sources outside the backup window | Advisory only — restore succeeded. Expected if the backup was taken while traffic was active |
| `RestoreError: All N artifacts failed` | All artifacts failed checksum verification | Artifact corruption. Re-download from cloud and retry. If all cloud copies are corrupted, escalate per incident response procedure |
| `RestoreError: Checksum verification failed` | Single artifact is corrupt | Use `--fallback` to restore from a known-good earlier artifact |
| `RestoreError: Backup/Restore operation already in progress` | Another restore is running, or `backup:operation_lock` was left by a crashed process | Wait for the running operation or: `redis-cli del backup:operation_lock` (only if you are certain no backup/restore is active) |
| Cloud upload succeeds but `list` shows no artifacts | Wrong prefix in config | Check `backup.cloud_storage.s3.prefix` / `gcs.prefix` in `config/proxy.yml` |
