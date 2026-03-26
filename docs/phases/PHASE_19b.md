# Phase 19b — Backup & Restore Security Supplement

## Status: OPEN

> Implementation note: this supplement defines security requirements for Phase 19.
> Execute work using `docs/phases/PHASE_19_EXECUTION_PLAN.md`, which sequences
> these requirements into atomic TDD tasks.

## Purpose

This document supplements `PHASE_19.md`. Read that document first. This supplement adds:

1. ADR-019: Why backups are not encrypted in Phase 19, and what that means
2. Backup security threat model: who can attack the backup system and how
3. Access control specification: who can trigger, read, restore, and delete backups
4. Audit logging for all backup operations
5. Backup integrity chain of custody (beyond checksum verification)
6. Key management preparation for future encryption (Phase 21)
7. Sensitive data handling: which Redis keys must never appear in backups
8. TDD gaps: adversarial and security-specific tests that Phase 19 left skeletal

---

## 1. ADR-019: Why Backups Are Not Encrypted in Phase 19

**File:** `docs/decisions/ADR-019.md`

```markdown
# ADR-019: Backup Encryption Deferred to Phase 21

## Status: Accepted (with documented risk)

## Context

Phase 19 implements backup and restore for JA4proxy Redis state. The backup artifacts
contain operational security data: IP ban lists, CIDR blocks, JA4 blacklists/whitelists,
audit logs, policy configurations.

An unencrypted backup archive containing this data, if stolen, would reveal:
- The complete set of IPs and subnets the organisation is actively blocking
- The JA4 fingerprints identified as malicious (operational intelligence)
- The security policy configuration (attacker learns which bypasses are enabled)
- The audit log (names/IPs of operators who made changes)

## Why Not Encrypt in Phase 19

**Option A: Encrypt with a local symmetric key (AES-256-GCM)**
The key must be stored somewhere. If stored alongside the backup (same filesystem),
an attacker who accesses the backup can also access the key. Provides no protection
against filesystem-level access.

**Option B: Encrypt with an externally-managed key (KMS — AWS KMS, HashiCorp Vault)**
Provides real protection: the key is never on the same host as the backup data.
Rejected for Phase 19: requires external KMS dependency. Phase 19 targets zero
additional infrastructure beyond a local filesystem.

**Option C: No encryption (selected for Phase 19)**
Honest approach: document the risk and address it properly in Phase 21 with KMS.
Provide filesystem-level mitigations instead.

**Decision:** No encryption in Phase 19. Mitigate with filesystem permissions and
documented deployment requirements. Phase 21 adds KMS integration.

## Risk Acceptance

The following risk is explicitly accepted for Phase 19 deployments:

| Risk | Impact | Mitigation | Residual risk |
|------|--------|------------|---------------|
| Backup archive stolen from filesystem | Attacker learns all block lists, policy config, audit log | Restrict backup dir to root/backup-operator only (mode 0700) | An attacker with root/filesystem access already has Redis access — same data |
| Backup transferred over unencrypted channel | MITM reads backup content | Require HTTPS/SFTP for any off-host transfer | Operator responsibility |
| Backup manifest stored alongside archive | Attacker learns key counts and schema | Manifest contains metadata only; no key values | Low — metadata alone has limited value |

**The residual risk for on-host storage is low**: an attacker who can read
`/var/backups/ja4proxy/` has root (or equivalent) access. An attacker with root access
can already read Redis directly. The backup does not expand the attacker's access.

The risk is higher for **off-host storage** (S3, NFS, cloud object store). Phase 21
addresses this with at-rest encryption before upload.

## Consequences

1. `backup.destination` in `config/proxy.yml` MUST be on a filesystem accessible only
   to the backup operator user. The Phase 19 documentation must clearly state this.

2. Off-host backup transfer (scp, rsync, S3) requires TLS/SSH. The runbook must
   document this.

3. Phase 21 (when implemented) must be able to encrypt existing plaintext archives
   without re-running the backup job (migration path: `ja4proxy-admin backup encrypt-existing`).

## Revisit

When Phase 21 (cloud storage integration) is started, return to this ADR and update
status to Superseded.
```

---

## 2. Backup Security Threat Model

**File:** `docs/security/BACKUP_THREAT_MODEL.md`

### Adversaries and Their Capabilities

| Adversary | Capability | Likely target | Risk level |
|-----------|------------|---------------|------------|
| External attacker (no shell access) | Cannot reach `/var/backups/ja4proxy/` | Not a threat to on-host backups | None |
| External attacker (web exploit → limited shell) | Can read files as www-data / proxy user | Backup dir if permissions wrong | **HIGH if perms wrong; NONE if 0700/root** |
| Insider (dev/ops access, not root) | Can read files they own | Backup if stored world-readable | **MEDIUM if perms wrong** |
| Insider (root access) | Can read all files and Redis | Backup redundant — has Redis access | Acceptable — root already has all data |
| Supply chain (malicious backup script) | Can write arbitrary backup content | Restore path: inject malicious keys | **HIGH — see §2b** |

### 2a. Threats to Backup Confidentiality

**On-host storage (default)**

Mitigation: restrict `/var/backups/ja4proxy/` to the backup operator user:

```bash
# Set at deployment time (add to deployment checklist)
install -d -o backup-operator -g backup-operator -m 0700 /var/backups/ja4proxy
```

If the proxy runs as `proxy` user and the backup operator is a separate `backup-operator`
account, no other non-root user can read the backup directory.

**Off-host transfer**

Any transfer of backup archives off-host must use an encrypted transport:
- `scp` or `rsync` over SSH — acceptable
- `aws s3 cp` — acceptable only with S3 server-side encryption enabled
- HTTP without TLS — never acceptable

This is an operator responsibility. The backup system does not enforce it.

### 2b. Threats to Backup Integrity (Tampering)

An attacker who can write to the backup directory can replace a valid archive with a
tampered one. On restore:
- Injected ban entries: IPs added to the ban list that the attacker controls (clears their ban)
- Injected whitelist entries: attacker's JA4 fingerprint added to whitelist
- Injected config: `dial:current` set to 0 (monitor mode), bypasses enabled

**Mitigations in Phase 19:**

1. Manifest checksum (SHA-256) covers the archive content. A tampered archive will
   fail the checksum check and be rejected by `Restorer`.

2. The manifest and archive are stored as separate files. If an attacker replaces both
   (archive + manifest), the checksum will match the tampered content.

**The manifest-alongside-archive weakness:**

Phase 19's checksum provides integrity only against accidental corruption, not against
a determined attacker who can write to the backup directory. If the attacker can write
the directory, they can replace both the archive and its manifest.

**Phase 21 mitigation:** HMAC-sign the manifest with a key stored in the KMS. The
proxy validates the HMAC on restore. An attacker without KMS access cannot forge a
valid HMAC.

**Phase 19 partial mitigation:** The backup directory's inode history and filesystem
audit log (auditd) can detect unauthorized writes. Add to the runbook.

### 2c. Denial-of-Service Against the Backup System

**Disk exhaustion attack**: If an attacker can trigger many backup jobs (e.g., via the
CLI), they can fill the disk and deny service to the backup system.

Mitigations:
- CLI requires authentication (REDIS_URL password; see Phase 19b §3)
- Backup job rate-limited: at most 1 job per 15 minutes (configured in `backup.schedule`)
- Retention policy caps disk usage: `retain_count × max_backup_size`

**Redis key injection before backup**: Attacker writes millions of fake `ban:*` keys to
Redis before backup runs. Backup takes much longer / runs out of disk.

Mitigations:
- `backup.max_keys_per_run` config: cap the number of keys exported per job (default 5M)
- `backup.max_size_bytes` config: cap the total archive size (default 10GB)
- If either cap is exceeded, backup fails with `RETENTION_EXCEEDED` error code and alert fires

---

## 3. Access Control Specification

The backup system has three operations with different sensitivity:

| Operation | Who can do it | Authentication | Audit logged |
|-----------|---------------|----------------|-------------|
| Read backup list | backup-operator, root | OS permissions (file read) | No |
| Trigger manual backup | backup-operator | `REDIS_URL` + `--confirm` | Yes |
| Restore | backup-operator | `REDIS_URL` + `--confirm` + `--force` for destructive | Yes |
| Delete backup artifact | backup-operator | OS permissions + `--confirm` | Yes |
| Validate backup | anyone with file read | None | No |

### OS User Requirements

The backup system must run as a dedicated OS user with minimal privileges:

```
backup-operator:
  uid: 9000 (or next available)
  groups: backup-operator
  shell: /bin/bash (needed for CLI; /sbin/nologin if cron-only)
  home: /var/backups/ja4proxy
  sudoers: NONE
```

The `proxy` user must not have write access to the backup directory. The backup
worker reads from Redis (via `REDIS_URL`) and writes to the backup directory. If
the proxy process is compromised, it cannot corrupt the backups.

### REDIS_URL Access Scoping (Preparation for Phase 21)

Phase 19 uses the same `REDIS_URL` for both the proxy and the backup worker. This
grants the backup worker write access to all Redis keys, which is more than it needs
(it only needs to read keys and write the `backup:*` control keys).

Phase 21 should scope access with Redis ACLs:

```
# /etc/redis/users.acl (Phase 21 scope)
user backup-operator on >backup-password ~backup:* ~ja4:* ~ban:* ~config:* +@read +SET +DEL +LPUSH +LTRIM
```

For Phase 19: document this as a known over-privilege and defer.

---

## 4. Audit Logging for Backup Operations

Every backup and restore operation must write an entry to `management:audit_log` in
addition to stdout logging. This ensures all backup activity is visible in the
management UI Audit Log page.

### Audit Log Entry Schema

**Backup completed:**
```json
{
  "event": "backup_completed",
  "actor_ip": "backup-operator@ops-host.example.com",
  "timestamp": "2026-03-10T12:00:00.000000",
  "detail": {
    "type": "full",
    "keys_exported": 847523,
    "filename": "ja4proxy-backup-2026-03-10T120000Z.tar.gz",
    "size_bytes": 45892341,
    "duration_seconds": 12.4,
    "triggered_by": "cron"
  }
}
```

**Restore completed:**
```json
{
  "event": "restore_completed",
  "actor_ip": "jsmith@ops-workstation-01.example.com",
  "timestamp": "2026-03-10T14:30:00.000000",
  "detail": {
    "backup_filename": "ja4proxy-backup-2026-03-10T120000Z.tar.gz",
    "destructive": false,
    "keys_restored": 847523,
    "validation_passed": true,
    "triggered_by": "manual"
  }
}
```

**Backup deleted (retention):**
```json
{
  "event": "backup_deleted",
  "actor_ip": "system@ops-host.example.com",
  "timestamp": "2026-03-10T00:05:00.000000",
  "detail": {
    "filename": "ja4proxy-backup-2026-02-24T120000Z.tar.gz",
    "reason": "retention_policy",
    "age_days": 15,
    "retain_count": 14
  }
}
```

The `actor_ip` field for CLI operations uses `{user}@{hostname}` format (not an IP
address — CLI is run locally, not over the network). Cron-triggered backups use
`system@{hostname}`.

---

## 5. Sensitive Data Handling

Some Redis keys must never appear in backup archives, regardless of pattern matching.

### Redacted Key Patterns

| Key pattern | Reason for exclusion | Notes |
|-------------|---------------------|-------|
| `mgmt:ratelimit:*` | Transient auth failure counters — no value in backup | TTL < 60s |
| `session:*` | Per-connection transient state | Not in backup patterns already |
| `abuseipdb:quota:*` | Resets daily — point-in-time value useless | Fetched fresh on startup |
| `management:audit_log` | Should NOT be in standard backup — it's large and grows unboundedly | Include only in `selective` backup with explicit flag |

### Handling `management:audit_log`

The audit log can grow to 1,000 entries × arbitrary JSON size. It should be:
- Excluded from standard `full` and `incremental` backups (too large, not critical)
- Available as a `selective` backup option: `ja4proxy-admin backup --include-audit-log`
- If included, size-capped at most recent 1,000 entries (already LTRIM'd in Redis)

Add config option:
```yaml
backup:
  include_audit_log: false   # Default: false. Set true to include management:audit_log
                             # in full backups. Adds up to 1MB per backup.
```

### No Plaintext Secrets in Backups

The backup worker must never export Redis keys that contain credentials or API keys:

```python
# src/backup/worker.py
_KEY_PATTERNS_NEVER_BACKUP = [
    "abuseipdb:api_key",        # Should not be in Redis at all, but guard anyway
    "config:redis_password",    # Should not be in Redis at all
    "*:auth_token",             # Any auth token pattern
]
```

Add a startup assertion: if any key matching `_KEY_PATTERNS_NEVER_BACKUP` is found in
Redis, log a WARN and do not include it in the backup. This is defensive — these keys
should never be in Redis, but the guard prevents an accidental export.

---

## 6. Key Management Preparation for Phase 21

Phase 21 will add encryption using a KMS. Phase 19 should lay the groundwork so
that Phase 21 can be added without redesigning the archive format.

### Archive Format Extensibility

The archive format must include a header that allows Phase 21 to add encryption
metadata without breaking existing readers:

```python
# Manifest schema (add to Phase 19 manifest format)
{
  "artifact": {
    ...,
    "encryption": {
      "enabled": false,           # Phase 19: always false
      "provider": null,           # Phase 21: "aws-kms" | "vault" | "local-aes"
      "key_id": null,             # Phase 21: KMS key ARN or Vault key path
      "algorithm": null           # Phase 21: "AES-256-GCM"
    }
  }
}
```

When `encryption.enabled = false`, the `Restorer` reads the archive as plain .tar.gz.
When `encryption.enabled = true` (Phase 21), the `Restorer` first decrypts using the
specified provider and key, then processes the plaintext archive.

### Key Rotation Preparation

Add to the manifest format (Phase 19):

```json
"key_rotation_hint": {
  "encrypt_before_offsite_transfer": true,
  "minimum_encryption_phase": 21,
  "contact": "security@yourorg.example.com"
}
```

This field is a documentation marker — not processed by any code in Phase 19. It
signals to operators and future implementers that off-host transfer requires encryption.

---

## 7. Security-Specific Tests (Completing Phase 19's Skeletal Tests)

Phase 19's adversarial and FP corpus tests were written as stubs. This section
provides the complete specifications.

### 7a. Adversarial Tests (`tests/adversarial/test_backup_attacks.py`)

Minimum 8 tests:

```python
class TestBackupTampering:
    def test_restore_rejects_mismatched_checksum(self, tmp_path):
        """Restorer refuses archive whose SHA-256 does not match manifest."""
        archive, manifest = _make_valid_backup(tmp_path)
        # Corrupt archive content
        archive.write_bytes(archive.read_bytes()[:-10] + b"\x00" * 10)
        result = Restorer(REDIS_URL, archive).restore()
        assert result["success"] is False
        assert "checksum" in result["error"].lower()

    def test_restore_rejects_manifest_with_wrong_filename(self, tmp_path):
        """Restorer refuses manifest that references a different archive filename."""
        archive, manifest = _make_valid_backup(tmp_path)
        data = json.loads(manifest.read_text())
        data["artifact"]["filename"] = "different-file.tar.gz"
        manifest.write_text(json.dumps(data))
        result = Restorer(REDIS_URL, archive).restore()
        assert result["success"] is False

    def test_restore_without_force_does_not_clear_redis(self, tmp_path, redis_client):
        """Non-destructive restore never clears existing Redis keys."""
        redis_client.set("existing_key", "existing_value")
        archive, manifest = _make_valid_backup(tmp_path)
        Restorer(REDIS_URL, archive).restore(delete_data_first=False)
        assert redis_client.get("existing_key") == "existing_value"

    def test_backup_excludes_never_backup_patterns(self, redis_client, tmp_path):
        """Keys matching _KEY_PATTERNS_NEVER_BACKUP are not included in archive."""
        redis_client.set("abuseipdb:api_key", "secret-key-value")
        worker = BackupWorker(REDIS_URL, tmp_path, ...)
        result = worker.run()
        assert result["success"] is True
        # Verify archive does not contain the key
        keys = _list_keys_in_archive(result["filepath"])
        assert "abuseipdb:api_key" not in keys

    def test_backup_caps_at_max_keys_per_run(self, redis_client, tmp_path):
        """BackupWorker stops at max_keys_per_run; does not export unbounded keys."""
        # Inject 1M ban entries
        pipe = redis_client.pipeline()
        for i in range(1_000_000):
            pipe.set(f"ban:10.{i//256//256}.{(i//256)%256}.{i%256}", "attack")
        pipe.execute()
        worker = BackupWorker(REDIS_URL, tmp_path, max_keys_per_run=100_000)
        result = worker.run()
        manifest = json.loads(Path(result["filepath"]).with_suffix(".json").read_text())
        assert manifest["artifact"]["keys_count"] <= 100_000

    def test_restore_rejects_keys_outside_permitted_patterns(self, tmp_path):
        """Restorer refuses archives containing keys that should never be backed up."""
        archive = _make_archive_with_keys(tmp_path, ["abuseipdb:api_key"])
        result = Restorer(REDIS_URL, archive).restore()
        assert result["success"] is False
        assert "forbidden_key" in result["error"].lower()

    def test_manifest_injection_via_symlink(self, tmp_path):
        """Restorer is not tricked by a manifest that is a symlink to /etc/passwd."""
        archive, _ = _make_valid_backup(tmp_path)
        manifest_path = archive.with_suffix(".json").with_suffix("")
        # Replace manifest with symlink
        manifest_path.unlink()
        manifest_path.symlink_to("/etc/passwd")
        result = Restorer(REDIS_URL, archive).restore()
        assert result["success"] is False   # Should fail: not a valid JSON manifest

    def test_backup_audit_log_written_on_tamper_attempt(self, tmp_path, redis_client):
        """Failed restore due to checksum mismatch writes WARN to audit log."""
        archive, manifest = _make_valid_backup(tmp_path)
        archive.write_bytes(b"tampered content")
        Restorer(REDIS_URL, archive).restore()
        audit_entries = [json.loads(e) for e in redis_client.lrange("management:audit_log", 0, 5)]
        events = [e["event"] for e in audit_entries]
        assert "restore_failed" in events
```

### 7b. FP Corpus Tests (`tests/fp_corpus/test_backup_fp.py`)

```python
class TestBackupDoesNotExcludeCriticalKeys:
    """Verify the exclusion patterns do not accidentally exclude critical security keys."""

    def test_ja4_blacklist_not_excluded(self, redis_client, tmp_path):
        """ja4:blacklist SET is included in every backup."""
        redis_client.sadd("ja4:blacklist", "t13d1516h2_8daaf6152771_02713d6af862")
        worker = BackupWorker(REDIS_URL, tmp_path)
        result = worker.run()
        keys = _list_keys_in_archive(result["filepath"])
        assert "ja4:blacklist" in keys

    def test_ban_ips_not_excluded(self, redis_client, tmp_path):
        """ban:{ip} keys are included in backup."""
        redis_client.set("ban:1.2.3.4", "manual:test ban")
        worker = BackupWorker(REDIS_URL, tmp_path)
        result = worker.run()
        keys = _list_keys_in_archive(result["filepath"])
        assert any(k.startswith("ban:") for k in keys)

    def test_config_thresholds_included(self, redis_client, tmp_path):
        """config:thresholds is included in backup."""
        redis_client.hset("config:thresholds", mapping={"flag": 20, "ban": 85})
        worker = BackupWorker(REDIS_URL, tmp_path)
        result = worker.run()
        keys = _list_keys_in_archive(result["filepath"])
        assert "config:thresholds" in keys

    def test_transient_rate_limiting_keys_excluded(self, redis_client, tmp_path):
        """rate:ip:{ip}:{window}s keys are NOT included in backup (transient state)."""
        redis_client.zadd("rate:ip:1.2.3.4:60s", {str(time.time()): time.time()})
        worker = BackupWorker(REDIS_URL, tmp_path)
        result = worker.run()
        keys = _list_keys_in_archive(result["filepath"])
        assert not any(k.startswith("rate:") for k in keys)
```

---

## 8. Deployment Security Checklist

**File:** Add to `docs/DEPLOYMENT_SECURITY_MODEL.md` under "Backup Security"

```markdown
## Backup Security (Phase 19)

Before deploying the backup system:

- [ ] `/var/backups/ja4proxy` created with mode 0700, owned by `backup-operator` user
- [ ] `backup-operator` user has no sudo privileges
- [ ] Proxy process does not have write access to backup directory
- [ ] `REDIS_URL` for backup operator stored in environment, not in scripts
- [ ] Off-host transfer (if any) uses SSH/SFTP or S3 with server-side encryption
- [ ] Retention policy set: `backup.retain_count` and `backup.retention_days`
- [ ] `backup.max_keys_per_run` set to prevent disk exhaustion attacks

### Known Limitations (Phase 19)

1. **Backups are not encrypted at rest.** Anyone with filesystem access to
   `/var/backups/ja4proxy` can read the backup content (ban lists, policy config,
   audit log). Mitigate by restricting filesystem permissions.

2. **Manifest checksum does not protect against a determined attacker who can write
   to the backup directory.** An attacker who can replace both the archive and its
   manifest can create a tampered backup that passes checksum validation.

3. **REDIS_URL grants full read/write access to Redis.** The backup worker does not
   operate with a reduced-privilege ACL. Phase 21 will scope this.

These limitations are documented in `docs/decisions/ADR-019.md`.
```

---

## 9. Acceptance Criteria (Supplement)

These extend the acceptance criteria in `PHASE_19.md`.

### Security Tests

- [ ] 8 adversarial tests in `test_backup_attacks.py` all pass
- [ ] 4 FP corpus tests in `../../tests/fp_corpus/test_backup_fp.py` all pass (critical keys included, transient excluded)
- [ ] `test_backup_excludes_never_backup_patterns` passes (confirms secrets not exported)
- [ ] `test_restore_without_force_does_not_clear_redis` passes (non-destructive guarantee)

### Access Control

- [ ] Backup directory created with mode 0700 in deployment scripts
- [ ] Deployment checklist in `docs/DEPLOYMENT_SECURITY_MODEL.md` includes backup items
- [ ] CLI audit log entries written to `management:audit_log` for backup, restore, delete

### ADR and Threat Model

- [ ] `docs/decisions/ADR-019.md` exists with encryption deferral rationale and risk table
- [ ] `docs/security/BACKUP_THREAT_MODEL.md` exists with attacker table and mitigation analysis
- [ ] Manifest schema includes `encryption` block (extensibility for Phase 21)

### Configuration

- [ ] `backup.max_keys_per_run` config key exists with default 5,000,000
- [ ] `backup.max_size_bytes` config key exists with default 10GB
- [ ] `backup.include_audit_log` config key exists with default false
- [ ] All three new config keys documented with inline comments in `config/proxy.yml`

### Documentation

- [ ] `docs/DEPLOYMENT_SECURITY_MODEL.md` backup section exists with known limitations
- [ ] `CHANGELOG.md` entry for Phase 19b
