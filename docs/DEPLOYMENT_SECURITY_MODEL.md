<!--
title: Deployment_Security_Model
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy Deployment Security Model

This document describes the security model for production JA4proxy deployments:
required OS users, filesystem permissions, network exposure, secret management,
and known limitations that operators must accept and mitigate.

---

## Table of Contents

1. [OS User Model](#1-os-user-model)
2. [Network Exposure](#2-network-exposure)
3. [Secret Management](#3-secret-management)
4. [Redis Security](#4-redis-security)
5. [Backup Security (Phase 19)](#5-backup-security-phase-19)
6. [Known Limitations](#6-known-limitations)
7. [Pre-Deployment Security Checklist](#7-pre-deployment-security-checklist)

---

## 1. OS User Model

JA4proxy components run as dedicated non-root OS users. Separating users ensures
that a compromise of one component cannot directly affect another.

| Component | OS User | Privileges | Notes |
|-----------|---------|-----------|-------|
| Proxy (Python/Go) | `ja4proxy` | Read config, write logs, connect to Redis | No filesystem writes except log rotation |
| Backup worker | `backup-operator` | Read Redis, write backup directory | Must not be `ja4proxy` user |
| Analytics node | `ja4analytics` | Read Redis Streams, write findings keys | No access to backup directory |
| Management UI | `ja4mgmt` | Read Redis, write policy keys | No access to backup directory |

### Required OS Setup

```bash
# Create dedicated users (no home dir, no shell login)
useradd -r -s /sbin/nologin -d /var/lib/ja4proxy ja4proxy
useradd -r -s /sbin/nologin -d /var/backups/ja4proxy backup-operator
useradd -r -s /sbin/nologin ja4analytics
useradd -r -s /sbin/nologin ja4mgmt
```

---

## 2. Network Exposure

### Inbound (what JA4proxy listens on)

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 8080 | TCP | HAProxy (internal only) | Proxy traffic from load balancer |
| 9090 | HTTP | Monitoring network only | Prometheus `/metrics` endpoint |
| 8090 | HTTP | Internal network only | Management UI (Phase 13) |

**Never expose port 8080 directly to the Internet.** It must sit behind HAProxy which
provides the PROXY protocol header for real client IP extraction.

### Outbound (what JA4proxy connects to)

| Destination | Protocol | Purpose |
|-------------|----------|---------|
| Redis | TCP 6379 | All state operations |
| AbuseIPDB API | HTTPS 443 | IP reputation lookups |
| RDAP IANA bootstrap | HTTPS 443 | WHOIS/netblock lookups |
| MaxMind GeoLite2 | HTTPS 443 | GeoIP/ASN database updates |
| DNS resolvers | UDP/TCP 53 | FCrDNS enrichment |

---

## 3. Secret Management

### Required Secrets

| Secret | Where stored | Never stored in |
|--------|-------------|-----------------|
| Redis password | Environment variable `REDIS_PASSWORD` or Docker secret | Config file, logs, code |
| AbuseIPDB API key | Environment variable `ABUSEIPDB_API_KEY` or Docker secret | Redis, logs, backups |
| mTLS CA certificate | File `config/trusted_cas.pem` | Redis, logs |
| Grafana admin password | Docker secret | Config file, logs |

### Docker Compose Secrets (Production)

Use Docker Compose secrets for credential injection:

```yaml
# docker/docker-compose.prod.yml
secrets:
  redis_password:
    file: ./deploy/secrets/redis_password.txt
  abuseipdb_api_key:
    file: ./deploy/secrets/abuseipdb_api_key.txt

services:
  proxy:
    secrets:
      - redis_password
      - abuseipdb_api_key
    environment:
      REDIS_PASSWORD_FILE: /run/secrets/redis_password
      ABUSEIPDB_API_KEY_FILE: /run/secrets/abuseipdb_api_key
```

The `deploy/secrets/*.txt` files must be mode 0600 and gitignored.

---

## 4. Redis Security

### Authentication

Redis must require a password in production:

```bash
# /etc/redis/redis.conf
requirepass <strong-password>
```

JA4proxy will refuse to start in production (ENVIRONMENT=production) if Redis
has no password set. See `src/security/pipeline.py` `_init_redis()`.

### Network Binding

Redis must bind only to the internal network interface:

```bash
# /etc/redis/redis.conf
bind 127.0.0.1 <internal-ip>   # Never 0.0.0.0
```

### ACL Scoping (Phase 21)

In Phase 19, the backup worker uses the same REDIS_URL as the proxy and has
full read/write access. Phase 21 will scope this with Redis ACLs:

```
user backup-operator on >backup-password ~backup:* ~ja4:* ~ban:* ~config:* +@read +SET +DEL +LPUSH +LTRIM
```

---

## 5. Backup Security (Phase 19)

### Filesystem Permissions

The backup directory must be owned by `backup-operator` and not accessible to
other users:

```bash
install -d -o backup-operator -g backup-operator -m 0700 /var/backups/ja4proxy
```

If permissions are too open (world-writable or group-writable), the backup worker
will refuse to write and log a `filesystem_validation_failed` event.

### What Backups Contain

Backup artifacts contain operational security data:
- IP ban lists (`ban:*`)
- JA4 blacklists and whitelists (`ja4:blacklist`, `ja4:whitelist`)
- CIDR blocks (`config:*`)
- Security policy configuration (`config:security_policy`)
- Tor exit node lists (`tor:exit:ips`)
- RDAP enrichment data (`rdap:*`)

An attacker who obtains a backup learns which IPs are blocked, which fingerprints
are blacklisted, and the full security policy configuration.

### Sensitive Keys Never Backed Up

The following key patterns are excluded regardless of backup type:

```python
_KEY_PATTERNS_NEVER_BACKUP = [
    "abuseipdb:*",          # Any AbuseIPDB key (API quota state, keys)
    "config:redis_password", # Should never be in Redis, but guarded
    "*:auth_token",         # Any auth token pattern
]
```

### Encryption Status

**Backup artifacts are encrypted at rest using AES-256-GCM (Phase 40).** 
Authenticated encryption ensures confidentiality and prevents tamper-then-restore attacks.

Secret Management: The `BACKUP_ENCRYPTION_KEY` must be provided to the backup worker and 
restorer via environment variables or Docker secrets.

**Off-host transfer** (rsync, scp, S3) must still use encrypted transport (SSH/TLS) for 
defense-in-depth.

### Backup Integrity

Integrity is ensured via:
1. **SHA-256 Checksum**: Detects accidental corruption.
2. **AES-GCM Authentication Tag**: Detects determination-level tampering of the 
   ciphertext.
3. **Redis Distributed Locking**: Prevents concurrent backup/restore operations 
   from corrupting live Redis state.

Use `auditd` to detect unauthorized writes to the backup directory:

```bash
# /etc/audit/rules.d/ja4proxy-backup.rules
-w /var/backups/ja4proxy -p wa -k ja4proxy_backup_write
```

---

## 6. Known Limitations

| Limitation | Phase | Mitigation |
|------------|-------|-----------|
| Redis lock stale after crash | 40 | If worker crashes during backup, lock must be manually cleared: `redis-cli DEL backup:operation_lock` |
| No automated S3/GCS replication | 43 | Phase 57 will add native cloud storage adapters. Current mitigation: `rsync/rclone` cron job. |
| Zero-downtime Rollouts require HAProxy | 43 | Blue/Green deployment is orchestrated at the LB layer. |

---

## 7. Pre-Deployment Security Checklist

### Before Starting JA4proxy in Production

- [ ] Redis bound to internal interface only (not 0.0.0.0)
- [ ] Redis `requirepass` set to a strong password
- [ ] `REDIS_PASSWORD` environment variable set (not in config file)
- [ ] `ABUSEIPDB_API_KEY` environment variable set (not in config file)
- [ ] Port 8080 NOT exposed to internet (behind HAProxy only)
- [ ] Prometheus port 9090 firewalled to monitoring network only
- [ ] `ENVIRONMENT=production` set (enables Redis password enforcement and JSON logs)

### Before Enabling Backup (Phase 19/40)

- [ ] `/var/backups/ja4proxy` created with `mode 0700`, owned by `backup-operator`
- [ ] `backup-operator` user has no `sudo` privileges
- [ ] `BACKUP_ENCRYPTION_KEY` set in environment (AES-256-GCM enforced)
- [ ] Proxy process (`ja4proxy` user) does NOT have write access to backup directory
- [ ] `REDIS_URL` for backup worker stored in environment, not in scripts or config files
- [ ] Off-host transfer (if any) uses SSH/SFTP or S3 with server-side encryption enabled
- [ ] `backup.retain_count` and `backup.retention_days` set to limit disk usage
- [ ] `backup.max_keys_per_run` set to prevent disk-exhaustion attacks (default: 5M)
- [ ] `backup.max_size_bytes` set to cap artifact size (default: 10 GB)

### After Enabling Backup

- [ ] Verify `ja4proxy_backup_last_success_timestamp` metric is updating
- [ ] Verify Grafana `BackupStale` alert fires after simulated 25h gap
- [ ] Confirm backup artifacts are not world-readable: `stat /var/backups/ja4proxy/`
- [ ] Test non-destructive restore in staging before production deployment
- [ ] Document RPO/RTO for your deployment:
  - **RPO target:** ≤ 1h (can lose up to 1h of bans/blocks)
  - **RTO target:** < 30 min (time to restore from latest backup)

---

*Last updated: 2026-03-31, Phase 43 complete.*
*See `docs/runbooks/zero_downtime_rollouts.md` for blue/green deployment procedures.*
*See `docs/security/BACKUP_THREAT_MODEL.md` for full threat analysis.*
