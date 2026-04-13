<!--
title: SecOps Operations Guide
audience: SecOps analysts, infrastructure operators
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — SecOps Operations Guide

> **Audience:** SecOps analysts, infrastructure operators
> **Prerequisites:** JA4proxy deployed and running; Redis accessible
> **Related:** [Incident Response](INCIDENT_RESPONSE.md) · [Quick Reference](QUICK_REFERENCE.md)

## Quick Start (3 steps)

```bash
# 1. Configure your backend server
cp .env.example .env
nano .env           # Set BACKEND_HOST and BACKEND_PORT

# 2. Start everything
./start-all.sh      # or: make start

# 3. Verify
./status.sh         # or: make status
```

---

## Step 1 — Configure the Backend Destination

Edit `.env`:

```bash
# The server that JA4proxy protects
BACKEND_HOST=192.168.1.100   # IP address of your real server
BACKEND_PORT=443             # Port on that server (almost always 443)
```

**Common scenarios:**

| Setup | BACKEND_HOST | BACKEND_PORT |
|-------|-------------|-------------|
| On-premise server | `192.168.1.100` | `443` |
| Cloud VM on same network | `10.0.0.50` | `443` |
| DNS name | `myapp.internal` | `443` |
| POC (mock backend) | `backend` (default) | `443` |

Changes to `BACKEND_HOST`/`BACKEND_PORT` require a restart:

```bash
./stop-all.sh && ./start-all.sh
```

---

## Step 2 — Passwords and Secrets

### First startup (auto-generated)

If `.env` doesn't exist, `../scripts/start-poc.sh` creates it with random passwords and prints them once. To retrieve them later:

```bash
cat .env
```

### Changing passwords

```bash
# Generate new Redis password
NEW_PW=$(openssl rand -base64 32 | tr -d '/+=')

# Update .env
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=${NEW_PW}/" .env

# Restart to apply
./stop-all.sh && ./start-all.sh
```

### File permissions

```bash
chmod 600 .env    # Ensure .env is not world-readable
```

---

## Starting and Stopping

### Commands at a glance

| Action | Command | Also |
|--------|---------|------|
| Start everything | `./start-all.sh` | `make start` |
| Start POC only | `./start-poc.sh` | `make deploy-poc` |
| Start monitoring only | `./start-monitoring.sh` | `make start-monitoring` |
| Stop everything | `./stop-all.sh` | `make stop` |
| Stop + wipe data | `./stop-all.sh --clean` | `make stop-clean` |
| Full clean rebuild | — | `make rebuild` |
| View status | `./status.sh` | `make status` |
| View logs | `make logs` | `docker compose -f docker/docker-compose.poc.yml logs -f proxy` |

### What `stop-all.sh --clean` does

Removes all Docker volumes — Redis data, logs, etc. Use this to start fresh after testing. **Warning:** this also clears the ban/block lists.

---

## Incident Response

See [`docs/INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md) for the full attack runbook.

Quick commands (all take effect **immediately** — no restart):

```bash
./scripts/ja4-admin.sh status                      # Overall snapshot
./scripts/ja4-admin.sh top 10                      # Top fingerprints by volume
./scripts/ja4-admin.sh block-ja4 <fingerprint>     # Instant RST for C2 tool
./scripts/ja4-admin.sh block-ip <ip> [secs]        # Hard-block an IP
./scripts/ja4-admin.sh block-country RU            # Block a whole country
./scripts/ja4-admin.sh report                      # Full blocking report
make flush-redis                                   # Clear bans/blocks (keep lists)
```

---

## Monitoring

| Dashboard | URL | Credentials |
|-----------|-----|-------------|
| Grafana | http://localhost:3001 | admin / `GRAFANA_PASSWORD` from .env |
| Prometheus | http://localhost:9091 | — |
| HAProxy Stats | http://localhost:8404/stats | — |
| Proxy Metrics | http://localhost:9090/metrics | — |

### Key Grafana panels

- **JA4proxy Security Overview** — blocked vs allowed, top fingerprints
- **Traffic by Country** — geographic breakdown
- **Top Blocked JA4 Fingerprints** — name of the attacking tool

---

## Port Reference

| Service | Default Host Port | Configurable? |
|---------|------------------|---------------|
| HAProxy TLS (client-facing) | 443 | `HAPROXY_TLS_PORT` in .env |
| HAProxy HTTP | 8880 | `HAPROXY_HTTP_PORT` in .env |
| HAProxy Stats | 8404 | `HAPROXY_STATS_PORT` in .env |
| JA4 Proxy API | 8080 (localhost only) | — |
| Proxy Metrics | 9090 (localhost only) | `PROXY_METRICS_PORT` in .env |
| Backend (mock) | 8443 (localhost only) | — |
| Tarpit | 8888 (localhost only) | — |
| Prometheus | 9091 | `PROMETHEUS_PORT` in .env |
| Grafana | 3001 | `GRAFANA_PORT` in .env |
| Alertmanager | 9093 | — |

Security note: all internal ports bind to `127.0.0.1` — not exposed to other hosts. Only port 443 (HAProxy) is publicly reachable.

---

## Threat Intelligence — Keeping Fingerprints Fresh

Pull and review new malicious fingerprints from FoxIO GitHub / ja4db.com:

```bash
make fetch-db          # Pull latest fingerprints → queues for review
make list-pending      # See what was found before approving
./scripts/ja4-admin.sh approve <fingerprint>   # Approve one
make approve-all       # Approve all (asks for confirmation)
```

For API access to the full ja4db.com database, add to `.env`:

```
JA4DB_API_KEY=your_key_here
```

After approving, persist to `config/proxy.yml` so the block survives restarts:

```yaml
security:
  blacklist:
    - "t13d190900_9dc949149365_97f8aa674fd9"  # Sliver C2 — approved 2026-02-23
```

---

## Configuration File Reference

`config/proxy.yml` controls all runtime settings. Key sections:

```yaml
proxy:
  backend_host: "${BACKEND_HOST:-backend}"  # override in .env → BACKEND_HOST=192.168.1.100
  backend_port: "${BACKEND_PORT:-443}"      # override in .env → BACKEND_PORT=443

security:
  multi_strategy_policy: "majority" # any | all | majority
  block_unknown_ja4: false          # true = block unrecognised tools (strict mode)
  permanent_ban: false              # true = bans never expire (use carefully)

  thresholds:
    suspicious: 20   # connections/sec before logging
    block: 50        # connections/sec before blocking
    ban: 100         # connections/sec before banning

geoip:
  enabled: false     # Enable country-based blocking
  safe_countries:    # These countries can NEVER be auto-blocked
    - IE
    - GB
    - US
    - CA
```

Changes to `config/proxy.yml` require a proxy restart. Security state changes made via `../scripts/ja4-admin.sh` (blacklist, country blocks, CIDR blocks, IP blocks) take effect immediately — no restart needed.

---

## Backup and Recovery

### What to back up

```bash
# Active configuration
config/proxy.yml          # Blacklists, thresholds, GeoIP config
.env                      # Secrets (Redis/Grafana passwords, backend)

# Snapshots (created by scripts)
scripts/ja4-admin.sh report > backup-$(date +%Y%m%d).txt
```

### Redis persistence

Redis is configured with `--save ""` (no persistence) for the POC — all transient state (bans, rate windows) is intentionally ephemeral. The `ja4:blacklist` and `ja4:whitelist` sets are the only Redis keys worth preserving — they mirror `config/proxy.yml` on startup.

To export the live blacklist:

```bash
docker exec ja4proxy-redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning SMEMBERS ja4:blacklist
```

---

## Routine Maintenance

### GeoIP database — update monthly

JA4proxy uses the IP2Location LITE database (DB1 — country-level) to map IPs to countries. IP2Location publishes updated databases monthly. The database is loaded at proxy startup, so a restart is required after updating.

```bash
make check-geoip          # See how old the current database is
make update-geoip         # Download latest version (no account needed)
make stop && make start   # Restart to load the new database
```

GeoIP is **disabled by default**. To enable it, set `geoip: enabled: true` in `config/proxy.yml` and add countries to `country_blacklist`. The `safe_countries` list protects named countries from auto-blocking even when GeoIP is active.

Suggested cron (1st of each month, 3am):
```bash
0 3 1 * * /path/to/scripts/update-geoip.sh >> /var/log/ja4proxy.log 2>&1
5 3 1 * * cd /path/to/JA4proxy && make stop && make start
```

### JA4 fingerprint feed — update as needed

Pull new known-malicious fingerprints from FoxIO and optionally ja4db.com:

```bash
make fetch-db        # Download and queue for review
make list-pending    # Review before approving
make approve-all     # Approve (prompts for confirmation)
```

After approving, persist to `config/proxy.yml` so they survive restarts.

### Alertmanager — configure notification targets

By default, Alertmanager is running but all external notification channels (email, Slack, PagerDuty) are placeholders. Edit `deploy/monitoring/alertmanager/alertmanager.yml` to configure real targets:

```yaml
global:
  smtp_smarthost: 'your-smtp:587'
  smtp_auth_username: 'alerts@yourcompany.com'
  smtp_auth_password: 'your-password'

receivers:
  - name: 'security-team'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/REAL/WEBHOOK'
        channel: '#security-alerts'
```

Reload after editing:
```bash
docker compose -f docker-compose.monitoring.yml restart alertmanager
```

### Log rotation

The `./logs/` directory is mounted read-write into the proxy container. Add a logrotate config to prevent disk fill:

```bash
sudo tee /etc/logrotate.d/ja4proxy << 'EOF'
/path/to/JA4proxy/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

Loki (if running) has its own retention — see `../docker/docker-compose.monitoring.yml`.

### Credential rotation

To rotate the Redis password:
```bash
NEW_PW=$(openssl rand -base64 32 | tr -d '/+=')
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=${NEW_PW}/" .env
make stop && make start
```

Both the Redis server and proxy container must restart together so they use the same password.

---

## Upgrading

```bash
git pull
./stop-all.sh
docker compose -f docker/docker-compose.poc.yml build
./start-all.sh
./poc-status-check.sh    # Verify everything is healthy
```

Check [CHANGELOG.md](../CHANGELOG.md) before upgrading for any config changes needed.

---

## Troubleshooting

### Services won't start

```bash
# Check Docker
docker info

# Restart Docker daemon if needed
sudo systemctl restart docker

# Try again
./start-all.sh
```

### "Redis auth failed" errors in proxy logs

```bash
cat .env | grep REDIS_PASSWORD     # What password the .env has
make logs | grep -i redis          # What error the proxy sees
```

Redis and proxy must both use the same `REDIS_PASSWORD`. If they diverge (e.g. after manual edit), restart both:

```bash
./stop-all.sh && ./start-all.sh
```

### Good traffic being blocked

```bash
./scripts/ja4-admin.sh blocked     # See what's currently blocked
./scripts/ja4-admin.sh unblock-ip <ip>
make flush-redis                   # Nuclear option — clear all transient blocks
```

See [INCIDENT_RESPONSE.md — Pattern 5: False positive](INCIDENT_RESPONSE.md).

### Password forgotten

```bash
cat .env                           # Passwords are stored here
./status.sh                        # Shows Grafana password in access summary
```

### Docker build fails — "Temporary failure in name resolution"

This occurs on hosts where Docker is configured with `"iptables": false` (common when UFW is
managing the firewall) and the system DNS is `127.0.0.53` (systemd-resolved), which containers
cannot reach.

**Fix (run once, persists across reboots):**

```bash
sudo bash scripts/fix-docker-dns.sh
```

This script:
- Adds `"dns": ["8.8.8.8", "1.1.1.1"]` to `/etc/docker/daemon.json`
- Adds a NAT MASQUERADE rule to `/etc/ufw/before.rules` (keeps UFW in control)
- Sets `DEFAULT_FORWARD_POLICY=ACCEPT` in `/etc/default/ufw`
- Enables `net.ipv4.ip_forward`
- Reloads UFW and restarts Docker
- Verifies DNS and pip work inside containers

**Diagnostics:**

```bash
sudo bash scripts/docker-net-diag.sh    # Shows iptables rules, container DNS, connectivity
```

---

## Tarpit Resource Sizing (Phase 14c)

### Capacity planning

The tarpit uses two in-process limits (no Redis):

| Config key | Default | Notes |
|---|---|---|
| `tarpit.max_concurrent_connections` | 500 | Global cap across all IPs |
| `tarpit.max_per_ip` | 3 | Per source-IP cap |
| `tarpit.overflow_action` | `block` | What happens when cap is reached: `block` \| `rst` \| `allow` |

**Rule of thumb:** set `max_concurrent_connections` ≤ 25% of the host's open-file-descriptor
limit (`ulimit -n`).  Each tarpitted connection holds one socket for the duration of the
tarpit delay (default 60 s).

### Capacity formula

```
max_concurrent ≤ (ulimit_n - 100) * 0.25
# Example: ulimit -n 65536 → max_concurrent ≤ ~16 000
# Conservative default of 500 leaves headroom on modest hosts (ulimit 2048)
```

### Symptoms of tarpit exhaustion

- `ja4proxy_tarpit_overflow_total` counter rising rapidly — attacker is flooding tarpit slots
- `ja4proxy_tarpit_concurrent` gauge pegged at `max_concurrent_connections`
- Legitimate scoring connections unaffected (tarpit overflow goes to `overflow_action`)

### Runbook: tarpit exhaustion attack

1. Check current gauge: `curl -s http://localhost:9090/metrics | grep tarpit`
2. If `ja4proxy_tarpit_concurrent / max_concurrent_connections > 0.9`:
   - Identify flooding IPs in logs: `grep "tarpit" /app/logs/*.log | grep "event=redirect" | awk '{print $3}' | sort | uniq -c | sort -rn | head -20`
   - Consider lowering `tarpit.max_per_ip` to 1 (hot-reload with SIGHUP)
   - If single ASN: add to `config/proxy.yml` `geoip.asn_blacklist`
3. If `overflow_action=block` is dropping real users, switch to `overflow_action=allow` temporarily (fail open to backend)
4. Set `tarpit.max_concurrent_connections` lower to shed load faster; reload with SIGHUP

### Graceful shutdown interaction

At shutdown (SIGTERM), the proxy stops accepting new connections immediately.
In-flight tarpit connections count toward `active_connections` and are included
in the drain window (`drain_timeout_seconds`).  If the tarpit delay is longer than
`drain_timeout_seconds`, tarpitted connections will be force-closed; this is expected
and logged in `shutdown_complete` as `forced_close`.

---

## Backup & Restore Operations (Phase 19)

### Configuration

Backup settings are in `config/proxy.yml` under the `backup:` block:

```yaml
backup:
  enabled: true
  destination: "/app/backups"
  retention_days: 30
  retain_count: 10
  schedule: "0 2 * * *"  # Daily at 2 AM
  max_keys_per_run: 1000
  max_size_bytes: 104857600  # 100 MB
  include_audit_log: true
```

**Key settings:**
- `destination`: Directory where backups are stored (must be writable by proxy user)
- `retention_days`: Delete backups older than this many days
- `retain_count`: Keep at most this many backups (count-based retention)
- `max_keys_per_run`: Maximum keys to back up in a single operation
- `include_audit_log`: Include management audit log in backups

### Manual Backup

```bash
# Create a backup
python3 -m src.cli.backup_cli backup --destination /custom/path

# List existing backups
python3 -m src.cli.backup_cli list

# Validate a backup
python3 -m src.cli.backup_cli validate /app/backups/backup_20240321T143000Z.bin
```

### Manual Restore

```bash
# Non-destructive restore (safe default - preserves existing keys)
python3 -m src.cli.backup_cli restore /app/backups/backup_20240321T143000Z.bin

# Destructive restore (wipes all existing Redis data first)
python3 -m src.cli.backup_cli restore /app/backups/backup_20240321T143000Z.bin --force
```

**Safety notes:**
- Non-destructive restore preserves existing keys not in the backup
- Destructive restore requires explicit `--force` flag
- All restore operations are logged in `management:audit_log`

### Backup File Structure

Each backup consists of two files:
- `backup_{timestamp}.bin`: Binary backup data (Redis dump format)
- `backup_{timestamp}.bin.manifest.json`: JSON manifest with metadata

**Manifest fields:**
- `filename`: Backup filename
- `created_at`: ISO timestamp of backup creation
- `backup_type`: Always "full" for Phase 19
- `keys_count`: Number of keys in backup
- `checksum_sha256`: SHA256 checksum of backup data
- `size_bytes`: Size of backup data in bytes
- `included_patterns`: Key patterns included in backup
- `excluded_patterns`: Key patterns excluded from backup

### Monitoring and Alerts

**Key metrics to monitor:**
- `ja4proxy_backup_operations_total{status="success"}`: Successful backups
- `ja4proxy_backup_last_success_timestamp`: Time of last successful backup
- `ja4proxy_backup_operations_total{status="failure"}`: Failed backups
- `ja4proxy_restore_operations_total{status="success"}`: Successful restores

**Alert conditions:**
- No successful backup in 24 hours
- Backup failure rate > 10% over 1 hour
- Restore operation taking > 30 seconds

### Troubleshooting

**Backup failures:**
1. Check filesystem permissions: `ls -la /app/backups`
2. Verify Redis connectivity: `redis-cli ping`
3. Check logs: `grep "backup_failed" /app/logs/*.log`
4. Validate directory permissions: `stat /app/backups`

**Restore failures:**
1. Verify checksum: `python3 -m src.cli.backup_cli validate /path/to/backup.bin`
2. Check Redis connectivity and memory: `redis-cli info memory`
3. Review manifest for key count: `cat /path/to/backup.bin.manifest.json`

**Common issues:**
- **World-writable backup directory**: Backup worker refuses to write to directories with `o+w` permissions
- **Group-writable backup directory**: Backup worker refuses to write to directories with `g+w` permissions
- **Checksum mismatch**: Indicates corrupted backup file or manifest tampering
- **Redis connection errors**: Verify Redis is running and network connectivity

### Security Considerations

**Never-backup keys:**
The following key patterns are never included in backups:
- `abuseipdb:*` (API keys and sensitive data)
- `config:redis_password` (passwords)
- `*:auth_token` (authentication tokens)

**Backup directory security:**
- Must be owned by the proxy user
- Must not be world-writable or group-writable
- Should have permissions `700` (drwx------)

**Audit logging:**
All backup and restore operations are logged in:
- `management:audit_log` Redis list
- Structured JSON logs with `subsystem: "backup"` or `subsystem: "restore"`

---

## Cloud Backup Operations (Phase 57)

Phase 57 adds optional cloud upload of completed local backup artifacts to AWS S3
or Google Cloud Storage. The local artifact is always written first; cloud upload is
a non-blocking async step. Cloud upload failure is non-fatal and never prevents the
local artifact from being available for restore.

Full operational procedures are in the dedicated runbook:
**[docs/runbooks/cloud_backup_operations.md](runbooks/cloud_backup_operations.md)**

### Quick Reference

```bash
# Upload a local artifact to S3
python3 scripts/ja4proxy_admin.py backup cloud upload /app/backups/backup_latest.bin --provider s3

# List artifacts in S3
python3 scripts/ja4proxy_admin.py backup cloud list --provider s3

# Download an artifact from GCS for DR restore
python3 scripts/ja4proxy_admin.py backup cloud download backup_20260406T020000Z.bin \
  --provider gcs --dest /tmp/recovery/

# Restore with fallback (Phase 57f)
python3 scripts/ja4proxy_admin.py backup restore primary.bin primary.bin.manifest.json \
  --fallback fallback.bin --confirm

# DSAR: redact a subject's IP before cloud upload
python3 scripts/ja4proxy_admin.py backup dsar-redact /app/backups/backup_latest.bin \
  --ip 192.0.2.1 --output /app/backups/backup_latest_redacted.bin
```

### Key Metrics

| Metric | Alert condition |
|--------|----------------|
| `ja4proxy_backup_cloud_upload_total{result="failure"}` | Any non-zero value warrants investigation |
| `ja4proxy_backup_cloud_upload_total{result="success"}` | Should be non-zero after each scheduled backup window |
| `ja4proxy_backup_last_success_timestamp` | No successful local backup in 25 hours |

### Manifest Fields Added in Phase 57

| Field | Description |
|-------|-------------|
| `format_version` | `1` for all Phase 57+ artifacts; absent in legacy artifacts |
| `format_flags` | Bitmask: `0x01`=full, `0x02`=incremental (reserved), `0x04`=encrypted |
| `dsar_scanned` | `true` if DSAR redaction has been run against this artifact |
| `sequence_number` | `0` for full backups; reserved for incremental chain (Phase 58) |
