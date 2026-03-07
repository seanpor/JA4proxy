# JA4proxy — SecOps Operations Guide

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

If `.env` doesn't exist, `start-poc.sh` creates it with random passwords and prints them once. To retrieve them later:

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
| View logs | `make logs` | `docker compose -f docker-compose.poc.yml logs -f proxy` |

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

Changes to `config/proxy.yml` require a proxy restart. Security state changes made via `ja4-admin.sh` (blacklist, country blocks, CIDR blocks, IP blocks) take effect immediately — no restart needed.

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

By default, Alertmanager is running but all external notification channels (email, Slack, PagerDuty) are placeholders. Edit `monitoring/alertmanager/alertmanager.yml` to configure real targets:

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

Loki (if running) has its own retention — see `docker-compose.monitoring.yml`.

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
docker compose -f docker-compose.poc.yml build
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
