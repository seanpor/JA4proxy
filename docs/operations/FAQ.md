<!--
title: Faq
audience: operator
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy — Frequently Asked Questions

Practical answers to common operational questions. For active incidents, see [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md).

---

## Setup and Configuration

**Q: Where do I configure the backend server IP and port?**

In `.env`:
```
BACKEND_HOST=192.168.1.100
BACKEND_PORT=443
```
Then restart: `make stop && make start`. The proxy cannot change its backend target without a restart.

---

**Q: I lost the Redis or Grafana password. How do I find it?**

```bash
cat .env
```
Or `./status.sh` displays the Grafana password in the access summary.

---

**Q: How do I change credentials?**

```bash
NEW_PW=$(openssl rand -base64 32 | tr -d '/+=')
sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=${NEW_PW}/" .env
make stop && make start
```
Both Redis and the proxy container must restart together so they share the same password.

---

**Q: Can I change rate limits or blacklist entries without restarting?**

Most security changes take effect immediately (no restart):
- Blacklist/whitelist fingerprints: `./scripts/ja4-admin.sh block-ja4 <fp>`
- Country blocks: `./scripts/ja4-admin.sh block-country RU`
- CIDR blocks: `./scripts/ja4-admin.sh block-cidr 185.220.0.0/16`
- IP blocks: `./scripts/ja4-admin.sh block-ip 203.0.113.42`
- Flush bans/blocks: `make flush-redis`

Changes to `config/proxy.yml` thresholds, rate limits, or backend address require a restart.

---

## GeoIP Country Blocking

**Q: Why isn't country blocking working?**

Three possible reasons:
1. **GeoIP is disabled by default.** Enable it in `config/proxy.yml`: `geoip: enabled: true`
2. **No countries are in the blacklist.** Either add to `config/proxy.yml` `country_blacklist` or use: `./scripts/ja4-admin.sh block-country RU`
3. **GeoIP database is missing.** Run `make check-geoip` to verify. If missing, run `make update-geoip`.

---

**Q: How do I update the GeoIP database?**

```bash
make update-geoip        # Download latest IP2Location LITE DB
make stop && make start  # Restart required — database is loaded at startup
```
IP2Location publishes monthly updates. If the automated download fails, the script prints a manual download URL. Check database age anytime: `make check-geoip`.

---

**Q: How often should I update the GeoIP database?**

Monthly. Run `make update-geoip` on a schedule:

```bash
# Cron: update at 3am on the 1st of each month, restart at 3:05am
0 3 1 * * /path/to/scripts/update-geoip.sh >> /var/log/ja4proxy.log 2>&1
5 3 1 * * cd /path/to/JA4proxy && make stop && make start
```

---

**Q: I'm blocking traffic from a country but legitimate users from there are being affected.**

Add the country to the safe list so it can never be auto-blocked:
```bash
./scripts/ja4-admin.sh safe-country IE
```
Or add directly to `config/proxy.yml` under `geoip.safe_countries`. Countries in this list cannot be added to the block list, either manually or by the auto-block monitor.

---

## Security and Blocking

**Q: Traffic isn't being blocked even though I can see malicious fingerprints.**

Check the configuration:
```bash
./scripts/ja4-admin.sh list-ja4      # Is the fingerprint in the blacklist?
./scripts/ja4-admin.sh status        # Are blocks/bans actually firing?
make logs | grep BLOCKED             # Any BLOCKED log entries?
```
If the fingerprint is not blacklisted and rate limits are not triggering, the rate thresholds may need tuning. Defaults are conservative (block at 50 conn/s, ban at 100 conn/s).

---

**Q: Good traffic is being blocked (false positives).**

```bash
./scripts/ja4-admin.sh blocked       # See what's currently blocked
./scripts/ja4-admin.sh unblock-ip <ip>
make flush-redis                     # Clear all transient bans (keeps blacklist)
```
If browser traffic is being rate-limited, check that browser fingerprints are in the whitelist: `./scripts/ja4-admin.sh list-ja4`. Chrome, Firefox, and Safari are whitelisted by default.

---

**Q: Can I block an entire botnet with one command?**

Yes — that's the main advantage of JA4 fingerprinting. If all botnet nodes share the same TLS fingerprint:
```bash
./scripts/ja4-admin.sh block-ja4 <fingerprint>
```
This blocks every IP using that fingerprint simultaneously with an instant TCP RST, regardless of how many nodes are in the botnet.

---

**Q: How do I keep the JA4 fingerprint blacklist up to date?**

```bash
make fetch-db        # Pull latest known-malicious fingerprints from FoxIO / ja4db.com
make list-pending    # Review before approving
make approve-all     # Approve (prompts for confirmation)
```
Run `make fetch-db` periodically or set up a cron job. Fingerprints require admin approval before being added to the blacklist.

---

**Q: What does the tarpit do?**

When a connection is rate-limited (but not yet banned), it is redirected to the tarpit server, which sends data at 1 byte per second. This keeps the attacker's connection occupied without doing anything useful, slowing down scanning tools. Banned connections get an instant TCP RST instead.

---

## Monitoring and Alerts

**Q: Grafana or Prometheus isn't showing any data.**

```bash
./status.sh              # Check all services are running
make logs                # Check proxy logs for errors
```
If services are running but Grafana is empty, ensure the proxy has received some traffic first: `./generate-tls-traffic.sh 30 15 5`.

---

**Q: How do I set up email or Slack alerts?**

Edit `deploy/monitoring/alertmanager/alertmanager.yml`. The file contains placeholder sections for SMTP, Slack, PagerDuty, and SIEM — replace the placeholder values with your real credentials:

```yaml
global:
  smtp_smarthost: 'your-smtp-server:587'
  smtp_auth_username: 'alerts@yourcompany.com'
  smtp_auth_password: 'your-password'

receivers:
  - name: 'security-team'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/REAL/WEBHOOK'
        channel: '#security-alerts'
```
Restart monitoring after changes: `docker compose -f docker-compose.monitoring.yml restart alertmanager`.

---

**Q: Alerts are firing but I'm not receiving notifications.**

Alertmanager is configured but all notification targets are placeholders until you edit `deploy/monitoring/alertmanager/alertmanager.yml`. Until then, alerts fire internally but go nowhere. See previous question.

---

## Scaling and Performance

**Q: Can I run multiple proxy instances?**

Yes. All instances share Redis state (bans, rate windows, blacklists), so scaling is horizontal:
```bash
./scale-proxies.sh 4    # Run 4 proxy instances (~840 conn/s combined)
```
HAProxy load-balances across instances automatically. Measured throughput is ~210 conn/s per instance.

---

**Q: How much traffic can the proxy handle?**

Single instance: ~210 connections/sec sustained, ~99% malicious fingerprint block rate with near-zero false positives on browser traffic. See [Performance Benchmark](../reports/PERFORMANCE_BENCHMARK.md) for measured results.

---

## Maintenance

**Q: How do I back up the blacklist/whitelist?**

The blacklist and whitelist are the only Redis data worth preserving (everything else is transient). Export them:
```bash
docker exec ja4proxy-redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning SMEMBERS ja4:blacklist
docker exec ja4proxy-redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning SMEMBERS ja4:whitelist
```
The canonical source is `config/proxy.yml` — the blacklist there loads into Redis on each startup. Keep the config file in version control.

---

**Q: How do I upgrade JA4proxy?**

```bash
git pull
make stop
docker compose -f deploy/docker/docker-compose.poc.yml build
make start
./poc-status-check.sh    # Verify
```
Check the [Changelog](../../CHANGELOG.md) for any config changes needed before upgrading.

---

**Q: Redis is full / running out of memory.**

Redis is configured with a 256 MB limit and `volatile-lru` eviction (drops expiring keys first). If it's filling up, either the ban duration is too long or traffic volume is very high. Check:
```bash
docker exec ja4proxy-redis redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning INFO memory
make flush-redis    # Clear all transient state (keeps blacklist/whitelist)
```

---

**Q: Logs are filling the disk.**

The `./logs/` directory is mounted into the proxy container. Add a logrotate config:
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
Loki (if running) has its own retention controlled by `../docker/docker-compose.monitoring.yml`.

---

**Q: How do I do a completely clean restart (wipe all state)?**

```bash
make stop-clean      # Stops everything and removes all Docker volumes
make start           # Fresh start — regenerates .env if missing
```
Note: `stop-clean` also removes Redis data, so the blacklist will reload from `config/proxy.yml` on next start.
