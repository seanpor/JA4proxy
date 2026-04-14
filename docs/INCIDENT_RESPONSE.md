<!--
title: Incident Response Runbook
audience: SecOps analysts, incident responders
last_reviewed: 2026-03-27
phase: 21
-->

# JA4proxy Incident Response Runbook

> **Audience:** SecOps analysts, incident responders
> **Prerequisites:** JA4proxy deployed; Redis and Prometheus accessible
> **Related:** [SecOps Operations](SECOPS_OPERATIONS.md) · [Quick Reference](QUICK_REFERENCE.md)

Quick reference for responding to active attacks. All commands take effect **immediately** — no proxy restart needed.

## Incident Severity Matrix

| Severity | Definition | Example | Response Time |
|----------|------------|---------|---------------|
| **P1 — Critical** | Proxy down; all traffic blocked or all traffic passing unscored | Redis connection lost; tarpit overflow blocking all connections | Immediate (<15 min) |
| **P2 — High** | Major function impaired; false positive rate elevated | External enrichment API down; Spamhaus feed stale >4h; Dial misconfiguration | Urgent (<1 hour) |
| **P3 — Medium** | Single signal module failing; metrics missing | AbuseIPDB quota exhausted; DNS enrichment queue backed up; Individual signal module crash | Standard (<4 hours) |
| **P4 — Low** | Cosmetic or informational | Alert rule false-positive; Dashboard panel broken; Documentation error | Next business day |

**Escalation Path:**
- P1: Immediate page to on-call engineer
- P2: Slack alert + 15-minute acknowledgment requirement
- P3: Ticket creation + next business day resolution
- P4: Backlog for next sprint

---

## You're Under Attack RIGHT NOW

### Step 1 — Identify what's hitting you

```bash
./scripts/ja4-admin.sh status     # How many bans/blocks active, overall blocked %
./scripts/ja4-admin.sh top 10     # Top fingerprints by traffic volume
```

Red rows in `top` output are fingerprints that are currently being **blocked**. Note the fingerprint hash in the rightmost column.

You can also check logs directly:

```bash
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep BLOCKED | tail -20
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep BLACKLISTED | tail -20
```

### Step 2 — Block the attacking fingerprint

```bash
# Add to blacklist → instant TCP RST for all future connections (permanent, no TTL)
./scripts/ja4-admin.sh block-ja4 t13d190900_9dc949149365_97f8aa674fd9

# Check Grafana for the fingerprint_name label to get a human-readable name before blocking
# http://localhost:3001 → JA4proxy Security Overview → Top Blocked JA4 Fingerprints
```

### Step 3 — Verify it's working

```bash
./scripts/ja4-admin.sh status
./scripts/ja4-admin.sh list-ja4

# In logs, blocked connections now show as BLACKLISTED (instant RST) instead of BLOCKED (rate-limit)
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep BLACKLISTED | tail -5
```

### Step 4 — Block by IP if needed

If the attack comes from a known IP range:

```bash
./scripts/ja4-admin.sh block-ip 203.0.113.42          # 1-hour hard block (default)
./scripts/ja4-admin.sh block-ip 203.0.113.0 86400     # 24-hour block for subnet gateway
```

### Step 5 — Persist the fix in config

Redis changes survive until a container restart. After the incident, add the fingerprint permanently to `config/proxy.yml`:

```yaml
security:
  blacklist:
    - "t13d190900_9dc949149365_97f8aa674fd9"  # Sliver C2 — seen in incident 2026-02-22
    # ... your new fingerprint here
```

Then commit and push so the fix survives container rebuilds.

---

## Country and CIDR Blocking

### Block a country

```bash
./scripts/ja4-admin.sh block-country RU    # instant effect, no restart
./scripts/ja4-admin.sh list-countries      # verify + see Prometheus stats per country
./scripts/ja4-admin.sh unblock-country RU  # reverse it
```

Protected countries (IE, GB, US, CA, etc.) are in `geoip:safe_countries` and will be **refused** by `block-country`. To see the full safe list: `./scripts/ja4-admin.sh list-countries`.

### Block a subnet

```bash
./scripts/ja4-admin.sh block-cidr 203.0.113.0/24     # /24 subnet
./scripts/ja4-admin.sh block-cidr 185.220.0.0/16     # /16 block (e.g. Tor exit range)
./scripts/ja4-admin.sh list-cidrs                    # show all active CIDR blocks
./scripts/ja4-admin.sh unblock-cidr 203.0.113.0/24   # remove
```

The proxy picks up CIDR changes within 30 seconds (Redis cache TTL).

### Auto-block countries under attack

```bash
# Run once — auto-blocks any country with >50 blocked connections in 5 min
./scripts/geoip-monitor.sh

# Run in watch mode (loops every 60s)
./scripts/geoip-monitor.sh --watch

# Preview what would be blocked without actually blocking
./scripts/geoip-monitor.sh --dry-run

# Via Makefile
make geoip-monitor
make geoip-watch
```

Tune thresholds: `BLOCK_THRESHOLD=100 BLOCK_PCT_THRESHOLD=90 ./scripts/geoip-monitor.sh`

---

## Keeping Fingerprints Up to Date (ja4db)

New malware families appear regularly. Pull the latest known-bad fingerprints:

```bash
make fetch-db              # or: ./scripts/fetch-ja4db.sh
make list-pending          # review what was found
./scripts/ja4-admin.sh approve t13d190900_9dc949149365_97f8aa674fd9
make approve-all           # bulk approve (asks for confirmation)
```

For ja4db.com API access (broader database), add to `.env`:
```
JA4DB_API_KEY=your_key_here
```

After approving, persist to `config/proxy.yml` so they survive container restarts:
```yaml
security:
  blacklist:
    - "t13d190900_9dc949149365_97f8aa674fd9"  # approved from ja4db 2026-02-23
```

---

## Comprehensive Report

```bash
./scripts/ja4-admin.sh report    # or: make geoip-report
```

Shows: fingerprint counts, dynamic country blocks with reasons, CIDR blocks, rate-limit enforcement, traffic breakdown by mechanism, top blocked countries.

---

## Common Attack Patterns

### Pattern 1: Known C2 Tool (Sliver, CobaltStrike, etc.)

**Signs:** Grafana shows fingerprint matching a known tool name. Block rate spikes suddenly.

**Response:**
```bash
./scripts/ja4-admin.sh block-ja4 <fingerprint>   # Instant RST for all connections from that tool
```

Already blocked by default: Sliver C2, CobaltStrike (wininet/winhttp), IcedID, Evilginx, SoftEther VPN.

### Pattern 2: High-volume scan / credential stuffing

**Signs:** Many connections from one IP, `by_ip` rate limit triggers. Fingerprint may be `Python stdlib`, `curl`, or `Go default`.

**Response:**
```bash
./scripts/ja4-admin.sh top 10              # Identify fingerprint
./scripts/ja4-admin.sh blocked             # Confirm it's already rate-limited
./scripts/ja4-admin.sh block-ip <ip>       # Add hard block if rate limit isn't enough
./scripts/ja4-admin.sh block-ja4 <fp>      # If it's a specific scanning tool
```

**Caution:** Don't blacklist `h2`/`h1` fingerprints — those are browsers.

### Pattern 3: Botnet (many IPs, same tool fingerprint)

**Signs:** `by_ja4` rate limit triggers. Hundreds of different IPs, all with the same JA4.

**Response:**
```bash
./scripts/ja4-admin.sh block-ja4 <fingerprint>   # Blocks ALL IPs using that tool simultaneously
```

This is the key advantage of JA4 fingerprinting over IP blocking — one command blocks the entire botnet.

### Pattern 4: Distributed scan (many IPs, many fingerprints)

**Signs:** `JA4ProxyHighFingerprintDiversity` alert fires (>100 unique FPs in 10 min). No single fingerprint dominates.

**Response:**
- Enable GeoIP country blacklist in `config/proxy.yml` if attack is geographically concentrated
- Enable `permanent_ban: true` temporarily to stop repeat offenders
- Check Grafana → "Traffic by Country" panel

### Pattern 5: False positive (good traffic being blocked)

**Signs:** Users reporting failures. Logs show browser fingerprints in BLOCKED lines.

**Response:**
```bash
# Check what's blocked
./scripts/ja4-admin.sh blocked

# Remove the block immediately
./scripts/ja4-admin.sh unblock-ip <ip>
./scripts/ja4-admin.sh flush        # Nuclear option — clears all blocks/bans

# If a fingerprint was wrongly blacklisted
./scripts/ja4-admin.sh unblock-ja4 <fingerprint>

# Check whitelist — browsers should be in here
./scripts/ja4-admin.sh list-ja4
```

**Prevention:** Browser fingerprints (`h2`/`h1` ALPN) are whitelisted by default via `whitelist_patterns` and can never be rate-blocked.

---

## TLS Version Enforcement — Legitimate Traffic Blocked (Phase 3)

**Symptoms:** Users on older devices or enterprise software report connection failures. Logs show connections dropped with `tls_version_blocked` or `weak_cipher_blocked`. The `ja4proxy_tls_version_total` metric shows a spike for a version like `TLSv1` or `TLSv1.1`.

**Check which versions are being blocked:**
```bash
# Look for tls_version_bypass disabled warning at startup
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep bypass_disabled

# Check metrics for blocked TLS version breakdown
curl -s http://localhost:9090/metrics | grep ja4proxy_tls_version_total
curl -s http://localhost:9090/metrics | grep ja4proxy_weak_cipher_total
```

**If a legitimate client is being blocked:**
```bash
# Option 1: Disable TLS version bypass — sends those connections through the scorer instead of hard-blocking
# In config/proxy.yml under security_policy:
#   tls_version_bypass:
#     enabled: false
# Then send SIGHUP to hot-reload (no restart required)
kill -HUP $(pgrep -f proxy.py)

# Option 2: If a specific IP needs immediate relief
./scripts/ja4-admin.sh whitelist-ja4 <fingerprint>    # if fingerprint is known-good
./scripts/ja4-admin.sh block-ip <ip> 0                # unblock (set TTL to expire immediately — use unblock-ip instead)
./scripts/ja4-admin.sh unblock-ip <ip>
```

**Prevention:** TLS 1.0/1.1 blocking has near-zero false positives on modern deployments. If a legitimate user is blocked, the long-term fix is to upgrade their TLS library. Short-term: disable the `tls_version_bypass` in config to route those connections through the scorer, where they can still pass at dial=0 (monitor mode).

---

## SNI Anomalies — DGA Scorer False Positive (Phase 4)

**Symptoms:** A legitimate domain is flagged as DGA-generated. Users connecting to a specific hostname are being scored as suspicious or blocked. The SNI in logs looks like a real brand domain but has unusual character patterns that trigger the DGA heuristic (high entropy, digit-heavy, or long random-looking labels).

**Check the SNI analysis:**
```bash
# Find the flagged SNI in logs
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep "sni_analysis" | grep -v '"score": 0' | tail -20

# Identify the client's JA4 fingerprint
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep "<affected-ip>" | tail -10
```

**Immediate relief:**
```bash
# Whitelist the fingerprint if the client tool is known-good
./scripts/ja4-admin.sh whitelist-ja4 <fingerprint>

# Or unblock the specific IP
./scripts/ja4-admin.sh unblock-ip <ip>
```

**Tune the DGA scorer (config/proxy.yml):**
```yaml
sni_analysis:
  dga_scorer:
    enabled: true
    entropy_threshold: 4.0     # raise to reduce false positives (default: 3.5)
    min_label_length: 8        # only score labels of this length or longer
    score: 30                  # risk score contribution
```

Send SIGHUP after config change: `kill -HUP $(pgrep -f proxy.py)`

**Root cause:** Some legitimate CDN hostnames (e.g. `a0b1c2d3.cdn.example.com`) or auto-generated subdomains have high entropy. If the domain is known-good, raise the threshold or add it to an SNI allowlist in config.

---

## Spamhaus DROP False Positive (Phase 8)

**Symptoms:** A legitimate IP is being hard-blocked immediately. Logs show `spamhaus_drop_match` or `blocklist_match`. The IP belongs to a real business or residential ISP that has been reassigned from a formerly abusive range.

**Verify the IP is actually in a Spamhaus DROP list:**
```bash
# Check if the IP is in an active blocklist CIDR
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep "<affected-ip>" | grep blocklist

# Check blocklist feed freshness
curl -s http://localhost:9090/metrics | grep ja4proxy_blocklist_entries
```

**Immediate relief:**

Option 1 — Disable the Spamhaus hard-block bypass (routes through scorer instead):
```yaml
# In config/proxy.yml under security_policy:
spamhaus_bypass:
  enabled: false
# Spamhaus matches now produce a RiskSignal (+80) instead of a hard block.
# At dial=0 (monitor mode) the connection still passes.
```
Then `kill -HUP $(pgrep -f proxy.py)` to hot-reload.

Option 2 — Add the specific IP to the static allowlist (overrides all block decisions):
```yaml
# In config/proxy.yml:
security:
  static_allowlist:
    - "203.0.113.42"   # Legitimate IP wrongly in Spamhaus DROP — confirmed YYYY-MM-DD
```
Then hot-reload with SIGHUP. Static allowlist entries bypass all scoring and blocklist checks.

**Report to Spamhaus:** If the IP is legitimately misclassified, submit a removal request at https://www.spamhaus.org/delist/. Spamhaus DROP lists are intended for hijacked/unused netblocks and they do accept removal requests for reassigned ranges.

**After resolution:** Remove the allowlist entry once Spamhaus has updated the list (feeds refresh per `refresh_interval_seconds` in config, typically 3600s).

---

## Reference

### The `ja4-admin` tool

```
./scripts/ja4-admin.sh status                  Quick attack snapshot
./scripts/ja4-admin.sh top [N]                 Top N fingerprints by traffic
./scripts/ja4-admin.sh blocked                 Active blocks/bans with TTL
./scripts/ja4-admin.sh list-ja4               Current blacklist + whitelist

./scripts/ja4-admin.sh block-ja4   <FP>        Blacklist fingerprint (instant RST)
./scripts/ja4-admin.sh unblock-ja4 <FP>        Remove from blacklist
./scripts/ja4-admin.sh whitelist-ja4   <FP>    Whitelist fingerprint
./scripts/ja4-admin.sh unwhitelist-ja4 <FP>    Remove from whitelist

./scripts/ja4-admin.sh block-ip   <IP> [secs]  Hard-block an IP (default 3600s)
./scripts/ja4-admin.sh unblock-ip <IP>          Remove IP blocks

./scripts/ja4-admin.sh flush                   Reset all transient state
```

### Block duration reference

| Mechanism | Duration | Redis key pattern |
|-----------|----------|-------------------|
| Tarpit block | 300s (config) | `blocked:tarpit:<entity>` |
| Hard block | 300s (config) | `blocked:block:<entity>` |
| Temporary ban | 300s (config) | `banned:temporary:<entity>` |
| Manual IP block | 3600s (default) | `blocked:block:<ip>` |
| JA4 blacklist | Permanent | `ja4:blacklist` (Redis SET) |

### Prometheus alerts to watch

| Alert | Means |
|-------|-------|
| `JA4ProxyHighBlockRate` | >10 req/s blocked — active attack |
| `JA4ProxyDDoSPattern` | >1000 req/s AND >500 blocked/s |
| `JA4ProxyMaliciousFingerprint` | Ban events detected — new threat tool |
| `JA4ProxyHighFingerprintDiversity` | >100 unique FPs/10min — scanning/distributed |

### Finding fingerprints from logs

```bash
# Show all unique fingerprints seen in last 100 log lines
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | tail -100 \
  | grep -oP 'JA4: \S+' | sort | uniq -c | sort -rn

# Show fingerprint for a specific IP
docker compose -f deploy/docker/docker-compose.poc.yml logs proxy | grep "203.0.113.42" | tail -5
```

### Looking up fingerprints

- **https://ja4db.com/** — FoxIO's public JA4 fingerprint database; search by fingerprint hash to identify the tool/malware
- **Grafana** → JA4proxy Security Overview → "Top Blocked JA4 Fingerprints" panel shows fingerprint names

### After the incident

1. Add fingerprint(s) to `config/proxy.yml` `blacklist` section with a comment
2. Commit the change: `git add config/proxy.yml && git commit -m "Blacklist <tool> — seen in incident <date>"`
3. Run `make flush-redis` to reset counters for clean next-run metrics
4. Check `./scripts/ja4-admin.sh status` to confirm clean state

---

## Backup & Restore Recovery Procedures (Phase 19)

### When to Use Backup Recovery

| Scenario | Recovery action |
|----------|----------------|
| Accidental `FLUSHDB` or `FLUSHALL` | Restore from latest backup (non-destructive or destructive) |
| Redis data corruption | Restore from backup before corruption timestamp |
| Migration to new Redis instance | Backup old instance → restore to new |
| Accidental deletion of ban list or blacklist | Restore selectively by pattern |

### Step 1 — Find the most recent valid backup

```bash
python3 -m src.cli.backup_cli list
```

Output shows backup filename, creation time, key count, and size.
Pick the most recent backup that predates the data loss event.

### Step 2 — Validate backup integrity

```bash
python3 -m src.cli.backup_cli validate /app/backups/backup_20260321T143000Z.bin
```

Expected output:
```
Manifest validated successfully: backup_20260321T143000Z.bin
Checksum verification passed
```

If validation fails with "Checksum verification failed", the archive is corrupted.
Try the next-most-recent backup.

### Step 3 — Non-destructive restore (safe default)

Non-destructive restore writes keys from the backup into Redis **without** deleting
existing keys first. Keys in Redis but not in the backup are preserved.

Use this when you need to recover specific keys (ban list, blacklist) without
affecting other state:

```bash
python3 -m src.cli.backup_cli restore /app/backups/backup_20260321T143000Z.bin
```

Expected output:
```
Restore completed successfully (non-destructive mode)
```

### Step 4 — Destructive restore (full wipe + restore)

Destructive restore calls `FLUSHDB` before writing backup data. Use this only
when the current Redis state is known-corrupted and must be completely replaced.

**Warning: this is irreversible without another backup.**

```bash
python3 -m src.cli.backup_cli restore /app/backups/backup_20260321T143000Z.bin --force
```

Confirm the operation when prompted:
```
Restore completed successfully (destructive mode)
```

### Step 5 — Verify restored state

```bash
./scripts/ja4-admin.sh status         # Check overall state
./scripts/ja4-admin.sh list-bans      # Confirm bans restored
./scripts/ja4-admin.sh list-ja4       # Confirm blacklist/whitelist restored
```

### Backup Monitoring Alerts

| Alert | Meaning | Action |
|-------|---------|--------|
| `BackupStale` | No successful backup in 24h | Check `ja4proxy_backup_last_success_timestamp`; run manual backup |
| `BackupFailureDetected` | Backup job failed | Check logs: `grep backup_failed /var/log/ja4proxy/backup.log` |
| `RestoreFailureDetected` | Restore failed | Check manifest validity; try previous backup |

### Manual Backup (on-demand)

To create an immediate backup outside the scheduled window:

```bash
python3 -m src.cli.backup_cli backup --destination /app/backups
```

### Checking Backup Metrics

```bash
# Last successful backup timestamp
curl -s http://localhost:9090/metrics | grep ja4proxy_backup_last_success_timestamp

# Total backup operations
curl -s http://localhost:9090/metrics | grep ja4proxy_backup_operations_total

# Is a backup currently running?
curl -s http://localhost:9090/metrics | grep ja4proxy_backup_currently_running
```

### Known Limitations

- Backup artifacts are **not encrypted at rest**. Keep `/var/backups/ja4proxy/` mode 0700.
- The manifest checksum detects accidental corruption; it does not prevent a
  determined attacker who can write to the backup directory from creating a tampered
  backup that passes checksum validation.
- Backup is non-incremental in Phase 19. Each backup is a full export of matching keys.
