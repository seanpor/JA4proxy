<!--
title: Feed_Management
audience: Operators, Security Teams
last_reviewed: 2026-03-27
phase: 21
-->

# Runbook: Threat Intelligence Feed Management

## Overview

JA4proxy consumes two categories of threat intelligence feeds: Spamhaus DROP/EDROP
(Phase 8) for hard-block CIDR lists, and MaxMind GeoLite2 (Phase 6) for GeoIP and ASN
data. Both are cached in Redis and in-process. Feed updates never cause proxy restarts.

---

## Spamhaus DROP/EDROP (Phase 8)

### Automatic refresh

The `FeedManager` component refreshes feeds every `refresh_interval_seconds` (default:
3600). It uses HTTP ETag caching: if the feed has not changed since the last fetch, the
server returns HTTP 304 and no update is applied.

The `FeedManager` uses leader election (Redis `SET NX`) so only one proxy instance
fetches the feed when multiple instances are running. All instances read from the shared
Redis cache.

### Manual refresh

To force a re-fetch (e.g., after a suspected partial write):

```bash
# Delete the ETags so the next scheduled fetch downloads fresh content
redis-cli DEL blocklist:etag:spamhaus_drop
redis-cli DEL blocklist:etag:spamhaus_edrop

# Trigger config reload which re-initialises the feed manager
docker compose kill -s SIGHUP proxy
```

The feed manager will fetch new content on its next scheduled cycle (within
`refresh_interval_seconds`). To force an immediate fetch without waiting:

```bash
docker compose restart proxy
```

### Verify feed loaded

```bash
# Check the stored CIDR list (JSON array)
redis-cli GET blocklist:cidrs:spamhaus_drop | python3 -m json.tool | head -20

# Check the entry count
redis-cli GET blocklist:cidrs:spamhaus_drop | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d), 'CIDRs')"

# Check feed age (last successful fetch timestamp)
redis-cli GET blocklist:last_updated:spamhaus_drop
```

### Feed staleness alert

**Alert:** `ja4proxy_blocklist_feed_age_seconds > 86400`

This fires when a feed has not been successfully updated in more than 24 hours.

**Diagnose:**
```bash
# Check when the last update occurred
redis-cli GET blocklist:last_updated:spamhaus_drop
redis-cli GET blocklist:last_updated:spamhaus_edrop

# Check error counter
# Prometheus: ja4proxy_blocklist_feed_errors_total{feed="spamhaus_drop"}

# Check proxy logs for feed fetch errors
docker compose logs proxy | grep -i 'blocklist\|spamhaus\|feed' | tail -30
```

**If the Spamhaus feed URL is temporarily unreachable:**

The last known CIDR list is retained in Redis. The proxy continues to block based on
the cached data. A WARN is emitted to the log:
```
WARN | blocklist | event=feed_stale | feed=spamhaus_drop | age_seconds=7200
```

No immediate operator action is required unless staleness exceeds 48 hours, at which
point manual verification of the Spamhaus feed URL is warranted.

**If the URL has changed:**
1. Check Spamhaus documentation for the current DROP/EDROP URLs.
2. Update `config/proxy.yml` under `blocklists.feeds`.
3. Send SIGHUP: `docker compose kill -s SIGHUP proxy`.

### Disable Spamhaus hard-block (route through scorer instead)

```yaml
# config/proxy.yml
security_policy:
  spamhaus_bypass:
    enabled: false
```

Send SIGHUP. Spamhaus matches will now generate a RiskSignal (+80) instead of an
immediate hard block. The dial setting then controls whether those connections are
blocked. A startup WARN is emitted:
```
WARN | policy | event=bypass_disabled | bypass=spamhaus_drop_bypass | effect=Spamhaus DROP matches scored as signal(+80) instead of hard block
```

---

## GeoIP (Phase 6)

### MaxMind GeoLite2 database refresh

MaxMind releases database updates on Tuesdays. The database should be refreshed at
least monthly. A stale database causes inaccurate country and ASN lookups.

**Refresh procedure:**

```bash
# Run the update script (downloads fresh .mmdb files to /data/geoip/)
scripts/update-geoip.sh
```

The script downloads `GeoLite2-ASN.mmdb` and `GeoLite2-Country.mmdb` from the MaxMind
download API. A valid MaxMind license key must be configured in the script or as the
environment variable `MAXMIND_LICENSE_KEY`.

**Apply new databases without restart:**

```bash
# Trigger hot reload — the config loader signals the ASN classifier to reload its mmap
docker compose kill -s SIGHUP proxy
```

The proxy logs database reload:
```
INFO | asn_classifier | event=db_reloaded | path=/data/geoip/GeoLite2-ASN.mmdb
```

**Verify new database is active:**
```bash
# GeoIP database is loaded at startup from file, not tracked in Redis
# Check the filesystem mtime of the .mmdb file
stat /data/geoip/GeoLite2-ASN.mmdb
```

**Database age check:**
```bash
# Check filesystem mtime directly
stat -c %Y /data/geoip/GeoLite2-ASN.mmdb
# Value is Unix timestamp. Age = now - mtime.
# Alert if age > 30 days (2592000 seconds).
```

**If MaxMind download fails:**

The existing database continues to serve lookups. No proxy restart or operator action
needed. Schedule a retry.

If the license key has expired:
1. Renew the MaxMind license at maxmind.com.
2. Update `MAXMIND_LICENSE_KEY` in the deployment environment.
3. Re-run `scripts/update-geoip.sh`.

### ASN datacenter list refresh

The static ASN datacenter classification list is at `config/asn_datacenter_list.yml`.
This is not auto-fetched — it is maintained manually.

To update:
1. Edit `config/asn_datacenter_list.yml`.
2. Send SIGHUP: `docker compose kill -s SIGHUP proxy`.
3. The ASN classifier reloads the YAML on the next lookup.

---

## Feed Health Dashboard Queries

```promql
# Feed age (seconds since last successful update)
ja4proxy_blocklist_feed_age_seconds

# Feed fetch errors
rate(ja4proxy_blocklist_feed_errors_total[5m])

# CIDRs loaded per feed
ja4proxy_blocklist_cidr_count{feed="spamhaus_drop"}
ja4proxy_blocklist_cidr_count{feed="spamhaus_edrop"}

# Hard blocks triggered by Spamhaus
rate(ja4proxy_blocklist_matches_total{feed="spamhaus_drop"}[5m])
```

---

## Related

- `docs/phases/complete/PHASE_08.md` — Spamhaus integration architecture
- `docs/phases/complete/PHASE_06.md` — ASN classification and GeoIP
- `docs/runbooks/redis_operations.md` — Redis key inspection
- `docs/reference/REDIS_SCHEMA.md` — Blocklist key patterns
