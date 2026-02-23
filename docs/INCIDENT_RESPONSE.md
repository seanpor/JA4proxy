# JA4proxy Incident Response Runbook

Quick reference for responding to active attacks. All commands take effect **immediately** — no proxy restart needed.

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
docker compose -f docker-compose.poc.yml logs proxy | grep BLOCKED | tail -20
docker compose -f docker-compose.poc.yml logs proxy | grep BLACKLISTED | tail -20
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
docker compose -f docker-compose.poc.yml logs proxy | grep BLACKLISTED | tail -5
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
docker compose -f docker-compose.poc.yml logs proxy | tail -100 \
  | grep -oP 'JA4: \S+' | sort | uniq -c | sort -rn

# Show fingerprint for a specific IP
docker compose -f docker-compose.poc.yml logs proxy | grep "203.0.113.42" | tail -5
```

### Looking up fingerprints

- **https://ja4db.com/** — FoxIO's public JA4 fingerprint database; search by fingerprint hash to identify the tool/malware
- **Grafana** → JA4proxy Security Overview → "Top Blocked JA4 Fingerprints" panel shows fingerprint names

### After the incident

1. Add fingerprint(s) to `config/proxy.yml` `blacklist` section with a comment
2. Commit the change: `git add config/proxy.yml && git commit -m "Blacklist <tool> — seen in incident <date>"`
3. Run `make flush-redis` to reset counters for clean next-run metrics
4. Check `./scripts/ja4-admin.sh status` to confirm clean state
