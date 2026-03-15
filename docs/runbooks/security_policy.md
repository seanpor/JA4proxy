# Runbook: Security Policy Management

## Overview

JA4proxy's security policy is controlled via `config/proxy.yml` under the
`security_policy` key, plus the dial setting stored in Redis. All changes are hot-
reloadable via SIGHUP without proxy restart. Every change is written to the policy
audit trail in Redis.

**The core principle:** when in doubt, fail open. A missed bad request is recoverable.
A blocked legitimate user is not. Every policy tightening increases false-positive risk
and must be a conscious decision by a secops admin.

---

## The 8 Bypass Toggles

Each bypass can be independently enabled or disabled. Defaults are conservative.

### ALLOW bypasses (disabling routes connections through the scorer)

| Bypass | Default | Risk of disabling |
|--------|---------|-------------------|
| `alpn_browser_bypass` | enabled | Browser traffic scored; false positive risk elevated |
| `ja4_whitelist_bypass` | enabled | Whitelisted fingerprints may be blocked if they score above threshold |
| `mtls_bypass` | enabled | mTLS clients scored; trusted clients may be blocked |
| `static_ip_allowlist` | enabled | Allowlisted IPs scored; trusted IPs may be blocked |

### BLOCK bypasses (disabling routes connections through the scorer instead of hard-blocking)

| Bypass | Default | Effect of disabling |
|--------|---------|---------------------|
| `ja4_blacklist_bypass` | enabled | Blacklisted fingerprints scored; blocked only if score >= threshold |
| `country_blacklist_bypass` | enabled | Blocked countries go through scorer |
| `spamhaus_bypass` | enabled | Spamhaus matches generate +80 signal instead of hard block |
| `tls_version_bypass` | enabled | Old TLS versions go through scorer with risk contribution |

---

## How to Disable a Bypass

1. Edit `config/proxy.yml`:
   ```yaml
   security_policy:
     alpn_browser_bypass:
       enabled: false
   ```
2. Send SIGHUP:
   ```bash
   docker compose kill -s SIGHUP proxy
   ```
3. Verify the startup WARNING appears in logs:
   ```bash
   docker compose logs proxy | grep bypass_disabled
   ```

The proxy emits a WARN for every high-risk bypass that is disabled:
```
WARN | policy | event=bypass_disabled | bypass=alpn_browser_bypass | effect=browser traffic will be scored; false positive risk elevated
```

This WARN is also reflected as a Prometheus gauge so it can be alerted on:
```promql
ja4proxy_bypass_disabled{bypass="alpn_browser_bypass"} == 1
```

---

## Policy Audit Trail

Every policy change via the Management UI or config reload is written to Redis:

```
management:policy_audit  LIST of JSON objects (last 1000 entries, no TTL)
```

**Inspect recent policy changes:**
```bash
redis-cli LRANGE management:policy_audit 0 19
# Returns 20 most recent entries (newest first)
```

Each entry has the format:
```json
{
  "timestamp": "2026-03-15T14:23:01Z",
  "changed_by": "192.0.2.1",
  "item": "security_policy.alpn_browser_bypass.enabled",
  "old_value": true,
  "new_value": false
}
```

Changes via config file reload are attributed to `"config_reload"` in `changed_by`.

---

## Dial Control

The dial (0–100) controls how aggressively scored traffic is blocked.

- `dial=0`: monitor mode — all traffic is scored and logged but never blocked.
- `dial=100`: full blocking — configured thresholds apply.
- Intermediate values interpolate between monitor and full blocking.

Action thresholds at `dial=100`:
- flag >= 20
- rate_limit >= 35
- tarpit >= 55
- block >= 70
- ban >= 85

At `dial=50`, effective thresholds are shifted toward the upper end of the range,
reducing false positives at the cost of some missed blocks.

**Check current dial value:**
```bash
redis-cli GET dial:setting
```

**Increment dial safely (recommended: max 10 points at a time):**
```bash
# Check current value first
redis-cli GET dial:setting

# Set to new value (example: 10 → 20)
redis-cli SET dial:setting 20

# Trigger reload so DialManager reads the new value
docker compose kill -s SIGHUP proxy
```

> The `DialManager` enforces a maximum increment per step. Attempting to jump from 0 to
> 100 in one step will log a WARNING and cap the increment. The proxy must be explicitly
> told to `blocking_acknowledged: true` in config before it will operate above dial=0.

**Emergency dial=0 (monitor mode):**
```bash
redis-cli SET dial:setting 0
docker compose kill -s SIGHUP proxy
```

This is the fastest way to stop all blocking without a proxy restart. Effective within
seconds of the SIGHUP.

---

## JA4 Candidate Review

Phase 12 analytics identifies JA4 fingerprints that appear in a disproportionate number
of flagged or blocked connections. These are written to a sorted set for secops review.

**View top candidates:**
```bash
redis-cli ZREVRANGE analytics:ja4:candidates 0 9 WITHSCORES
# Returns top 10 candidates with their suspicion score (higher = more suspicious)
```

**Inspect a specific fingerprint:**
```bash
# Get recent connections for this fingerprint
redis-cli ZREVRANGE analytics:ja4:t13d1516h2_aabbccddeeff_aabbccddeeff 0 49 WITHSCORES
```

**Promote a candidate to the blacklist:**

This must be a conscious secops decision. There is no automation for promotion — the
risk of blocking a legitimate user population sharing a fingerprint is too high.

1. Review the candidate in the Management UI (live feed, IP list, connection patterns).
2. Verify no legitimate browser or API client uses this fingerprint.
3. Add to blacklist in `config/proxy.yml`:
   ```yaml
   ja4_blacklist:
     - "t13d1516h2_aabbccddeeff_aabbccddeeff"
   ```
4. Send SIGHUP.
5. Monitor `ja4proxy_blocklist_matches_total{list="ja4_blacklist"}` for unexpected spikes.

---

## Ban Management

### List active bans

```bash
# IP bans
redis-cli SCAN 0 MATCH 'ban:*' COUNT 100

# CIDR bans (from RDAP block expansion)
redis-cli SCAN 0 MATCH 'ban_cidr:*' COUNT 100
```

### Inspect a specific ban

```bash
redis-cli TTL ban:192.0.2.1
# Seconds remaining on the ban. -2 = key does not exist (ban expired or lifted).

redis-cli GET ban:192.0.2.1
# Returns ban metadata (reason, timestamp, action that triggered it).
```

### Manually lift a ban

```bash
redis-cli DEL ban:192.0.2.1
```

The proxy's local cache may hold the ban decision for up to 30 seconds (BLOCK cache
TTL). After that, the unbanned IP is allowed through. If immediate release is needed:

```bash
# Restart proxy to flush local cache
docker compose restart proxy
```

### Manually impose a ban

```bash
# Ban for 24 hours (86400 seconds)
redis-cli SET ban:192.0.2.1 '{"reason":"manual_secops","timestamp":"2026-03-15T14:23:01Z"}' EX 86400
```

### CIDR ban lift

```bash
redis-cli DEL ban_cidr:203.0.113.0/24
```

---

## Related

- `docs/decisions/ADR-003.md` — Why RDAP block expansion is off by default
- `docs/runbooks/redis_operations.md` — Redis key inspection and TTL management
- `docs/runbooks/feed_management.md` — JA4 blacklist/whitelist feed management
- `CLAUDE.md` — Cross-cutting bypass requirements and the core asymmetry principle
