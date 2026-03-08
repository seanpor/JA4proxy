# JA4proxy — Redis Key Schema

> This is the single source of truth for all Redis key patterns.
> Update this file in the same phase that introduces each key.
> Every key must document: pattern, type, TTL, written-by, and notes.

---

## Conventions

- All key segments use `snake_case`, colon-separated.
- Variable parts are shown in `{braces}`: `{ip}`, `{ja4}`, `{org_handle}`.
- IPs are always canonical form (see `src/utils/ip.py:canonical_ip()`).
- JA4 fingerprints are the full opaque string from the TLS parser.
- `none` TTL = no expiry (key persists until explicitly deleted).

---

## Phase 0 — Infrastructure

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `config:dial` | String (integer 0–100) | none | Management UI, config reload | Current dial value; read by every proxy instance per connection |
| `config:reload` | Pub/Sub channel | N/A | Any instance | Payload `{"type":"config_reload"}` triggers hot reload on all instances |
| `ja4:whitelist` | SET of JA4 strings | none | Management UI, config reload | JA4 whitelist; loaded into in-process frozenset on startup |
| `ja4:blacklist` | SET of JA4 strings | none | Management UI, config reload | JA4 blacklist; loaded into in-process frozenset on startup |
| `ban:{ip}` | String (reason) | `ban_duration_seconds` | Proxy (Phase 1+) | Active IP ban; presence means IP is banned |
| `block:cidr:{cidr}` | String | none | Management UI, RDAP (Phase 11) | Manual or auto-expanded CIDR blocks |
| `session:ip:{ip}:ja4:{ja4}` | Hash `{total, resumed}` | 3600s | Proxy (Phase 5) | TLS session resumption tracking per IP+JA4 pair |
| `lifespan:{ip}` | Sorted Set of durations (ms) | 1800s | Proxy (Phase 5) | Connection lifespan samples; score = timestamp |
| `concurrent:{ip}` | Integer (INCR/DECR) | 60s | Proxy (Phase 5) | Live concurrent connection count per IP |
| `visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Proxy (Phase 5) | Return visitor tracking |
| `static:allowlist` | SET of IP/CIDR strings | none | Management UI (Phase 13) | UI-added static allowlist entries; config-file entries are authoritative |
| `management:audit_log` | List (last 1000 entries) | none | Management UI | All secops admin actions |
| `management:policy_audit` | List (last 1000 entries) | none | Management UI, config reload | Security policy bypass changes |

### Phase 6 — ASN & Datacenter Classification

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `tor:exit:ips` | SET of IP strings | 3900s (1h + 5m buffer) | Leader instance | Tor exit node IP addresses; refreshed hourly |
| `leader:tor_exit_download` | String (instance_id) | 3600s (1h) | Leader instance | Leader election lock for Tor consensus download |

### Pub/Sub channel: `ja4proxy:invalidate`

All proxy instances subscribe on startup. Message format: `{"type": "...", "value": "..."}`.

| `type` field | `value` | Effect |
|---|---|---|
| `whitelist_remove` | JA4 string | Remove from local whitelist cache + in-process set |
| `ban_release` | IP string | Remove from local block_decisions cache |
| `ja4_blacklist_add` | JA4 string | Add to in-process blacklist set immediately |
| `dial_change` | Integer 0–100 | Update local_cache.dial on all instances |
| `config_reload` | *(none)* | Trigger hot reload of proxy.yml on all instances |

---

## Phase 7 — FCrDNS & Passive DNS Enrichment

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `dns:ptr:{ip}` | JSON (ptr_hostname, classification, fcrdns_pass, fetched_at) | 21600s (6h) | DNS enrichment worker | PTR lookup result and FCrDNS status per IP |
| `bloom:dns_enriched` | Bloom filter | none (no expiry) | DNS enrichment worker | Dedup filter; prevents re-queuing already-enriched IPs |

---

## Phase 1 — Risk Scorer

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `config:dial` | String (integer 0–100) | none | Management UI | Reused from Phase 0; now actively read by ActionDecider |
| `ban:{ip}` | String (reason) | `ban_duration_seconds` | Proxy | Set when scorer action = ban; key presence = banned |

---

## Phase 2 — Monitor Mode & Dial

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `config:dial:change_count:{YYYY-MM-DD-HH}` | String (INCR) | 3600s | Proxy, Management UI | Hourly dial change counter; rate-limiting guard |
| `ja4proxy:events` | Stream (XADD) | maxlen=100,000 | Pipeline | Per-connection events with counterfactuals; consumed by Analytics (Phase 12) |

---

## Phase 5 — TCP & Connection Behaviour

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `session:ip:{ip}:ja4:{ja4}` | Hash `{total, resumed}` | 3600s | Proxy | TLS session resumption counters |
| `lifespan:{ip}` | Sorted Set of floats (ms) | 1800s | Proxy | Connection lifespan samples for median calculation |
| `concurrent:{ip}` | Integer (INCR/DECR) | 60s | Proxy | Live concurrent connection count per IP |
| `visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Proxy | Return visitor tracking |
| `tls_alerts:{ip}` | Integer (INCR) | 60s | Proxy (tcp_analyzer) | TLS alert message rate per IP; triggers risk signal when count exceeds `tls_alerts.rate_threshold` |

---

## Phase 8 — Spamhaus DROP/EDROP (planned)

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `blocklist:spamhaus:last_updated` | String (ISO timestamp) | none | Blocklist updater | Freshness check for Spamhaus feed |

---

## Phase 9 — Beaconing Detector

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `beacon:{ip}:{ja4}` | Sorted Set — member=`{ts:.6f}:{uuid4hex[:8]}`, score=unix_timestamp_float | `observation_window_seconds` + 60 s (default 3660 s) | `BeaconingDetector.maybe_record()` | Short-window connection timestamps for IAT analysis. UUID suffix prevents member collision on same-millisecond arrivals. Trimmed to newest `window_size` entries (default 20). |
| `beacon:long:{ip}:{ja4}` | Sorted Set — member=`{ts:.6f}:{uuid4hex[:8]}`, score=unix_timestamp_float | `long_window.window_seconds` + 60 s (default 86460 s) | `BeaconingDetector.maybe_record()` | 24-hour window for slow-burn APT beacon detection. Independent of short window. Only written when `long_window.enabled: true`. |
| `beacon:suspects` | Sorted Set — member=`{ip}:{ja4}`, score=beacon_confidence (0.0–0.9) | None (managed by Phase 13 UI) | `BeaconingDetector._check_window()` | Running leaderboard of suspected beaconers. Score updated on every confirmed signal. ZCARD used to drive `ja4proxy_beaconing_suspects` gauge. |

---

## Phase 10 — AbuseIPDB (planned)

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `abuseipdb:score:{ip}` | String (integer 0–100) | 14400s (4 h) | Proxy enrichment | Cached AbuseIPDB confidence score |
| `bloom:abuseipdb_enriched` | Bloom filter | none | Proxy enrichment | Dedup filter; fallback: `bloom_fallback:abuseipdb_enriched` SET |

---

## Phase 11 — RDAP Enrichment (planned)

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `rdap:org:{org_handle}` | Hash `{name, country, reputation, fetched_at}` | 3600s | Proxy enrichment | Cached RDAP org data |
| `rdap:netblock:{cidr}` | Hash `{org_handle, registered_at, fetched_at}` | 3600s | Proxy enrichment | Cached RDAP netblock data |
| `bloom:rdap_enriched` | Bloom filter | none | Proxy enrichment | Dedup filter; fallback: `bloom_fallback:rdap_enriched` SET |

---

## Phase 12 — Analytics Node (planned)

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `analytics:agg:ip:{ip}` | String (JSON score + signals) | 300s (5 min) | Analytics node | Cross-instance aggregated score for IP; read by proxy pipeline |
| `hll:subnet:{cidr}` | HyperLogLog | 86400s (24 h) | Proxy | Unique IPs per /24 (IPv4) or /48 (IPv6); PFADD/PFCOUNT |
| `analytics:events` | Redis Stream | 604800s (7d) | Proxy | Per-connection events; XADD from proxy, XREADGROUP from analytics |
| `analytics:baseline:hourly:{YYYY-MM-DD-HH}` | Hash | 172800s (48 h) | Analytics node | Hourly traffic baseline for anomaly detection |

---

## Phase 8 — Spamhaus DROP/EDROP & Blocklist Feed Framework

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `blocklist:cidrs:{list_name}` | JSON list of CIDR strings | `refresh_interval_seconds` + 1800s | Leader instance | Parsed CIDR list for one feed; distributed to all instances |
| `blocklist:etag:{list_name}` | String (HTTP ETag) | `refresh_interval_seconds` + 1800s | Leader instance | Last ETag for conditional HTTP download; avoids redundant processing on 304 |
| `leader:blocklist_download:{list_name}` | String (instance_id) | `refresh_interval_seconds` / 2 | Leader instance | Leader election lock; only one instance downloads per feed per interval |

---

## Cross-Cutting Rate Limiting Keys (Phase 0 — existing)

These keys are written by the existing `MultiStrategyRateTracker` (see `src/security/rate_tracker.py`):

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `rate:ip:{ip}:{window}s` | Sorted Set (score=timestamp) | `max(60s, 2×window)` | RateTracker | Sliding window connection times for BY_IP strategy |
| `rate:ip:{ip}:{window}s:counter` | Integer | same | RateTracker | Monotonic counter for unique member IDs |
| `rate:ja4:{ja4}:{window}s` | Sorted Set | same | RateTracker | Sliding window for BY_JA4 strategy |
| `rate:pair:{ip}:{ja4}:{window}s` | Sorted Set | same | RateTracker | Sliding window for BY_IP_JA4_PAIR strategy |

---

*Last updated: Phase 8*
