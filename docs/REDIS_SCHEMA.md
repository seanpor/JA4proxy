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

## Phase 13 — Management UI

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `mgmt:session:{token}` | String (username) | 3600s | Auth router (POST /api/v1/auth/login) | Session token → username mapping; presence validates a login-issued token |
| `mgmt:ratelimit:{ip}` | String (INCR) | 60s | Management auth | Auth failure counter per IP; rate-limit gate |
| `mgmt:dial_changes:{YYYYMMDDHH}` | String (INCR) | 3600s | Dial router | Hourly dial change counter; max 10/hour safety gate |
| `policy:bypass:{name}` | String "true"/"false" | none | Policy router, config reload | Enabled state of each of the 8 security bypasses |
| `management:audit_log` | List (JSON entries) | none | All routers | Admin action audit trail; LPUSH+LTRIM 1000 |
| `management:policy_audit` | List (JSON entries) | none | Policy router, config reload | Security policy change audit; LPUSH+LTRIM 1000 |
| `dial:current` | String (integer 0–100) | none | Dial router, proxy | Current dial value |
| `dial:blocking_acknowledged` | String "true"/"false" | none | Dial router | Blocking risk acknowledgment flag |
| `config:thresholds` | Hash | none | Config router | flag/rate_limit/tarpit/block/ban score thresholds |
| `config:features:{name}` | String "true"/"false" | none | Config router | Individual feature flags |
| `config:countries:blocklist` | Set (ISO-2 codes) | none | Config router | GeoIP country blocklist |

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

## Phase 10 — AbuseIPDB Integration

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `abuseipdb:score:{ip}` | String (integer 0–100) | 14400s (4 h) | `AbuseIPDBChecker._process_lookup()` | Cached AbuseIPDB confidence score; 0 on API error (fail open). Shared across all proxy instances. |
| `abuseipdb:quota:{YYYY-MM-DD}` | String (integer count) | 90000s (25 h) | `AbuseIPDBChecker._check_quota()` | Daily API request count; atomically incremented with INCR; rolled back on over-limit; auto-expires next day. |
| `bloom:abuseipdb_enriched` | Bloom filter | 86400s (24 h) | `AbuseIPDBChecker._enqueue_lookup()` | Dedup filter; 24h TTL ensures IPs are re-enriched daily (not permanently suppressed). BF.ADD returns 1=new, 0=already present. |
| `bloom_fallback:abuseipdb_enriched:{ip}` | String ("1") | 86400s (24 h) | `AbuseIPDBChecker._enqueue_lookup()` | Fallback when RedisBloom is unavailable; per-IP SET+TTL dedup. Used when BF.ADD raises an exception. |
| `analytics:enrich:abuseipdb` | Set of IP strings | none (managed) | `AbuseIPDBChecker._enqueue_lookup()` | AbuseIPDB enrichment queue when `delegate_to_analytics: true`; drained by Analytics node (Phase 12); results written to `abuseipdb:score:{ip}`. |

---

## Phase 11 — RDAP Enrichment

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `rdap:ip:{ip}` | JSON (RDAPResult: netblock, org_name, org_handle, asn, country, registration_date, fetched_at, is_unknown) | 86400s (24h) | `RDAPEnricher._cache_result()` | Full RDAP enrichment result for one IP address. |
| `rdap:org:{org_handle}` | JSON (org_name, known_bad, reason, score, netblocks[]) | 604800s (7d) | `RDAPEnricher._cache_result()` | Org reputation cache; keyed by registry org handle. |
| `rdap:expansions` | List of JSON audit entries (LPUSH+LTRIM to 1000) | none | `RDAPEnricher._log_expansion_audit()` | Immutable audit trail of all automatic block expansions. Each entry includes trigger IP, score, CIDR, org, guards checked, instance ID. |
| `rdap:expansions:count:{YYYY-MM-DDTHH}` | String (integer count) | 3600s | `RDAPEnricher._check_expansion_rate_limit()` | Per-hour cross-instance expansion counter; atomically INCRed; DECRed on cap rejection; expires after 1h. |
| `rdap:bootstrap:v4` | JSON (IANA IPv4 bootstrap services array) | 86400s (24h) | `RDAPEnricher._download_bootstrap()` (leader only) | Maps IP prefixes to RIR RDAP base URLs; loaded from Redis on startup by non-leader instances. |
| `rdap:bootstrap:v6` | JSON (IANA IPv6 bootstrap services array) | 86400s (24h) | `RDAPEnricher._download_bootstrap()` (leader only) | Maps IPv6 prefixes to RIR RDAP base URLs; sibling of v4 bootstrap. |
| `browser:seen:subnet:{subnet}` | String ("1") | 86400s (24h) | `RDAPEnricher.record_browser_subnet()` | Written for every h2/h1 ALPN connection (browser traffic). Presence blocks CIDR expansion for that subnet (guard 3). Subnet is /24 for IPv4, /48 for IPv6. |
| `bloom:rdap_enriched` | Bloom filter | 86400s (24h) | `RDAPEnricher._enqueue_lookup()` | Dedup filter; 24h TTL ensures IPs are re-enriched daily. BF.ADD returns 1=new, 0=already present. Fallback: `bloom_fallback:rdap_enriched:{ip}` SET+TTL when RedisBloom unavailable. |
| `ban_cidr:{cidr}` | String ("1") | `expansion_ban_duration`s (default 3600) | `RDAPEnricher._apply_expansion()` | CIDR-level ban from automatic block expansion. Prefix `ban_cidr:` distinguishes from per-IP `ban:{ip}` keys. Checked at startup via SCAN and loaded into pytricia trie; updated via `cidr_ban_add` pub/sub. |
| `analytics:enrich:rdap` | Set of IP strings | none (managed) | `RDAPEnricher._enqueue_lookup()` | RDAP enrichment queue when `delegate_to_analytics: true`; drained by Analytics node (Phase 12); results written to `rdap:ip:{ip}`. |

### Pub/Sub channel update: `ja4proxy:invalidate`

Phase 11 adds a new message type:

| `type` field | `value` | Effect |
|---|---|---|
| `cidr_ban_add` | CIDR string (e.g. "1.2.3.0/24") | Call `BlocklistManager.load_cidrs([cidr], "rdap_expansion", ...)` on all instances; updates pytricia trie immediately |

---

## Phase 12 — Analytics Node

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `ja4proxy:events` | Redis Stream | maxlen=100,000 (approximate trim) | `Pipeline._emit_stream_event()` | Per-connection events (ip, ja4, risk_score, action_taken, dial_setting, counterfactuals); consumed by Analytics via consumer group `analytics` |
| `analytics:agg:{window}:{subnet}` | String (JSON) | 300s (5 min) | Analytics node | Cross-instance aggregated stats per 5-min window per IP, /24 (IPv4), or /48 (IPv6); fields: request_count, block_rate, score_stats |
| `analytics:hll:{subnet}` | HyperLogLog | 86400s (24 h) | Analytics node | Unique IP count per /24 (IPv4) or /48 (IPv6); PFADD/PFCOUNT; ~0.81% error |
| `analytics:campaign:{subnet}` | String (JSON) | 3600s (1 h) | Analytics node | Campaign detection result: density>0.15 AND block_rate>0.70; read by proxy scorer (+35 risk) |
| `analytics:slowscan:{subnet}` | String (JSON) | 1800s (30 min) | Analytics node | Slow-scan detection result: avg_requests_per_ip<3 AND unique_ips>20; read by proxy scorer (+30 risk) |
| `analytics:ja4:candidates` | Sorted Set (score=block_rate) | none | Analytics node | JA4 fingerprints with >95% block rate; secops admin review only; never auto-applied to blacklist |
| `analytics:baseline:hourly:{YYYY-MM-DD-HH}` | String (JSON) | 604800s (7 days) | Analytics node | Hourly score distribution snapshot: median, mean, stddev, histogram, event_count |
| `analytics:alerts:score_drift` | String (JSON) | 3600s (1 h) | Analytics node | Current drift alert; auto-clears when TTL expires; set when \|z-score\| > 2.0 from 7-day baseline |
| `analytics:alerts:calibration_issue` | String (JSON) | 3600s (1 h) | Analytics node | Shadow score calibration alert; triggered when h2/h1 ALPN shadow median exceeds threshold |
| `analytics:enrich:abuseipdb` | Set of IP strings | none (managed) | `AbuseIPDBChecker._enqueue_lookup()` | AbuseIPDB enrichment queue when `delegate_to_analytics: true`; drained by Analytics node; results written to `abuseipdb:score:{ip}` |
| `analytics:enrich:rdap` | Set of IP strings | none (managed) | `RDAPEnricher._enqueue_lookup()` | RDAP enrichment queue when `delegate_to_analytics: true`; drained by Analytics node; results written to `rdap:ip:{ip}` |

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

*Last updated: Phase 10*
