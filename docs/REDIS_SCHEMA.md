<!--
title: Redis_Schema
audience: Developers
last_reviewed: 2026-03-27
phase: 21
-->

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
|-------------|-|-|--------|-|--|
| `config:dial` | String (integer 0–100) | none | Management UI, config reload | Current dial value; read by every proxy instance per connection |
| `config:reload` | Pub/Sub channel | N/A | Any instance | Payload `{"type":"config_reload"}` triggers hot reload on all instances |
| `ja4:whitelist` | SET of JA4 strings | none | Management UI, config reload | JA4 whitelist; loaded into in-process frozenset on startup |
| `ja4:blacklist` | SET of JA4 strings | none | Management UI, config reload | JA4 blacklist; loaded into in-process frozenset on startup |
| `ban:{ip}` | String (reason) | configurable (default 3600s) | Scorer (Phase 1+), ActionEnforcer | Active ban from risk score or manual action; presence in Redis means IP is banned. TTL from config `ban_duration_seconds` field; default 3600s, configurable per-rate strategy. Escalates to `banned:temporary`. Permanent at `duration=0`, written to `banned:permanent` instead. |
| `session:ip:{ip}:ja4:{ja4}` | Hash `{total, resumed}` | 3600s | Proxy (Phase 5) | TLS session resumption tracking per IP+JA4 pair |
| `lifespan:{ip}` | Sorted Set of durations (ms) | 1800s | Proxy (Phase 5) | Connection lifespan samples; score = timestamp |
| `concurrent:{ip}` | Integer (INCR/DECR) | 60s | Proxy (Phase 5) | Live concurrent connection count per IP |
| `visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Proxy (Phase 5) | Return visitor tracking |
| `static:allowlist` | SET of IP/CIDR strings | none | Management UI | UI-added static allowlist entries; config-file entries are authoritative |
| `management:audit_log` | List (last 1000 entries) | none | Management UI | All secops admin actions |
| `management:policy_audit` | List (last 1000 entries) | none | Management UI, config reload | Security policy bypass changes |

---

## Phase 6 — ASN & Datacenter Classification

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|----|--------|-|
| `tor:exit:ips` | SET of IP strings | 3900s (1h + 5m buffer) | Leader instance | Tor exit node IP addresses; refreshed hourly |
| `leader:tor_exit_download` | String (instance_id) | 3600s (1h) | Leader instance | Leader election lock for Tor consensus download |

---

## Phase 7 — FCrDNS & Passive DNS Enrichment

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|----|--------|-|
| `dns:ptr:{ip}` | JSON (ptr_hostname, classification, fcrdns_pass, fetched_at) | 21600s (6h) | DNS enrichment worker | PTR lookup result and FCrDNS status per IP |
| `bloom:dns_enriched` | Bloom filter | none (no expiry) | DNS enrichment worker | Dedup filter; prevents re-queuing already-enriched IPs |

---

## Phase 1 — Risk Scorer

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `config:dial` | String (integer 0–100) | none | Management UI | Read by ActionDecider per connection |
| `ban:{ip}` | String (reason, entity_id) | `ban_duration_seconds` | Proxy | Set when scorer action = ban; key presence = banned |

---

## Phase 2 — Monitor Mode & Dial

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `config:dial:change_count:{YYYY-MM-DD-HH}` | String (INCR) | 3600s | Proxy, Management UI | Hourly dial change counter; rate-limiting guard |
| `ja4proxy:events` | Stream (XADD) | maxlen=100,000 | Pipeline | Per-connection events with counterfactuals; consumed by Analytics (Phase 12) |

---

## Phase 5 — TCP & Connection Behaviour

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `session:ip:{ip}:ja4:{ja4}` | Hash `{total, resumed}` | 3600s | Proxy | TLS session resumption counters |
| `lifespan:{ip}` | Sorted Set of floats (ms) | 1800s | Proxy | Connection lifespan samples for median calculation |
| `concurrent:{ip}` | Integer (INCR/DECR) | 60s | Proxy | Live concurrent connection count per IP |
| `visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Proxy | Return visitor tracking |
| `tls_alerts:{ip}` | Integer (INCR) | 60s | Proxy (tcp_analyzer) | TLS alert message rate per IP; triggers risk signal when count exceeds threshold |

---

## Phase 8 — Spamhaus DROP/EDROP (planned)

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `blocklist:spamhaus:last_updated` | String (ISO timestamp) | none | Blocklist updater | Freshness check for Spamhaus feed |

---

## Phase 9 — Beaconing Detector

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `beacon:{ip}:{ja4}` | Sorted Set — member=`{ts:.6f}:{uuid4hex[:8]}`, score=unix_timestamp_float | `observation_window_seconds` + 60s (default 3660s) | BeaconingDetector.maybe_record() | Short-window connection timestamps for IAT analysis. UUID suffix prevents member collision on same-millisecond arrivals. Trimmed to newest entries (default 20). |
| `beacon:long:{ip}:{ja4}` | Sorted Set — member=`{ts:.6f}:{uuid4hex[:8]}`, score=unix_timestamp_float | `long_window.window_seconds` + 60s (default 86460s) | BeaconingDetector.maybe_record() | 24-hour window for slow-burn APT beacon detection. Independent of short window. Only written when enabled. |
| `beacon:suspects` | Sorted Set — member=`{ip}:{ja4}`, score=beacon_confidence (0.0–0.9) | None (managed by UI) | BeaconingDetector._check_window() | Running leaderboard of suspected beaconers. Score updated on every confirmed signal. Used to drive beaconing suspects gauge. |

---

## Phase 10 — AbuseIPDB Integration

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `abuseipdb:score:{ip}` | String (integer 0–100) | 14400s (4h) | AbuseIPDBChecker._process_lookup() | Cached AbuseIPDB confidence score; 0 on API error (fail open). Shared across all proxy instances. |
| `abuseipdb:quota:{YYYY-MM-DD}` | String (integer count) | 90000s (25h) | AbuseIPDBChecker._check_quota() | Daily API request count; atomically incremented with INCR; rolled back on over-limit; auto-expires next day. |
| `bloom:abuseipdb_enriched` | Bloom filter | 86400s (24h) | AbuseIPDBChecker._enqueue_lookup() | Dedup filter; 24h TTL ensures IPs are re-enriched daily. BF.ADD returns 1=new, 0=already present. |
| `bloom_fallback:abuseipdb_enriched:{ip}` | String ("1") | 86400s (24h) | AbuseIPDBChecker._enqueue_lookup() | Fallback when RedisBloom unavailable; per-IP SET+TTL dedup. Used when BF.ADD raises exception. |

---

## Phase 11 — RDAP Enrichment

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `rdap:ip:{ip}` | JSON (RDAPResult fields) | 86400s (24h) | RDAPEnricher._cache_result() | Full RDAP enrichment result for one IP address. |
| `rdap:org:{org_handle}` | JSON (org_name, known_bad, reason, score, netblocks[]) | 604800s (7d) | RDAPEnricher._cache_result() | Org reputation cache; keyed by registry org handle. |
| `rdap:expansions` | List of JSON audit entries (LPUSH+LTRIM to 1000) | none | RDAPEnricher._log_expansion_audit() | Immutable audit trail of all automatic block expansions. Each entry includes trigger IP, score, CIDR, org, guards checked, instance ID. |
| `rdap:expansions:count:{YYYY-MM-DDTHH}` | String (integer count) | 3600s | RDAPEnricher._check_expansion_rate_limit() | Per-hour cross-instance expansion counter; atomically INCRed; DECRed on cap rejection; expires after 1h. |
| `rdap:bootstrap:v4` | JSON (IANA IPv4 bootstrap services array) | 86400s (24h) | RDAPEnricher._download_bootstrap() (leader only) | Maps IP prefixes to RIR RDAP base URLs; loaded from Redis on startup by non-leader instances. |
| `rdap:bootstrap:v6` | JSON (IANA IPv6 bootstrap services array) | 86400s (24h) | RDAPEnricher._download_bootstrap() (leader only) | Maps IPv6 prefixes to RIR RDAP base URLs; sibling of v4 bootstrap. |
| `browser:seen:subnet:{subnet}` | String ("1") | 86400s (24h) | RDAPEnricher.record_browser_subnet() | Written for every h2/h1 ALPN connection. Presence blocks CIDR expansion for that subnet (guard 3). Subnet is /24 for IPv4, /48 for IPv6. |
| `bloom:rdap_enriched` | Bloom filter | 86400s (24h) | RDAPEnricher._enqueue_lookup() | Dedup filter; 24h TTL ensures IPs are re-enriched daily. Fallback: bloom_fallback:rdap_enriched:{ip} SET+TTL when RedisBloom unavailable. |
| `ban_cidr:{cidr}` | String ("1") | expansion_ban_duration (default 3600) | RDAPEnricher._apply_expansion() | CIDR-level ban from automatic block expansion. Prefix distinguishes from per-IP ban keys. Checked at startup via SCAN and loaded into pytricia trie; updated via cidr_ban_add pub/sub. |
| `analytics:enrich:rdap` | Set of IP strings | none (managed) | RDAPEnricher._enqueue_lookup() | RDAP enrichment queue; drained by Analytics node; results written to rdap:ip:{ip}. |

---

## Phase 12 — Analytics Node

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `ja4proxy:events` | Redis Stream | maxlen=100,000 (approximate trim) | Pipeline._emit_stream_event() | Per-connection events (ip, ja4, risk_score, action_taken, dial_setting, counterfactuals); consumed via consumer group. |
| `analytics:agg:{window}:{subnet}` | String (JSON) | 300s (5 min) | Analytics node | Cross-instance aggregated stats per 5-min window; fields: request_count, block_rate, score_stats. |
| `analytics:hll:{subnet}` | HyperLogLog | 86400s (24h) | Analytics node | Unique IP count per /24 or /48; PFADD/PFCOUNT; ~0.81% error. |
| `analytics:campaign:{subnet}` | String (JSON) | 3600s (1h) | Analytics node | Campaign detection result: density>0.15 AND block_rate>0.70; read by proxy scorer (+35 risk). |
| `analytics:slowscan:{subnet}` | String (JSON) | 1800s (30min) | Analytics node | Slow-scan detection result: avg_requests_per_ip<3 AND unique_ips>20; read by proxy scorer (+30 risk). |
| `analytics:ja4:candidates` | Sorted Set (score=block_rate) | none | Analytics node | JA4 fingerprints with >95% block rate; secops admin review only; never auto-applied to blacklist. |
| `analytics:baseline:hourly:{YYYY-MM-DD-HH}` | String (JSON) | 604800s (7 days) | Analytics node | Hourly score distribution snapshot: median, mean, stddev, histogram, event_count. |
| `analytics:alerts:score_drift` | String (JSON) | 3600s (1h) | Analytics node | Current drift alert; auto-clears when TTL expires; set when \|z-score\| > 2.0 from 7-day baseline. |
| `analytics:alerts:calibration_issue` | String (JSON) | 3600s (1h) | Analytics node | Shadow score calibration alert; triggered when h2/h1 ALPN shadow median exceeds threshold. |


---

## Phase 19 — Backup & Restore

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `backup:latest` | String (filename) | none | BackupWorker.create_backup() | Filename of most recent successful backup. Used for quick reference and validation. |
| `backup:last_success` | String (ISO timestamp) | none | BackupWorker.create_backup() | Timestamp of last successful backup operation. Updated on every successful backup. |
| `backup:last_failure` | String (ISO timestamp) | none | BackupWorker.create_backup() | Timestamp of last failed backup operation. Updated on every backup failure. |
| `backup:last_restore` | String (ISO timestamp) | none | BackupRestorer.restore_backup() | Timestamp of last restore operation. Used for tracking restore history. |
| `backup:restored_from` | String (filename) | none | BackupRestorer.restore_backup() | Filename of backup used for last restore. Used for audit trail and troubleshooting. |

---

## Phase 20 — TAP Mode Fingerprint Store

Written by `src/tap/fingerprint_store.py`. All keys are prefixed `fp:`.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `fp:conn:{conn_id}` | Hash | 7 days | FingerprintStore.write() | Full connection fingerprint record. Fields: ja4, ja4s, ja4t, ja4x, ja4h, ja4h2, h2_fingerprint, client_ip, server_ip, server_port, os_fingerprint, action, score, timestamp. One key per connection. |
| `fp:ip:{client_ip}` | Sorted Set | 30 days | FingerprintStore.write() | Per-IP connection history. Score = UNIX timestamp. Member = conn_id. Trimmed to last 1000 entries. Use ZRANGEBYSCORE for time-range queries. |
| `fp:ja4:hll:{ja4}` | HyperLogLog | 30 days | FingerprintStore.write() | Approximate unique IP count per JA4 fingerprint (PFADD client_ip). Use PFCOUNT for cardinality. ~0.81% error rate. |
| `fp:ja4:count:{ja4}` | String (int) | 30 days | FingerprintStore.write() | Total connection count for this JA4 fingerprint. Incremented on every observed connection. |
| `fp:os:count:{os_fingerprint}` | String (int) | 30 days | FingerprintStore.write() | Total connection count for this OS fingerprint (JA4T-derived). |
| `fp:os:ip:{client_ip}` | String | 24 hours | FingerprintStore.write() | Most recently observed OS fingerprint for this IP. Updated on every connection. |
| `fp:ja4_to_ja4s:{ja4}` | Hash | 7 days | FingerprintStore.write() | Maps JA4 (client) → JA4S (server) co-occurrence counts. Field = ja4s value, Value = count (HINCRBY). Used to detect server fingerprint inconsistencies. |

### TAP Enforcement Keys

Written by `src/tap/enforcement_bridge.py` and `src/tap/tap_pipeline.py`.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `tap:ban:{ip}` | String | configurable | TapPipeline.process() | TAP-mode ban record. Value = JSON {score, reason, timestamp}. TTL = tap_enforcement.ban_ttl_s. Consumed by passthrough proxy via PubSub. |
| `tap:block_decisions` | List | 24 hours | TapPipeline.process() | Recent block/ban decisions for the management UI. Each entry is JSON {ip, action, score, ja4, timestamp}. Capped at 1000 entries by LTRIM. |

### TAP Intelligence Export Keys

Written by `src/tap/export/` exporters.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `tap:edl:{list_name}` | Set | none | EDLServer | IP addresses in the named External Dynamic List. Members added by TapPipeline when action >= signal_block. Used by EDL HTTP server for firewall pull. |

---

*Last updated: 2026-03-28, Phase 20 complete*
