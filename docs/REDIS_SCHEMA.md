<!--
title: Redis_Schema
audience: Developers
last_reviewed: 2026-04-01
phase: 54
-->

# JA4proxy — Redis Key Schema

> This is the single source of truth for all Redis key patterns.
> Update this file in the same phase that introduces each key.
> Every key must document: pattern, type, TTL, written-by, and notes.

---

## Conventions

- All key segments use `snake_case`, colon-separated.
- Variable parts are shown in `{braces}`: `{ip}`, `{ja4}`, `{org_handle}`, `{fp}`.
- IPs are always canonical form (see `src/utils/ip.py:canonical_ip()`).
- JA4 fingerprints are the full opaque string from the TLS parser.
- `none` TTL = no expiry (key persists until explicitly deleted).

---

## Phase 0 — Infrastructure

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `config:dial` | String (integer 0–100) | none | Management UI, config reload | Current dial value; read by every proxy instance per connection |
| `config:reload` | Pub/Sub channel | N/A | Any instance | Payload `{"type":"config_reload"}` triggers hot reload on all instances |
| `ja4:whitelist` | SET of JA4 strings | none | Management UI, config reload | JA4 whitelist; loaded into in-process frozenset on startup |
| `ja4:blacklist` | SET of JA4 strings | none | Management UI, config reload | JA4 blacklist; loaded into in-process frozenset on startup |
| `ban:{ip}` | String (reason) | configurable (default 3600s) | Scorer (Phase 1+), ActionEnforcer | Active ban from risk score or manual action; presence in Redis means IP is banned. |
| `ip:blacklist` | SET of IPv4/IPv6 strings | none | Manual operator action | Static IP-level blocklist (distinct from `ja4:blacklist` which holds JA4 fingerprints). Read by `scripts/redis-to-ebpf.py` to populate the XDP kernel-drop map. IPv6 entries are logged but not enforced at the XDP layer (IPv4 only). *(Phase 35)* |
| `session:ip:{ip}:ja4:{ja4}` | Hash `{total, resumed}` | 3600s | Proxy (Phase 5) | TLS session resumption tracking per IP+JA4 pair |
| `lifespan:{ip}` | Sorted Set of durations (ms) | 1800s | Proxy (Phase 5) | Connection lifespan samples; score = timestamp |
| `concurrent:{ip}` | Integer (INCR/DECR) | 60s | Proxy (Phase 5) | Live concurrent connection count per IP |
| `visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Proxy (Phase 5) | Return visitor tracking |
| `static:allowlist` | SET of IP/CIDR strings | none | Management UI | UI-added static allowlist entries; config-file entries are authoritative |
| `management:audit_log` | List (last 1000 entries) | none | Management UI | All secops admin actions |
| `management:policy_audit` | List (last 1000 entries) | none | Management UI, config reload | Security policy bypass changes |
| `management:gdpr_erasure_log` | LIST of JSON | no TTL (last 1000 entries) | scripts/gdpr_delete.py | Audit trail of GDPR erasure requests; each entry: {timestamp, ip, dry_run, keys_deleted, keys_skipped_hll, zset_members_removed, invoked_by} |

---

## Phase 32 — Attacker Attribution

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `attribution:profile:{fp}` | String (JSON) | 7776000s (90d) | AttributionManager._update_correlation() | Full AttackerProfile JSON (fingerprint, category, timestamps, tags, metadata). |
| `attribution:ips:{fp}` | SET of IP strings | 2592000s (30d) | AttributionManager._update_correlation() | Set of all IP addresses associated with a unique attacker fingerprint. |

---

## Phase 54 — Behavioral Attribution

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `behavioral:probing:{fp}` | SET of SNI strings | 3600s (1h) | BehavioralAnalyzer._check_sequential_probing() | Set of unique hostnames probed by a specific fingerprint. |
| `behavioral:burst:{sni}` | Sorted Set | 10s | BehavioralAnalyzer._check_coordinated_burst() | Millisecond timestamps of recent hits to an SNI. Member = `{ip}:{ts_ms}`, Score = `ts_ms`. |
| `behavioral:known_ja4` | SET of JA4 strings | none | BehavioralAnalyzer._check_fingerprint_drift() | Registry of all JA4 fingerprints seen in this environment. Used for new-fingerprint alerting. |

---

## Phase 53 — Advanced Traffic Intelligence (Secondary Feeds)

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `greynoise:data:{ip}` | String (JSON) | 21600s (6h) | GreyNoiseProvider._process_lookup() | Cached GreyNoise Community data (noise, riot, classification). |
| `bloom:greynoise_enriched` | Bloom filter | 86400s (24h) | GreyNoiseProvider._maybe_lookup() | Dedup filter for GreyNoise lookups. |
| `alienvault:data:{ip}` | String (JSON) | 3600s (1h) | AlienVaultOTXProvider._process_lookup() | Cached AlienVault OTX data (pulse_count). |
| `bloom:alienvault_enriched` | Bloom filter | 86400s (24h) | AlienVaultOTXProvider._maybe_lookup() | Dedup filter for AlienVault OTX lookups. |
| `misp:data:{ip}` | String (JSON) | 21600s (6h) | MISPProvider._process_lookup() | Cached MISP reputation data and attributes. |
| `threatfox:data:{ip}` | String (JSON) | 21600s (6h) | ThreatFoxProvider._process_lookup() | Cached ThreatFox IOC data. |
| `virustotal:data:{ip}` | String (JSON) | 21600s (6h) | VirusTotalProvider._process_lookup() | Cached VirusTotal reputation and engine stats. |
| `virustotal:quota:{YYYY-MM-DD}` | String (int) | 90000s (25h) | VirusTotalProvider._check_quota() | Daily API quota tracker for VirusTotal. |
| `confidence:scores` | Hash | none | ConfidenceManager.save_state() | Persistent historical accuracy scores (TP/FP) per threat feed. |

---

## Phase 58 — Advanced Intelligence: Confidence Weighting

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `ja4proxy:confidence:state` | Hash | No TTL | ConfidenceManager | Per-feed confidence tracking: fields `{feed_name}:successes`, `{feed_name}:total`, `{feed_name}:weight`. Updated on each lookup result. In-memory primary; Redis used for persistence across restarts. |

---

## Phase 12 — Analytics Node

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `ja4proxy:events` | Redis Stream | maxlen=100,000 | Pipeline._emit_stream_event() | Per-connection events (ip, ja4, risk_score, action_taken, dial_setting, counterfactuals). |
| `analytics:agg:{window}:{subnet}` | String (JSON) | 300s (5 min) | Analytics node | Cross-instance aggregated stats per 5-min window. |
| `analytics:campaign:{subnet}` | String (JSON) | 3600s (1h) | Analytics node | Campaign detection result: density>0.15 AND block_rate>0.70. |
| `analytics:alerts:score_drift` | String (JSON) | 3600s (1h) | Analytics node | Current drift alert; set when \|z-score\| > 2.0. |

---

## Phase 19/40 — Backup & Restore

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `backup:latest` | String (filename) | none | BackupWorker.create_backup() | Filename of most recent successful backup. |
| `backup:last_success` | String (ISO timestamp) | none | BackupWorker.create_backup() | Timestamp of last successful backup operation. |
| `backup:operation_lock` | String ("backup"\|"restore") | 600s (10m) | BackupWorker, BackupRestorer | Distributed lock to prevent concurrent backup/restore operations from corrupting state. |
| `backup:last_restore` | String (ISO timestamp) | none | BackupRestorer.restore_backup() | Timestamp of last restore operation. |

---

## Phase 57 — Cloud Backup & Restore Hardening

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `backup:restored_from` | String (JSON) | none | BackupRestorer._write_restored_from() | Written after each successful restore. JSON: `{"filename":"...","restored_at":"ISO-8601","keys_count":N}`. Useful as an audit trail and post-restore sanity check. |
| `backup:artifacts` | Sorted Set | optional | BackupWorker (if artifact tracking enabled) | Score = Unix timestamp, member = JSON metadata blob. Populated only when artifact tracking is enabled in config. Not written in default configuration. |

---

## Phase 6 — ASN & Datacenter Classification

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|----|--------|-|
| `tor:exit:ips` | SET of IP strings | 3900s (1h + 5m buffer) | Leader instance | Tor exit node IP addresses; refreshed hourly |
| `leader:tor_exit_download` | String (instance_id) | 3600s (1h) | Leader instance | Leader election lock for Tor consensus download |

---

## Phase 11 — RDAP Enrichment

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `rdap:ip:{ip}` | JSON (RDAPResult fields) | 86400s (24h) | RDAPEnricher._cache_result() | Full RDAP enrichment result for one IP address. |
| `rdap:org:{org_handle}` | JSON | 604800s (7d) | RDAPEnricher._cache_result() | Org reputation cache; keyed by registry org handle. |
| `ban_cidr:{cidr}` | String ("1") | expansion_ban_duration | RDAPEnricher._apply_expansion() | CIDR-level ban from automatic block expansion. |

---

## Phase 79 — Management API v2: Bearer Token Infrastructure

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `mgmt:token:{id}` | Hash | none (permanent until revoked; 60s grace TTL during rotation) | `POST /api/v1/tokens`, `POST /api/v1/tokens/{id}/rotate` | Bearer token record. Fields: `id` (UUID4), `name` (human label), `role` (`auditor`\|`analyst`\|`operator`\|`admin`), `hash` (bcrypt of raw token — never returned via API), `created_at` (ISO 8601 UTC), `expires_at` (ISO 8601 UTC or empty string), `last_used_at` (ISO 8601 UTC or empty string). The `hash` field stores a bcrypt digest of the raw bearer token. The raw token is shown only once at creation. *(Phase 79)* |
| `mgmt:token:idx` | SET of token ID strings | none | `POST /api/v1/tokens` (SADD), `DELETE /api/v1/tokens/{id}` (SREM) | Index of all active bearer token IDs. Used by the bearer auth middleware to enumerate tokens for hash-check lookup. *(Phase 79)* |

*Cluster 2 (RBAC) introduced no new Redis keys. Role enforcement is in-process only.*

### Cluster 3 — Resource Model (UUID + managed_by)

| Key pattern | Type | TTL | Written by | Description |
|---|---|---|---|---|
| `allowlist:entry:{uuid}` | Hash | none | `POST /api/v1/allowlist`, migration | Full allowlist resource record. Fields: `id` (UUID4), `entry` (fingerprint/IP), `list_type` (`allowlist`), `managed_by`, `note`, `created_at`, `created_by`, `expires_at`. *(Phase 79)* |
| `allowlist:idx` | SET of UUIDs | none | `POST /api/v1/allowlist` (SADD), `DELETE /api/v1/allowlist/{id}` (SREM) | UUID enumeration index for allowlist. *(Phase 79)* |
| `allowlist:migrated` | String `"1"` | none | Migration (startup) | Flag preventing duplicate migration runs. Set before migrating entries; checked at startup. *(Phase 79)* |
| `blocklist:entry:{uuid}` | Hash | none | `POST /api/v1/blocklist`, migration | Full blocklist resource record. Same fields as allowlist. *(Phase 79)* |
| `blocklist:idx` | SET of UUIDs | none | `POST /api/v1/blocklist` (SADD), `DELETE` (SREM) | UUID enumeration index for blocklist. *(Phase 79)* |
| `blocklist:migrated` | String `"1"` | none | Migration | Migration completion flag for blocklist. *(Phase 79)* |
| `watchlist:entry:{uuid}` | Hash | none | `POST /api/v1/watchlist`, migration | Full watchlist resource record. *(Phase 79)* |
| `watchlist:idx` | SET of UUIDs | none | `POST /api/v1/watchlist` (SADD), `DELETE` (SREM) | UUID enumeration index for watchlist. *(Phase 79)* |
| `watchlist:migrated` | String `"1"` | none | Migration | Migration completion flag for watchlist. *(Phase 79)* |
| `ip_allowlist:entry:{uuid}` | Hash | none | `POST /api/v1/allowlist` with `list_type=ip` | IP/CIDR allowlist resource record. *(Phase 79)* |
| `ip_allowlist:idx` | SET of UUIDs | none | POST/DELETE | UUID index for IP allowlist entries. *(Phase 79)* |
| `ip_allowlist:migrated` | String `"1"` | none | Migration | Migration flag for IP allowlist. *(Phase 79)* |

**Existing proxy SETs kept in sync (dual-write):**
- `ja4:whitelist` — written by `POST /api/v1/allowlist`, removed by `DELETE`
- `ja4:blacklist` — written by `POST /api/v1/blocklist`, removed by `DELETE`
- `ja4:watchlist` — written by `POST /api/v1/watchlist` (new SET, same pattern)
- `static:allowlist` — written by `POST /api/v1/allowlist?list_type=ip`

### Cluster 4 — New Endpoints

| Key pattern | Type | TTL | Written by | Description |
|---|---|---|---|---|
| `webhook:{id}` | Hash | none | `POST /api/v1/webhooks` | Webhook subscription. Fields: `id` (UUID4), `url`, `events` (JSON-encoded list), `secret_hash` (bcrypt of raw secret — never returned via API), `active`, `created_at`, `managed_by`. *(Phase 79)* |
| `webhook:idx` | SET of IDs | none | `POST /api/v1/webhooks` (SADD), `DELETE` (SREM) | Enumeration index for webhook subscriptions. *(Phase 79)* |
| `proxy:reload` | Pub/Sub channel | n/a | `POST /api/v1/nodes/{host}/reload` | Control channel for triggering config reload on proxy instances. Message format: `{"action": "reload", "host": str}`. *(Phase 79)* |

*Note: `mgmt:node:{host}:{port}` heartbeat Hashes are read by `GET /api/v1/nodes` but written by the proxy process, not the management API.*

---

*Last updated: 2026-04-07, Phase 79 Cluster 4 complete*
