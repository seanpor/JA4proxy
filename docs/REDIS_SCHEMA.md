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

---

## Phase 80 — ECS Structured Logging & SIEM Integration

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `events:connection` | Redis Stream | none | Go proxy (`cmd/proxy/main.go` `handleConn()`) | Source stream of connection events written via fire-and-forget XADD after every connection decision. Each entry has a single field `event` = ECS JSON string. Consumed by the webhook dispatcher via `XREAD` with `lastID` tracking; no consumer group required. |
| `webhooks:dlq` | Redis Stream | none | Webhook `Dispatcher.deliverToEndpoint()` | Dead-letter queue for webhook deliveries that exhausted all retry attempts. Each entry has a single field `payload` = original ECS event JSON (including the `signature` field). Operators must manually inspect and replay or discard DLQ entries. |

---

## Phase 82 — Policy-as-Code, Shadow Mode & Governance

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `decisions:pending:{id}` | Hash | none (explicit delete on approve/reject) | Management API (`src/governance/policy_applier.py`) | Pending approval queue entry. Fields: `proposed_by`, `action`, `resource_type`, `resource_id`, `payload`, `status`, `created_at`, `itsm_ticket`. |
| `decisions:history` | Stream (XADD) | none | Management API (`src/governance/policy_applier.py`) | Append-only log of all approve/reject decisions. Each entry records actor, decision, timestamp, and the original `decisions:pending` payload. |
| `sim:conn:{hour_epoch}:{conn_id}` | Hash | 7776000s (90d) | Analytics node (`analytics/signal_retention.py`) | Connection signal snapshot for shadow mode replay. Fields: `timestamp`, `source_ip`, `ja4`, `score`, `signals` (JSON array). LZ4-compressed when `shadow_mode.backend: redis`. |
| `sim:job:{sim_id}` | Hash | 604800s (7d) | Analytics node (`analytics/simulation_runner.py`) | Simulation job state. Fields: `status`, `hypothetical_dial`, `from_ts`, `to_ts`, `result_json`. |

---

*Last updated: 2026-04-07, Phase 82 complete*
