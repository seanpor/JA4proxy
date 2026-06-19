<!--
title: Redis_Schema
audience: reference
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
| `session:{ip}` | Hash `{total, resumed}` | 3600s | Go proxy (Phase 5, `internal/security/tcp_analyzer.go`) | TLS session-resumption tracking per IP. *(Phase 309 R3: corrected from the previously-documented `session:ip:{ip}:ja4:{ja4}` — the Go proxy keys on IP only.)* |
| ~~`lifespan:{ip}`~~ | Sorted Set of durations (ms) | 1800s | — | **DEPRECATED (Phase 309 R3): no writer in the Go proxy.** The Python prototype wrote this; it now appears only in the sync-ACL skip-list. |
| `beacon:{ip}:{ja4}` | Sorted Set | trimmed to long window (default 24h) | BeaconingDetector (Phase 9) | Connection timestamps per (IP, JA4); score = member = unix seconds. ZRANGEBYSCORE over the short window feeds the inter-arrival CV computation. |
| `beacon:suspects` | Sorted Set | trimmed to short window (default 1h) | BeaconingDetector (Phase 9; Go gauge phase-309 WP-6) | Leaderboard of active beaconing suspects. Member = `{ip}:{ja4}`, score = last-seen unix seconds; entries older than the short window are trimmed on each write. `ZCARD` backs the `ja4proxy_beaconing_suspects` gauge / `BeaconingDetected` alert. |
| `concurrent:{ip}` | Integer (INCR/DECR) | 60s | Proxy (Phase 5) | Live concurrent connection count per IP |
| `return_visitor:{ip}` | Hash `{first_seen, last_seen, total, allowed, blocked}` | 604800s (7d) | Go proxy (Phase 5, `internal/security/tcp_analyzer.go`) | Return-visitor tracking. *(Phase 309 R3: corrected from the previously-documented `visitor:{ip}`.)* |
| `static:allowlist` | SET of IP/CIDR strings | none | Management UI | UI-added static allowlist entries; config-file entries are authoritative |
| `management:audit_log` | List (last 1000 entries) | none | Management UI | All secops admin actions. Phase 79 C5 enhanced schema — each entry is a JSON object with fields: `timestamp` (ISO 8601 UTC), `actor_id` (token identity or username), `actor_ip` (client IP), `action_type` (dot-separated verb, e.g. `allowlist.created`), `resource_type`, `resource_id`, `before_value` (null on creates), `after_value` (null on deletes), `session_id`, `role` (actor role at time of action). |
| `management:policy_audit` | List (last 1000 entries) | none | Management UI, config reload | Security policy bypass changes |
| `management:gdpr_erasure_log` | LIST of JSON | no TTL (last 1000 entries) | scripts/gdpr_delete.py | Audit trail of GDPR erasure requests; each entry: {timestamp, ip, dry_run, keys_deleted, keys_skipped_hll, zset_members_removed, invoked_by} |

---

## Phase 32 — Attacker Attribution

> **⚠ DEPRECATED (Phase 309 R3) — no live writer.** Written by the Python
> `AttributionManager` (`src/security/attribution.py`), which was deleted with
> the Python proxy. No Go code writes these keys. Retained for historical
> reference only.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `attribution:profile:{fp}` | String (JSON) | 7776000s (90d) | AttributionManager._update_correlation() | Full AttackerProfile JSON (fingerprint, category, timestamps, tags, metadata). |
| `attribution:ips:{fp}` | SET of IP strings | 2592000s (30d) | AttributionManager._update_correlation() | Set of all IP addresses associated with a unique attacker fingerprint. |

---

## Phase 54 — Behavioral Attribution

> **⚠ DEPRECATED (Phase 309 R3) — no live writer.** Written by the Python
> `BehavioralAnalyzer` (`src/security/`), deleted with the Python proxy. No Go
> writer. (`behavioral:burst:` still appears in the Go sync-ACL skip-list but is
> never written.) Retained for historical reference only.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `behavioral:probing:{fp}` | SET of SNI strings | 3600s (1h) | BehavioralAnalyzer._check_sequential_probing() | Set of unique hostnames probed by a specific fingerprint. |
| `behavioral:burst:{sni}` | Sorted Set | 10s | BehavioralAnalyzer._check_coordinated_burst() | Millisecond timestamps of recent hits to an SNI. Member = `{ip}:{ts_ms}`, Score = `ts_ms`. |
| `behavioral:known_ja4` | SET of JA4 strings | none | BehavioralAnalyzer._check_fingerprint_drift() | Registry of all JA4 fingerprints seen in this environment. Used for new-fingerprint alerting. |

---

## Phase 53 — Advanced Traffic Intelligence (Secondary Feeds)

> **⚠ DEPRECATED (Phase 309 R3) — no live writer.** The GreyNoise / AlienVault /
> MISP / ThreatFox / VirusTotal provider classes lived in `src/security/` and
> were deleted with the Python proxy. No Go code writes these keys. Retained for
> historical reference only.

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

> **⚠ DEPRECATED (Phase 309 R3) — no live writer.** Written by the Python
> `ConfidenceManager`, deleted with the Python proxy. No Go writer. Retained for
> historical reference only.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `ja4proxy:confidence:state` | Hash | No TTL | ConfidenceManager | Per-feed confidence tracking: fields `{feed_name}:successes`, `{feed_name}:total`, `{feed_name}:weight`. Updated on each lookup result. In-memory primary; Redis used for persistence across restarts. |

---

## Phase 20 — TAP / SPAN Mode Fingerprints

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `fp:conn:{id}` | Hash | 7d | TAP `FingerprintStore` | Per-connection fingerprint bundle (ja4, ja4s, ja4t, ja4h, ja4x, ja4l, ja4h2, ja4ssh, quic). **Read by:** Go proxy `tap_consumer` (Phase 203a) — *not currently; 203a reads only `fp:os:ip:{ip}`. Listed here for completeness.* |
| `fp:ip:{ip}` | ZSET | 30d | TAP `FingerprintStore` | Per-IP fingerprint history (score = timestamp). |
| `fp:ja4:hll:{ja4}` | HyperLogLog | 30d | TAP `FingerprintStore` | Unique-IP cardinality per JA4. |
| `fp:ja4:count:{ja4}` | String (INCR) | 30d | TAP `FingerprintStore` | Occurrence counter per JA4. |
| `fp:os:count:{fp}` | String (INCR) | 30d | TAP `FingerprintStore` | Per-OS-fingerprint occurrence counter. |
| `fp:os:ip:{ip}` | String (OS class) | 24h | Go TAP sensor `tap.Store` (Phase 316b); formerly Python `FingerprintStore` | Passive OS class observed for the client IP. **Value domain (316b):** exactly one canonical bare class — `windows`, `macos`, `linux`, or `ios` (the `fingerprint.OSClass` vocabulary). `unknown`/ambiguous classifications are **never written** (the key is simply absent), so a reader never sees an encoded or compound value. IP is canonical (`netip.Addr.String()`), v4 and v6. **Read by:** Go proxy `tap_consumer` (Phase 203a) for the OS-mismatch signal, which fires only when both the observed class and the JA4-implied class are concrete and disagree. |
| `fp:ja4t:ip:{ip}` | String (JA4T) | 24h | Go TAP sensor `tap.Store` (Phase 316c) | Passive JA4T TCP fingerprint observed on the client's SYN. **Value:** the canonical FoxIO JA4T string `{window}_{options}_{mss}_{wscale}` (e.g. `65535_2-1-3-1-1-8-4_1460_7`); written only when a client SYN was observed (mid-stream captures write nothing, so the key is simply absent). IP is canonical (`netip.Addr.String()`), v4 and v6. **Read by:** Go proxy `ja4t_consumer` (Phase 316c) for the advisory `tap_ja4t_blocklist` signal, which fires only when the observed JA4T is on the operator-configured blocklist (empty by default → silent). |
| `fp:ja4_to_ja4s:{ja4}` | Hash | 7d | TAP `FingerprintStore` | JA4 → JA4S co-occurrence map. |
| `fp:ban_intent:ip:{ip}` | String (provenance) | 1h (configurable) | Go TAP sensor `tap.Enforcer` (Phase 316d) | Advisory watchlist entry written whenever a client's observed JA4T is on the sensor's enforcement blocklist. **Value:** provenance string `ja4t={fingerprint}`. **Always** written on a match (even when armed), never enforced — it is the monitor-first surface and audit trail for sensor enforcement. Lives under `fp:*` so the sensor's least-privilege ACL already covers it. IP canonical, v4 and v6. **Read by:** humans / dashboards only (no inline consumer — intentional). |

> **`ban:{ip}` may also be written by the TAP sensor (Phase 316d).** When the
> sensor is *armed* (`--enforce` **and** a widened Redis ACL `~ban:*`), a
> blocklisted client also gets a short-TTL `ban:{ip}` (value
> `tap_enforce:ja4t={fingerprint}`, default 5m) — the **same** canonical
> operator-ban key the inline proxy already hard-blocks on (see the Phase 231a
> row). The inline proxy enforces it on the client's *next* connection; it
> ignores the value, which exists purely for provenance/redaction. Off by
> default: the unarmed sensor writes only `fp:ban_intent:ip`.

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
| `backup:operation_lock` | String (RFC3339 timestamp) | 600s (10m) | `internal/backup.Engine` (Go, `ja4p backup`, phase-315a); restore in 315b | Distributed lock (`SET NX EX 600`) preventing concurrent backup/restore from producing a torn artifact. The Go engine acquires it at the top of a run and releases it on completion/failure. (The Python `BackupWorker`/`BackupRestorer` that previously wrote this were archived in `5afeba26`.) |
| `backup:last_restore` | String (RFC3339 timestamp) | none | `internal/backup` (Go, `ja4p restore`, phase-315b) | Timestamp of the last restore. (Was the archived Python `BackupRestorer`.) |

---

## Phase 57 — Cloud Backup & Restore Hardening

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `backup:restored_from` | String (JSON) | none | `internal/backup` (Go, `ja4p restore`, phase-315b) | Written after each successful restore. JSON: `{"filename","restored_at","keys_count","actor"}`. Audit trail + post-restore sanity check. A restore also appends a `backup.restored` entry to `management:policy_audit`. |
| `backup:artifacts` | Sorted Set | optional | BackupWorker (if artifact tracking enabled) | Score = Unix timestamp, member = JSON metadata blob. Populated only when artifact tracking is enabled in config. Not written in default configuration. |

---

## Phase 6 — ASN & Datacenter Classification

> **⚠ DEPRECATED (Phase 309 R3) — no live writer.** The Go proxy classifies Tor
> exit nodes from a **file-backed** list loaded into an in-process set
> (`config.tor_exit_list`, `internal/config/loader.go`), not from Redis. No Go
> code writes either key below; they were written by the deleted Python proxy's
> leader instance. Retained for historical reference only.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|----|--------|-|
| `tor:exit:ips` | SET of IP strings | 3900s (1h + 5m buffer) | Leader instance (Python, removed) | Tor exit node IP addresses; refreshed hourly. |
| `leader:tor_exit_download` | String (instance_id) | 3600s (1h) | Leader instance (Python, removed) | Leader election lock for Tor consensus download. |

---

## Phase 11 — RDAP Enrichment

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `rdap:ip:{ip}` | JSON (RDAPResult fields) | 86400s (24h) | RDAPEnricher._cache_result() | Full RDAP enrichment result for one IP address. |
| `rdap:org:{org_handle}` | JSON | 604800s (7d) | RDAPEnricher._cache_result() | Org reputation cache; keyed by registry org handle. |
| `ban_cidr:{cidr}` | String ("1") | expansion_ban_duration | RDAPEnricher._apply_expansion() | CIDR-level ban from automatic block expansion. |

---

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

*Note (updated Phase 309 R3): The Go proxy **now publishes a heartbeat** —
`cmd/ja4pd/main.go` writes `proxy:heartbeat:{hostname}` (`SET … EX 90` every 60s,
added in Phase 232b; documented in the Go-proxy runtime section below). The
`mgmt:node:{host}:{port}` Hash that `GET /api/v1/nodes` historically read still
has no producer; node-status reads should be served from `proxy:heartbeat:*`.
See `docs/phases/PHASE_234.md` §5.0.*

### Phase 79 — Cluster 6: TOTP MFA

| Key | Type | TTL | Written by | Purpose |
|-----|------|-----|-----------|---------|
| `mgmt:totp:{user_id}` | String | none | `GET /auth/mfa/totp/setup` | Fernet-encrypted base32 TOTP secret. Caller must decrypt with `MANAGEMENT_MFA_ENCRYPTION_KEY` (Fernet). *(Phase 79)* |
| `mgmt:totp:backup:{user_id}` | LIST | none | `GET /auth/mfa/totp/setup` | bcrypt-hashed backup codes (8 entries). Each entry is consumed (LREM) on first successful use — single-use. *(Phase 79)* |
| `mgmt:totp:used:{user_id}:{code}` | String `"1"` | 90s | `POST /auth/mfa/totp/verify` | Anti-replay guard. Set after a TOTP code is successfully verified; presence causes the same code to be rejected within the 90-second valid window (±1 step = ±30s). *(Phase 79)* |
| `mgmt:mfa:session:{sha256_of_jwt}` | String `"verified"` | 8h | `POST /auth/mfa/totp/verify` | Marks a cookie-JWT session as MFA-verified. Key is SHA-256 of the raw JWT string. TTL matches JWT expiry. Only set for cookie-JWT sessions; bearer-token callers bypass the gate. *(Phase 79)* |

---

### Phase 79 — Cluster 7: WebAuthn / FIDO2

| Key | Type | TTL | Written by | Purpose |
|-----|------|-----|-----------|---------|
| `mgmt:webauthn:challenge:{user_id}` | String (JSON) | 5min | `POST /auth/mfa/webauthn/register/begin`, `POST /auth/mfa/webauthn/auth/begin` | Active challenge for this user. JSON: `{"challenge": "<base64url>", "type": "registration"\|"authentication"}`. Deleted after successful complete. *(Phase 79)* |
| `mgmt:webauthn:credential:{credential_id}` | Hash | none | `POST /auth/mfa/webauthn/register/complete` | Per-credential record. Fields: `user_id`, `public_key` (base64url), `sign_count` (updated after each assertion), `created_at` (ISO 8601). `credential_id` is base64url-encoded. *(Phase 79)* |
| `mgmt:webauthn:user:{user_id}:credentials` | SET of credential ID strings | none | `POST /auth/mfa/webauthn/register/complete` (SADD) | All credential IDs registered by this user. Used by auth/begin to build `allowCredentials` and by register/begin to build `excludeCredentials`. *(Phase 79)* |

---

### Phase 79 — Cluster 8: SAML 2.0 SSO

| Key | Type | TTL | Written by | Purpose |
|-----|------|-----|-----------|---------|
| `mgmt:saml:nonce:{nonce}` | String (redirect URL) | 5min | `GET /auth/sso/saml/login` | CSRF protection nonce. Value is the post-login redirect URL (default "/"). Generated at login, consumed and deleted at ACS — single-use. *(Phase 79)* |

---

### Phase 79 — Cluster 9: OIDC SSO

| Key | Type | TTL | Written by | Purpose |
|-----|------|-----|-----------|---------|
| `mgmt:oidc:state:{state}` | String (JSON) | 5min | `GET /auth/sso/oidc/login` | PKCE and CSRF state. JSON: `{"code_verifier": "...", "redirect": "/"}`. Generated at login, consumed (deleted) at callback — single-use. *(Phase 79)* |

---

---

---

## Phase 80 — ECS Structured Logging & SIEM Integration

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `events:connection` | Redis Stream | none | Go proxy daemon (`cmd/ja4pd/main.go` `handleConn()`) | Source stream of connection events written via fire-and-forget XADD after every connection decision. Each entry has a single field `event` = ECS JSON string. Consumed by the webhook dispatcher via `XREAD` with `lastID` tracking; no consumer group required. |
| `webhooks:dlq` | Redis Stream | none | Webhook `Dispatcher.deliverToEndpoint()` | Dead-letter queue for webhook deliveries that exhausted all retry attempts. Each entry has a single field `payload` = original ECS event JSON (including the `signature` field). Operators must manually inspect and replay or discard DLQ entries. |

---

## Phase 82 — Policy-as-Code, Shadow Mode & Governance

> **⚠ DEPRECATED (Phase 309 R3) — no live writer.** The governance/shadow-mode
> applier and analytics simulation runner referenced here have no implementation
> in the current `src/` or `management/` tree (no writer found for
> `decisions:*` / `sim:*`). Retained for historical reference only.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `decisions:pending:{id}` | Hash | none (explicit delete on approve/reject) | Management API (`src/governance/policy_applier.py`) | Pending approval queue entry. Fields: `proposed_by`, `action`, `resource_type`, `resource_id`, `payload`, `status`, `created_at`, `itsm_ticket`. |
| `decisions:history` | Stream (XADD) | none | Management API (`src/governance/policy_applier.py`) | Append-only log of all approve/reject decisions. Each entry records actor, decision, timestamp, and the original `decisions:pending` payload. |
| `sim:conn:{hour_epoch}:{conn_id}` | Hash | 7776000s (90d) | Analytics node (`analytics/signal_retention.py`) | Connection signal snapshot for shadow mode replay. Fields: `timestamp`, `source_ip`, `ja4`, `score`, `signals` (JSON array). LZ4-compressed when `shadow_mode.backend: redis`. |
| `sim:job:{sim_id}` | Hash | 604800s (7d) | Analytics node (`analytics/simulation_runner.py`) | Simulation job state. Fields: `status`, `hypothetical_dial`, `from_ts`, `to_ts`, `result_json`. |

---

## Phase 84 — Compliance Reporting & Evidence Pack

| Key pattern | Type | TTL | Written by | Notes |
|-------------|-|-|--------|-|
| `ja4proxy:events` | Stream | none (XTRIM via purge) | Proxy / Go proxy | Main connection event stream. Purged to enforce `gdpr.retention_days` via `POST /api/v1/compliance/purge-expired`. |
| `gdpr:purge:last_run` | String | none | Management API (`management/compliance/purge.py`) | ISO-8601 timestamp of the last GDPR purge run. |
| `gdpr:purge:last_summary` | String (JSON) | none | Management API (`management/compliance/purge.py`) | JSON summary of the most recent purge: `stream_events_purged`, `beaconing_keys_purged`, `rv_hashes_purged`, `monthly_aggs_purged`, `errors`, `completed_at`. |
| `reporting:monthly:{YYYY-MM}` | Hash | none | Analytics node | Monthly aggregate for compliance trend data. Fields: `connections_total`, `blocked_total`, `flagged_total`, `allowed_total`, `unique_ips`. Written by analytics; read by the report renderer. |

---

*Last updated: 2026-04-08, Phase 84 complete*

---

## Phase 85 — Threat Intelligence Feed Ingestion

All keys are written by the analytics-container feed runner
(`src/analytics/ti_feeds/runner.py`) and the per-feed state helper
(`src/analytics/ti_feeds/state.py`). The Management API does **not** read or
write these keys directly — they are an internal sidecar index that records
which rules each feed created so differential cleanup can run after every poll.
Provenance for the rules themselves lives on the canonical resources via
`managed_by="feed"` and `note="feed:{feed_id}:{stix_id}"` (blocklist) or
`reason="feed:{feed_id}"` (bans).

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `ti_feed:{feed_id}:blocklist_uuids` | SET | none | `state.record_created()` | Resource UUIDs created by this feed via `POST /api/v1/blocklist`. Used at cleanup time to know what to `DELETE`. A rule is **only** removed by the feed that created it. |
| `ti_feed:{feed_id}:ban_ips` | SET | none | `state.record_created()` | IP strings (canonical form, IPv6 fully expanded) banned by this feed via `POST /api/v1/bans/{ip:path}`. Same lifecycle as `blocklist_uuids`. |
| `ti_feed:{feed_id}:active_stix_ids` | HASH | none | `state.replace_active_stix_ids()` | Map `{stix_indicator_id → resource_uuid_or_ip}` representing the indicators that were present in the **last successful** poll. Differential cleanup compares the next poll's set against this hash, deletes the dropped entries, then atomically replaces the hash. |
| `ti_feed:{feed_id}:poll_state` | HASH | none | `state.update_poll_state()` | Per-feed scheduling and health: `last_success_ts`, `last_error_ts`, `last_added_after` (TAXII watermark), `circuit_state` (`closed`/`half_open`/`open`), `failure_count`, `consecutive_successes`. Drives the circuit breaker (§5.4 of Phase 85 design doc) and the runner's next-poll calculation. |
| `ti_feed:{feed_id}:runtime_enabled` | String (`"1"` / `"0"`) | none | `POST /api/v1/threat-intel/feeds/{feed_id}/{enable\|disable}` | UI toggle override. When unset, the feed inherits the static `enabled:` value from `config/proxy.yml`. When set, this key wins and survives container restarts. |
| `ti_feed:leader_lock` | String + TTL | 30 s | `runner.py` leader-election loop | Single-leader election across analytics replicas. Pattern is the same one Phase 8 uses for the Spamhaus feed manager — only the holder of this key polls feeds. The 30 s TTL bounds the recovery window after a crashed leader. |

Naming hygiene. `feed_id` is operator-supplied via `config/proxy.yml` and
is interpolated unescaped into every key in this section. The runner **must**
validate `feed_id` against a strict regex (`^[a-z0-9][a-z0-9_-]{1,63}$`) at
config-load time so it cannot contain `:` or otherwise pivot into another key
namespace (for example `ban_cidr:` from Phase 11). This validation is tracked
as a Phase 85 security follow-up (see Phase 85 security findings).

---

## Phase 316e — EDL Export Feed

The outbound EDL feed (`management/api/routes/edl.py`,
`GET /api/v1/edl/{list_name}`) is **read-only over ban state** — it serves a
plaintext blocklist that firewalls (F5, Palo Alto) pull. It introduces no new
persisted intelligence; it only **reads** `ban:{ip}` (Phase 231a / TAP 316d) and
`ban_cidr:{cidr}` (Phase 11) via SCAN. The one key it writes is a transient
per-token poll-rate limiter.

| Key pattern | Type | TTL | Written by | Notes |
|---|---|---|---|---|
| `edl:ratelimit:{identity}` | ZSET (sorted set, score = epoch seconds) | 60 s | `edl._check_rate_limit` | Sliding-window poll-rate limit per EDL token identity. Same pattern as the Phase-85 threat-intel limiter; fail-open (any Redis error skips the check rather than blocking a poll). `identity` is the token name from the `mgmt:token:*` store, never raw client input. |

---

## Go Proxy Runtime Keys (Phases 6–316)

> Added in Phase 309 R3. These keys are written by the **Go proxy**
> (`cmd/ja4pd`, `internal/`) on the live hot path but were never recorded in the
> per-phase tables above (the schema doc predates the Go signal-module port).
> They are listed here key-by-key, each verified against a concrete writer.

| Key pattern | Type | TTL | Written by | Notes |
|-------------|------|-----|------------|-------|
| `ratelimit:ip:{ip}` | Sorted Set (sliding window, Lua) | window-bounded | `internal/security/rate_limiter.go` | Per-IP request rate. `ZCARD` over the window backs the by-IP rate signal. |
| `ratelimit:ja4:{ja4}` | Sorted Set (sliding window, Lua) | window-bounded | `internal/security/rate_limiter.go` | Per-JA4 request rate (by-JA4 signal). |
| `ratelimit:ip_ja4:{ip}:{ja4}` | Sorted Set (sliding window, Lua) | window-bounded | `internal/security/rate_limiter.go` | Per-(IP, JA4) request rate. The three strategies vote 2-of-3 in the scorer. |
| `dns:fcrdns:{ip}` | String (verdict) | configurable (default 24h) | `internal/security/dns_enrichment.go` | Cached FCrDNS verdict for the client IP. Value domain: `no_ptr`, `fcrdns_failed`, `confirmed_residential`. Written fire-and-forget after async PTR/forward resolution. IP canonical, v4 and v6. |
| `abuseipdb:{ip}` | String (confidence int 0–100) | 86400s (24h) | `internal/security/abuseipdb.go` | Cached AbuseIPDB confidence score. Written after a successful API call; absence means not-yet-enriched (fail-open). |
| `audit:last_score:{ip}` | String (int 0–100) | 300s (5m) | `internal/security/pipeline.go` `auditDecision()` | Last risk score seen for this IP, used for cross-mesh score-drift detection (`>20`-point swing increments `ja4proxy_signal_drift_total` and logs a warning). |
| `proxy:heartbeat:{hostname}` | String (Unix seconds) | 90s | `cmd/ja4pd/main.go` (Phase 232b) | Liveness heartbeat; `SET … EX 90` written immediately at startup then every 60s. `DEL` on graceful shutdown; TTL expiry covers hard crashes. Read by the management API for node-status. |
| `geoip:blocked_cidrs` | SET of CIDR strings | none | `cmd/ja4pd/main.go` | Operator country/CIDR blocklist seeded from config and kept in sync; loaded into the in-process trie. Refreshed on the `geoip:cidr:update` pub/sub signal. |
| `config:dial:sig` | String (HMAC signature) | none | Management API / sync agent | Detached HMAC over `config:dial`. The proxy refuses to trust a dial value whose signature is missing while the integrity key is set (defaults to dial 0 — fail-safe). See `internal/redis/client.go`. |
| `ja4proxy:dc:{dc}:sync:out` | Redis Stream | maxlen-bounded | `internal/cluster/sync/agent.go` | Per-datacenter outbound mutation stream for multi-DC replication. One consumer group per peer (avoids head-of-line blocking). Carries `ban:*`, `ja4:whitelist`/`ja4:blacklist`, and `config:dial` mutations only (see `maybeSync` allow-list). |

### Management-API keys not previously documented

These are written by the FastAPI management service (`management/`) and read by
the proxy or the UI. Listed for completeness; consult the route source for the
authoritative field set.

| Key pattern | Type | Written by | Notes |
|-------------|------|------------|-------|
| `ja4:watchlist` | SET of JA4 strings | `POST /api/v1/watchlist` | Watch-only JA4 list (dual-write companion to `ja4:whitelist`/`ja4:blacklist`). |
| `static:blocklist` / `static:watchlist` | SET of IP/CIDR | management API | UI-added static IP lists (companions to `static:allowlist`). |

## Pub/Sub Channel Registry

The Go proxy subscribes to the following channels (`internal/redis/pubsub.go`).
Channels marked *critical* are HMAC-verified when a pub/sub secret is configured
(JA4PROXY-2026-0019) — unsigned messages are dropped.

| Channel | Critical | Effect on proxy | Published by |
|---------|----------|-----------------|--------------|
| `config:reload` | yes | Triggers full config hot-reload | sync agent / SIGHUP path (see discrepancy note) |
| `config:dial:change` | yes | Triggers reload (re-reads dial) | `internal/cluster/sync/agent.go` |
| `ja4:blacklist:add` / `ja4:blacklist:remove` | yes | Refreshes in-process JA4 blacklist | management API |
| `ja4:whitelist:add` / `ja4:whitelist:remove` | yes | Refreshes in-process JA4 whitelist | management API |
| `geoip:cidr:update` | yes | Reloads `geoip:blocked_cidrs` into the trie | management API |

## Known Code/Schema Discrepancies (Phase 309 R3)

The R3 audit surfaced two writer/reader mismatches in **code** (not in this
doc). They are recorded here so the schema reflects reality; fixing them is
tracked as separate follow-up work, not part of this documentation pass.

1. **`MultiCheck` reads bare `whitelist` / `blacklist` keys (dead code).**
   `internal/redis/client.go` `MultiCheck()` calls `SIsMember(ctx, "blacklist", …)`
   and `SIsMember(ctx, "whitelist", …)` — bare keys that **nothing writes** (every
   writer uses the namespaced `ja4:whitelist` / `ja4:blacklist`). `MultiCheck` is
   declared on the `RedisClient` interface but has **no caller** on the hot path,
   so the mismatch is currently a latent landmine rather than a live bug. The
   proxy actually consults JA4 lists via the in-process sets loaded from config
   and from `ja4:whitelist`/`ja4:blacklist` `SMEMBERS` at startup/refresh.

2. **Config-reload channel name mismatch (live).** The proxy subscribes to
   `config:reload` (colon — `internal/redis/pubsub.go`). The management API's
   `POST /api/v1/config/reload` publishes to `config.reload` (**dot** —
   `management/api/routes/config_ops.py`). The two names do not match, so a
   UI-triggered config reload never reaches the proxy. (Dial changes and
   blacklist/whitelist edits use their own correctly-matched channels above and
   are unaffected.)

---

*Last updated: 2026-06-19, Phase 309 R3 — REDIS_SCHEMA reconciled against Go proxy code*

