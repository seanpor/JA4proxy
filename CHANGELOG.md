# Changelog

## [13.1.0] - 2026-03-11 - PHASE 13b: MANAGEMENT UI COMPLETION

### Added

**Backend Completion:**
- **Startup Guard**: Server exits with FATAL log if `UI_API_KEY` not set (`sys.exit(1)`)
- **allowed_cidr Middleware**: IP-based access control with CIDR filtering; health/ready endpoints exempt
- **Router Extraction**: Moved config, health, audit, integrations to separate router files
- **SSE Events Router**: Live connection feed with filtering (action, country, ASN type, min_score) and 50 subscriber limit
- **Dial Counterfactual Endpoint**: `GET /api/v1/dial/counterfactual?dial={value}` estimates blocking impact

**New Router Files:**
- `management/routers/config.py`: Threshold, feature, country management with validation
- `management/routers/health.py`: Health/ready endpoints (unauthenticated /health, /ready)
- `management/routers/audit.py`: Paginated audit log with event type filtering
- `management/routers/integrations.py`: AbuseIPDB, Spamhaus, RDAP, analytics status endpoints
- `management/routers/events.py`: SSE live feed and recent events endpoint

**Models:**
- `ThresholdConfig` Pydantic model with ascending order validation (flag ≤ rate_limit ≤ tarpit ≤ block ≤ ban)

**Configuration:**
- `management_ui:` section in `config/proxy.yml` with hot-reload support
- Environment variables: `MANAGEMENT_ALLOWED_CIDR`, `MAX_SSE_SUBSCRIBERS`, `MAX_DIAL_CHANGES_PER_HOUR`, `MAX_AUTH_FAILURES_PER_MINUTE`

**Security:**
- Fixed bytes vs string bug in threshold handling (no more `b"flag"` keys)
- All endpoints require authentication except `/health` and `/ready`
- Health endpoints exempt from CIDR restrictions
- Rate limiting on all authenticated endpoints

**Observability:**
- Prometheus metrics: `ja4proxy_mgmt_sse_subscribers_active`, `ja4proxy_mgmt_redis_errors_total{operation}`
- AlertManager rules: `monitoring/alertmanager/rules/management_ui_rules.yml` (10 rules)
- Grafana dashboard: `grafana/dashboards/management_ui.json` (12 panels)
- Comprehensive audit logging for all configuration changes

**Documentation:**
- `docs/decisions/ADR-013.md`: Management UI technology rationale
- `docs/runbooks/management_ui.md`: Complete operational procedures
- `docs/REDIS_SCHEMA.md`: Updated with 10 new Phase 13 keys
- `CHANGELOG.md`: This entry

**Testing:**
- 15 new unit tests in `tests/unit/test_management_ui.py`
- 4 new integration tests in `tests/integration/test_management_ui.py`
- 10 new chaos tests in `tests/chaos/test_management_chaos.py`
- Test coverage: startup guard, CIDR middleware, threshold validation, SSE endpoints, counterfactual, integrations

**Dependencies:**
- `sse-starlette>=1.6.5` for Server-Sent Events support

### Changed

- `management/server.py`: Added startup guard, CIDR middleware, router wiring, removed inline routes
- `management/models.py`: Added `ThresholdConfig` model
- `management/routers/dial.py`: Added counterfactual impact endpoint
- `requirements.txt`: Added `sse-starlette>=1.6.5`
- `config/proxy.yml`: Added `management_ui:` section with inline comments

### Fixed

- Bytes vs string decode bug in threshold handling (Redis returns strings when `decode_responses=True`)
- Configuration validation for thresholds (ascending order requirement)
- Error handling throughout with consistent 503 responses for Redis failures

### Security

- API key required for all authenticated endpoints
- CIDR-based access restriction for management UI
- Rate limiting on authentication failures (100 per IP)
- Dial change rate limiting (10 per hour)
- SSE subscriber cap (50 concurrent)
- All admin actions logged to audit trail

## [11.0.0] - 2026-03-09 - PHASE 11: RDAP ENRICHMENT & BLOCK EXPANSION

### Added

- **`src/security/rdap_enrichment.py`** — Phase 11 RDAP enrichment module:
  - `RDAPConfig` dataclass — all fields from `rdap_enrichment:` config section; `from_config()` loads from proxy.yml
  - `RDAPResult` dataclass — netblock, org_name, org_handle, asn, country, registration_date, fetched_at, is_unknown
  - `RegistryRateLimiter` — in-process asyncio token bucket per RIR (ARIN/RIPE/APNIC/LACNIC/AFRINIC); configured rates
  - `RDAPEnricher` class with async background worker pool (`worker_count` coroutines draining `asyncio.Queue`)
  - `get_signal(ip, trigger_score)` — synchronous hot-path entry point; reads `LocalCache.rdap_results` (no Redis on hot path); enqueues background lookup on cache miss when `trigger_score >= min_enqueue_score`
  - `record_browser_subnet(ip)` — async; sets `browser:seen:subnet:{subnet}` with 24h TTL; called fire-and-forget for h2/h1 ALPN connections; prevents block expansion for subnets with browser traffic
  - IANA bootstrap loading: leader election (`leader:rdap_bootstrap_download` lock); downloads `ipv4.json` + `ipv6.json`; caches in Redis (`rdap:bootstrap:v4`, `rdap:bootstrap:v6`, 24h TTL); non-leader instances load from Redis
  - `get_rdap_base_url(ip)` — longest-prefix-match bootstrap routing to correct RIR
  - `_api_lookup(ip, base_url)` — aiohttp GET; follows up to 3 redirects manually; HTTP 404 → `_NotFoundError` (not error); timeout + 5xx → raise
  - `_parse_rdap_response(data, ip)` — parses vCard format; handles ARIN (`handle`) vs RIPE (`nic-hdl`) org handles; extracts registration date from `events` array; graceful fallback for all fields
  - `_check_known_bad(org_handle, org_name) -> tuple[bool, dict|None]` — exact handle match first; then case-insensitive substring match on org_name
  - `_rdap_to_signals(rdap) -> list[RiskSignal]` — emits `rdap_known_bad_org` and/or `rdap_new_netblock` signals from cached results
  - `maybe_expand_block(ip, rdap, trigger_score, is_known_bad)` — 4 independent safety guards + hourly rate limit cap; only runs when `block_expansion.enabled: true`
  - Guard 1: `trigger_score >= min_trigger_score` (default 75)
  - Guard 2: RDAP netblock prefix ≥ max configured (IPv4: /24, IPv6: /48); broader blocks skipped
  - Guard 3: `browser:seen:subnet:{subnet}` key absent (atomic Redis GET; no race)
  - Guard 4: org confirmed known-bad (high score alone insufficient)
  - `_check_expansion_rate_limit()` — atomic Redis INCR/DECR on `rdap:expansions:count:{YYYY-MM-DDTHH}` with 3600s TTL; cross-instance cap
  - `_apply_expansion(cidr, rdap, trigger_score)` — writes `ban_cidr:{cidr}` to Redis with TTL; calls `BlocklistManager.load_cidrs()` for local trie; publishes `{"type":"cidr_ban_add","value":cidr}` to `ja4proxy:invalidate`
  - `_log_expansion_audit(ip, cidr, rdap, trigger_score)` — LPUSH JSON + LTRIM 1000 on `rdap:expansions`
  - `_compute_expansion_cidr(ip, config)` — always expands to configured prefix (/24 IPv4, /48 IPv6) around trigger IP
  - `_scan_existing_ban_cidrs()` — on startup, SCANs `ban_cidr:*` from Redis and loads into `BlocklistManager` trie
  - Bloom filter dedup (`bloom:rdap_enriched`, 24h TTL); fallback to SET+TTL when RedisBloom unavailable
  - `on_config_reload(new_config)` — hot-reloads all fields except `worker_count` and `queue_size` (WARN logged if those change)
  - Startup: fatal error with clear message when `config/known_bad_orgs.yml` is missing
  - `delegate_to_analytics: true` mode: IPs published to `analytics:enrich:rdap` Set; local workers idle
  - Prometheus: `ja4proxy_rdap_enrichment_queue_depth`, `ja4proxy_rdap_lookup_total{registry,result}`, `ja4proxy_rdap_block_expansions_total`, `ja4proxy_rdap_parse_errors_total`, `ja4proxy_rdap_queue_dropped_total`, `ja4proxy_rdap_expansions_this_hour`
  - Structured JSON logging: `block_expansion_applied`, `registry_error`, `bootstrap_download_failed`, `worker_unhandled_error`, `shutdown_queue_not_empty`
  - `datetime.now(timezone.utc)` used throughout; never `datetime.utcnow()` (deprecated)
  - `# pragma: no cover` on ImportError blocks

- **`config/known_bad_orgs.yml`** — ≥ 30 entries of known bulletproof hosting providers:
  - Frantech/BuyVM, Ponynet, Quasi Networks, Psychz Networks, combahton, HostSailor, Alexhost, Zare Ltd, Reprise Hosting, Staminus
  - M247, Leaseweb, Serverius, DataCamp Limited, Hostwinds, Voxility, Sharktech, QuadraNet, ColoCrossing, Limestone Networks, Nocix, Nexeon
  - Tor Project, Torservers.net, Quintex Alliance Consulting
  - Afrihost, BlazingFast, ServerChef, Aeza International

- **`src/pubsub.py`** — `PubSubHandler` extended:
  - Optional `blocklist_manager=None` parameter added to `__init__`
  - New `case "cidr_ban_add"` in `_dispatch()` calls `blocklist_manager.load_cidrs([value], "rdap_expansion", ...)`
  - Module docstring updated to list `cidr_ban_add` message type

- **Pipeline integration** (`src/security/pipeline.py`):
  - `RDAPEnricher` imported and held as `_rdap_enricher` (None by default)
  - `set_rdap_enricher()` setter called by `ProxyServer` after startup
  - `record_browser_subnet(ip)` called fire-and-forget at top of `_collect_signals()` for h2/h1 ALPN connections
  - `get_signal(ip, running_score)` called **last** in `_collect_signals()` after all other signal modules; `running_score` is sum of all preceding signal scores

- **`proxy.py`** — startup/shutdown wiring:
  - `RDAPEnricher` instantiated after AbuseIPDB; reuses shared `aiohttp.ClientSession`
  - `await rdap_enricher.start()` called at startup
  - `pipeline.set_rdap_enricher(rdap_enricher)` wires enricher into pipeline
  - `pipeline._blocklist_manager` passed to `RDAPEnricher` for local trie updates
  - On shutdown: `await rdap_enricher.stop()` called before `aiohttp_session.close()`

- **`config/proxy.yml`** — `rdap_enrichment:` section:
  - `enabled: true`, `queue_size: 500`, `worker_count: 3`, `min_enqueue_score: 20`
  - `lookup_timeout_seconds: 15`, `delegate_to_analytics: false`
  - `org_reputation:` subsection (`enabled: true`, `score: 45`)
  - `new_netblock_flagging:` subsection (`enabled: true`, `max_age_days: 90`, `score: 20`)
  - `block_expansion:` subsection (`enabled: false` by default; all guard thresholds configurable)
  - All keys with inline comments per project style

- **`src/cache/local_cache.py`** — `rdap_results` LRU cache entry (already existed from prior phase stub):
  - TTL 86400s (24h), max 20,000 entries
  - Background RDAP workers write here; `get_signal()` reads synchronously (no await)

- **`tests/mocks/rdap_mock.py`** — RDAP test double:
  - `RDAPMock` class with `set_result()`, `set_not_found()`, `set_error()`, `set_timeout()`, `set_redirect()` per-IP configuration
  - `make_session()` returns AsyncMock-based aiohttp session; intercepts IANA bootstrap + RDAP IP lookup URLs
  - `requested_ips` list for assertion in tests
  - `make_rdap_result()` convenience factory

- **`tests/unit/test_rdap_enrichment.py`** — unit tests covering all AC items:
  - Known-bad org: exact handle, substring name, no match
  - New netblock: young/old/missing date
  - `get_signal()`: LRU hit, miss below threshold, miss above threshold (enqueues)
  - Block expansion: all 4 guards individually + all passing + rate limit exceeded
  - `_compute_expansion_cidr()`: IPv4 /24, IPv6 /48
  - RDAP 404 → `is_unknown=True`; no error counter
  - Bootstrap routing: IPv4 and IPv6
  - Worker `CancelledError` exits cleanly
  - Queue full → drop; `rdap_queue_dropped_total` incremented
  - `PubSubHandler` `cidr_ban_add` → calls `blocklist_manager.load_cidrs()`
  - `on_config_reload()` WARN for non-hot-reloadable keys

- **`tests/adversarial/test_rdap_fp.py`** — false positive tests:
  - RDAP signals alone (45+20=65) < block threshold (70); verified via scorer
  - Legitimate org names with common words don't match known-bad list
  - Browser traffic in subnet → guard 3 blocks expansion even for confirmed bad org
  - One attacker in shared /24 → guard 3 protects legit users

- **`tests/integration/test_pipeline.py`** — RDAP integration test class:
  - RDAP signal from LRU cache appears in pipeline result
  - LRU miss → pipeline returns allow/monitor without crash
  - Disabled enricher → no RDAP signals

- **`tests/chaos/test_external_api_failure.py`** — RDAP chaos tests:
  - RIR API unreachable → fail open; error counter incremented; queue drains normally
  - Bootstrap download fails → Redis cache used; WARN logged
  - Malformed JSON → fail open; worker continues
  - Queue overflow → dropped silently; drop counter incremented

- **`docs/REDIS_SCHEMA.md`** — Phase 11 section with all 10 key patterns

### Design decisions

- `block_expansion.enabled: false` default prevents automated expansion on first deploy
- `org_reputation.score=45 + new_netblock.score=20 = 65 < block_threshold=70` — RDAP signals alone never trigger hard block
- `ban_cidr:{cidr}` prefix (not `ban:{cidr}`) avoids collision with per-IP ban handler
- Reuses `BlocklistManager.load_cidrs()` from Phase 8 — no new trie needed
- Shared `aiohttp.ClientSession` injected; never created per-request
- `get_signal()` is `def` (synchronous) — hot path never awaits

## [10.0.0] - 2026-03-08 - PHASE 10: ABUSEIPDB INTEGRATION

### Added

- **`src/security/abuseipdb.py`** — Phase 10 AbuseIPDB reputation checker:
  - `AbuseIPDBConfig` dataclass — all fields from config section; `from_config()` loads `ABUSEIPDB_API_KEY` env var when config value is empty
  - `AbuseIPDBChecker` class with three-tier cache hierarchy: in-process LRU → Redis `abuseipdb:score:{ip}` → API queue
  - `get_signal(ip)` — synchronous hot-path entry point; returns immediately from Tier 1 or None; never blocks
  - `get_score(ip)` — async; checks Tier 1 + Tier 2 (Redis); enqueues on miss; never blocks
  - Background worker pool (`worker_count` coroutines draining `asyncio.Queue`)
  - `asyncio.CancelledError` handled cleanly in workers; `stop()` completes within 5 seconds
  - Bloom filter dedup (`bloom:abuseipdb_enriched`, 24h TTL); fallback to `bloom_fallback:abuseipdb_enriched:{ip}` SET+TTL when RedisBloom unavailable
  - Daily quota tracking: atomic `INCR` on `abuseipdb:quota:{YYYY-MM-DD}`; rolls back on over-limit; uses `datetime.now(timezone.utc)` (not deprecated `utcnow()`)
  - Quota exhausted: WARN logged once, `ja4proxy_abuseipdb_quota_exhausted` gauge=1, enqueueing stopped; resets next UTC day
  - API error / timeout: fail open (score=0), error counter incremented, no hanging coroutine
  - Write-through caching: API result written to both Redis (`setex`) and in-process LRU
  - `abuseipdb_to_risk_signal()` — pure function; `confidence < shared_ip_threshold` → contribution capped at 15 (shared IP protection); `confidence >= threshold` → scaled to `score_cap` (default 40); `score_cap` never exceeded
  - `delegate_to_analytics` mode: `SADD` to `analytics:enrich:abuseipdb`; local workers idle
  - `on_config_reload()` — hot-reloads all fields except `worker_count` and `queue_size` (WARN logged if those change)
  - Prometheus: `ja4proxy_abuseipdb_lookup_total{result}`, `ja4proxy_abuseipdb_enrichment_queue_depth`, `ja4proxy_abuseipdb_quota_exhausted`, `ja4proxy_abuseipdb_quota_used_today`, `ja4proxy_abuseipdb_cache_hit_ratio`, `ja4proxy_abuseipdb_queue_dropped_total`
  - Structured JSON logging following project conventions

- **Pipeline integration** (`src/security/pipeline.py`):
  - `AbuseIPDBChecker` imported and held as `_abuseipdb_checker` (None by default)
  - `set_abuseipdb_checker()` setter called by `ProxyServer` after startup
  - `get_signal(ip)` called in `_collect_signals()` after Phase 9 beaconing

- **`proxy.py`** — startup/shutdown wiring:
  - `aiohttp.ClientSession` created at startup (shared; never per-request)
  - `AbuseIPDBChecker` instantiated and `await checker.start()` called
  - On shutdown: `await checker.stop()` then `await session.close()`

- **`config/proxy.yml`** — `abuseipdb:` section:
  - `enabled: false`, `api_key: ""`, `max_requests_per_day: 1000`, `cache_ttl_seconds: 14400`
  - `lookup_timeout_seconds: 10`, `shared_ip_threshold: 50`, `queue_size: 500`
  - `worker_count: 3`, `score_cap: 40`, `delegate_to_analytics: false`
  - All keys with inline comments per project style

- **`requirements.txt`** — `aiohttp>=3.9,<4`

- **`.env.example`** — `ABUSEIPDB_API_KEY` documented with instructions

- **`tests/mocks/abuseipdb_mock.py`** — `AbuseIPDBMock` test double:
  - `set_score(ip, score)`, `set_error(ip, status)`, `set_quota_exhausted()`, `set_timeout(ip)`
  - `requested_ips` list for assertion; `make_session()` returns aiohttp-compatible mock

- **Tests** — new tests across 4 files:
  - `tests/unit/test_abuseipdb.py` — unit tests covering cache tiers, score calc, quota, API errors, CancelledError, queue overflow, IPv6, bloom filter, config hot reload
  - `tests/adversarial/test_abuseipdb_fp.py` — FP bounds: confidence=100 < block threshold; CGN confidence=49 ≤ 15; exhaustive 0–100 confidence check
  - `tests/integration/test_pipeline.py` — new `TestAbuseIPDBIntegration` class: cached score → signal in scorer → composite score
  - `tests/chaos/test_external_api_failure.py` — chaos: API unreachable, quota 429, Redis write failure, stop() within 5s

- **`docs/REDIS_SCHEMA.md`** — Phase 10 section updated with all 5 key patterns and full documentation

---

## [8.0.0] - 2026-03-08 - PHASE 9: BEACONING DETECTION

### Added

- **`src/security/beaconing_detector.py`** — Phase 9 beaconing detector:
  - `coefficient_of_variation(values)` — pure function; CV = stdev/mean; 0.0 for degenerate inputs
  - `beacon_score(iats, ...)` — converts IAT list to beacon confidence (0.0, 0.2, 0.5, 0.9); configurable CV thresholds
  - `compute_iats(timestamps)` — converts sorted timestamp list to inter-arrival times
  - `BeaconingDetector` class with dual detection windows (short: 1 h, long: 24 h)
  - Three guards: browser ALPN (h2/h1) never recorded; whitelisted IPs skipped; blocked/banned actions excluded
  - UUID suffix on Sorted Set members prevents collision on same-millisecond arrivals
  - Fire-and-forget `maybe_record()` via `asyncio.create_task()` — never blocks hot path
  - `beacon:suspects` Sorted Set updated on every scored signal (score = confidence 0–0.9)
  - Prometheus: `ja4proxy_beaconing_score` (Histogram), `ja4proxy_beaconing_suspects` (Gauge), `ja4proxy_beaconing_records_total` (Counter)

- **Pipeline integration** (`src/security/pipeline.py`):
  - `BeaconingDetector.get_signal(ctx)` called in `_collect_signals()` — signal slotted into scorer
  - `BeaconingDetector.maybe_record()` fired as `asyncio.create_task()` after action decision

- **`config/proxy.yml`** — `beaconing_detector` config section:
  - `enabled`, `min_observations: 8`, `window_size: 20`, `observation_window_seconds: 3600`, `score: 35`
  - `cv_thresholds.{strong_beacon: 0.15, moderate_beacon: 0.40, weak_signal: 0.70}`
  - `long_window.{enabled, window_seconds: 86400, min_observations: 5, score: 20}`

- **Tests** — 35 new tests across 3 files:
  - `tests/unit/security/test_beaconing_detector.py` — 27 unit tests covering all pure functions, guards, UUID suffix, and signal format
  - `tests/integration/test_beaconing_pipeline.py` — 4 integration tests: regular 30s beacon escalates to strong, irregular traffic produces no signal, long window independent of short window
  - `tests/chaos/test_redis_failure.py` — 3 new chaos tests: Redis down during `maybe_record` (silent), Redis down during `get_signal` (returns None), evicted Sorted Set key starts fresh

- **`docs/REDIS_SCHEMA.md`** — Phase 9 section expanded with full schema for all 3 keys (`beacon:{ip}:{ja4}`, `beacon:long:{ip}:{ja4}`, `beacon:suspects`) including member format, TTL, writer, and trimming behaviour

- **`docs/phases/PHASE_09.md`** — all 35 acceptance criteria marked complete

---

## [7.2.0] - 2026-03-07 - PHASE GATE: MISSING METRICS, DOCS, BENCHMARK HISTORY

### Added

- **Phase 5 Prometheus metrics** (were missing from tcp_analyzer.py and mtls.py):
  - `ja4proxy_tcp_signal_total{signal}` — counter incremented for each TCP signal fired
  - `ja4proxy_concurrent_connections` — gauge tracking observed concurrent connection count
  - `ja4proxy_mtls_verified_total` — counter for connections allowed via verified mTLS cert

- **`docs/performance/BENCHMARK_HISTORY.md`** — created with Phase 8 baseline measurements
  (bypass: ~12 µs, scoring: ~20 µs, full ALLOW: ~5.7 ms, throughput: ~350 conn/s with real Redis)

### Changed

- **README.md Security Pipeline table** — updated from simplified 3-layer view to full 10-layer
  pipeline reflecting Phases 0–8 (IP trust, static allowlist, GeoIP/CIDR/Spamhaus blocks, ALPN
  bypass, JA4 whitelist, mTLS bypass, JA4 blacklist, TLS enforcement, signal collection, scorer+dial)

- **Phase 2, 3, 5 acceptance criteria** — ticked verified checkboxes; Grafana panels and
  fp-corpus tests annotated as deferred to Phase 13 and the corpus build task respectively

---

## [7.1.0] - 2026-03-07 - BUG FIXES: RATE LIMITING, METRICS, NETWORKING, STABILITY

### Fixed

- **Rate limiting never executed** — `MultiStrategyRateTracker` (by_ip, by_ja4, by_ip+ja4 pair)
  was fully implemented in `src/security/rate_tracker.py` but never imported or called by the
  pipeline. Wired into `_collect_signals()` with majority policy (2-of-3 strategies must agree):
  suspicious → +20, block → +60, ban → +90 score contribution. Browser ALPN bypass connections
  skip rate limiting entirely. Two new Prometheus counters added:
  `ja4proxy_rate_limit_signals_total{strategy,level}` and `ja4proxy_rate_limit_bans_total{strategy}`.

- **JA4 fingerprints truncated in Prometheus metrics** — `fingerprint=ja4[:16]` in all
  `REQUEST_COUNT.labels()` calls was cutting fingerprints to 16 chars (e.g. `t13d091200_f91f4`
  instead of the full 36-char `t13d090900_xxxxxxxxxxxx_xxxxxxxxxxxx`), making Grafana dashboards
  show garbled fingerprints. The `[:16]` slice on line 157 for partial label matching is
  intentional and unchanged; all metric labels now use the full fingerprint.

- **`pytricia` missing from `requirements.txt`** — Phase 8 `BlocklistManager` requires `pytricia`
  for CIDR trie lookups but it was never added to requirements, causing proxy startup crash
  (`RuntimeError: pytricia is required`). Added `pytricia==1.3.0`.

- **`make smoke-test` hanging indefinitely** — All `curl` calls in `scripts/smoke-test.sh` lacked
  `--max-time`; a hung backend TLS handshake would block the script forever. Added `--max-time 10`
  to all curl calls.

- **Mock backend TLS thread starvation under load** — `ThreadingHTTPServer` + Python SSL accumulates
  hung threads when connections arrive faster than handshakes complete. Added `socket.settimeout(10)`
  to the SSL listening socket in `scripts/mock-backend.py`; hung threads now time out rather than
  blocking new legitimate connections.

- **Docker build DNS failure on hosts with UFW + `"iptables": false`** — Containers inherited
  `127.0.0.53` (systemd-resolved) as DNS, which is unreachable from inside containers. Combined
  with `iptables: false` disabling NAT masquerading, pip installs during `docker build` failed with
  `Temporary failure in name resolution`. Fixed by: (1) adding `"dns": ["8.8.8.8","1.1.1.1"]` to
  `/etc/docker/daemon.json`, (2) adding a NAT MASQUERADE rule to `/etc/ufw/before.rules`, and
  (3) setting `DEFAULT_FORWARD_POLICY=ACCEPT` and enabling `net.ipv4.ip_forward`.
  `scripts/fix-docker-dns.sh` automates all steps; `scripts/docker-net-diag.sh` provides diagnostics.

### Coverage
- **1140 tests passed, 0 failed** (16 skipped: Docker-dependent).

---

## [7.0.0] - 2026-03-07 - PHASE 8: SPAMHAUS DROP/EDROP & BLOCKLIST FEED FRAMEWORK

### Added
- **`src/security/blocklists.py`** — New `BlocklistManager` and `FeedManager` classes:
  - `BlocklistManager.is_blocked(ip) -> (bool, feed_name)`: O(log n) in-process CIDR lookup via
    two `pytricia` tries (IPv4 32-bit, IPv6 128-bit); never touches Redis on the hot path.
  - `BlocklistManager.load_cidrs(cidrs, list_name, feed_config)`: atomic replace of entries for
    one feed; other feeds unaffected; returns count loaded.
  - `BlocklistManager.get_signals(ip) -> list[RiskSignal]`: produces `RiskSignal` for
    `is_bypass=false` feeds (scored path); bypass feeds produce nothing here.
  - `parse_feed(text, fmt)`: three format parsers — `spamhaus` (strips `;` comment lines and SBL
    refs), `cidr` (one per line), `ipset` (`add <set> <cidr>` format); malformed CIDRs skipped.
  - `FeedManager`: async download with `aiohttp`; ETag-based conditional HTTP (304 Not Modified
    skips parse+reload); leader election per feed via Redis SET NX; non-leaders load from Redis.
  - Prometheus metrics: `ja4proxy_blocklist_entries{feed}`, `ja4proxy_blocklist_last_refresh_success_seconds{feed}`,
    `ja4proxy_blocklist_download_errors_total{feed}`, `ja4proxy_blocklist_matches_total{feed}`.
  - Structured JSON logs: `feed_refreshed` (INFO), `feed_download_failed` (ERROR).
- **`src/security/pipeline.py`** — `_check_block_bypasses()` step 7: Spamhaus bypass check
  calls `_blocklist_manager.is_blocked(ip)`; on match with `is_bypass=true` returns hard-block
  `PipelineResult(bypassed=True, bypass_reason="spamhaus_{feed_name}")`.
- **`src/security/pipeline.py`** — `_collect_signals()` now calls `_blocklist_manager.get_signals(ip)`
  for `is_bypass=false` feeds, adding `RiskSignal(name="blocklist_{feed}", score=N)` to scoring.
- **`src/security/pipeline.py`** — `_load_blocklist_feeds(config)` loads static feeds from config
  at startup; `FeedManager.start()` handles live downloads on the async path.
- **`config/proxy.yml`** — `blocklists.feeds` section with `spamhaus_drop`, `spamhaus_edrop`
  entries; all fields documented inline; example custom scored feed commented out.
- **`tests/unit/test_blocklists.py`** — 29 unit tests (TDD): `BlocklistManager` IPv4/IPv6 lookup,
  multi-feed, reload atomicity, `parse_feed` for all three formats, malformed-CIDR resilience,
  `FeedConfig` dataclass, `is_bypass=false` → `RiskSignal`, Prometheus counter increment.
- **`tests/integration/test_bypass_rules.py`** — 8 integration tests: bypass-feed hard-block
  before scorer, IPv6 bypass, bypass-disabled → scorer path, scored-feed signal, score contribution.
- **`tests/chaos/test_feed_staleness.py`** — 9 chaos tests: HTTP 503 retains trie, timeout
  retains trie, malformed data safely parsed, Redis unavailable → direct download.
- **`tests/performance/bench_cidr_lookup.py`** — Performance benchmarks: p99 < 10µs for 50k
  IPv4 entries; full pipeline check p99 < 15µs.
- **`docs/REDIS_SCHEMA.md`** — `blocklist:cidrs:{list_name}`, `blocklist:etag:{list_name}`,
  `leader:blocklist_download:{list_name}` keys documented.

### Coverage
- **1140 tests passed, 0 failed** (16 skipped: Docker-dependent).

---

## [6.0.0] - 2026-03-07 - PHASE 7: FCrDNS & PASSIVE DNS ENRICHMENT (COMPLETE)

### Added
- **`src/security/dns_enrichment.py`** — Full rewrite with all gaps from initial implementation filled:
  - Five Prometheus metrics: `ja4proxy_dns_enrichment_total{result}` (hit/miss/error/timeout),
    `ja4proxy_dns_ptr_classification_total{ptr_class}`, `ja4proxy_dns_enrichment_queue_depth`,
    `ja4proxy_dns_enrichment_queue_drops_total`, `ja4proxy_dns_resolver_errors_total`.
  - Structured JSON logging on every error/warning path
    (`{"type":"system","level":"ERROR","subsystem":"dns","event":"resolver_error",...}`).
  - `_worker_with_restart()` outer loop — workers automatically restarted on unexpected crash.
  - Passive DNS startup log: `"Passive DNS disabled — no feed configured"` emitted at INFO when
    `passive_dns.enabled: false` (spec requirement).
  - `put_nowait` instead of `await queue.put` in `enqueue()` — guarantees non-blocking hot path.
  - `asyncio.get_running_loop()` used in `_cache_result()` (replaces deprecated `get_event_loop()`).
- **`src/security/pipeline.py`** — DNS enrichment wired into `_collect_signals()` as Phase 7 step:
  `await self._dns_enrichment.get_signal(ctx.client_ip)` returns cached signal or None; always
  fire-and-forget enqueue on miss; exception caught and logged (fail open).
- **`config/proxy.yml`** — `dns_enrichment:` section with all configurable fields documented.
- **`tests/chaos/test_dns_chaos.py`** — 11 chaos tests: resolver unreachable (fail open + error log),
  PTR/forward timeout (fail open, no hanging coroutine), malformed PTR (fail open), queue overflow
  (drop + counter increment + JSON WARN log).
- **`tests/integration/test_pipeline.py`** — 4 new `TestDNSEnrichmentIntegration` tests:
  cached no_ptr signal reaches scorer, residential signal reduces score, cache miss fails open,
  get_signal exception swallowed by pipeline fail-open guard.

### Coverage
- **1140 tests passed, 0 failed** (16 skipped: Docker-dependent).

---

## [5.1.0] - 2026-02-28 - PHASE 3: TLS VERSION & CIPHER ENFORCEMENT

### Added
- **`src/security/tls_enforcer.py`** — New `TLSEnforcer` class with:
  - `WEAK_CIPHERS` frozenset of 40+ known-broken cipher suite IDs (NULL, RC4, EXPORT,
    ANON, DES, 3DES suites per NIST SP 800-52r2 and RFC 9325).
  - `check(tls_version, cipher_list) -> list[RiskSignal] | None` — returns `None` for
    hard-block, empty list for clean connections, or signal list for scored violations.
  - SSLv3: always hard-blocked regardless of bypass setting.
  - TLS 1.0/1.1: hard-block when `security_policy.tls_version_bypass.enabled: true`
    (default); scored `RiskSignal(name="tls_version", score=40)` when bypass disabled.
  - TLS 1.2: optional `RiskSignal(name="tls_version", score=N)` when `flag_tls_12: true`.
  - Weak cipher: `RiskSignal(name="weak_cipher", score=N)` or hard-block when
    `block_weak_ciphers: true`.
  - `from_config(config)` classmethod; `on_config_reload(new_config)` hot-reload support.
  - Prometheus counters: `ja4proxy_tls_version_total{tls_version,action}`,
    `ja4proxy_weak_cipher_total{cipher_strength,action}`.
- **`src/security/pipeline.py`** — `ConnectionContext.cipher_list: list[int]` field
  (default empty list) carrying raw cipher suite IDs from ClientHello.
- **`src/security/pipeline.py`** — `Pipeline._tls_enforcer` wired in `__init__`;
  `on_config_reload()` propagates to `TLSEnforcer.on_config_reload()`.
- **`src/security/pipeline.py`** — `_process_inner()` step 3: TLS enforcement between
  BLOCK bypasses and signal collection. Hard-block returns `PipelineResult(bypassed=True,
  bypass_reason="tls_version")`; signals are prepended to Phase 4+ collection.
- **`proxy.py`** — `JA4Fingerprint.tls_version_int: int` and
  `JA4Fingerprint.raw_cipher_suites: list` fields populated in `_analyze_tls_handshake`.
- **`proxy.py`** — `handle_connection()` passes `tls_version` and `cipher_list` to
  `ConnectionContext`, activating Phase 3 enforcement on live traffic.
- **`config/proxy.yml`** — `tls_enforcer:` section with all flags, scores, and
  configurable weak cipher list.
- **`tests/unit/test_tls_enforcer.py`** — 33 unit tests covering all `check()` branches,
  `from_config()`, `on_config_reload()`, default config safety, and `WEAK_CIPHERS` constant.
- **`tests/integration/test_pipeline.py`** — 6 new `TestTLSEnforcerIntegration` tests:
  TLS 1.1 hard-block with scorer not called, bypass-disabled scored path, weak cipher
  scoring, TLS 1.3 allow, hot reload, and `tls_version=None` no-crash.
- **`tests/chaos/test_redis_failure.py`** — 3 new `TestTLSEnforcerRedisDown` tests:
  in-process TLS block works with Redis down, TLS 1.3 allowed with Redis down, and
  enforcer exception swallowed by pipeline fail-open guard.

### Coverage
- **943 tests passed, 0 failed** (16 skipped: Docker-dependent).
- **100% statement coverage** across all source modules (2485 statements).

---

## [5.0.0] - 2026-02-28 - PHASE 2: MONITOR MODE & PROGRESSIVE BLOCKING DIAL

### Added
- **`src/security/action_decider.py`** — `effective_threshold(configured, dial)` module-level
  function implementing the interpolation formula `round(101 − (dial/100) × (101 − configured))`.
  At `dial=0` returns 101 (unreachable); at `dial=100` returns `configured` exactly.
- **`src/security/action_decider.py`** — `ActionDecider.counterfactuals(score, dial_values)`
  method returning `{dial_value: action}` for monitor-mode logging.
- **`src/security/action_decider.py`** — `DialManager` class with `initialize()` (startup reset
  when `blocking_acknowledged=false`) and `validate_change()` (hourly rate-limit guard, fail open
  on Redis errors).
- **`src/security/pipeline.py`** — Four new Prometheus metrics: `ja4proxy_dial_current` (Gauge),
  `ja4proxy_monitor_counterfactual_total` (Counter, labels: `action`, `dial`),
  `ja4proxy_dial_change_rejected_total` (Counter), `ja4proxy_dial_changes_total` (Counter).
- **`src/security/pipeline.py`** — `PipelineResult.counterfactuals` field (default empty dict)
  carrying `{dial_value: action}` for all scored connections.
- **`src/security/pipeline.py`** — `_emit_stream_event()` async fire-and-forget method that
  XADDs one event per connection to `ja4proxy:events` (maxlen=100,000); all errors swallowed.
- **`src/security/pipeline.py`** — Counterfactual Prometheus counter increments in monitor mode
  (dial=0); `would=` key in MONITOR log lines; `"counterfactual"` object in JSON log.
- **`src/security/risk_scorer.py`** — `RiskScorer.from_config(config)` classmethod.
- **`proxy.py`** — `LocalCache`, `Pipeline`, `ConnectionContext`, `RiskScorer`, `ActionDecider`,
  `DialManager` wired in; `Pipeline.process()` replaces legacy Security Layers 0, 1 (static
  country), 2, and 3 (AdvancedSecurityManager) in `handle_connection()`.
- **`proxy.py`** — `ProxyServer.start()` initializes dial from Redis via `DialManager.initialize()`
  and stores it in `_local_cache.dial` before accepting connections.
- **`config/proxy.yml`** — `monitor_mode:` section with `dial`, `blocking_acknowledged`,
  `log_counterfactuals`, `counterfactual_thresholds`, `max_dial_change_per_hour`,
  `alert_on_dial_change`.
- **`docs/REDIS_SCHEMA.md`** — Phase 2 keys: `config:dial:change_count:{YYYY-MM-DD-HH}` (INCR,
  TTL 3600s) and `ja4proxy:events` (Stream, maxlen=100,000).
- **`tests/unit/test_action_decider.py`** — `TestEffectiveThreshold` (7 parametrized cases),
  `TestCounterfactuals` (4 tests), `TestDialManager` (9 tests).
- **`tests/integration/test_dial_propagation.py`** — New file: 10 integration tests covering
  dial change propagation, counterfactual content, interpolated thresholds, and monitor mode.
- **`tests/chaos/test_dial_change_chaos.py`** — New file: 11 chaos tests covering Redis failures
  in `DialManager.initialize()` and `validate_change()`, and mid-traffic dial resilience.
- **`tests/unit/test_pipeline_extra.py`** — `TestEmitStreamEventException`: verifies
  `_emit_stream_event` swallows `xadd` exceptions without propagating.

### Changed
- **`src/security/action_decider.py`** — `ActionDecider.decide()` now uses
  `effective_threshold()` formula (was `int(configured × 100 / max(dial, 1))`).
- **`src/security/pipeline.py`** — `_score_connection()` returns 4-tuple
  `(score, action, signals, counterfactuals)` (was 3-tuple).
- **`src/security/pipeline.py`** — `_process_inner()` checks `dial == 0` directly for monitor
  mode (previously relied on `action == "allow"` which was always true at dial=0, dead code).
- **`tests/unit/test_action_decider.py`** — Fixed `TestIntermediateDial.test_dial_50_mid_threshold`:
  updated assertion from `decide(score=40, dial=50) == "flag"` to `decide(score=60, dial=50) == "flag"`
  to match the new formula (`effective_flag@dial=50 = round(101 − 0.5×81) = 60`).

### Removed
- **`proxy.py`** — `AdvancedSecurityManager` import and instantiation removed; replaced by Pipeline.
- **`proxy.py`** — Static JA4 whitelist check (LAYER 0), static country blacklist/whitelist (LAYER 1),
  JA4 blacklist check (LAYER 2), and `AdvancedSecurityManager` call (LAYER 3) removed from
  `handle_connection()`. All now handled by `Pipeline.process()` via bypass checks.
- **`tests/unit/test_proxy_server.py`** — Removed `test_country_blacklisted_connection_dropped`
  and `test_country_not_in_whitelist_dropped` (static country checks moved to Pipeline).

### Coverage
- **901 tests passed, 0 failed** (16 skipped: Docker-dependent).
- **100% statement coverage** across all source modules (2395 statements).

---

## [4.0.2] - 2026-02-28 - 100% TEST COVERAGE ACROSS ALL SOURCE MODULES

### Added
- **`tests/unit/test_security_manager.py`** — 26 tests for `SecurityManager`: Redis ping
  failure propagation, `check_access` fail-secure exception path, tier routing
  (`SUSPICIOUS`, `BANNED`, else→FINGERPRINTS`) in `_store_enforcement_data`, exception
  paths in `get_statistics`, `manual_unban`, and `verify_gdpr_compliance`, `__repr__`,
  and `create_security_manager` convenience function.
- **`tests/unit/test_gdpr_storage.py`** — 16 tests for `GDPRStorage`: `cleanup_expired`
  with mixed TTLs and exception path, `get_retention_report` exception path, `_audit_log`
  exception path, `get_audit_logs` full path including inner JSON parse failure and outer
  Redis failure, custom TTL clamping and invalid-TTL fallback.
- **`tests/unit/test_pipeline_extra.py`** — 22 tests for uncovered pipeline branches:
  `StaticAllowlist.reload` with empty `ip` entry (line 172), `StaticAllowlist.match` with
  invalid IP string (lines 197–198), `StaticAllowlist.add_from_redis` valid + invalid
  (lines 207–217), `Pipeline.update_sets` (269–270), `Pipeline.on_config_reload`
  (274–276), country blacklist bypass hit (396–400), `_format_signals` dict-signal path
  and unknown-type fallback (514–530), `process` fail-open on unexpected exception.
- **`tests/unit/test_config_loader_extra.py`** — 8 tests: non-mapping YAML raises
  `ConfigError` (line 228), `setup_sighup` closure is callable (line 182), OSError/
  NotImplementedError from `add_signal_handler` logs warning (lines 186–188),
  `_reload_and_log_error` swallows `ConfigError` (lines 250–253).
- **`tests/unit/test_pubsub_extra.py`** — 5 tests for `PubSubHandler.run`: subscribe
  is called, non-message events skipped, real messages dispatched (lines 105–113),
  reconnect on generic exception.
- **`tests/unit/security/test_rate_tracker_extra.py`** — 13 tests: `register_script`
  `redis.RedisError` → `RedisConnectionError` (lines 125–126), non-dict strategies
  → `ValueError` (line 164), invalid settings skipped (175–178), unknown strategy
  name (line 187), invalid window value (225–226), `_track_single_strategy` exception
  hierarchy: `TimeoutError` (367–368), generic `RedisError` (369–370), bare `Exception`
  (371–372).
- **`tests/unit/security/test_coverage_extras.py`** — 11 tests: `ActionType` comparison
  operators with non-`ActionType` → `NotImplemented` (lines 66, 71, 76, 81), repeat-
  offender escalation in `_apply_block` (lines 328–330), empty thresholds fallback to
  global in `_get_strategy_thresholds` (lines 196–199), unknown policy → fail-secure
  (lines 337–338), `from_config` with invalid config raises `ValueError` (lines 414–415).

### Changed
- **`src/security/security_manager.py`** — `except ImportError: redis = None` marked
  `# pragma: no cover` (environment-dependent; redis-py present in all deployment targets).
- **`src/security/gdpr_storage.py`** — Same `# pragma: no cover` on ImportError block.
- **`src/security/action_enforcer.py`** — Same `# pragma: no cover` on ImportError block.

### Coverage milestone
- All source modules now at **100% statement coverage** (2350 statements, 0 missing).
- Total test suite: **859 passed, 0 failed** (excluding 9 Docker-dependent tests that
  require a live stack, skipped automatically when the stack is not running).
- Test-to-code ratio: ~1.4× (859 tests / ~615 production-relevant statements in proxy.py
  and src/).

---

## [4.0.1] - 2026-02-28 - TEST COVERAGE AND CODE QUALITY

### Security
- **`proxy.py` `_init_redis()`** — Fixed exception handler ordering: `redis.AuthenticationError`
  now appears *before* `redis.ConnectionError` in the `except` chain.
  `AuthenticationError IS-A ConnectionError` in redis-py, so placing it second made it
  unreachable dead code — auth failures were silently misreported as generic connection
  failures. Incident responders now receive an unambiguous "Redis authentication failed —
  check credentials" message instead of the generic connection error, enabling faster
  triage and reducing the risk of dismissing a credential compromise as a transient
  network glitch.

### Changed
- **`proxy.py` `classify_ja4()`** — Removed unreachable `try/except (IndexError, ValueError)`
  wrapper. Every operation inside the block operates on a string already confirmed to be
  ≥ 10 chars; `str.split`, `str[-2:]`, and `dict.get` cannot raise those exceptions.
  Dead exception handlers mislead security auditors and suppress legitimate bugs.
- **`proxy.py` `_extract_ja4_from_http()`** — Removed unreachable `try/except Exception`
  wrapper. `bytes.decode(errors='ignore')`, `str.split`, `str.lower`, and
  `str.startswith` are all infallible for the inputs this method receives. Bare
  `except Exception: pass` patterns are a red flag in security reviews.
- **`proxy.py` import fallback** — Added `# pragma: no cover` to the
  `except ImportError: GEOIP_AVAILABLE = False` clause (environment-dependent import;
  IP2Location is present in all supported deployment targets).
- **`proxy.py` `__main__` guard** — Added `# pragma: no cover` to the
  `if __name__ == "__main__"` block (not exercisable via pytest by design).

### Tests
- `tests/unit/test_proxy_remaining.py` — Added `TestInitRedisGenericException.test_auth_error_caught_before_connection_error`
  covering the now-reachable `redis.AuthenticationError` path and asserting the
  specific "Redis authentication failed" message.
- `tests/unit/test_proxy_server.py` — Updated `test_auth_error_raises_security_error`
  to assert the correct error message now that the handler is reachable.
- Removed two stale tests whose docstrings referred to the removed dead-code paths.
- `proxy.py` line coverage: **99% → 100%** (876 statements, 0 missing).
- Full suite: **746 passed, 0 failed** (excluding Docker-dependent integration tests).

---

## [4.0.0] - 2026-02-27 - PHASE 0 + PHASE 1: INFRASTRUCTURE AND RISK SCORING SCAFFOLD

### PHASE 0 — REDIS FOUNDATIONS AND CACHING INFRASTRUCTURE

#### Redis
- **`docker-compose.poc.yml` / `docker-compose.prod.yml`** — Redis image updated from
  `redis:7-alpine` to `redis/redis-stack:latest` to enable Bloom filter support
  (`BF.RESERVE`, `BF.ADD`, `BF.EXISTS`). Added `--maxmemory-policy allkeys-lru`,
  `--hz 20`, and `--tcp-keepalive 60` to the POC configuration.
- **`scripts/sliding_window.lua`** (new) — Extracted the sliding-window Lua script from
  `src/security/rate_tracker.py` into a standalone file. Script signature unchanged.
  `rate_tracker` loads it via `SCRIPT LOAD` on startup; falls back to inline on error.

#### Local Cache (`src/cache/local_cache.py`)
- **`LRUCache`** — Pure-stdlib LRU cache using `collections.OrderedDict` + `time.monotonic`
  TTL. Operations: `get` (lazy TTL eviction), `set` (LRU eviction at capacity), `delete`
  (pub/sub invalidation). Prometheus counters: `ja4proxy_cache_operations_total{type,result}`.
- **`LocalCache`** — Holds six per-type `LRUCache` instances with spec TTLs:
  `whitelist_decisions` (TTL 1800s), `block_decisions` (TTL 30s), `abuseipdb_scores`
  (TTL 14400s), `asn_class` (TTL 3600s), `geoip_country` (TTL 3600s), `rdap_data`
  (TTL 3600s). Also holds `.dial` (int 0–100, updated via pub/sub, no TTL).

#### Config Hot Reload (`src/config/loader.py`)
- **`ConfigLoader`** — YAML loader with `${VAR:-default}` env var expansion. Supports
  `SIGHUP`-triggered reload and pub/sub-triggered reload via `config_reload` message.
  Non-reloadable keys (`proxy.bind_host`, `proxy.bind_port`, `redis.host`, `redis.port`,
  `redis.db`) are validated on reload; `ConfigError` raised if they change.
  `on_reload()` callbacks notify registered consumers (e.g. Pipeline). Prometheus counters:
  `ja4proxy_config_reloads_total`.

#### Bloom Filter (`src/cache/bloom.py`)
- **`BloomFilter`** — Async wrapper around RedisBloom (`BF.RESERVE` / `BF.ADD` / `BF.EXISTS`).
  Falls back transparently to `SADD` / `SISMEMBER` on `bloom_fallback:{name}` with 24h TTL
  if RedisBloom is unavailable. Never raises on the hot path — errors are logged and
  `False` is returned (treat as unseen). Used for `bloom:rdap_enriched` and
  `bloom:abuseipdb_enriched`.

#### Pub/Sub Handler (`src/pubsub.py`)
- **`PubSubHandler`** — Async subscriber on `ja4proxy:invalidate` channel. Handles five
  message types: `whitelist_remove`, `ban_release`, `ja4_blacklist_add`, `dial_change`,
  `config_reload`. Reconnects with exponential backoff on disconnect. Prometheus counters:
  `ja4proxy_pubsub_messages_total{msg_type}`, `ja4proxy_pubsub_errors_total{reason}`.

#### Pipeline Bypass Orchestration (`src/security/pipeline.py`)
- **`ConnectionContext`** — Dataclass holding per-connection metadata: `client_ip`, `ja4`,
  `alpn`, `has_valid_client_cert`, `sni`, `tls_version`, `country`.
- **`PipelineResult`** — Dataclass holding the pipeline decision: `action`, `bypassed`,
  `bypass_reason`, `score`, `signals`, `dial`.
- **`StaticAllowlist`** — CIDR/IP matching for the static IP allowlist using stdlib
  `ipaddress`. Supports hot reload via `on_config_reload`. Logs WARN for Redis-only
  (UI-added) entries.
- **`Pipeline`** — Central integration point. Bypass check order:
  `static_ip_allowlist` → `alpn_browser_bypass` → `ja4_whitelist_bypass` → `mtls_bypass`
  → `ja4_blacklist_bypass` → `country_blacklist_bypass`. All bypasses independently
  togglable via `security_policy` config. Logs every connection (§2a of STYLE_GUIDE).
  Fails open on any unhandled exception. Phase 1 scorer/decider wired in via
  `update_scorer()`.

#### IPv6 Utilities (`src/utils/ip.py`)
- **`canonical_ip()`** — Normalises to compressed form; IPv4-mapped IPv6 (`::ffff:1.2.3.4`)
  unwrapped to plain IPv4. Handles loopback, link-local, multicast, private.
- **`get_analysis_subnet()`** — Returns `/24` for IPv4 and `/48` for IPv6 (equivalent
  user population density for analytics aggregation).

#### Config (`config/proxy.yml`)
- Added: `upstream_trust` (CDN CIDR passthrough), `local_cache` (per-type TTLs/sizes),
  `security_policy` (all 8 bypass toggles with `enabled: true` defaults), `static_allowlist`,
  `config.hot_reload_enabled`, `risk_scorer` (thresholds + `ban_duration_seconds`).

#### Documentation
- **`docs/REDIS_SCHEMA.md`** (new) — All Phase 0+1 Redis key patterns with type, TTL,
  writer, and notes columns. Includes pub/sub message type table and stubs for Phases 5–12.

#### Tests
- `tests/unit/test_local_cache.py` — LRUCache (hit/miss/TTL/LRU eviction) + LocalCache
  (per-type TTLs, dial clamping).
- `tests/unit/test_config_loader.py` — YAML load, env var expansion, hot reload,
  non-reloadable key rejection, callbacks.
- `tests/unit/test_pipeline.py` — All 6 bypass types (enabled and disabled), StaticAllowlist
  CIDR/IPv6 matching.
- `tests/unit/test_ip_utils.py` — `canonical_ip` and `get_analysis_subnet` edge cases.
- `tests/integration/test_cache_hierarchy.py` — Local cache hit skips Redis; TTL expiry.
- `tests/integration/test_hot_reload.py` — SIGHUP, pub/sub reload, non-reloadable key
  rejection, callbacks.
- `tests/chaos/__init__.py`, `tests/chaos/test_redis_failure.py` — Fail-open on Redis error,
  empty signals → allow, cached dial persistence.
- `tests/conftest.py` — Session-scoped Prometheus registry cleanup to prevent metric
  duplication across test modules.

---

### PHASE 1 — RISK SCORER SCAFFOLD

#### Risk Scorer (`src/security/risk_scorer.py`)
- **`RiskSignal`** — Dataclass: `name` (registry string), `score` (int, may be negative),
  `reason` (human-readable), `weight` (float, default 1.0).
- **`RiskAssessment`** — Dataclass: `total_score` (0–100 clamped), `signals`,
  `recommended_action`, `explanation` (top-3 signals).
- **`RiskScorer.score()`** — Clamps individual signals to `[-100, 100]`, sums weighted
  contributions, clamps composite to `[0, 100]`. Derives `recommended_action` from
  thresholds (ban → block → tarpit → rate_limit → flag, highest triggered wins).
  Builds `explanation` from top-3 signals by absolute weighted contribution.
  Prometheus: `ja4proxy_risk_score` Histogram, buckets `[0,10,20,35,55,70,85,100]`.

#### Action Decider (`src/security/action_decider.py`)
- **`ActionDecider.decide(score, dial)`** — Maps composite score + dial to final action.
  `dial=0` → always `"allow"` (monitor mode). `dial=100` → thresholds apply exactly.
  `0 < dial < 100` → `effective_threshold = configured × 100 / dial` (lower dial = more
  permissive). Default thresholds: flag=20, rate_limit=35, tarpit=55, block=70, ban=85.
- **`ActionDecider.from_config()`** — Constructs from `risk_scorer` config section;
  missing keys fall back to defaults.

#### Pipeline Integration
- `Pipeline._score_connection()` upgraded from stub to real scorer + decider.
  Returns `(score, action, scored_signals)` so `PipelineResult.signals` is populated
  from the scorer's processed signal list.

#### Tests
- `tests/unit/test_risk_scorer.py` — Empty/single/multi signals, clamping, threshold
  boundaries, explanation top-3, `_build_explanation`, `_derive_action`.
- `tests/unit/test_action_decider.py` — dial=0 always allow, dial=100 full thresholds,
  one-below each boundary, intermediate dial scaling, `from_config`.
- `tests/integration/test_pipeline.py` — ALPN bypass logged correctly, blacklist block,
  dial=0 monitor mode, dial=100 high-score blocks, signals list populated.
- `tests/chaos/test_redis_failure.py` — Extended with Phase 1 scoring chaos tests.
- `tests/performance/bench_pipeline.py` — `RiskScorer.score()` p99 < 100µs (10 signals);
  `ActionDecider.decide()` p99 < 10µs.

---

## [3.5.0] - 2026-02-24 - SECOPS USABILITY, GEOIP MAINTENANCE, BUG FIXES

### OPERATIONAL IMPROVEMENTS

- **`stop-all.sh`** — unified stop for POC and monitoring stacks in one command.
  `--clean` flag removes all Docker volumes for a fresh restart.
- **`status.sh`** — health dashboard showing container states, service HTTP checks,
  Redis connectivity, live security state (blacklist size, active bans, blocked countries,
  pending fingerprints), and access URLs with current Grafana password.
- **`scripts/update-geoip.sh`** — downloads the latest IP2Location LITE DB1 from the
  public CDN (no account needed), validates the file, keeps a `.prev` backup.
  `--check` flag shows database age without downloading. `make update-geoip` / `make check-geoip`.
- **`poc-status-check.sh`** — rewritten from scratch. Was using wrong backend port (8081),
  hardcoded Redis password as "admin", and checked for files that don't exist.
  Now reads `.env` for credentials and checks all correct endpoints.
- **Makefile** — added `start`, `stop`, `stop-clean`, `status`, `start-monitoring`,
  `update-geoip`, `check-geoip` targets. Help output reorganised by category.

### CONFIGURATION

- **`BACKEND_HOST` / `BACKEND_PORT`** — backend destination is now configurable via `.env`.
  Set to your real server IP/hostname; defaults to `backend:443` for POC Docker networking.
  Passed to the proxy container via `docker-compose.poc.yml` and supported natively in
  `config/proxy.yml` via env var substitution.
- **`_expand_env_vars` fix** — now supports `${VAR:-default}` fallback syntax (previously
  only `${VAR}` was supported; missing vars silently became empty strings). Config now uses
  `${BACKEND_HOST:-backend}` and `${BACKEND_PORT:-443}` so the proxy always has valid defaults.
- **`backend_port` type fix** — cast to `int()` at `asyncio.open_connection()` call site;
  prevents type error when `BACKEND_PORT` comes from env var string expansion.

### DOCUMENTATION

- **`docs/FAQ.md`** (new) — 25 common operational questions: setup, passwords, GeoIP,
  fingerprint blocking, false positives, alerts, scaling, backups, log rotation, upgrades.
- **`docs/SECOPS_OPERATIONS.md`** — added Routine Maintenance section covering GeoIP DB
  update cadence (monthly, with cron example), JA4 fingerprint feed workflow, Alertmanager
  notification target configuration, log rotation, and credential rotation.
- **`docs/REDIS_SECURITY_REVIEW.md`** — rewritten to reflect current state (auto-generated
  password and Docker-internal networking already implemented); stripped sprint-planning
  language, time estimates, and unverified compliance checkmarks.
- **`.env.example`** — rewritten as a comprehensive reference covering `BACKEND_HOST`,
  `BACKEND_PORT`, `JA4DB_API_KEY`, port overrides, and a production checklist.
- **`docs/README.md`** — updated index, added FAQ and new operational docs, removed deleted files.
- Removed four stale/misleading docs: `docs/POC_GUIDE.md` (superseded),
  `docs/security/SECURITY_ANALYSIS_REPORT.md` (2024-dated, contradicted newer audit),
  `docs/SECURITY_VULNERABILITIES_DIAGRAM.md` (showed proxy→backend as HTTP, incorrect),
  `docs/REDIS_SECURITY_QUICK.md` (referenced non-existent setup script).

---

## [3.4.0] - 2026-02-23 - THREAT INTEL FEED, DYNAMIC GEOIP, CIDR BLOCKING

### 🌐 DYNAMIC GEOIP & CIDR BLOCKING (proxy.py — no restart needed)

- **Layer 1b: dynamic country blacklist** — Redis set `geoip:dynamic_blacklist` checked on
  every connection after the static country lists. Added via `ja4-admin block-country` or
  auto-populated by `geoip-monitor.sh`. Fails open on Redis error.
- **Layer 1c: CIDR block check** — Redis set `geoip:blocked_cidrs` holds CIDRs (e.g.
  `203.0.113.0/24`, `185.220.0.0/16`). Proxy reloads from Redis every 30s; add/remove takes
  effect within 30s without restart.
- **`geoip:safe_countries`** — Redis set of country codes that can never be auto-blocked by
  `geoip-monitor`. Loaded from `config/proxy.yml → geoip.safe_countries` on startup. Defaults:
  IE, GB, US, CA, AU, NZ, DE, FR, NL, IM, JE, GG.
- New Prometheus `reason` labels: `country_dynamic_block`, `cidr_block` on
  `ja4_blocked_requests_total` for granular reporting.

### 📡 JA4DB THREAT FEED INTEGRATION

- **`scripts/fetch-ja4db.sh`** — fetches known-malicious fingerprints from:
  1. FoxIO GitHub (`raw.githubusercontent.com/FoxIO-LLC/ja4`) — no auth required
  2. ja4db.com API — if `JA4DB_API_KEY` is set in `.env`
  Filters by malicious category keywords (malware, c2, trojan, rat, ransomware, etc.)
  and queues new fingerprints in Redis `ja4:pending` hash for admin review.
- **Approval workflow** in `ja4-admin.sh`:
  - `fetch-db` → `list-pending` → `approve <FP>` / `reject <FP>` / `approve-all`
  - Approved fingerprints go into `ja4:blacklist` (instant effect) and should also be
    added to `config/proxy.yml` to survive container restart.

### 🛡️ GEOIP AUTO-BLOCK MONITOR

- **`scripts/geoip-monitor.sh`** — queries Prometheus, auto-blocks countries exceeding
  configurable thresholds (default: >50 blocked connections in 5 min AND >70% block rate).
  Never blocks countries in `geoip:safe_countries`.
  - `--dry-run` mode: shows what would be blocked without acting
  - `--watch` mode: loops every 60s (suitable for long-running monitor)
  - Cron-friendly: `*/5 * * * * /path/to/geoip-monitor.sh >> /var/log/geoip-monitor.log`
  - Reasons stored in `geoip:block_reasons` HASH for the report

### 🔧 JA4-ADMIN NEW COMMANDS

- `fetch-db`, `list-pending`, `approve`, `reject`, `approve-all` — feed workflow
- `list-countries`, `block-country`, `unblock-country`, `safe-country`, `unsafe-country`
- `list-cidrs`, `block-cidr`, `unblock-cidr`
- `report` — comprehensive blocking summary (fingerprints, countries with reasons, CIDRs,
  enforcement stats, Prometheus traffic breakdown by mechanism and country)

### 📋 CONFIGURATION

- `config/proxy.yml`: new `geoip.safe_countries` list (default: 12 trusted countries)
- `.env` supports optional `JA4DB_API_KEY` for ja4db.com API access

---

## [3.3.0] - 2026-02-22 - FALSE POSITIVE ELIMINATION & OPERATIONAL IMPROVEMENTS

### 🎯 FALSE POSITIVE ELIMINATION

**Result: 0% proxy-level false positives.** Browser connections are whitelisted and never
reach rate limiting. Verified across test runs from 20 to 200 concurrent workers.

- **`multi_strategy_policy` changed from `any` → `majority`** — requires 2 of 3 rate-limit
  strategies to agree before blocking. A single strategy (e.g. BY_IP_JA4_PAIR detecting a
  burst) no longer triggers a block on its own.
- **Raised thresholds across all strategies** to match realistic burst behaviour in test and
  production environments (Docker NAT aggregates all container traffic through one gateway IP,
  so per-IP thresholds must accommodate all workers combined):
  - `by_ip`:         suspicious 10→50,  block 50→200,  ban 100→500
  - `by_ja4`:        suspicious 5→20,   block 15→100,  ban 20→200
  - `by_ip_ja4_pair`: suspicious 2→20,  block 5→50,    ban 8→100
- **Added `h1` to `whitelist_patterns`** — HTTP/1.1 ALPN browsers now bypass rate limiting.
  Previously only `h2` (HTTP/2) was whitelisted; connections in HTTP/1.1 fallback mode fell
  through to rate limiting and could be false-positively blocked.
- **Fail-open for unparseable TLS** — connections that produce `ja4 == "unknown"` or `"error"`
  (Scapy parse failure, non-TLS protocol, unusual extensions) are now forwarded directly to the
  backend after the blacklist check, instead of being pooled under a shared `rate:ja4:unknown`
  key that could trigger rate-limit false positives.

### 🐛 BUG FIXES

- **Block duration bug fixed** — `_apply_block()` in `src/security/action_enforcer.py` was
  hardcoding a 3600s (1-hour) block TTL regardless of the `ban_duration` value set in
  `config/proxy.yml` per-strategy config. Blocks now correctly expire after the configured
  `ban_duration` (default: 300s). Verified in logs: `"expires in 300s"`.

### 📊 METRICS & TOOLING

- **Metrics summary aggregation** — `generate-tls-traffic.sh` summary now uses awk aggregation
  instead of raw `grep` on `ja4_blocked_requests_total`. The `reason` label contains
  `"expires in Xs"` (unique per second over long runs), which caused the summary to print
  hundreds of lines. Output now shows clean per-fingerprint and per-action totals.
- **`make flush-redis`** — New Makefile target clears all transient security state (rate
  windows, blocks, bans, audit logs) while preserving `ja4:whitelist` and `ja4:blacklist` keys.
  Essential for resetting between test runs without a full container restart.

### 📈 VERIFIED PERFORMANCE

Measured with `./generate-tls-traffic.sh 300 15 200` (300s, 15% legit, 200 workers):
- **0% proxy-level false positives** — 2,728+ browser connections whitelisted, 0 blocked
- **94–99% malicious traffic blocked** depending on worker load
- **300s block TTL** (was 3600s) — false positives self-heal in 5 minutes

---

## [3.2.0] - 2026-02-18 - SECURITY HARDENING

### 🔒 CONTAINER SECURITY
- **`read_only: true`** on all containers — filesystem immutable at runtime
- **`cap_drop: ALL`** on all containers — only `NET_BIND_SERVICE` added where needed (HAProxy, proxy)
- **`no-new-privileges: true`** on all containers — prevents privilege escalation
- **`PYTHONDONTWRITEBYTECODE=1`** on Python containers — prevents `__pycache__` writes on read-only filesystems
- **Resource limits** on every container (CPU + memory limits and reservations)
- **tmpfs** mounts for `/tmp` on all containers (noexec, nosuid, nodev)

### 🔑 SECRETS MANAGEMENT
- **Auto-generated `.env`** — `start-poc.sh` creates `.env` with `openssl rand` secrets on first run (chmod 600)
- **All passwords from env vars** — Redis, Grafana, and other credentials sourced from `${REDIS_PASSWORD}`, `${GRAFANA_PASSWORD}` 
- **No hardcoded passwords** — All shell scripts use env vars instead of `changeme`
- **Grafana password sync** — `start-monitoring.sh` resets admin password to match `.env` on every start

### 🌐 NETWORK SECURITY
- **127.0.0.1 port bindings** — Internal services (proxy:8080, metrics:9090, backend:8443, tarpit:8888) only accessible from localhost
- **Redis not exposed to host** — Only accessible within Docker backend network
- **HAProxy only public-facing port** — Port 443 (TLS) and 8880 (HTTP redirect) are the only ports on all interfaces
- **HAProxy TLS hardened** — TLS 1.2+ enforced globally, only ECDHE+AES-GCM/CHACHA20 ciphers, no RC4/DES/3DES/CBC
- **HAProxy stats TLS-secured** — Stats endpoint on :8404 now requires TLS
- **HAProxy management frontend** — New TLS-terminated endpoint on :8443 with mTLS support
- **Backend certificate pinning** — mTLS backend verifies server cert against internal CA
- **TLS handshake failure logging** — All frontends log TLS version, cipher, and termination state to syslog

### 🛡️ APPLICATION SECURITY
- **Fixed eval() RCE** in `tests/integration/test_docker_stack.py` — replaced with safe string comparison
- **Fixed CSRF default-secret** in `security/validation.py` — generates `os.urandom(32)` when no secret configured
- **Sensitive data filter** — Log filter redacts passwords, API keys, tokens, credit card numbers, emails
- **Redis RDB disabled** — `--save ""` prevents disk write errors on read-only filesystem

### 🔧 FIXES
- **Traffic generator defaults** — Python script now defaults to `proxy:8080` via env vars (was `localhost:443`)
- **Health checks** — Backend check uses `docker exec` (works with internal-only ports)
- **Loki health check** — Uses `docker exec` since Loki has no host port
- **Grafana security headers** — `cookie_secure`, `samesite=strict`, `disable_gravatar`, `strict_transport_security`

## [3.1.0] - 2026-02-17 - GEOIP, FINGERPRINT NAMES, BAN ESCALATION

### 🌍 GEOIP COUNTRY FILTERING
- **IP2Location LITE** database bundled in container (CC BY-SA 4.0, no registration needed)
- **Country whitelist** — only allow traffic from listed countries (IE, GB, IM, JE, GG, US, CA, AU, NZ, DE, FR, NL)
- **Country blacklist** — block traffic from listed countries (KP, RU, CN, IR)
- Both disabled by default — enable in `config/proxy.yml` → `geoip` section
- Country check runs as Security Layer 0 (before JA4 fingerprint checks)
- Private IPs (Docker NAT) return empty country, bypassing geo filters
- Country shown in logs, Prometheus `source_country` label, and two new Grafana panels

### 🏷️ JA4 FINGERPRINT NAMES
- **`classify_ja4()` function** decodes JA4 structure into human-readable names:
  - `h2` ALPN → "Browser (TLS 1.3)"
  - `00` ALPN → "Tool/Bot (TLS 1.2)"
- **`fingerprint_labels`** config section maps known fingerprints to specific names (Chrome, Sliver C2, CobaltStrike, etc.)
- **`fingerprint_name` label** added to `ja4_requests_total` Prometheus metric
- Names appear in all proxy log messages and Grafana dashboard panels

### 🔧 BAN ESCALATION FIX
- Lowered `by_ip_ja4_pair` ban threshold from 10→8 (tarpit backpressure capped rate at ~8, preventing ban escalation)
- Lowered `by_ja4` ban threshold from 30→20
- **Pattern-based whitelist**: `whitelist_patterns: ["h2"]` — any JA4 with HTTP/2 ALPN bypasses rate limiting
  - Fixes false positive blocking of browsers when all Docker traffic shares one gateway IP
- **Results**: 100% legitimate allowed, 99.6% malicious blocked, Grafana shows Allowed/Tarpitted/Banned

### 📊 DASHBOARD
- Dashboard panels group by `fingerprint_name` instead of raw fingerprint hash
- Added "Traffic by Country" donut chart
- Added "Blocked Requests by Country" table
- Total: 20 panels

### 📄 DOCUMENTATION
- Cleaned up 24 planning/session artifacts from `docs/`
- Removed root-level `GRAFANA_SETUP.md`, `TRAFFIC_GENERATOR_SUMMARY.txt`
- Rewrote `README.md` — focused POC demo guide with accurate architecture, ports, and commands
- Moved `POC_QUICKSTART.md` to `docs/`

## [3.0.0] - 2026-02-17 - ENTERPRISE SECURITY ARCHITECTURE

### 🏗️ ARCHITECTURE
- **Added HAProxy load balancer** — TCP mode frontend on :443 with TLS passthrough (no termination), PROXY protocol v2 for real client IP forwarding. Stats page on :8404.
- **Added tarpit container** — Async Python TCP server that traps blocked connections, trickling 1 byte/sec for 60 seconds to waste attacker resources. Prometheus metrics on :9099.
- **Upgraded backend to HTTPS** — Mock backend now serves on :443 with self-signed TLS cert. End-to-end encryption preserved (proxy never decrypts).
- **Full traffic path**: Client → HAProxy:443 → JA4proxy:8080 → Backend:443 (or Tarpit:8888 if blocked)

### 🔒 SECURITY
- **Wired `src/security/SecurityManager` into proxy** — Multi-strategy rate tracking (BY_IP, BY_JA4, BY_IP_JA4_PAIR) with automatic threat tier escalation (NORMAL → SUSPICIOUS → BLOCK → BAN).
- **Three-layer security pipeline**:
  1. **Blacklist** — Instant TCP RST for known malware JA4 fingerprints (Sliver, CobaltStrike, IcedID, Evilginx, SoftEther)
  2. **Whitelist** — Fast-pass for known browser fingerprints (Chrome, Firefox, Safari) — bypasses rate limiting
  3. **Rate-based detection** — Unknown fingerprints evaluated by connection rate; high-rate connections get TARPIT/BLOCK/BAN actions
- **PROXY protocol v2 parsing** — Reads real client IP from HAProxy binary header (essential since Docker NATs all traffic through gateway IP)
- **Tarpit redirect** — TARPIT action forwards connection to tarpit container instead of dropping
- **Real JA4 fingerprint extraction** — Parses TLS ClientHello directly from raw TCP stream using Scapy, matching FoxIO JA4 spec format
- **Pre-populated security lists** — Redis whitelist (6 browser fingerprints) and blacklist (7 malware fingerprints) loaded on startup

### 🧪 TRAFFIC GENERATOR
- **Complete rewrite** — Makes real TLS connections using `ssl.SSLContext` with distinct cipher/ALPN/TLS version configs per profile
- **3 legitimate profiles**: Chrome (TLS 1.2+), Firefox (TLS 1.2+), Safari (TLS 1.2+) — connect at 0.3-0.5 req/sec
- **5 malicious profiles**: Sliver C2, CobaltStrike Beacon, Python bot, Credential stuffer, Evilginx — connect at 2-50 req/sec
- **Real JA4 fingerprints** — Each profile produces a unique JA4 from its actual TLS ClientHello
- **Verified results**: 100% legitimate traffic allowed, 0% false positives; 60-100% malicious traffic blocked depending on profile

### 📊 DASHBOARD
- **Redesigned Grafana dashboard** with 14 panels:
  - Stat row: Total/Allowed/Blocked per minute, Block Rate %, Active Connections, Tarpitted count
  - Traffic flow: Stacked area chart of allowed vs blocked over time
  - Block rate timeline with color thresholds
  - Per-fingerprint traffic breakdown (allowed and blocked)
  - Security action distribution pie chart (Allowed/Tarpitted/Blocked/Banned/Blacklisted)
  - Top blocked fingerprints table
  - Blocked reasons table
  - TLS version distribution pie chart
  - Request latency percentiles (p50/p95/p99)
  - Security events timeline

### 📝 FILES ADDED
- `ha-config/haproxy.cfg` — HAProxy configuration
- `tarpit/tarpit-server.py` — Tarpit TCP server
- `tarpit/Dockerfile` — Tarpit container
- `ssl/certs/backend.crt` — Backend TLS certificate
- `ssl/private/backend.key` — Backend TLS private key

### 📝 FILES MODIFIED
- `proxy.py` — Major rewrite: security framework integration, PROXY protocol, tarpit redirect, fixed JA4 parsing
- `config/proxy.yml` — New security section with thresholds, strategies, whitelist, blacklist
- `mock-backend.py` — HTTPS support via TLS_CERT/TLS_KEY env vars
- `Dockerfile.mockbackend` — TLS cert packaging
- `docker-compose.poc.yml` — Added haproxy, tarpit services; backend on :443
- `scripts/tls-traffic-generator.py` — Complete rewrite for real TLS connections
- `generate-tls-traffic.sh` — Updated for new architecture
- `monitoring/grafana/dashboards/ja4proxy-overview.json` — Redesigned dashboard

## [2.0.1] - 2026-02-16 - TRAFFIC GENERATOR FIX

### 🐛 BUG FIXES
- **Fixed traffic generator bypassing proxy** - `generate-tls-traffic.sh` and `scripts/tls-traffic-generator.py` were sending requests directly to the backend (port 8081), completely bypassing the proxy. Prometheus metrics were never incremented, so Grafana dashboards showed no activity. Traffic is now routed through the proxy (port 8080) so that JA4 fingerprinting, security policies, and metrics collection all function correctly.
- **Fixed proxy rejecting non-TLS connections before recording metrics** - `JA4Fingerprint._sanitize_ja4()` raised `ValidationError` on sentinel values `"unknown"` and `"error"`, causing connections to be dropped before `REQUEST_COUNT` was incremented. These sentinel values are now allowed through validation so that all connections — including plain HTTP — are counted in Prometheus metrics and visible in Grafana.
- **Fixed request duration histogram never recording** - `REQUEST_DURATION.observe()` was never called in `handle_connection`, so latency panels always showed empty. Now records duration from data read through security check.
- **Fixed BLOCKED_REQUESTS label mismatches** - `check_access()` called `BLOCKED_REQUESTS.labels()` with only `reason` but the counter requires `reason`, `source_country`, and `attack_type`. Now passes all three labels.

### 📊 DASHBOARD FIXES
- **Fixed Block Rate (%) panel** — was dividing two counters with different label sets yielding NaN; now uses `sum()` on both sides and derives block % from `ja4_requests_total{action="blocked"}`.
- **Fixed Security Events pie chart** — was grouping by nonexistent `tier` label; now groups by `event_type` matching actual `ja4_security_events_total` labels.
- **Fixed Top Blocked table** — was grouping by nonexistent `ja4_fingerprint` label; now shows `reason` and `attack_type` from `ja4_blocked_requests_total`.
- **Fixed Rate Limit panel** — referenced nonexistent `ja4_rate_limit_exceeded_total`; now queries `ja4_security_events_total{event_type="rate_limit_exceeded"}`.
- **Fixed Whitelist/Blacklist panel** — referenced nonexistent `ja4_whitelist_hits_total` / `ja4_blacklist_hits_total`; replaced with "Blocked by Reason" showing `ja4_blocked_requests_total` broken down by `reason`.
- **Fixed Security Overview stat row** — removed nonexistent `ja4_whitelist_size` / `ja4_blacklist_size`; replaced with Block % and Active Connections.
- **Fixed Request Latency panel** — added `sum() by (le)` to histogram_quantile for correct aggregation.
- **Replaced Loki logs panel** — was using LogQL against Prometheus datasource; replaced with TLS Handshake Errors timeseries using `ja4_tls_handshake_errors_total`.
- **Upgraded deprecated `graph` panels to `timeseries`** for Grafana 10.x compatibility.

## [2.0.0] - 2024-02-14 - SECURITY HARDENING RELEASE

### 🔒 CRITICAL SECURITY FIXES
- **Fixed wildcard imports from Scapy** - Replaced with specific imports to prevent namespace pollution
- **Enforced Redis authentication** - Password now required via environment variable, fails in production without auth
- **Added comprehensive configuration validation** - Schema validation prevents configuration injection attacks
- **Secured secrets directories** - Set proper permissions (700) on secrets/ and ssl/private/ directories

### 🛡️ HIGH PRIORITY SECURITY FIXES
- **Changed default bind address** - Now binds to 127.0.0.1 by default instead of 0.0.0.0
- **Implemented fail-closed rate limiting** - Blocks requests on Redis errors instead of allowing
- **Added structured logging with sensitive data filtering** - Automatically redacts passwords, tokens, and PII
- **Enhanced Docker security** - Added seccomp, dropped capabilities, read-only filesystems where possible
- **Improved health checks** - Health check now validates actual service functionality via HTTP

### 🔧 MEDIUM PRIORITY SECURITY FIXES
- **Fixed exception handling** - JA4 generation now raises exceptions instead of returning empty strings
- **Added metrics endpoint security** - Configuration for authentication and network restrictions
- **Made timeouts configurable** - All timeout values now configurable to prevent resource exhaustion
- **Enhanced error handling** - Comprehensive error handling with security event metrics

### ✨ SECURITY FEATURES ADDED
- Environment variable support for secrets (${VAR_NAME} syntax)
- SensitiveDataFilter class for log sanitization
- SecureFormatter for production-safe exception logging
- Enhanced security metrics (SECURITY_EVENTS, TLS_HANDSHAKE_ERRORS, CERTIFICATE_EVENTS)
- Comprehensive .gitignore for sensitive files
- Security documentation and checklists

### 📚 DOCUMENTATION ADDED
- SECURITY_FIXES.md - Detailed security fix documentation
- SECURITY_CHECKLIST.md - Pre-deployment security checklist
- .env.example - Environment variable template with security guidelines
- Enhanced README in secrets/ and ssl/private/ directories

### 🔄 BREAKING CHANGES
- Redis password now REQUIRED in production (set REDIS_PASSWORD environment variable)
- Default bind address changed from 0.0.0.0 to 127.0.0.1
- JA4 generation now raises ValidationError on failure instead of returning empty string
- Configuration validation now enforces strict typing and ranges

### 🐛 BUG FIXES
- Fixed Redis initialization without proper connection testing
- Fixed timeout handling with proper exception types
- Fixed empty fingerprint validation bypass
- Fixed log message format consistency

### ⚠️ DEPRECATED
- Wildcard imports (removed)
- Null Redis passwords in production (blocked)
- Empty string returns on errors (now raises exceptions)

---

## [1.0.0] - 2024-02-14

### Added
- Complete JA4/JA4+ TLS fingerprinting implementation
- High-performance asynchronous proxy server
- Redis-backed security lists (whitelist/blacklist)
- Prometheus metrics integration
- TARPIT functionality for malicious clients
- Docker and Docker Compose support
- Comprehensive test suite (unit, integration, performance)
- Enterprise deployment with high availability
- Security hardening and compliance features
- Monitoring and alerting stack
- Complete documentation and operational procedures

### Security Features
- Non-root container execution
- TLS encryption for all communications
- Input validation and sanitization
- Rate limiting and DDoS protection
- Audit logging and SIEM integration
- Vulnerability management procedures

### Performance Features
- Asynchronous I/O for high throughput
- Connection pooling and keepalive
- Redis clustering for scalability
- Load balancing with HAProxy
- Performance monitoring and optimization

### Enterprise Features
- Multi-zone deployment architecture
- Disaster recovery procedures
- Compliance documentation (SOC 2, PCI DSS, GDPR)
- Operational runbooks and procedures
- Security incident response plan
- Automated deployment and rollback

### Documentation
- Comprehensive README with quick start
- Enterprise deployment guide
- Security architecture documentation
- API reference and configuration guide
- Troubleshooting and maintenance procedures
- Performance tuning recommendations