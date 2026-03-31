# JA4proxy — Agent Master Plan

> **Read this file first, every session.** Then read the specific phase file in
> `docs/phases/` for the phase you are working on. Do not skip ahead.

---

## What This Project Is

JA4proxy is a TLS-aware passthrough security proxy that sits in front of web server
infrastructure. It makes allow/block/tarpit decisions based entirely on **plaintext
metadata visible before and during the TLS handshake**. It never decrypts traffic,
never holds TLS keys, and forwards allowed connections byte-for-byte unchanged.

It is designed to be **completely standalone** — it requires nothing from the backend
webserver, does not inspect HTTP content, and makes all decisions purely from network
and TLS metadata.

### Architecture

```
Internet ──TLS──▶ HAProxy (LB) ──TCP──▶ JA4proxy ×N ──TLS──▶ Backend (HTTPS)
                      :443                  :8080               :443
                                              │  ▲
                           write events       │  │  write findings
                           (Redis Stream)     ▼  │  (Redis keys)
                                         ┌──────────────┐
                                         │  Analytics   │──▶ Prometheus
                                         │    Node      │
                                         └──────────────┘
                                         ┌──────────────┐
                                         │  Management  │  FastAPI + React
                                         │     UI       │  :8090
                                         └──────────────┘
```

### How the Pipeline Works

```
TCP accept
    │
    ├── Trusted upstream CIDR? (Phase 0) ──▶ extract real client IP from PROXY protocol
    │
    ├── IPv4/IPv6 normalisation (Phase 0)
    │
    ├── [BYPASS CHECKS — never reach scorer]
    │     ├── h2 / h1 ALPN?           ──▶ ALLOW immediately
    │     ├── JA4 in whitelist?        ──▶ ALLOW immediately
    │     ├── mTLS client cert valid?  ──▶ ALLOW immediately (Phase 5)
    │     ├── JA4 in blacklist?        ──▶ BLOCK immediately (RST)
    │     ├── Country in blacklist?    ──▶ BLOCK immediately
    │     └── Spamhaus DROP match?     ──▶ BLOCK immediately (Phase 8)
    │
    ├── [SIGNAL COLLECTION — all run, all produce RiskSignals]
    │     ├── TLS version/cipher check (Phase 3)
    │     ├── SNI analysis             (Phase 4)
    │     ├── TCP & connection behaviour (Phase 5)
    │     ├── ASN classification       (Phase 6)
    │     ├── FCrDNS enrichment        (Phase 7)
    │     ├── Beaconing detector       (Phase 9)
    │     ├── AbuseIPDB score          (Phase 10)
    │     ├── RDAP org reputation      (Phase 11)
    │     └── Analytics findings       (Phase 12)
    │
    ├── [COMPOSITE SCORER] (Phase 1) — aggregates all RiskSignals → score 0–100
    │
    ├── [ACTION DECIDER] (Phase 2) — applies dial setting to score → action
    │     dial=0:   ALLOW (monitor mode)
    │     dial=100: configured thresholds apply
    │
    └── Execute action: allow | flag | rate_limit | tarpit | block | ban
```

---

## The Core Asymmetry — This Governs Every Decision

| Error type | Example | Cost |
|-----------|---------|------|
| False negative | Bad bot slips through during cache sync window | Low |
| False positive | Real browser is blocked | **High** |

**When in doubt, fail open.** A missed bad request is recoverable. A blocked legitimate
user is not. This asymmetry must be reflected in every caching TTL, every threshold
default, every fallback behaviour, and every new feature.

Practical rules that flow from this:
- ALLOW decisions cached with long TTLs. BLOCK decisions with short TTLs.
- When Redis says "block" but local cache says "allow": **local cache wins**.
- When an external service is unreachable: **fail open**, log the failure.
- `h2`/`h1` ALPN browser traffic bypasses everything — it can never be blocked.
- Default dial is 0 (monitor only). The proxy never blocks on first deploy.

---

## Phase Index

| # | Phase | Key deliverable | Doc |
|---|-------|----------------|-----|
| 0 | Redis foundations & caching | Sorted Sets, Bloom filters, LRU cache, pipeline batching, IPv6, CDN IP trust, hot reload, **static IP allowlist** | [PHASE_00.md](docs/phases/PHASE_00.md) |
| 1 | Risk scorer scaffold | Empty scoring framework; all signals slot into it | [PHASE_01.md](docs/phases/PHASE_01.md) |
| 2 | **Monitor mode & dial** ⚠️ HIGH PRIORITY | Score all traffic; 0–100 dial controls blocking aggression | [PHASE_02.md](docs/phases/PHASE_02.md) |
| 3 | TLS version & cipher enforcement | Reject TLS 1.0/1.1 and weak ciphers; zero false positives | [PHASE_03.md](docs/phases/PHASE_03.md) |
| 4 | SNI analysis | Missing SNI, IP-literal, DGA scoring, unexpected hostname | [PHASE_04.md](docs/phases/PHASE_04.md) |
| 5 | TCP & connection behaviour + mTLS | JA4T, session resumption, lifespan, concurrency, return visitor, mTLS whitelist | [PHASE_05.md](docs/phases/PHASE_05.md) |
| 6 | ASN & datacenter classification | Datacenter/Tor/VPN detection; Tor exit list | [PHASE_06.md](docs/phases/PHASE_06.md) |
| 7 | FCrDNS & passive DNS enrichment | Async PTR lookup, residential classification, passive DNS | [PHASE_07.md](docs/phases/PHASE_07.md) |
| 8 | Spamhaus DROP/EDROP | Hard block layer; extensible feed framework | [PHASE_08.md](docs/phases/PHASE_08.md) |
| 9 | Beaconing detection | IAT coefficient of variation; sliding window timing | [PHASE_09.md](docs/phases/PHASE_09.md) |
| 10 | AbuseIPDB integration | Scored reputation lookup with aggressive caching | [PHASE_10.md](docs/phases/PHASE_10.md) |
| 11 | RDAP enrichment & block expansion | Org reputation; /24 block expansion; WHOIS pivot | [PHASE_11.md](docs/phases/PHASE_11.md) |
| 12 | Analytics node | Cross-instance aggregation; campaign/slow-scan detection; **score drift alerting** | [PHASE_12.md](docs/phases/PHASE_12.md) |
| 13 | Management UI - Ph 1: Backend API | FastAPI backend for real-time monitoring and configuration management | [PHASE_13_WORK_PLAN.md](docs/phases/details/PHASE_13_WORK_PLAN.md) |
| 51 | Management UI - Ph 2: Frontend | React-based dashboard for real-time visualization of proxy telemetry | [PHASE_51.md](docs/phases/PHASE_51.md) |
| 52 | Management UI - Ph 3: Admin | Interactive tools for managing allowlists, bans, and configuration | [PHASE_52.md](docs/phases/PHASE_52.md) |
| 14 | Production hardening | Secrets, Redis security, resource limits, observability, **tarpit self-protection** | [PHASE_14.md](docs/phases/PHASE_14.md) |
| 15 | **Go rewrite** | 10–50× throughput; Feature parity achieved including JA4X and Lua embedding | [PHASE_15.md](docs/phases/PHASE_15.md) |
| 16 | Extended fingerprinting | JA4X fingerprinting; adaptive rate limiting; coverage gates; OpenTelemetry tracing | [PHASE_16.md](docs/phases/PHASE_16.md) |
| 17 | Docker test optimisation | Fix Docker test container hang during teardown; zero-skip test policy | [PHASE_17.md](docs/phases/PHASE_17.md) |
| 18 | Security audit remediation | Specific exception types; lazy-format logging; `SignalCollector` Protocol | [PHASE_17b.md](docs/phases/PHASE_17b.md) |
| 19 | Backup & restore framework | Deterministic key enumeration; binary format; retention; CLI; observability | [PHASE_19.md](docs/phases/PHASE_19.md) |
| 20 | Passive TAP mode | AF_PACKET capture; out-of-band enforcement; backup schedule executor | [PHASE_20.md](docs/phases/PHASE_20.md) |
| 21 | **Documentation excellence** | Audience-first navigation, missing ADRs, GDPR hardening, operator/developer packs | [PHASE_21.md](docs/phases/PHASE_21.md) |
| 22 | Backup Enhancements - Ph 1: Core | Backup scheduling; pipeline batching; restore validation | [PHASE_22_WORK_PLAN.md](docs/phases/details/PHASE_22_WORK_PLAN.md) |
| 40 | Backup Enhancements - Ph 2: Security | AES-256-GCM encryption at rest; DSAR compliance utility | [PHASE_40_BACKUP_PLAN.md](docs/phases/details/PHASE_40_BACKUP_PLAN.md) |
| 57 | Backup Enhancements - Ph 3: Cloud | S3/GCS adapters; incremental backup strategy | [PHASE_57.md](docs/phases/PHASE_57.md) |
| 23 | Advanced Intelligence - Ph 1: Primary | Integrate AbuseIPDB and GreyNoise feeds for real-time reputation | [PHASE_23_WORK_PLAN.md](docs/phases/details/PHASE_23_WORK_PLAN.md) |
| 53 | Advanced Intelligence - Ph 2: Feed | Integrate specialized threat intelligence feeds (MISP, VT) | [PHASE_53.md](docs/phases/PHASE_53.md) |
| 31 | Advanced Intelligence - Ph 3: Geo | GeoIP lookup and country-based blocking; geographical threat analysis | [PHASE_31_WORK_PLAN.md](docs/phases/details/PHASE_31_WORK_PLAN.md) |
| 32 | Advanced Intelligence - Ph 4: Attribution | Attacker fingerprinting and JA4 correlation logic | [PHASE_32_WORK_PLAN.md](docs/phases/details/PHASE_32_WORK_PLAN.md) |
| 54 | Advanced Intelligence - Ph 5: Beh | Implement complex behavioral patterns and cross-IP correlation | [PHASE_54.md](docs/phases/PHASE_54.md) |
| 33 | Advanced Intelligence - Ph 6: Diagrams | Standardize all diagrams to Mermaid format for consistent rendering | [PHASE_33_WORK_PLAN.md](docs/phases/details/PHASE_33_WORK_PLAN.md) |
| 24 | Go strategy assessment *(closed)* | TLS parsing is not the bottleneck; gRPC IPC would add overhead | [PHASE_24_STRATEGY_ASSESSMENT.md](docs/phases/PHASE_24_STRATEGY_ASSESSMENT.md) |
| 25 | Docker container management | Image version pinning; CVE scan gaps; first-party scanning; update policy | [PHASE_25.md](docs/phases/PHASE_25.md) |
| 26 | **Python throughput hardening** | Parallel signals (`asyncio.gather`); Redis pipeline batching; Unix socket | [PHASE_26.md](docs/phases/PHASE_26.md) |
| 27 | Advanced Pentest Remediation | Remediate critical vulnerabilities: IP spoofing, sync/async Redis mismatch | [PHASE_27.md](docs/phases/PHASE_27.md) |
| 28 | Python Hardening - Ph 2: Redis | Redis pipeline batching; Unix domain socket; 30-40% latency reduction | [PHASE_28_WORK_PLAN.md](docs/phases/details/PHASE_28_WORK_PLAN.md) |
| 29 | Python Hardening - Ph 3: Multi-Proc | Multi-process worker model with Docker Compose and HAProxy LB | [PHASE_29_WORK_PLAN.md](docs/phases/details/PHASE_29_WORK_PLAN.md) |
| 30 | Python Hardening - Ph 4: Optimization | Deferred write batching; comprehensive benchmark validation | [PHASE_30_THROUGHPUT_PLAN.md](docs/phases/details/PHASE_30_THROUGHPUT_PLAN.md) |
| 34 | APT Hardening - Ph 1: Isolation | Parser process isolation and Zero-Trust Redis ACLs with signatures | [PHASE_34.md](docs/phases/PHASE_34.md) |
| 55 | APT Hardening - Ph 2: Detection | Implement subnet correlation, anti-evasion checks, and Seccomp | [PHASE_55.md](docs/phases/PHASE_55.md) |
| 35 | Advanced APT - Ph 1: Integrity | Implement supply chain integrity monitoring and eBPF/XDP blocking | [PHASE_35.md](docs/phases/PHASE_35.md) |
| 56 | Advanced APT - Ph 2: Deceptive | Implement honey-fingerprints, honey-SNIs, and namespace isolation | [PHASE_56.md](docs/phases/PHASE_56.md) |
| 36 | Go Test Quality & Parity Gaps | Fix JA4 fixtures; real cert JA4X tests; cross-language parity | [PHASE_36.md](docs/phases/PHASE_36.md) |
| 37 | Lint & Static Analysis Cleanup | Resolve remaining mypy/ruff/bandit warnings; strictly enforced CI gates | [PHASE_37.md](docs/phases/PHASE_37.md) |
| 38 | ISP Blocking Operations | Vetting, implementation, and monitoring procedures for malicious ISPs | [PHASE_38.md](docs/phases/PHASE_38.md) |
| 39 | Documentation Audit & Sync | Audit all phase docs, synchronize manifest/todo, clean up details/ | [PHASE_39.md](docs/phases/PHASE_39.md) |
| 41 | Robust Health Check API | Deep health/readiness endpoints; anti-flap hysteresis logic | [PHASE_41.md](docs/phases/PHASE_41.md) |
| 42 | Zero-Downtime Data Upgrades | Atomic hot-reloading of GeoIP DB and config without process restart | [PHASE_42.md](docs/phases/PHASE_42.md) |
| 43 | Blue/Green Deployment Tooling | Parallel container releases; traffic-shifting; automated rollbacks | [PHASE_43.md](docs/phases/PHASE_43.md) |
| 44 | Test Audit and Documentation | Audit test suite for genuine assertions; document coverage and gaps | [PHASE_44_TEST_AUDIT.md](docs/phases/PHASE_44_TEST_AUDIT.md) |
| 45 | Adversarial Test Expansion | Expand adversarial tests for SQLi, XSS, and command injection | [PHASE_45_ADVERSARIAL_TESTS.md](docs/phases/PHASE_45_ADVERSARIAL_TESTS.md) |
| 46 | Coverage Improvement | Achieve >80% coverage for all critical modules | [PHASE_46_COVERAGE.md](docs/phases/PHASE_46_COVERAGE.md) |
| 58 | Advanced Intelligence - Ph 3: Opt | Confidence weighting, adaptive caching, and feed reliability | [PHASE_58.md](docs/phases/PHASE_58.md) |

**Do phases in order. Complete all acceptance criteria before starting the next phase.**

---

## Supporting Documents

Read these before starting any phase:

| Document | Purpose |
|----------|---------|
| `docs/STYLE_GUIDE.md` | Config syntax, log format, test format, documentation language — read before writing anything |
| `docs/TEST_ORGANIZATION.md` | Test file layout, conftest structure, fixture factories, parametrize patterns, module-to-test mapping |
| `docs/OBSERVABILITY_STANDARDS.md` | Prometheus metric registry, JSON log schema, Grafana dashboard layout, Alertmanager rules, health endpoint, SLIs |
| `docs/TESTING_STRATEGY.md` | Full testing methodology — categories, infrastructure, CI pipeline, FP monitoring, phase completion gate |
| `docs/DOCUMENTATION_STANDARDS.md` | CHANGELOG format, REDIS_SCHEMA format, runbook update policy, API docs, ADR format |
| `docs/REDIS_SCHEMA.md` | All Redis key patterns (create in Phase 0, update every phase) |
| `docs/DMZ_DEPLOYMENT_READINESS.md` | Read before Phase 14 |
| `docs/security/COMPREHENSIVE_SECURITY_AUDIT.md` | Read before Phase 14 |

---

## Cross-Cutting Requirements

These apply to every phase without exception.

### The Bypass Rules (Configurable — See `security_policy` Config)

Every bypass condition is independently configurable by the secops admin. All have
safe defaults. Disabling any ALLOW bypass increases false positive risk. Disabling any
BLOCK bypass reduces hard-block coverage but routes those connections through the scorer
instead — they can still be blocked by score.

**The proxy emits a startup WARNING for every high-risk bypass that is disabled.**

```python
# Built from config at startup. All conditions are toggleable.
ALWAYS_ALLOW = []
if policy.alpn_browser_bypass.enabled:
    hard-allow.append(lambda c: c.alpn in ("h2", "h1"))
if policy.ja4_whitelist_bypass.enabled:
    hard-allow.append(lambda c: c.ja4 in whitelist_set)
if policy.mtls_bypass.enabled:
    hard-allow.append(lambda c: c.has_valid_client_cert)
if policy.static_ip_allowlist.enabled:
    hard-allow.append(lambda c: c.ip in static_allowlist)

ALWAYS_BLOCK = []
if policy.ja4_blacklist_bypass.enabled:
    hard-block.append(lambda c: c.ja4 in blacklist_set)
if policy.country_blacklist_bypass.enabled:
    hard-block.append(lambda c: c.country in country_blacklist)
if policy.spamhaus_bypass.enabled:
    hard-block.append(lambda c: spamhaus_trie.match(c.ip))
if policy.tls_version_bypass.enabled:
    hard-block.append(lambda c: c.tls_version in blocked_versions)
```

**Config — `config/proxy.yml` under `security_policy`:**

```yaml
security_policy:
  # ── ALLOW BYPASSES ──────────────────────────────────────────────────────
  # Each bypass short-circuits the pipeline before the scorer runs.
  # Disabling an ALLOW bypass routes those connections through the full scorer.

  alpn_browser_bypass:
    enabled: true             # h2/h1 ALPN → ALLOW without scoring
    # Default: true. Disable only to score specific h2 API clients.
    # CAUTION: browser traffic will be scored; false positive risk is elevated.

  ja4_whitelist_bypass:
    enabled: true             # JA4 fingerprint in whitelist → ALLOW without scoring
    # Default: true. Disable to route whitelisted fingerprints through the scorer.
    # CAUTION: whitelisted fingerprints may be blocked if they score above the threshold.

  mtls_bypass:
    enabled: true             # Valid mTLS client cert → ALLOW without scoring (Phase 5+)
    # Default: true. Disable to score mTLS clients instead of bypassing.
    # CAUTION: mTLS clients may be blocked if they score above the dial threshold.

  static_ip_allowlist:
    enabled: true             # IP in static allowlist → ALLOW without scoring (Phase 0)

  # ── BLOCK BYPASSES ──────────────────────────────────────────────────────
  # Disabling a BLOCK bypass means those connections go through the scorer.
  # They can still be blocked if they score above the dial threshold.

  ja4_blacklist_bypass:
    enabled: true             # JA4 in blacklist → immediate RST, no scoring
    # If disabled: blacklisted fingerprints are scored. Block only if score ≥ threshold.
    # Use case: temporarily "downgrade" a blacklist entry to observe its traffic.

  country_blacklist_bypass:
    enabled: true             # Country in GeoIP blocklist → immediate block
    # If disabled: blocked countries go through scorer.

  spamhaus_bypass:
    enabled: true             # Spamhaus DROP/EDROP match → immediate block
    # If disabled: Spamhaus matches produce a RiskSignal (+80) instead of hard block.
    # Use case: investigating traffic from Spamhaus-listed ranges.

  tls_version_bypass:
    enabled: true             # TLS 1.0/1.1 → immediate RST (Phase 3+)
    # If disabled: old TLS versions go through scorer with a risk score contribution.
```

**Startup warnings** — emitted to log (WARN level) and reflected in Prometheus when any
high-risk bypass is disabled. Format follows the system log standard:
```
WARN  | policy | event=bypass_disabled | bypass=alpn_browser_bypass    | effect=browser traffic will be scored; false positive risk elevated
WARN  | policy | event=bypass_disabled | bypass=spamhaus_drop_bypass    | effect=Spamhaus DROP matches scored as signal(+80) instead of hard block
```

**Policy audit log** — every change to `security_policy` config is written to:
```
management:policy_audit  → LIST of {timestamp, changed_by, item, old_value, new_value}
                           last 1000 entries, no TTL
```

Changes via Management UI (Phase 13) are attributed to the secops admin's session IP.
Changes via config file reload are attributed to `"config_reload"`.

**Interaction with the dial (Phase 2):**
- ALLOW bypasses are unaffected by the dial — they always allow (this is the design intent;
  if you want to score a bypass category, disable that bypass, not lower the dial)
- BLOCK bypasses route to the scorer when disabled — the dial then controls whether
  they're actually blocked (at dial=0 they still pass through in monitor mode)

### IPv6 (Cross-Cutting — Handle From Phase 0 Onwards)

Every feature that touches an IP address must handle both IPv4 and IPv6:

- **Rate limiting keys:** use full IP as-is. Do not truncate IPv6 addresses.
- **CIDR matching:** `pytricia` handles both natively. Go's `net/netip` handles both.
- **GeoIP:** MaxMind GeoLite2 covers both. Verify lookups use the right DB.
- **HyperLogLog per subnet:** IPv4 use `/24` (256 addresses). IPv6 use `/48` (same
  approximate user population density). Key: `hll:cidr48:{cidr}` for IPv6.
- **Beaconing keys:** `beacon:{ip}:{ja4}` — full IP string, works for both.
- **Ban keys:** `ban:{ip}` — full IP string, works for both.
- **RDAP:** IPv6 lookups route to the same RIRs via IANA bootstrap.
- **Block expansion:** never auto-expand IPv6 beyond `/48` (equivalent to IPv4 `/24`).
- **Log format:** always log the full IP. Do not abbreviate IPv6.

When in doubt: store IPs as their canonical string representation
(`ipaddress.ip_address(ip).compressed` in Python, `netip.Addr.String()` in Go).

### Async / Non-Blocking

- No blocking I/O on the hot path under any circumstances.
- All external service calls (AbuseIPDB, RDAP, DNS) use `asyncio.create_task()` —
  fire-and-forget from the hot path.
- No `time.sleep()` anywhere. Use `asyncio.sleep()`.

### Fail Open

Every external service call must have an explicit failure handler that:
1. Logs the failure with context
2. Increments a Prometheus error counter
3. Returns a zero/neutral result (not an error that propagates)

### Config-Driven

Every new feature must be toggleable in `config/proxy.yml` with sensible defaults.
New config keys require inline YAML comments explaining purpose and valid values.
Defaults must be conservative (fail open, low false-positive rate).

### Hot Config Reload (Phase 0+)

Config changes must not require a proxy restart. The proxy watches for `SIGHUP` and
reloads `config/proxy.yml`. The Management UI (Phase 13) triggers reload via a Redis
pub/sub message. After reload, new config applies to all subsequent connections.

Config sections that cannot be hot-reloaded (require restart): listen port, Redis URL,
TLS certificate paths. Document these limitations.

### Testing Standards

See `docs/TESTING_STRATEGY.md` for the full methodology. Summary:
- Maintain ~1.3× test-to-code ratio throughout.
- Test categories required: unit, integration, chaos/resilience, adversarial/fuzz, FP corpus, performance, E2E.
- All external services use mock servers in `tests/mocks/` — never call real APIs in tests.
- Every failure mode documented in code must have a chaos test verifying it.
- New signals: FP rate test against real-world corpus (Tranco top 10k for domains).
- Phase completion gate (`docs/TESTING_STRATEGY.md §5`) must fully pass before next phase.

### Documentation Standards

See `docs/DOCUMENTATION_STANDARDS.md` for the full spec. Summary:
- CHANGELOG.md: one entry per phase in the standard format defined in that doc.
- `docs/REDIS_SCHEMA.md`: every Redis key documented in the same phase it's introduced.
- Runbook docs updated whenever a new service, failure mode, or command is added.
- ADRs written for non-obvious decisions in `docs/decisions/ADR-NNN.md`.
- Per-phase documentation gate in `docs/DOCUMENTATION_STANDARDS.md §7` must pass.

### Code Style (Python)

- Type hints on all public functions and class attributes.
- Docstrings on all public classes and non-trivial functions.
- Follow existing patterns in `proxy.py` and `src/security/`.

### Code Style (Go — Phase 15)

- `gofmt`-formatted. Exported functions have godoc comments.
- Errors returned, not panicked (except unrecoverable startup).
- Context propagation for shutdown cancellation.

### Documentation

- Update `README.md` pipeline table when adding new layers.
- All Redis key patterns in `docs/REDIS_SCHEMA.md` (create if missing).
- New Docker Compose services in README Services table.
- Update `CHANGELOG.md` after each phase.
- Update `docs/phases/manifest.yaml`: set the phase `status` to `COMPLETE`, remove any gaps that were closed. Then run `python3 scripts/sync-roadmap.py` to regenerate `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`. Commit all four files together. This is the **source of truth** for phase status — if it is not updated, downstream tooling and future sessions will show stale state.

### Prometheus Naming

```
ja4proxy_{subsystem}_{metric_name}_{unit}
# Examples:
ja4proxy_abuseipdb_lookups_total{result="hit|miss|error"}
ja4proxy_risk_score_distribution        # histogram
ja4proxy_dial_setting                   # gauge
```

### Redis Data Structure Quick Reference

| Use case | Structure | Why |
|----------|-----------|-----|
| JA4 blacklist / whitelist | Redis SET + in-process Python/Go set | O(1) SISMEMBER; small and static |
| IP bans | String + TTL | Per-key TTL required |
| Sliding window rate limiting | Sorted Set + Lua (EVALSHA) | True sliding window; no boundary errors |
| Beaconing timestamps | Sorted Set (score=timestamp) | ZRANGEBYSCORE for time windows |
| Session resumption ratio | Hash (total, resumed) | Atomic HINCRBY |
| Concurrent connection count | INCR/DECR String | Simple atomic counter |
| Return visitor tracking | Hash (first_seen, total, allowed, blocked) | Multi-field HINCRBY |
| Unique IP per CIDR | HyperLogLog (PFADD/PFCOUNT) | O(1), 12KB/key, ~0.81% error |
| Enrichment dedup | Bloom filter (BF.ADD) | False positives acceptable; O(1) |
| CIDR matching | In-process pytricia / Go trie | No CIDR primitive in Redis |
| GeoIP / ASN lookup | In-process mmap (MaxMind) | Designed for mmap |
| Cross-instance events | Redis Stream (XADD/XREADGROUP) | Persistent, replayable |
| Analytics findings | String + TTL | Read by proxy as scorer inputs |

**Never use Redis for CIDR matching. Always in-process trie.**  
**Bloom filter fallback:** if RedisBloom unavailable, use SET + 24h TTL.

---

## File Locations

```
proxy.py                            # Proxy entry point (→ Go in Phase 15)
src/
  security/
    pipeline.py                     # Pipeline orchestration
    risk_scorer.py                  # Phase 1
    action_decider.py               # Phase 2 (dial)
    tls_enforcer.py                 # Phase 3
    sni_analyzer.py                 # Phase 4
    tcp_analyzer.py                 # Phase 5
    mtls.py                         # Phase 5
    asn_classifier.py               # Phase 6
    dns_enrichment.py               # Phase 7
    blocklists.py                   # Phase 8
    beaconing_detector.py           # Phase 9
    abuseipdb.py                    # Phase 10
    rdap_enrichment.py              # Phase 11
  cache/
    local_cache.py                  # Phase 0
  config/
    loader.py                       # Phase 0: hot reload
analytics/                          # Phase 12 (stays Python)
# management/                       # Phase 13 DEFERRED — removed; re-implement after Phase 15
config/
  proxy.yml
  asn_datacenter_list.yml           # Phase 6
  known_bad_orgs.yml                # Phase 11
  trusted_cas.pem                   # Phase 5 (mTLS)
docs/
  phases/                           # Per-phase plan files
  REDIS_SCHEMA.md
  DMZ_DEPLOYMENT_READINESS.md
  security/COMPREHENSIVE_SECURITY_AUDIT.md
```

---

## Decision Log

| Decision | Rationale |
|----------|-----------|
| Default dial=0 | Never block on first deploy; must consciously raise |
| Score always, act based on dial | Retrospective analysis requires scores even at dial=0 |
| Dial increment limit | Prevents accidental jump to full blocking |
| ALLOW bypasses unaffected by dial | Disabling bypass is the right way to score a category; dial controls scoring threshold |
| ALLOW cached 30min, BLOCK cached 30s | False positive (blocking real user) costs more |
| Redis says block, local cache says allow → local wins | If Redis down, real browsers keep working |
| Pub/Sub only for removals/releases | New blocks can propagate slowly; removals need immediate effect |
| Spamhaus DROP: scorer bypass by default | Near-zero FP rate — but admin can disable bypass to route through scorer for investigation |
| AbuseIPDB: never hard-block < score 50 | Shared IPs (NAT/VPN) make hard-blocking unsafe |
| RDAP block expansion: off by default | High-impact; secops admin must consciously opt in |
| RDAP block expansion: never > /24 (IPv4), /48 (IPv6) | A /16 could affect entire ISP customers |
| Browser ALPN whitelist: never enqueue for enrichment | No value; their netblock must never be expanded |
| JA4 auto-classify: candidate list only | Auto-applying to blacklist could block legitimate traffic |
| Analytics: Redis Streams not Pub/Sub | Streams persistent and replayable after downtime |
| Analytics: fire-and-forget XADD | Stream writes must never add hot-path latency |
| Analytics node: separate container | numpy/pandas/scipy must not bloat proxy; failure isolation |
| Go rewrite: Phase 15 (last) | Prove design in Python first; rewrite once, with stable spec |
| Go not Rust | 10–50× Python gain; GC pauses negligible at this scale; faster to write |
| Python analytics + UI stay Python | Not performance-critical; scipy ecosystem irreplaceable |
| Trusted upstream CIDRs: explicit config | Prevents IP spoofing via X-Forwarded-For if not behind CDN |
| IPv6 /48 equivalent to IPv4 /24 | Same approximate user population density for analytics |
| mTLS: scorer bypass by default | Client cert is cryptographic proof; scoring adds no value — but admin can disable bypass if desired |
| Hot reload: SIGHUP + pub/sub | Config changes must not require restart or traffic gap |

---

## How to Run a Phase

### Starting
1. Read this file (`CLAUDE.md`) in full.
2. Read the specific phase file `docs/phases/PHASE_XX.md`.
3. Read the existing code in `proxy.py` and `src/security/` before writing anything new.
4. Read `config/proxy.yml` to understand the config structure.

### Implementing
5. Implement, following the acceptance criteria in the phase file.
6. Run `make test` — all tests must pass with zero warnings.

### Closing (mandatory — do not skip)
7. Update `CHANGELOG.md` with a standard entry for the phase.
8. Update `docs/phases/manifest.yaml`: set `status: COMPLETE`, remove any gaps that were resolved.
9. Run `python3 scripts/sync-roadmap.py` — regenerates `docs/phases/TODO.md` and `docs/PROJECT_STATUS.md`.
10. Commit code, `CHANGELOG.md`, `docs/phases/manifest.yaml`, `docs/phases/TODO.md`, and `docs/PROJECT_STATUS.md` as one atomic commit.
11. Do not start the next phase until all acceptance criteria pass.
