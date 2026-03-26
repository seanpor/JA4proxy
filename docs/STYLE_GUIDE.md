# JA4proxy — Style Guide

> This is the authoritative reference for configuration syntax, log message format,
> test acceptance criteria format, and documentation language.
>
> Every phase file, every config block, every log line, and every test specification
> in this plan follows these rules. When writing new code or documentation, check
> here first.

---

## §0. Naming Conventions

This section defines the correct case style for every naming context in the project.
Follow these rules in code, config, documentation, and UI. When in doubt, check here first.

---

### 0a. Quick Reference

| Context | Style | Example |
|---------|-------|---------|
| Python class | `PascalCase` | `RiskScorer`, `ASNClassifier`, `BlocklistManager` |
| Python function / method | `snake_case` | `get_score()`, `classify()`, `maybe_expand_block()` |
| Python variable / parameter | `snake_case` | `trigger_score`, `list_name`, `org_handle` |
| Python constant | `SCREAMING_SNAKE_CASE` | `MAX_DIAL_VALUE`, `DEFAULT_BLOCK_THRESHOLD` |
| Python module filename | `snake_case` | `../src/security/risk_scorer.py`, `../src/security/asn_classifier.py`, `../src/cache/local_cache.py` |
| Python dataclass field | `snake_case` | `total_score`, `recommended_action`, `fetched_at` |
| Config key (YAML) | `snake_case` | `queue_size`, `worker_count`, `min_enqueue_score` |
| Config filename | `snake_case` | `../config/proxy.yml`, `../config/asn_datacenter_list.yml`, `../config/known_bad_orgs.yml` |
| Environment variable | `SCREAMING_SNAKE_CASE` | `ABUSEIPDB_API_KEY`, `UI_API_KEY`, `REDIS_URL` |
| Redis key segment | `snake_case`, colon-separated | `abuseipdb:score:{ip}`, `beacon:{ip}:{ja4}` |
| Redis key variable part | `{snake_case}` in braces | `{ip}`, `{ja4}`, `{org_handle}`, `{list_name}` |
| Prometheus metric | `snake_case` with `ja4proxy_` prefix | `ja4proxy_connections_total`, `ja4proxy_dial_current` |
| Prometheus label key | `snake_case` | `asn_type`, `ptr_class`, `tls_version` |
| Prometheus label value | `snake_case` | `spamhaus_drop`, `alpn_browser`, `rate_limit` |
| Docker service name | `kebab-case` | `ja4proxy`, `redis-stack`, `analytics-node`, `management-ui` |
| Docker image name | `kebab-case` | `ja4proxy-proxy`, `ja4proxy-analytics` |
| Docker volume name | `kebab-case` | `redis-data`, `geoip-db` |
| Log event name | `snake_case` | `feed_refreshed`, `bypass_disabled`, `startup_failed` |
| Log subsystem token | `snake_case` (short noun) | `blocklist`, `beaconing`, `rdap`, `abuseipdb` |
| Signal name (`RiskSignal.name`) | `snake_case` | `missing_sni`, `asn_tor`, `rdap_known_bad_org` |
| Action string | `snake_case` | `allow`, `rate_limit`, `tarpit`, `block`, `ban` |
| UI section name (display) | Title Case | `Live Connection Feed`, `IP & CIDR Management` |
| UI button label | Title Case or Sentence case (imperative) | `Add IP`, `Release Ban`, `Approve Candidate` |
| UI status label | Sentence case | `Quota exhausted`, `Feed stale`, `Connected` |
| Management API endpoint | `kebab-case` path segments | `/api/v1/ip-bans`, `/api/v1/ja4-blacklist` |
| Management API JSON field | `snake_case` | `"org_handle"`, `"trigger_score"`, `"added_by"` |
| Test file | `test_` + `snake_case` | `../tests/unit/test_risk_scorer.py`, `../tests/integration/test_dial_propagation.py` |
| Test function | `test_` + `snake_case` describing scenario | `test_beacon_score_below_minimum_observations()` |
| Test class | `Test` + `PascalCase` module/scenario | `TestASNClassifierDetection` |
| Grafana dashboard filename | `snake_case` with numeric prefix | `01_operations.json`, `02_security.json` |
| Grafana panel title | Title Case | `Risk Score Distribution`, `Dial Readiness` |
| Alertmanager rule name | `PascalCase` | `BlocklistFeedStale`, `ScoreDriftDetected` |
| ADR filename | `ADR-NNN-` + `kebab-case` | `ADR-001-go-not-rust-for-phase-15.md` |
| Changelog section | Sentence case | `Added`, `Changed`, `Breaking Changes` |

---

### 0b. Python Naming Rules in Detail

**Classes** use `PascalCase`. Acronyms in class names are fully capitalised:
```python
# ✓ CORRECT
class ASNClassifier:      # ASN is an acronym — all caps
class RDAPResult:         # RDAP is an acronym — all caps
class FCrDNSResult:       # FCrDNS is a term of art — preserve capitalisation
class LocalCache:
class BlocklistManager:

# ✗ WRONG
class AsnClassifier:      # ASN should be all caps
class RdapResult:         # RDAP should be all caps
class Localcache:
```

**Functions and methods** use `snake_case`. Internal helpers are prefixed with `_`:
```python
# ✓ CORRECT
def classify(self, ip: str) -> ASNClassification: ...
def _download_tor_consensus(self) -> frozenset[str]: ...
async def maybe_expand_block(ip: str, rdap: RDAPResult) -> bool: ...

# ✗ WRONG
def Classify(self, ip): ...
def downloadTorConsensus(self): ...
```

**Constants** use `SCREAMING_SNAKE_CASE` at module level:
```python
# ✓ CORRECT
MAX_DIAL_VALUE = 100
DEFAULT_BLOCK_THRESHOLD = 70
RISK_SCORE_CAP = 100
LEADER_LOCK_TTL = 3600

# ✗ WRONG
maxDialValue = 100
DefaultBlockThreshold = 70
```

**Type annotations** use the class name as defined, plus standard library types:
```python
# ✓ CORRECT
def get_score(ip: str) -> int | None: ...
def classify(self, ip: str) -> ASNClassification: ...
signals: list[RiskSignal]
result: tuple[bool, str]

# ✗ WRONG
def get_score(ip: str) -> Optional[int]: ...   # Use | None, not Optional
```

---

### 0c. YAML Config Key Rules

**All keys are `snake_case`**. No camelCase, no kebab-case, no PascalCase.

```yaml
# ✓ CORRECT
dns_enrichment:
  queue_size: 1000
  worker_count: 5
  min_enqueue_score: 10
  resolver_timeout_seconds: 5
  fcrdns:
    enabled: true
    cache_ttl_seconds: 21600
    score: 15

# ✗ WRONG
dnsEnrichment:              # camelCase
  queueSize: 1000           # camelCase
  WorkerCount: 5            # PascalCase
  min-enqueue-score: 10     # kebab-case
```

**The top-level config key is the Python module filename stem.** All config for
a module lives under one top-level key. The key is the same string as the `.py`
filename without the extension — not a descriptive phrase, not the class name,
not a shortened form.

```yaml
# ✓ CORRECT — key matches tls_enforcer.py
tls_enforcer:
  block_tls_10: true

# ✗ WRONG — descriptive phrase, not the module name
tls_enforcement:
  block_tls_10: true
```

---

### 0c-i. Canonical Module Name Table

This table is the single source of truth for every name form for every module.
Use the exact strings shown — never invent alternatives.

| Python file | Config key | Prometheus subsystem | Log subsystem | Signal prefix |
|-------------|------------|----------------------|---------------|---------------|
| `../src/security/risk_scorer.py` | `risk_scorer` | `scorer` | `scorer` | *(produces no named signals)* |
| `../src/security/action_decider.py` | `action_decider` | `dial` | `dial` | *(decision, not a signal)* |
| `../src/security/tls_enforcer.py` | `tls_enforcer` | `tls` | `tls` | `tls_` |
| `../src/security/sni_analyzer.py` | `sni_analyzer` | `sni` | `sni` | *(varies: `missing_sni`, `dga`, etc.)* |
| `../src/security/tcp_analyzer.py` | `tcp_analyzer` | `tcp` | `tcp` | `tcp_`, `ja4t_`, etc. |
| `../src/security/mtls.py` | `mtls` | `tcp` | `mtls` | *(bypass, not a signal)* |
| `../src/security/asn_classifier.py` | `asn_classifier` | `asn` | `asn` | `asn_` |
| `../src/security/dns_enrichment.py` | `dns_enrichment` | `dns` | `dns` | `no_ptr`, `fcrdns_`, `residential_ptr` |
| `../src/security/blocklists.py` | `blocklists` | `blocklist` | `blocklist` | `spamhaus_drop`, etc. |
| `../src/security/beaconing_detector.py` | `beaconing_detector` | `beaconing` | `beaconing` | `beaconing` |
| `../src/security/abuseipdb.py` | `abuseipdb` | `abuseipdb` | `abuseipdb` | `abuseipdb` |
| `../src/security/rdap_enrichment.py` | `rdap_enrichment` | `rdap` | `rdap` | `rdap_` |
| `../src/cache/local_cache.py` | `local_cache` | `cache` | `cache` | *(infrastructure)* |
| `config_loader.py` | `config` | `config` | `config` | *(infrastructure)* |

**Rules for using this table:**

- Python file column → use when naming the source file or importing the module
- Config key column → use as the YAML top-level key in `config/proxy.yml`
- Prometheus subsystem column → use in metric names: `ja4proxy_{subsystem}_{measurement}`
- Log subsystem column → use in structured log lines: `"subsystem": "{subsystem}"`
- Signal prefix column → the `RiskSignal.name` starts with this prefix (see §0c-ii)

---

### 0c-ii. Canonical Signal Name Registry

Every `RiskSignal.name` value must come from this list. Do not invent new names
without adding them here first. Signal names are `snake_case` strings.

| `RiskSignal.name` | Producing module | Polarity |
|-------------------|-----------------|----------|
| `tls_version` | `tls_enforcer` | positive (raises score) |
| `weak_cipher` | `tls_enforcer` | positive |
| `missing_sni` | `sni_analyzer` | positive |
| `ip_literal_sni` | `sni_analyzer` | positive |
| `dga` | `sni_analyzer` | positive |
| `unexpected_sni` | `sni_analyzer` | positive |
| `ja4t_mismatch` | `tcp_analyzer` | positive |
| `no_resumption` | `tcp_analyzer` | positive |
| `short_lived` | `tcp_analyzer` | positive |
| `high_concurrency` | `tcp_analyzer` | positive |
| `tls_alert_rate` | `tcp_analyzer` | positive |
| `return_visitor` | `tcp_analyzer` | **negative** (reduces score) |
| `asn_tor` | `asn_classifier` | positive |
| `asn_datacenter` | `asn_classifier` | positive |
| `asn_vpn` | `asn_classifier` | positive |
| `no_ptr` | `dns_enrichment` | positive |
| `fcrdns_failed` | `dns_enrichment` | positive |
| `residential_ptr` | `dns_enrichment` | **negative** (reduces score) |
| `spamhaus_drop` | `blocklists` | positive (bypass — not scored by default) |
| `beaconing` | `beaconing_detector` | positive |
| `abuseipdb` | `abuseipdb` | positive |
| `rdap_known_bad_org` | `rdap_enrichment` | positive |
| `rdap_new_netblock` | `rdap_enrichment` | positive |
| `analytics_subnet` | analytics node | positive |
| `analytics_campaign` | analytics node | positive |
| `analytics_slow_scan` | analytics node | positive |

---

### 0d. Redis Key Rules

Redis keys use colon-separated `snake_case` segments. Variable parts are enclosed in `{braces}`:

```
{namespace}:{entity_type}:{identifier}

# Examples — all correct:
abuseipdb:score:{ip}
beacon:{ip}:{ja4}
dns:ptr:{ip}
rdap:org:{org_handle}
leader:blocklist_download:{list_name}
analytics:baseline:hourly:{YYYY-MM-DD-HH}
config:dial
bloom:abuseipdb_enriched
```

**Rules:**
- All segments `snake_case` — no camelCase, no uppercase
- Variable parts in `{snake_case}` — e.g. `{ip}`, `{ja4}`, `{list_name}`
- Date/time variables in ISO format: `{YYYY-MM-DD}`, `{YYYY-MM-DD-HH}`
- Namespace is always the module short name (same as Prometheus subsystem token)
- Maximum 4 segments before the variable part; avoid deep nesting

---

### 0e. Environment Variable Rules

All environment variables are `SCREAMING_SNAKE_CASE`:

```bash
# ✓ CORRECT
ABUSEIPDB_API_KEY=abc123
UI_API_KEY=secret
REDIS_URL=redis://localhost:6379
MAXMIND_DB_PATH=/data/GeoLite2-ASN.mmdb
LOG_LEVEL=INFO
DIAL=0

# ✗ WRONG
abuseipdb_api_key=abc123    # lowercase
uiApiKey=secret             # camelCase
```

All environment variables must be documented in `.env.example` with a comment:
```bash
# .env.example
ABUSEIPDB_API_KEY=         # Required if abuseipdb.enabled: true. Get from abuseipdb.com.
UI_API_KEY=                # Required. No default. Set before starting the management UI.
REDIS_URL=redis://localhost:6379  # Default shown. Override for production.
MAXMIND_DB_PATH=/data/GeoLite2-ASN.mmdb  # Path to MaxMind GeoLite2-ASN database file.
LOG_LEVEL=INFO             # Options: DEBUG | INFO | WARN | ERROR. Default: INFO.
```

---

### 0f. Terminology

Use the terms from this table. No alternatives. See also §4b for the full list.

| Use | Never use |
|-----|-----------|
| secops admin | operator, administrator, admin, security operator, user |
| connection | request (we process TLS connections, not HTTP requests) |
| composite score | total score, final score, risk total, overall score |
| signal | indicator, feature, factor, heuristic |
| bypass | short-circuit, fast-path, skip, exemption |
| fail open | fail safe, degrade gracefully (when the meaning is: allow on error) |
| enrichment | lookup, resolution (for async background data gathering) |
| feed | list, database, source (for threat intelligence inputs) |
| dial | threshold knob, aggression slider, blocking level, sensitivity |
| action | disposition, verdict, decision |
| secops admin session | operator session, admin session |

---

## §1. Configuration YAML

### 1a. Key Naming

**Risk score contributions always use the key `score:`** within their named subsection.
Never use `risk_score`, `risk_score_contribution`, `risk_score_multiplier`,
`risk_score_max`, `mismatch_risk_score`, or any other variant.

The module or subsection name already provides context; the key only needs to say
what it is — a score.

```yaml
# ✓ CORRECT
sni_analysis:
  missing_sni:
    enabled: true
    score: 30           # Risk score added to composite when signal fires

  ip_literal_sni:
    enabled: true
    score: 25

  dga_detection:
    enabled: true
    score_cap: 40       # Maximum score from this signal (multiplied by confidence 0–1)

# ✗ WRONG — inconsistent key names
sni_analysis:
  missing_sni_risk_score: 30
  ip_literal_risk_score: 25
  dga_risk_score_multiplier: 40
```

**Exception — `score_cap`:** when a signal score is computed as `confidence × cap`
(e.g. DGA, beaconing, AbuseIPDB), use `score_cap:` for the maximum and document
the formula in a comment.

**Thresholds use descriptive names without a `score` prefix:**
```yaml
risk_scorer:
  thresholds:
    flag:       20    # Allowed; elevated logging
    rate_limit: 35    # Rate limited
    tarpit:     55    # Slow-drained
    block:      70    # Connection rejected
    ban:        85    # Rejected; IP banned for ban_duration_seconds
```

### 1b. Structure — Always Expanded, Never Inline

All config blocks use the expanded multi-line form. Never use inline YAML objects
(`{ key: value, key2: value2 }`) in configuration files or in config examples in
documentation.

```yaml
# ✓ CORRECT
tcp_analysis:
  session_resumption:
    enabled: true
    min_connections: 10
    score: 15

# ✗ WRONG — inline form is harder to read and comment
tcp_analysis:
  session_resumption: { enabled: true, min_connections: 10, risk_score: 15 }
```

### 1c. Comment Format

Every non-obvious config key has an inline comment. Comments follow this structure:

```
key: value    # What this controls. Default: value. Range/options: x–y | a | b.
```

For keys with important implications:
```
key: value    # What this controls.
              # CAUTION: changing this may cause [consequence].
```

For keys disabled by default where the admin must consciously opt in:
```
key: false    # Disabled by default. Enable only after [prerequisite].
              # See docs/phases/PHASE_NN.md for operational guidance.
```

**Never use:** `# Optional`, `# Required`, `# WARNING if disabled`, `# Note`,
`# NOTE`, `# Important`. Use the structured format above instead.

Concrete examples:

```yaml
upstream_trust:
  enabled: false          # Enable when proxy sits behind a CDN or load balancer.
                          # CAUTION: enabling without setting trusted_cidrs accepts
                          # spoofed client IPs from any source.
  trusted_cidrs:
    - "10.0.0.0/8"        # Internal HAProxy instances — adjust to your network.

abuseipdb:
  enabled: false          # Disabled by default. Set api_key before enabling.
  api_key: ""             # Set via ABUSEIPDB_API_KEY environment variable.
  max_requests_per_day: 1000  # Free tier limit. Default: 1000.
  cache_ttl_seconds: 14400    # How long to cache scores. Default: 14400 (4 hours).

block_expansion:
  enabled: false          # Disabled by default. Read Phase 11 docs before enabling.
  min_trigger_score: 75   # Minimum composite score to trigger expansion. Default: 75.
                          # CAUTION: lowering this increases false expansion risk.
  max_prefix_v4: 24       # Never expand to a prefix shorter than this. Default: 24 (/24).
  max_prefix_v6: 48       # IPv6 equivalent. Default: 48 (/48).
```

### 1d. Enabled/Disabled Defaults

Document the default in a comment, not by the key name:

```yaml
# ✓ CORRECT — default is clear from comment
alpn_browser_bypass:
  enabled: true     # Default: true. Disable only to score specific h2 API clients.

# ✗ WRONG — key name encodes the default, which becomes misleading if changed
alpn_browser_bypass_enabled_by_default: true
```

### 1e. Actions

Connection actions are lowercase strings. The valid set is fixed:

```
allow | flag | rate_limit | tarpit | block | ban
```

Use exactly these strings in config values, code, and documentation. Never use
`"blocked"`, `"allowed"`, `"rate-limit"`, `"drop"`, `"reject"`, or other variants.

### 1f. Signal Names

`RiskSignal.name` values are `snake_case` strings matching the module that produced
them. These appear in logs and the UI. The full set:

```
tls_version        # Phase 3 — old TLS version
weak_cipher        # Phase 3 — weak cipher suite
missing_sni        # Phase 4
ip_literal_sni     # Phase 4
dga                # Phase 4 — domain generation algorithm match
unexpected_sni     # Phase 4 — SNI not in expected_hostnames
ja4t_mismatch      # Phase 5 — TCP fingerprint vs TLS fingerprint mismatch
no_resumption      # Phase 5 — zero session resumption rate
short_lived        # Phase 5 — connection lifespan below threshold
high_concurrency   # Phase 5 — too many concurrent connections from IP
tls_alert_rate     # Phase 5 — high rate of TLS alert messages
return_visitor     # Phase 5 — trust reduction for long-term clean IPs (negative score)
asn_datacenter     # Phase 6
asn_tor            # Phase 6
asn_vpn            # Phase 6
asn_unknown        # Phase 6
no_ptr             # Phase 7 — no PTR record
fcrdns_failed      # Phase 7 — PTR exists but does not forward-confirm
residential_ptr    # Phase 7 — residential PTR (negative score)
beaconing          # Phase 9
abuseipdb          # Phase 10
rdap_known_bad_org # Phase 11
rdap_new_netblock  # Phase 11
spamhaus_drop      # Phase 8 — only when bypass disabled
cross_instance     # Phase 12 — analytics aggregate signal
campaign_detected  # Phase 12
slow_scan          # Phase 12
```

---

## §2. Log Message Format

### 2a. Connection Decision Lines

Every connection produces exactly one decision log line. Format:

```
{VERB} | {ip} | score={N} | dial={N} | {detail}
```

**VERB** — always 8 characters, uppercase, right-padded with spaces:

| Verb       | Meaning |
|------------ |---------|
| `ALLOW   ` | Connection passed through (scored, below threshold) |
| `FLAG    ` | Connection passed; score above flag threshold; elevated monitoring |
| `RATELMT ` | Connection rate-limited |
| `TARPIT  ` | Connection being slow-drained |
| `BLOCK   ` | Connection rejected with RST |
| `BAN     ` | Connection rejected; IP added to ban list |
| `BYPASS  ` | Connection handled by bypass rule (not scored) — see bypass field |
| `MONITOR ` | dial=0; connection allowed regardless of score |

**Detail field** depends on verb:

For scored connections (`ALLOW`, `FLAG`, `RATELMT`, `TARPIT`, `BLOCK`, `BAN`):
```
signals=[signal_name(+N), signal_name(+N), ...]
```

For bypass connections (`BYPASS`):
```
bypass=alpn_browser | bypass=ja4_whitelist | bypass=mtls | bypass=static_allowlist
       | bypass=ja4_blacklist | bypass=country_blacklist | bypass=spamhaus_drop
       | bypass=tls_version
```

For monitor connections (dial=0):
```
would=block@50,ban@100   # Actions that would have been taken at those dial settings
```

**Complete examples:**

```
ALLOW    | 142.250.80.1  | score=12  | dial=75 | signals=[asn_unknown(+5), dga(+7)]
FLAG     | 91.108.4.1    | score=22  | dial=75 | signals=[no_ptr(+15), asn_unknown(+5), dga(+2)]
TARPIT   | 185.220.101.5 | score=61  | dial=75 | signals=[beaconing(+35), no_ptr(+15), asn_datacenter(+20)]
BLOCK    | 185.220.101.5 | score=78  | dial=75 | signals=[rdap_known_bad_org(+45), missing_sni(+30), asn_datacenter(+20)]
BAN      | 185.220.101.5 | score=88  | dial=90 | signals=[rdap_known_bad_org(+45), beaconing(+35), asn_tor(+40)]
BYPASS   | 142.250.80.1  | score=N/A | dial=75 | bypass=alpn_browser
BYPASS   | 1.10.16.0     | score=N/A | dial=75 | bypass=spamhaus_drop | ref=SBL123456
MONITOR  | 91.108.4.1    | score=61  | dial=0  | signals=[beaconing(+35), no_ptr(+15), asn_datacenter(+20)] | would=tarpit@50,block@75
```

**Notes:**
- Signals list shows top signals by contribution, descending. Maximum 5 shown; append `...` if more.
- `score=N/A` for bypass connections (scorer was not called).
- `ref=` field for blocklist matches that carry an external reference (Spamhaus SBL ID etc.).
- All fields separated by ` | ` (space-pipe-space). No trailing pipe.

### 2b. System Event Lines

Non-connection events (startup, config changes, background tasks) use structured
key=value format. No free-form prose in log lines.

```
{LEVEL} | {subsystem} | event={event_name} | {key=value} ...
```

**Level tokens** — always uppercase:

| Token   | When to use |
|---------|-------------|
| `DEBUG` | Detailed internal state; disabled in production by default |
| `INFO`  | Normal operational events (startup, config reload, feed refresh) |
| `WARN`  | Unexpected but recoverable condition; admin should be aware |
| `ERROR` | Operation failed; system degraded but still running |
| `FATAL` | Unrecoverable; process will exit |

**Subsystem tokens** — always lowercase, always the module short name:

```
proxy | scorer | dial | tls | sni | tcp | asn | dns | blocklist | beaconing
abuseipdb | rdap | analytics | cache | redis | config | mtls | allowlist
```

**Complete examples:**

```
INFO  | proxy     | event=startup            | version=1.4.2 | listen=:8080 | dial=0
INFO  | config    | event=reload             | changed=risk_scorer.thresholds.block,dial
INFO  | asn       | event=tor_list_refreshed | entries=1847 | elapsed_ms=340
INFO  | blocklist | event=feed_refreshed     | feed=spamhaus_drop | entries=923 | elapsed_ms=1204
INFO  | rdap      | event=block_expanded     | trigger_ip=185.220.101.5 | cidr=185.220.100.0/24 | org=Frantech | score=82
WARN  | asn       | event=tor_list_stale     | last_refresh_ago_s=7423 | using_cached=true
WARN  | abuseipdb | event=quota_exhausted    | used=1000 | limit=1000 | resets_at=2025-01-15T00:00:00Z
WARN  | policy    | event=bypass_disabled    | bypass=alpn_browser_bypass | set_by=config_reload
ERROR | blocklist | event=feed_download_failed | feed=spamhaus_drop | status=503 | keeping_entries=923
ERROR | redis     | event=connection_failed  | host=redis:6379 | error=connection_refused | failing_open=true
FATAL | proxy     | event=startup_failed     | reason=MaxMind database not found | path=/data/GeoLite2-ASN.mmdb
```

**Rules:**
- Event names are `snake_case`.
- String values are unquoted unless they contain spaces or special characters.
- Durations: always `_ms` suffix for milliseconds, `_s` for seconds.
- Counts: always `_count` suffix if ambiguous, bare name if obvious (`entries=923`).
- Never log secrets, API keys, or full Redis URLs.
- Never use free-form prose (`"Something went wrong"`) — every log line is parseable.

### 2c. Startup Policy Warnings

When a security policy bypass is disabled, emit at startup and on every config reload:

```
WARN  | policy | event=bypass_disabled | bypass={name} | effect={one-line description}
```

Examples:
```
WARN  | policy | event=bypass_disabled | bypass=alpn_browser_bypass    | effect=browser traffic will be scored; false positive risk elevated
WARN  | policy | event=bypass_disabled | bypass=spamhaus_drop_bypass    | effect=Spamhaus DROP matches scored as signal(+80) instead of hard block
WARN  | policy | event=bypass_disabled | bypass=tls_version_bypass      | effect=TLS 1.0/1.1 connections scored instead of rejected
```

### 2d. What Not to Log

- Never log: API keys, passwords, Redis URLs, TLS private keys.
- Never log: full request bodies or response bodies (not applicable here — no HTTP inspection — but keep the principle).
- Never log at `DEBUG` level in a production hot path (every connection). Debug logging in the hot path must be behind a compile-time flag or a runtime toggle that is off by default.
- Never log the same recurring error on every occurrence. Use rate-limited logging: emit the first occurrence at `ERROR`, subsequent identical errors at `DEBUG` with a `suppressed_count=N` counter emitted periodically.

---

## §3. Test Acceptance Criteria Format

### 3a. Structure

Each phase's acceptance criteria section uses these fixed categories in this order:

```
## Acceptance Criteria

### Functional
- [ ] {statement of what must be true}

### Configuration
- [ ] {config key exists and is validated on load}
- [ ] {hot reload applies new value without restart}

### Observability
- [ ] {Prometheus metric name and type}
- [ ] {log line format verified}

### Unit Tests  (`tests/unit/test_{module}.py`)
- [ ] {module}.{method}: {scenario} → {expected outcome}

### Integration Tests  (`tests/integration/test_{scenario}.py`)
- [ ] {scenario}: {what is exercised} — {what is verified}

### Chaos Tests  (`tests/chaos/test_{module}_resilience.py`)
- [ ] {dependency} {failure mode} → {expected system behaviour}

### False-Positive Tests  (`tests/fp_corpus/test_{module}_fp.py`)
- [ ] {signal}: {corpus name} ({N} samples) — FP rate < {threshold}%
  (only for phases with domain/IP classification signals)

### Performance Tests  (`tests/performance/bench_{module}.py`)
- [ ] {operation}: p99 < {N}ms at {load}
  (only for hot-path operations)
```

Not every phase needs every category. Omit categories that genuinely have nothing
to test. Do not add empty category headers.

### 3b. Statement Style

Test statements follow this pattern: **subject · condition · expected outcome**.

```
# ✓ CORRECT — subject, condition, outcome
- [ ] ASNClassifier.classify(): Tor exit IP (v4) → category=tor, score=40
- [ ] ASNClassifier.classify(): Tor exit IP (v6) → category=tor, score=40
- [ ] ASNClassifier.classify(): unlisted ASN, no pattern match → category=unknown, score=5
- [ ] Tor list download failure → cached list retained; tor_list_download_errors_total incremented
- [ ] Redis unreachable during Tor refresh → in-memory list used; no crash; WARN logged

# ✗ WRONG — vague, no outcome specified
- [ ] Test Tor exit detection
- [ ] Tests: classification, Tor refresh, leader election, download failure fallback
- [ ] Classification works for IPv4 and IPv6
```

Comma-separated lists of test cases in a single bullet are prohibited.
Every test case is its own bullet.

### 3c. Chaos Test Statements

Chaos tests always name:
1. The dependency that fails
2. The failure mode (unreachable, timeout, 503, OOM, corrupt data, etc.)
3. The expected system behaviour (what continues to work, what degrades gracefully)
4. What is verified (log line, metric, return value)

```
# ✓ CORRECT
- [ ] Redis: connection refused on startup → proxy starts; all decisions fail open; ERROR logged
- [ ] Redis: connection times out mid-request → in-process cache used; WARN logged once
- [ ] Spamhaus download: HTTP 503 → last known CIDR list retained; feed_download_failed ERROR logged; entries count unchanged

# ✗ WRONG
- [ ] Redis unavailable no crash
- [ ] Spamhaus download failure
```

### 3d. Prometheus Acceptance Criteria

Each metric listed in acceptance criteria specifies its type:

```
- [ ] Prometheus counter: ja4proxy_tor_list_download_errors_total — increments on each failed download attempt
- [ ] Prometheus gauge:   ja4proxy_tor_exit_list_size — set to entry count after each successful refresh
- [ ] Prometheus gauge:   ja4proxy_tor_list_last_refresh_timestamp — Unix timestamp of last successful refresh
- [ ] Prometheus histogram: ja4proxy_risk_score_distribution — bucket boundaries [0,10,20,35,55,70,85,100]
```

---

## §4. Documentation Language

### 4a. Voice and Tense

- Use **present tense** for what the system does: "The classifier returns..." not "The classifier will return..."
- Use **active voice**: "The worker enqueues the IP" not "The IP is enqueued by the worker."
- Use **imperative mood** for specifications: "Return `None` on cache miss" not "The function should return `None`."
- Avoid hedging words in specifications: not "should", "may", "might", "could" — use "must", "does", "returns".

```
# ✓ CORRECT
The scorer clamps the composite score to 0–100 before returning.
Return a `RiskSignal` with `score=0` when the cache returns `None`.

# ✗ WRONG
The scorer will clamp the score. The signal should be returned with score 0 when possible.
```

### 4b. Terminology — Use These, Not Alternatives

| Use | Not |
|-----|-----|
| secops admin | operator, security operator, admin, user |
| connection | request (we see TLS connections, not HTTP requests) |
| composite score | total score, final score, risk total |
| signal | indicator, feature, factor |
| bypass | short-circuit, fast-path, skip |
| fail open | fail safe, degrade gracefully (when meaning: allow on error) |
| enrichment | lookup, resolution (for async background data gathering) |
| feed | list, database, source (for threat intelligence inputs) |
| dial | threshold knob, aggression slider, blocking level |
| phase | sprint, stage, iteration |
| action | disposition, verdict, decision |
| `config/proxy.yml` | the config, the settings file |

### 4c. Module Names — Canonical References

Always refer to modules by their canonical name. In prose, use the human name.
In code references, use the module path.

| Human name | Module path |
|------------ |-------------|
| Risk scorer | `src/security/risk_scorer.py` |
| Action decider | `src/security/action_decider.py` |
| TLS enforcer | `src/security/tls_enforcer.py` |
| SNI analyser | `src/security/sni_analyzer.py` |
| TCP analyser | `src/security/tcp_analyzer.py` |
| mTLS handler | `src/security/mtls.py` |
| ASN classifier | `src/security/asn_classifier.py` |
| DNS enrichment | `src/security/dns_enrichment.py` |
| Blocklist manager | `src/security/blocklists.py` |
| Beaconing detector | `src/security/beaconing_detector.py` |
| AbuseIPDB client | `src/security/abuseipdb.py` |
| RDAP enrichment | `src/security/rdap_enrichment.py` |
| Local cache | `src/cache/local_cache.py` |
| Config loader | `src/config/loader.py` |

### 4d. Describing Failure Behaviour

Always be specific. Name the condition, the response, and the observable effect.

```
# ✓ CORRECT
If the AbuseIPDB API returns a non-200 status, the client returns `None`, the
connection proceeds without an AbuseIPDB signal, and
`ja4proxy_abuseipdb_api_errors_total` is incremented.

# ✗ WRONG
If the API is unavailable, the system handles it gracefully.
```

### 4e. Describing Defaults

Always state the default value and the rationale for it:

```
# ✓ CORRECT
Default: `false`. Disabled until an API key is configured and the quota budget
is understood. See Phase 10 for operational guidance.

# ✗ WRONG
This is optional. Set to true to enable.
```

### 4f. Headers and Section Naming

Phase files use this header hierarchy:
- `# Phase N — Name` — document title (one per file)
- `## Goal` — one paragraph, what this phase delivers
- `## {NN}{letter}. Section Name` — numbered sections within the phase
- `### Sub-section` — sub-topics within a section
- `## Acceptance Criteria` — always last, always this exact heading
- `### {Category}` — test category within acceptance criteria

Never use bold text as a substitute for a header. Never use headers inside
acceptance criteria test bullets.

---


---

## §6. Standard Phase File Structure

Every phase file follows this section order exactly. Omit sections that genuinely
do not apply (e.g. Phase 01 has no external feeds, so no Chaos Scenarios). Do not
reorder sections. Do not invent new top-level sections.

```
# Phase N — Short Descriptive Name

## Goal
One paragraph. What this phase delivers and why it matters. No bullet points.

## Na. First Major Section       (numbered: phase number + letter, e.g. 3a)
### Sub-section                  (### for sub-topics within a section)

## Nb. Second Major Section
...

## Redis Key Schema
Table of all Redis keys added by this phase.

## Config
Complete YAML block for all new config added by this phase.
Every key has an inline comment (see §1c).

## Chaos Scenarios
Table: Scenario | Expected behaviour
Every dependency failure mode that code documents must appear here.

## Acceptance Criteria

### Functional
- [ ] subject · condition → outcome

### Configuration
- [ ] config key exists and validated on startup
- [ ] hot reload applies without restart

### Observability
- [ ] Prometheus counter/gauge/histogram: name{labels} — description
- [ ] JSON log: event=name emitted when condition
- [ ] Health endpoint reflects state when condition

### Unit Tests  (`tests/unit/test_{module}.py`)
- [ ] ClassName.method(): scenario → expected outcome

### Integration Tests  (`tests/integration/test_{scenario}.py`)
- [ ] scenario: what is exercised — what is verified

### Chaos Tests  (`tests/chaos/test_{module}_resilience.py`)
- [ ] dependency failure-mode → expected system behaviour; what is verified

### False-Positive Tests  (`tests/fp_corpus/test_{module}_fp.py`)
(omit if phase has no classification signals)
- [ ] signal: corpus (N samples) — FP rate < threshold%

### Performance Tests  (`tests/performance/bench_{module}.py`)
(omit if phase adds no hot-path operations)
- [ ] operation: p99 < Nms at load
```

### Section Numbering

Subsections within a phase file are numbered `{phase_number}{letter}`:

```
# Phase 7 — FCrDNS & Passive DNS Enrichment

## 7a. The FCrDNS Check
## 7b. PTR Hostname Classification
## 7c. Score Contributions
...
```

The letter is lowercase. The number matches the phase. Subsections under a lettered
section use `###` headers (no further numbering):

```
## 7a. The FCrDNS Check
### Async implementation
### Timeout handling
```

### Chaos Scenarios Table Format

The Chaos Scenarios table has exactly two columns:

| Scenario | Expected behaviour |
|----------|--------------------|
| Dependency and failure mode (specific) | What continues to work; what degrades; what is logged or counted |

Scenario column: name the dependency, the failure mode, and any relevant condition.
Expected behaviour column: state the outcome for the *system*, not just the module.
Always include: whether traffic continues to flow, whether errors are logged, which
counter is incremented.

```markdown
## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Redis: connection refused on startup | Proxy starts; all pipeline decisions fail open; `ERROR redis event=connection_failed` logged once |
| Redis: connection refused mid-traffic | In-process cache used; decisions fail open; error counter incremented; WARN logged once per minute |
| Spamhaus DROP: HTTP 503 on refresh | Last known list retained; `ERROR blocklist event=feed_download_failed` logged; entries count unchanged in Prometheus |
```


---

## §7. Cross-Phase Implementation Patterns

Every module that owns persistent state, downloads data, or runs background workers
must implement four standard behaviours consistently. The phase files specify *what*
each module does; this section defines *how* these behaviours must be structured.

---

### 7a. Startup Sequence

Every module's `start()` coroutine must follow this order:

1. **Validate config** — fail fast with `FATAL` if required keys are absent or invalid
2. **Load from Redis** — warm in-process cache from Redis before serving connections
3. **Fall back to direct source** — if Redis is empty, load directly (download feed,
   call API, etc.)
4. **Emit startup log** — `INFO | {subsystem} | event=started | ...key metrics...`
5. **Start background workers** — only after state is loaded; never serve before ready

```python
async def start(self) -> None:
    self._validate_config()                          # Step 1 — raises on bad config
    loaded = await self._load_from_redis()           # Step 2 — warm from Redis
    if not loaded:
        await self._load_from_source()               # Step 3 — fallback
    log.info("subsystem", event="started", entries=len(self._data))  # Step 4
    self._worker_task = asyncio.create_task(self._worker())          # Step 5
```

**Missing required file (databases, certs):** log `FATAL` with the exact file path
and exit the process. Never silently skip a required dependency.

---

### 7b. Hot Reload

Every module's config section in its phase file must state — in the `## Config`
section — which keys are hot-reloadable and which require a restart.

**Standard comment for hot-reloadable keys:**

```yaml
score: 20    # Default: 20. Hot-reloadable. Change applies to next connection.
```

**Standard comment for non-reloadable keys:**

```yaml
queue_size: 1000    # Default: 1000. Requires restart to change.
                    # CAUTION: increasing after startup does not grow the queue.
```

**Keys that are never hot-reloadable** (always require restart):
- `queue_size` — in-memory queue allocated at startup
- `worker_count` — workers started at startup
- Any path to a file or database (`cert_path`, `db_path`, etc.)
- `enabled` — enabling a disabled module requires full initialisation

**Keys that are always hot-reloadable:**
- All `score:` and `score_cap:` values
- All `threshold:` values
- All `enabled:` flags on individual signals within an already-started module
- `refresh_interval_seconds` for background download workers

---

### 7c. Graceful Shutdown

Every module with background workers must implement a `stop()` coroutine called
on SIGTERM. The proxy waits for all `stop()` coroutines to complete before exiting.

```python
async def stop(self) -> None:
    self._shutdown_event.set()
    if self._worker_task:
        await asyncio.wait_for(self._worker_task, timeout=5.0)
    log.info("subsystem", event="stopped")
```

**Modules with queues:** drain the queue before stopping. If the queue is not
empty after the timeout, log a WARN with the number of items dropped.

**Modules with Redis connections:** close them in `stop()`. Do not rely on
Python garbage collection.

---

### 7d. Leader Election Pattern

Used by any module that downloads or refreshes a shared resource (feed, list,
database) in a multi-instance deployment.

**Pattern:** one instance acquires a Redis lock, performs the download, writes the
result to Redis. Other instances read from Redis. If the lock holder crashes, the
TTL expires and another instance takes over.

```python
LEADER_KEY = "leader:{subsystem}_download"
LEADER_TTL  = refresh_interval_seconds // 2  # Expires before next refresh cycle

async def _maybe_download(self) -> None:
    # Try to become leader
    acquired = await self.redis.set(
        LEADER_KEY, self._instance_id,
        nx=True, ex=LEADER_TTL
    )
    if acquired:
        await self._download_and_write_to_redis()
    else:
        await self._load_from_redis()  # Non-leader: read from Redis
```

**Redis key naming:** `leader:{module_short_name}_{resource}` — e.g.:
- `leader:tor_exit_download`
- `leader:blocklist_download:{list_name}`
- `leader:passive_dns_download`
- `leader:rdap_bootstrap_download`

**On download failure:** keep the last known in-memory data. Do not release the
leader lock — let the TTL expire so the next instance retries after the cooldown.
Increment the error counter and log `ERROR`.

**Phases using this pattern:** 6 (Tor list), 7 (passive DNS feeds), 8 (blocklists),
11 (RDAP IANA bootstrap).

---

### 7e. Worker Crash Recovery

Every background worker must restart automatically if it raises an unhandled
exception. Use `asyncio.create_task` with a restart wrapper:

```python
async def _start_worker(self, worker_fn: Callable) -> None:
    while not self._shutdown_event.is_set():
        try:
            await worker_fn()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.error("subsystem", event="worker_crashed",
                      error=str(exc), restarting_in_seconds=1)
            await asyncio.sleep(1)  # Brief pause before restart
```

Never let a worker die silently. A crashed worker that is not restarted is a silent
degradation — no error counter, no log, no restart. This is the most common source
of subtle bugs in async systems.



### Redis Key Schema Format

Every phase file's `## Redis Key Schema` section uses this exact table structure.
No code blocks with `→` arrows. No 4-column variant. Always 5 columns in this order:

```markdown
| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `namespace:segment:{variable}` | Type description | 3600s (1h) | Module name | What this stores and why |
```

**Column rules:**

| Column | Content | Format |
|--------|---------|--------|
| `Key` | Full key pattern with variable parts in `{braces}` | Always in backticks |
| `Type` | Redis data structure + value description | e.g. `String (integer 0–100)`, `Sorted Set (score=timestamp, member=uuid)` |
| `TTL` | Expiry in seconds with human time in parens, or `none (no expiry)` | e.g. `3600s (1h)`, `86400s (24h)`, `none (no expiry)` |
| `Written by` | Module or component that writes this key | e.g. `Proxy hot path`, `Leader instance`, `Management UI` |
| `Notes` | What it stores and operational significance | One sentence, no trailing period |

If a phase adds no Redis keys, use this exact prose line (not a table):

```markdown
Phase N adds no new Redis keys. [Reason — e.g. "TLS enforcement is in-process only."]
```

## §5. Applying This Guide

When writing a new phase file or updating an existing one:

1. Read this guide before writing anything.
2. Run the consistency check: `python3 scripts/check_style.py docs/phases/PHASE_NN.md`
   (to be implemented in Phase 0 as part of the developer toolchain).
3. Config blocks: verify every `risk_score*` key is renamed to `score`.
4. Config blocks: verify every inline YAML object is expanded.
5. Log format examples: verify they use the `VERB   | ip | score=N | dial=N` format.
6. Acceptance criteria: verify every test bullet has subject, condition, and outcome.
7. Test bullets: verify no comma-separated lists — one scenario per bullet.
