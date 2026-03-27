# JA4proxy — Observability Standards

> This is the authoritative reference for every observability concern:
> Prometheus metrics (naming, types, labels), structured log schema, Grafana
> dashboard layout, Alertmanager rules, health endpoints, and SLIs.
>
> Every phase that adds a metric, log line, or panel must conform to this document.
> The phase completion gate (`docs/TESTING_STRATEGY.md §5`) includes an observability
> checklist that references this document.

---

## §1. Prometheus Metrics

### 1a. Naming Convention

```
ja4proxy_{subsystem}_{measurement}_{unit}
```

**Rules — all mandatory:**

| Rule | Example |
|------|---------|
| Prefix is always `ja4proxy_` | `ja4proxy_` |
| Subsystem is the module short name | `blocklist`, `beaconing`, `rdap` |
| Measurement describes what is counted or observed | `connections`, `queue_depth`, `score` |
| Unit suffix is mandatory for dimensional quantities | `_seconds`, `_bytes`, `_total` |
| Counters always end in `_total` | `ja4proxy_blocklist_download_errors_total` |
| Gauges end in the unit or a noun | `ja4proxy_rdap_queue_depth`, `ja4proxy_dial_current` |
| Histograms end in the base unit — **never** embed `_histogram` in the name | `ja4proxy_risk_score` (not `ja4proxy_risk_score_histogram`) |
| Timestamps are `_last_success_seconds` (Unix epoch as float) | `ja4proxy_blocklist_last_refresh_success_seconds` |
| Ratios are expressed as two separate metrics (numerator + denominator) or as a gauge with `_ratio` only if it is pre-computed | `ja4proxy_cache_hit_ratio` is acceptable |
| Boolean flags are gauges with value 0 or 1 | `ja4proxy_abuseipdb_quota_exhausted` |

**Banned suffixes / patterns:**
- `_histogram` embedded in name — the Prometheus type declaration conveys this
- `_timestamp` — use `_last_success_seconds` or `_last_attempt_seconds`
- `_size` — use `_count` for countable items or the specific unit (`_bytes`)
- `_setting` — use `_current` for gauge values
- `_current` on counters — counters are cumulative totals, not current values

### 1b. Metric Type Rules

| Type | When to use | Example |
|------|------------|---------|
| **Counter** | Value only ever increases (resets on restart) | Connections processed, errors |
| **Gauge** | Value can go up or down (current state) | Queue depth, dial value, entry counts |
| **Histogram** | Distribution of observed values | Score distribution, latency, enrichment duration |
| **Summary** | Pre-computed quantiles (rare — prefer Histogram) | Only if Histogram is too expensive |

Never use a Counter for something that decreases (e.g. queue depth). Never use a
Gauge for cumulative totals that should persist through restarts.

### 1c. Label Vocabulary

Labels must be from this approved set. New labels require a decision log entry.

| Label | Type | Values | Used on |
|-------|------|--------|---------|
| `action` | string | `allow\|flag\|rate_limit\|tarpit\|block\|ban` | Risk action counters |
| `bypass` | string | `alpn_browser\|ja4_whitelist\|mtls\|static_allowlist\|ja4_blacklist\|country_blacklist\|spamhaus_drop\|tls_version` | Bypass counters |
| `signal` | string | Signal names from STYLE_GUIDE.md §1f | Signal fire counters |
| `asn_type` | string | `residential\|mobile\|datacenter\|vpn\|tor\|unknown` | ASN classification |
| `feed` | string | `spamhaus_drop\|spamhaus_edrop\|{custom_name}` | Blocklist metrics |
| `registry` | string | `arin\|ripe\|apnic\|lacnic\|afrinic\|unknown` | RDAP metrics |
| `result` | string | `hit\|miss\|error\|timeout\|quota_exceeded` | Cache and API metrics |
| `tls_version` | string | `1.0\|1.1\|1.2\|1.3\|unknown` | TLS version metrics |
| `cipher_strength` | string | `strong\|weak\|export\|null\|anon` | Cipher suite metrics |
| `ptr_class` | string | `residential\|datacenter\|confirmed\|fcrdns_failed\|no_ptr\|unknown` | DNS PTR metrics |
| `strength` | string | `strong\|moderate\|weak` | Beaconing signal strength |
| `dial` | integer-string | `"0"`, `"50"`, `"100"` | Counterfactual metrics |

### 1d. Complete Metric Registry

This is the canonical list of all metrics. Phases may not invent new metric names
without adding them here. The phase completion gate checks this document.

#### Core pipeline

```
ja4proxy_connections_total{action}                   counter  Connections by final action taken
ja4proxy_bypass_total{bypass}                        counter  Connections handled by each bypass rule
ja4proxy_risk_score                                  histogram Score distribution; buckets [0,10,20,35,55,70,85,100]
ja4proxy_pipeline_duration_seconds                   histogram End-to-end pipeline latency per connection
```

#### Monitor mode and dial

```
ja4proxy_dial_current                                gauge    Current dial value (0–100)
ja4proxy_dial_changes_total                          counter  Number of dial value changes
ja4proxy_dial_change_rejected_total                  counter  Dial changes rejected (increment limit)
ja4proxy_monitor_counterfactual_total{action,dial}   counter  Would-have-taken actions at given dial
```

#### TLS enforcement (Phase 3)

```
ja4proxy_tls_version_total{tls_version,action}       counter  Connections by TLS version and action taken
ja4proxy_weak_cipher_total{cipher_strength,action}   counter  Connections with weak cipher suites
```

#### SNI analysis (Phase 4)

```
ja4proxy_sni_signal_total{signal}                    counter  SNI signal fires (missing_sni, ip_literal_sni, etc.)
ja4proxy_sni_dga_score                               histogram DGA confidence score distribution
```

#### TCP analysis (Phase 5)

```
ja4proxy_tcp_signal_total{signal}                    counter  TCP signal fires (ja4t_mismatch, no_resumption, etc.)
ja4proxy_concurrent_connections                      gauge    Current concurrent connections per IP (max observed)
ja4proxy_mtls_verified_total                         counter  Connections with verified mTLS client certificate
```

#### ASN classification (Phase 6)

```
ja4proxy_asn_classification_total{asn_type}          counter  Connections by ASN classification
ja4proxy_tor_exit_list_entries                       gauge    Current number of Tor exit addresses
ja4proxy_tor_list_last_refresh_success_seconds       gauge    Unix timestamp of last successful Tor list refresh
ja4proxy_tor_list_download_errors_total              counter  Failed Tor consensus download attempts
```

#### DNS enrichment (Phase 7)

```
ja4proxy_dns_enrichment_total{result}                counter  DNS enrichment outcomes (hit, miss, error, timeout)
ja4proxy_dns_ptr_classification_total{ptr_class}     counter  PTR lookup outcomes by classification
ja4proxy_dns_enrichment_queue_depth                  gauge    Current DNS enrichment queue depth
ja4proxy_dns_enrichment_queue_drops_total            counter  DNS enrichment items dropped due to full queue
ja4proxy_dns_resolver_errors_total                   counter  DNS resolver errors
ja4proxy_dns_ptr_errors_total{error_type}            counter  DNS PTR lookup failures by type (timeout|nxdomain|servfail|other)
```

#### Blocklist management (Phase 8)

```
ja4proxy_blocklist_entries{feed}                     gauge    Current CIDR entries loaded per feed
ja4proxy_blocklist_last_refresh_success_seconds{feed} gauge   Unix timestamp of last successful feed refresh
ja4proxy_blocklist_download_errors_total{feed}       counter  Failed feed download attempts
ja4proxy_blocklist_matches_total{feed}               counter  Connections matched by each feed
```

#### Beaconing detection (Phase 9)

```
ja4proxy_beaconing_score                             histogram Beacon score distribution; buckets [0,.1,.2,.3,.5,.7,.9,1]
ja4proxy_beaconing_suspects                          gauge    Current number of suspected beaconers
ja4proxy_beaconing_records_total                     counter  Connection timestamps recorded for beaconing analysis
```

#### AbuseIPDB (Phase 10)

```
ja4proxy_abuseipdb_lookup_total{result}              counter  API lookup outcomes (hit, miss, error, timeout, quota_exceeded)
ja4proxy_abuseipdb_enrichment_queue_depth            gauge    Current AbuseIPDB enrichment queue depth
ja4proxy_abuseipdb_quota_exhausted                   gauge    1 if daily quota exhausted, else 0
ja4proxy_abuseipdb_quota_used_today                  gauge    API requests used today
ja4proxy_abuseipdb_cache_hit_ratio                   gauge    Cache hit ratio over last 5 minutes (pre-computed)
```

#### RDAP enrichment (Phase 11)

```
ja4proxy_rdap_lookup_total{registry,result}          counter  RDAP lookup outcomes by registry
ja4proxy_rdap_enrichment_queue_depth                 gauge    Current RDAP enrichment queue depth
ja4proxy_rdap_parse_errors_total                     counter  RDAP response parse failures
ja4proxy_rdap_block_expansions_total                 counter  Automatic block expansions applied
ja4proxy_rdap_lookup_errors_total{rir}               counter  RDAP lookup failures by RIR (bootstrap routing or registry error)
```

#### Analytics node (Phase 12)

```
ja4proxy_analytics_events_processed_total            counter    Stream events consumed by analytics node
ja4proxy_analytics_cycle_duration_seconds            histogram  Analytics cycle duration
ja4proxy_analytics_stream_lag_seconds                gauge      Current Redis Stream consumer lag (seconds)
ja4proxy_analytics_score_drift_detected              gauge      1 if score drift detected (|z| > 2.0), else 0
ja4proxy_analytics_calibration_issue                 gauge      1 if shadow score (h2/h1 traffic) exceeds baseline, else 0
ja4proxy_analytics_distribution_shift                gauge      1 if KS-test detects score distribution shift, else 0
ja4proxy_analytics_score_median                      gauge      Rolling 1-hour median risk score
ja4proxy_analytics_shadow_score_median               gauge      Rolling 1-hour median shadow score (browser ALPN traffic)
ja4proxy_analytics_signals_total                     counter    Analytics cross-instance signals applied to proxy scorer {signal_type="campaign|slowscan"}
ja4proxy_analytics_distribution_check_duration       histogram  Duration of KS-test distribution check
ja4proxy_analytics_drift_check_duration              histogram  Duration of z-score drift check
```

#### Local cache (Phase 0)

```
ja4proxy_cache_operations_total{type,result}         counter  Cache get/set operations by type and result (hit/miss/evict)
ja4proxy_cache_hit_ratio{type}                       gauge    Hit ratio per cache type over last 5 minutes
```

#### Config and system

```
ja4proxy_config_reloads_total                        counter  Successful config reloads
ja4proxy_config_reload_errors_total                  counter  Config reload failures (validation failed)
ja4proxy_static_allowlist_hits_total                 counter  Connections matched by static IP allowlist
ja4proxy_policy_changes_total{bypass}                counter  Security policy bypass changes
```

#### Tarpit (Phase 14)

```
ja4proxy_tarpit_concurrent                           gauge    Current concurrent tarpitted connections
ja4proxy_tarpit_overflow_total{action}               counter  Connections that hit tarpit capacity cap
```

#### Exception handling (Phase 17b)

```
ja4proxy_pipeline_unexpected_errors_total{phase}     counter  Unexpected errors reaching top-level pipeline handler (must be 0)
ja4proxy_exception_handled_total{module,exception_type} counter All caught exceptions by module and type — spike = new failure mode
ja4proxy_signal_skipped_total{module,reason}         counter  Signals skipped due to expected dependency failures (Redis/DNS/timeout)
ja4proxy_signal_error_total{module}                  counter  Signals failed due to unexpected internal errors
```

#### Backup & Restore (Phase 19)

```
ja4proxy_backup_operations_total{status}              counter  Total backup operations (success/failure)
ja4proxy_backup_keys_processed_total                 counter  Total keys processed during backups
ja4proxy_backup_duration_seconds                     histogram Backup operation duration distribution
ja4proxy_backup_size_bytes                           histogram Backup artifact size distribution
ja4proxy_backup_last_success_timestamp               gauge    Unix timestamp of last successful backup
ja4proxy_backup_last_failure_timestamp               gauge    Unix timestamp of last failed backup
ja4proxy_backup_currently_running                    gauge    1 if backup is running, 0 otherwise

ja4proxy_restore_operations_total{status,type}      counter  Total restore operations (success/failure, destructive/non-destructive)
ja4proxy_restore_duration_seconds                     histogram Restore operation duration distribution
ja4proxy_restore_last_success_timestamp               gauge    Unix timestamp of last successful restore
ja4proxy_restore_last_failure_timestamp               gauge    Unix timestamp of last failed restore
ja4proxy_restore_currently_running                    gauge    1 if restore is running, 0 otherwise
ja4proxy_restore_keys_restored_total                 counter  Total keys restored
```

---

## §2. Structured Log Schema

All log output is JSON. One JSON object per line. The schema is fixed — no ad hoc fields.

### 2a. Connection Log Schema

Emitted once per connection, at decision time.

```json
{
  "ts":       "2025-01-15T14:32:01.234Z",
  "type":     "connection",
  "verb":     "BLOCK",
  "ip":       "185.220.101.5",
  "ip_subnet":"185.220.101.0/24",
  "score":    78,
  "dial":     75,
  "action":   "block",
  "bypass":   null,
  "signals": [
    {"name": "rdap_known_bad_org", "score": 45, "reason": "Frantech Solutions"},
    {"name": "missing_sni",        "score": 30, "reason": "No SNI extension"},
    {"name": "asn_datacenter",     "score": 20, "reason": "AS53667 Frantech Solutions"}
  ],
  "counterfactual": {
    "action_at_50":  "tarpit",
    "action_at_100": "block"
  },
  "tls_version": "1.3",
  "alpn":      "",
  "sni":       null,
  "ja4":       "t13d190900_9dc949161b7c_000000000000",
  "ja4t":      "0_1-4-1-8-1_1-3",
  "asn":       53667,
  "asn_type":  "datacenter",
  "country":   "NL",
  "duration_ms": 2
}
```

For bypass connections, `score` is `null`, `signals` is `[]`, `bypass` is the bypass name string.

### 2b. System Event Log Schema

Emitted for operational events (startup, config reload, background tasks, errors).

```json
{
  "ts":        "2025-01-15T14:32:01.234Z",
  "type":      "system",
  "level":     "INFO",
  "subsystem": "blocklist",
  "event":     "feed_refreshed",
  "feed":      "spamhaus_drop",
  "entries":   923,
  "elapsed_ms": 1204
}
```

```json
{
  "ts":        "2025-01-15T14:32:01.234Z",
  "type":      "system",
  "level":     "ERROR",
  "subsystem": "blocklist",
  "event":     "feed_download_failed",
  "feed":      "spamhaus_drop",
  "http_status": 503,
  "entries_retained": 923,
  "error":     "HTTP 503 Service Unavailable"
}
```

```json
{
  "ts":        "2025-01-15T14:32:01.234Z",
  "type":      "system",
  "level":     "WARN",
  "subsystem": "policy",
  "event":     "bypass_disabled",
  "bypass":    "alpn_browser_bypass",
  "effect":    "browser traffic will be scored; false positive risk elevated",
  "set_by":    "config_reload"
}
```

### 2c. Required Fields

Every log line must have: `ts`, `type`, `level`.
Connection logs additionally require: `verb`, `ip`, `score`, `dial`, `action`.
System logs additionally require: `subsystem`, `event`.

All other fields are optional depending on context. Unknown fields are allowed
(future phases may add fields) but must not shadow the required fields.

### 2d. Field Types

| Field | Type | Notes |
|-------|------|-------|
| `ts` | ISO 8601 string with Z suffix | UTC always |
| `type` | `"connection"` or `"system"` | Fixed enum |
| `level` | `"DEBUG"\|"INFO"\|"WARN"\|"ERROR"\|"FATAL"` | Fixed enum |
| `verb` | 8-char uppercase string | From STYLE_GUIDE.md §2a |
| `ip` | string | Canonical form (Phase 0 normalisation) |
| `score` | integer or null | 0–100 or null for bypasses |
| `dial` | integer | 0–100 |
| `action` | string | From STYLE_GUIDE.md §1e |
| `bypass` | string or null | Bypass name or null |
| `signals` | array | Each: `{name, score, reason}` |
| Durations | integer | Always `_ms` suffix for milliseconds |
| Timestamps | ISO 8601 string | UTC, Z suffix |
| Counts | integer | |
| Ratios / scores | number | |

---

## §3. Grafana Dashboards

### 3a. Dashboard Structure

Three dashboards. All provisioned from `config/grafana/dashboards/`.

```
config/grafana/
  dashboards/
    01_operations.json      # Real-time traffic overview — the primary NOC screen
    02_security.json        # Signal analysis, attack campaigns, enrichment status
    03_system.json          # Infrastructure health, Redis, queue depths, errors
  datasources/
    prometheus.yaml
  provisioning.yaml
```

### 3b. Dashboard 01 — Operations

**Audience:** Secops admin monitoring live traffic.
**Refresh:** 10 seconds.

Row 1: **Traffic Overview**
- Total connections/sec (rate over 1m)
- Connections by action (stacked bar: allow/flag/rate_limit/tarpit/block/ban)
- Bypass hits/sec by type (stacked: alpn_browser, ja4_whitelist, etc.)

Row 2: **Dial and Blocking Readiness**
- Current dial (gauge, 0–100, colour: green <30, amber 30–70, red >70)
- Would-block at dial=50 (% of non-bypass traffic)
- Would-block at dial=75 (% of non-bypass traffic)
- Would-block at dial=100 (% of non-bypass traffic)

Row 3: **Score Distribution**
- Risk score histogram (last 5 minutes)
- Known-good browser shadow score (p95 — should be stable and low)
- Score p95 over time (24h trend — rises during attacks)

Row 4: **Policy Status**
- Security policy bypass table: each bypass, enabled/disabled, hits/min
- Any disabled high-risk bypass shown with amber/red indicator

### 3c. Dashboard 02 — Security

**Audience:** Secops admin investigating incidents or tuning signals.
**Refresh:** 30 seconds.

Row 1: **Signal Breakdown**
- Top signals by fire rate (table: signal name, fires/min, avg score contribution)
- Signal co-occurrence heatmap (which signals appear together)

Row 2: **Feed and Enrichment Health**
- Blocklist feed status: entries count and last refresh per feed
- Tor exit list: size and last refresh
- ASN classification breakdown (pie: residential/datacenter/vpn/tor/unknown)
- DNS PTR classification breakdown

Row 3: **Beaconing and Campaigns**
- Current beaconing suspects (gauge)
- Top suspected beaconers (table: IP, JA4, beacon score, confidence)
- Campaign detections (Phase 12): active campaigns, top subnets

Row 4: **Score Health**
- 7-day median score band with current 1-hour median overlaid
- Score drift alert indicator (red if `ja4proxy_analytics_score_drift_detected == 1`)

Row 5: **Enrichment Queues**
- AbuseIPDB queue depth and cache hit ratio
- RDAP queue depth and registry status table
- DNS enrichment queue depth

### 3d. Dashboard 03 — System

**Audience:** Platform/SRE team monitoring infrastructure health.
**Refresh:** 60 seconds.

Row 1: **Redis**
- Redis connected (binary indicator)
- Redis memory used vs max
- Cache hit ratios by type
- Pipeline batch RTT (p99)

Row 2: **Proxy Instances**
- Active instances (count)
- Per-instance connections/sec
- Per-instance pipeline p99 latency

Row 3: **Error Rates**
- AbuseIPDB API errors/min and quota status
- RDAP download errors by registry
- Blocklist download errors by feed
- DNS resolver errors/min

Row 3b: **Exception Health** (Phase 17b)
- **Exception Rate by Module** — Bar gauge, `rate(ja4proxy_exception_handled_total[5m]) by (module)`.
  Thresholds: 0 = green, > 0.1/s = yellow, > 1/s = red.
  Description: "Exceptions caught per module. Steady baseline is normal; sudden spike indicates new failure mode."
- **Pipeline Internal Errors (Must Be Zero)** — Stat, `rate(ja4proxy_pipeline_unexpected_errors_total[5m])`.
  Thresholds: 0 = green, any value > 0 = red (critical).
  Description: "Unexpected errors in pipeline logic. Non-zero requires immediate investigation."

Row 4: **Config and Reload**
- Last config reload timestamp
- Config reload errors (should be 0)
- Dial change history (step chart — last 24h)

---

## §4. Alertmanager Rules

Alert rules are organized into multiple files in `monitoring/alertmanager/rules/`:

| File | Covers |
|------|--------|
| `monitoring/alertmanager/rules/proxy.rules.yml` | Active connections, block rate, latency, dial anomalies |
| `monitoring/alertmanager/rules/redis.rules.yml` | Redis availability, memory, command latency |
| `monitoring/alertmanager/rules/security.rules.yml` | High score rate, bypass disabled, blacklist size anomalies |
| `monitoring/alertmanager/rules/backup.rules.yml` | Backup failures, retention violations |
| `monitoring/alertmanager/rules/management_ui_rules.yml` | Management UI availability and errors (deferred until Phase 13) |

```yaml
groups:
  - name: ja4proxy.availability
    interval: 30s
    rules:

      - alert: ProxyInstanceDown
        expr: count(up{job="ja4proxy"}) < 1
        for: 1m
        labels:
          severity: critical
          team: secops
        annotations:
          summary: "No ja4proxy instances reporting to Prometheus"
          runbook: "docs/INCIDENT_RESPONSE.md#proxy-instance-down"

      - alert: RedisConnectionFailed
        expr: increase(ja4proxy_cache_operations_total{result="error"}[5m]) > 10
        for: 2m
        labels:
          severity: critical
          team: secops
        annotations:
          summary: "Redis connection errors detected — proxy failing open"
          runbook: "docs/INCIDENT_RESPONSE.md#redis-connection-failed"

  - name: ja4proxy.feeds
    interval: 60s
    rules:

      - alert: BlocklistFeedStale
        expr: (time() - ja4proxy_blocklist_last_refresh_success_seconds) > 86400
        for: 5m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "Blocklist feed {{ $labels.feed }} has not refreshed in 24h"
          runbook: "docs/INCIDENT_RESPONSE.md#blocklist-feed-stale"

      - alert: TorListStale
        expr: (time() - ja4proxy_tor_list_last_refresh_success_seconds) > 7200
        for: 5m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "Tor exit list has not refreshed in 2h"
          runbook: "docs/INCIDENT_RESPONSE.md#tor-list-stale"

      - alert: SpamhausMatchRate
        expr: rate(ja4proxy_blocklist_matches_total{feed="spamhaus_drop"}[5m]) > 50
        for: 2m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "High Spamhaus DROP match rate — possible scan or attack"
          runbook: "docs/INCIDENT_RESPONSE.md#high-block-rate"

  - name: ja4proxy.scoring
    interval: 30s
    rules:

      - alert: ScoreDriftDetected
        expr: ja4proxy_analytics_score_drift_detected == 1
        for: 5m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "Risk score distribution has drifted from 7-day baseline"
          runbook: "docs/INCIDENT_RESPONSE.md#score-drift"

      - alert: BrowserShadowScoreElevated
        expr: histogram_quantile(0.95, rate(ja4proxy_risk_score_bucket{bypass="alpn_browser"}[5m])) > 15
        for: 10m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "Known-good browser shadow score p95 > 15 — signal may be miscalibrated"
          runbook: "docs/INCIDENT_RESPONSE.md#shadow-score-elevated"

      - alert: HighBlockRate
        expr: rate(ja4proxy_connections_total{action="block"}[5m]) > 100
        for: 2m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "Block rate exceeds 100/s — attack in progress or miscalibration"
          runbook: "docs/INCIDENT_RESPONSE.md#high-block-rate"

  - name: ja4proxy.quotas
    interval: 60s
    rules:

      - alert: AbuseIPDBQuotaExhausted
        expr: ja4proxy_abuseipdb_quota_exhausted == 1
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "AbuseIPDB daily quota exhausted — no new lookups until midnight UTC"
          runbook: "docs/INCIDENT_RESPONSE.md#abuseipdb-quota-exhausted"

      - alert: RDAPQueueDepthHigh
        expr: ja4proxy_rdap_enrichment_queue_depth > 400
        for: 5m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "RDAP enrichment queue depth > 400 — workers may be falling behind"
          runbook: "docs/INCIDENT_RESPONSE.md#enrichment-queue-high"

  - name: ja4proxy.policy
    interval: 30s
    rules:

      - alert: HighRiskBypassDisabled
        expr: ja4proxy_policy_changes_total{bypass="alpn_browser_bypass"} > 0
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "High-risk bypass {{ $labels.bypass }} has been disabled"
          runbook: "docs/INCIDENT_RESPONSE.md#bypass-disabled"

      - alert: TarpitCapacityNearLimit
        expr: ja4proxy_tarpit_concurrent / 500 > 0.8
        for: 2m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "Tarpit at >80% capacity — overflow actions may begin"
          runbook: "docs/INCIDENT_RESPONSE.md#tarpit-capacity"

  - name: ja4proxy.exceptions
    interval: 30s
    rules:

      - alert: PipelineInternalError
        expr: rate(ja4proxy_pipeline_unexpected_errors_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
          team: secops
        annotations:
          summary: "Pipeline internal error in {{ $labels.phase }}"
          description: "An unexpected exception was re-raised in the pipeline. Check logs immediately."
          runbook: "docs/runbooks/security_incident_response.md#pipeline-internal-error"

      - alert: ExceptionRateSpike
        expr: |
          rate(ja4proxy_exception_handled_total[5m]) > 2 *
          avg_over_time(rate(ja4proxy_exception_handled_total[5m])[1h:5m])
        for: 5m
        labels:
          severity: warning
          team: secops
        annotations:
          summary: "Exception rate 2× above 1h baseline in {{ $labels.module }}"
          description: "Spike may indicate a new failure mode. Current: {{ $value | humanize }}/s"
          runbook: "docs/runbooks/security_incident_response.md#exception-rate-spike"
```

---

## §5. Health Endpoint

The proxy exposes `GET /health` on a separate management port (default `:9090`).
This is distinct from the Prometheus `/metrics` endpoint.

### 5a. Response Schema

```json
{
  "status": "healthy",
  "version": "1.4.2",
  "uptime_seconds": 3612,
  "dial": 75,
  "components": {
    "redis":      {"status": "healthy", "latency_ms": 1},
    "blocklists": {
      "status": "healthy",
      "feeds": {
        "spamhaus_drop":  {"status": "healthy", "entries": 923,  "age_seconds": 12043},
        "spamhaus_edrop": {"status": "healthy", "entries": 2104, "age_seconds": 12043}
      }
    },
    "tor_list":   {"status": "healthy", "entries": 1847, "age_seconds": 3022},
    "analytics":  {"status": "degraded", "stream_lag_seconds": 45, "note": "lag elevated"},
    "abuseipdb":  {"status": "quota_exhausted", "quota_used": 1000, "quota_limit": 1000}
  },
  "policy": {
    "alpn_browser_bypass":     true,
    "ja4_whitelist_bypass":    true,
    "mtls_bypass":             true,
    "static_ip_allowlist":     true,
    "ja4_blacklist_bypass":    true,
    "country_blacklist_bypass": true,
    "spamhaus_bypass":         true,
    "tls_version_bypass":      true
  }
}
```

### 5b. Status Values

| Status | Meaning | HTTP code |
|--------|---------|-----------|
| `healthy` | All components nominal | 200 |
| `degraded` | One or more components degraded but proxy operational | 200 |
| `unhealthy` | Critical component failed; proxy may not be protecting | 503 |

The overall `status` field is the worst of all component statuses.
Redis failure → `unhealthy`. Stale feed → `degraded`. Everything nominal → `healthy`.

### 5c. Component Status Rules

| Component | Healthy | Degraded | Unhealthy |
|-----------|---------|----------|-----------|
| Redis | Ping < 10ms | Ping < 500ms | Ping fails |
| Blocklist feed | Age < 24h | Age 24–48h | Age > 48h or entries = 0 |
| Tor exit list | Age < 2h | Age 2–4h | Age > 4h or entries = 0 |
| Analytics | Stream lag < 60s | Lag 60–300s | Lag > 300s |
| AbuseIPDB | Quota available | — | `quota_exhausted` (not unhealthy — proxy still works) |

### 5d. Kubernetes / Docker Healthcheck

```yaml
# docker-compose.yml
healthcheck:
  test: ["CMD", "curl", "-sf", "http://localhost:9090/health"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

Liveness probe: `/health` returning 200.
Readiness probe: `/health` returning 200 with `status != "unhealthy"`.

---

## §6. Service Level Indicators

These are the measurable SLIs for the proxy. Alertmanager rules and Grafana
panels are defined against these.

| SLI | Definition | Target | Alert threshold |
|-----|-----------|--------|----------------|
| **False-Positive Rate** | Browser connections (h2/h1 ALPN) that receive any action other than `allow` or `bypass` | 0% | Any occurrence at dial > 0 |
| **Pipeline Latency p99** | Time from connection accept to action decision | < 5ms | > 10ms for 2m |
| **Redis Availability** | Successful Redis operations / total operations | > 99.9% | < 99% for 2m |
| **Feed Freshness** | Time since last successful feed download | < 24h per feed | > 24h for any feed |
| **Enrichment Queue Depth** | RDAP + DNS + AbuseIPDB queue depths | < 80% of max | > 400 for RDAP/DNS, > 400 for AbuseIPDB for 5m |
| **Score Stability** | Score p95 deviation from 7-day baseline | < 2 std dev | > 2 std dev for 5m |

---

## §7. Observability Acceptance Criteria Template

Every phase that adds metrics, log lines, or Grafana panels must include these
acceptance criteria in its phase file, following the format in STYLE_GUIDE.md §3a.

```markdown
### Observability

- [ ] Prometheus counter: ja4proxy_{subsystem}_{measurement}_total{labels} — description
- [ ] Prometheus gauge: ja4proxy_{subsystem}_{measurement}{labels} — description  
- [ ] Prometheus histogram: ja4proxy_{subsystem}_{measurement}{labels} — buckets [...]

- [ ] JSON log: connection log includes {field} field when {condition}
- [ ] JSON log: system log event={event_name} emitted when {condition}

- [ ] Health endpoint: /health component={component} reflects {state} when {condition}

- [ ] Grafana Dashboard 01 (Operations): {panel description} added to Row {N}
- [ ] Grafana Dashboard 02 (Security): {panel description} added to Row {N}
- [ ] Grafana Dashboard 03 (System): {panel description} added to Row {N}
  (only include dashboards that actually get new panels this phase)

- [ ] Alertmanager: {AlertName} rule fires when {condition}
  (only include if phase introduces a new alert)

- [ ] docs/OBSERVABILITY_STANDARDS.md metric registry updated with new metrics
```

---

## §8. Applying This Document

When implementing any phase:

1. Check the metric registry (§1d) before naming a new metric — it may already exist.
2. If adding a new metric, add it to the registry first, then implement.
3. All log lines must conform to the JSON schema (§2).
4. New Grafana panels slot into the existing dashboard rows (§3b–3d) — do not create new dashboards.
5. New alert rules go in the appropriate file in `monitoring/alertmanager/rules/` (§4) following the existing format.
6. Update `/health` component list (§5a) when adding a new dependency.
7. The observability acceptance criteria template (§7) must be present in every phase file that adds observable behaviour.
