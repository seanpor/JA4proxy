<!--
title: Observability Standards
audience: DevOps, SRE, Monitoring Teams
last_reviewed: 2026-03-27
phase: 21
-->

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

This is the canonical list of all metrics actually emitted by the current
system: the **Go proxy** (`internal/`, `cmd/`) and the **Python analytics
service** (`src/`). Phases may not invent new metric names without adding them
here, and entries here must correspond to a real metric in code — the phase
completion gate checks both directions. Generated against the code on
2026-06-10 (phase-309 WP-6).

> **Histogram series:** each `histogram` metric also exposes the Prometheus
> `_bucket`, `_sum`, and `_count` series (e.g. `ja4proxy_risk_score_bucket`).
>
> **⚠ Dashboards (§3) and alerts (§4) not yet fully reconciled.** Some example
> panels and alert rules below still reference metric names from the **legacy
> Python proxy** (e.g. `ja4proxy_pipeline_unexpected_errors_total`,
> `ja4proxy_exception_handled_total`, `ja4proxy_cache_operations_total`,
> `ja4proxy_*_last_refresh_success_seconds`, `ja4proxy_policy_changes_total`,
> `ja4proxy_abuseipdb_quota_exhausted`) that this registry shows are **not
> emitted** — those rules would never fire. Validate every PromQL expression
> against this registry before deploying. Full §3/§4 reconciliation is tracked
> as residual WP-6 work in `PHASE_309.md`.

#### Core pipeline & scoring
```
ja4proxy_connections_total{action}                   counter   Total connections by action
ja4proxy_bypass_total{rule}                          counter   Connections handled by each bypass rule
ja4proxy_risk_score                                  histogram Risk score distribution (0-100)
ja4proxy_pipeline_duration_seconds                   histogram Pipeline processing time in seconds
ja4proxy_signal_total{name}                          counter   Signal firings by name
ja4proxy_signal_latency_seconds                      histogram Execution latency for individual signal modules in seconds
ja4proxy_security_events_total{type}                 counter   Security events by type
ja4proxy_connection_errors_total                     counter   Unhandled errors in the connection handler before a policy decision
ja4proxy_handler_panics_total                        counter   Connection handler goroutine panics recovered
```

#### Monitor mode & dial
```
ja4proxy_dial_current                                gauge     Current dial value (0-100)
ja4proxy_dial_changes_total                          counter   Total dial setting changes
```

#### TLS & cipher (Phase 3)
```
ja4proxy_weak_cipher_total                           counter   Total weak cipher connections
ja4proxy_ja4_tls_mismatch_total{action}              counter   JA4-claimed TLS version vs negotiated TLS version mismatches
```

#### SNI analysis (Phase 4)
```
ja4proxy_sni_signal_total{signal}                    counter   SNI signal events
ja4proxy_sni_dga_score                               histogram SNI DGA score distribution
```

#### TCP & connection behaviour (Phase 5)
```
ja4proxy_tcp_signal_total{signal}                    counter   TCP signal events
ja4proxy_active_connections                          gauge     Current active connections
```

#### ASN & Tor (Phase 6)
```
ja4proxy_asn_classification_total{type}              counter   ASN classification events
ja4proxy_tor_exit_list_entries                       gauge     Current Tor exit list size
```

#### FCrDNS enrichment (Phase 7)
```
ja4proxy_dns_enrichment_total{result}                counter   DNS enrichment results
ja4proxy_dns_enrichment_queue_depth                  gauge     DNS enrichment queue depth
ja4proxy_dns_enrichment_queue_drops_total            counter   Dropped DNS enrichment requests
ja4proxy_dns_ptr_classification_total{type}          counter   DNS PTR classifications
ja4proxy_dns_ptr_errors_total{error}                 counter   DNS PTR lookup errors
ja4proxy_dns_resolver_errors_total                   counter   DNS resolver errors
```

#### Blocklists (Phase 8)
```
ja4proxy_blocklist_matches_total{list}               counter   Blocklist match counts
```

#### AbuseIPDB (Phase 10)
```
ja4proxy_abuseipdb_lookups_total{result}             counter   AbuseIPDB lookup results
ja4proxy_abuseipdb_enrichment_queue_depth            gauge     AbuseIPDB queue depth
ja4proxy_abuseipdb_queue_dropped_total               counter   Dropped AbuseIPDB requests
```

#### PROXY protocol & mTLS / cert
```
ja4proxy_proxy_protocol_parser_events_total{event}   counter   PROXY protocol parser security events. Labels: event=spoof_stripped|smuggling_blocked.
ja4proxy_tls_cert_expiry_timestamp_seconds           gauge     Listener TLS certificate NotAfter as a Unix timestamp (phase-63)
```

#### Tarpit & rate limiting
```
ja4proxy_tarpit_concurrent                           gauge     Current tarpit connections
ja4proxy_tarpit_overflow_total{action}               counter   Tarpit overflows by action
```

#### TAP mode (Phase 20)
```
ja4proxy_tap_lookups_total{result}                   counter   Phase-20 TAP fingerprint lookup results
ja4proxy_tap_signal_total{action}                    counter   TAP-derived OS mismatch signals emitted
ja4proxy_tap_ja4t_lookups_total{result}              counter   Passive JA4T fp:ja4t:ip lookups (316c): hit_blocklisted|hit_clean|miss|error
ja4proxy_tap_ja4t_signal_total{action}               counter   TAP-derived JA4T blocklist signals emitted (316c)
```

#### Go TAP sensor (Phase 316) — standalone binary `cmd/ja4-tap`, own registry
```
ja4proxy_tap_packets_received_total                  counter   Packets read from the capture source
ja4proxy_tap_packets_dropped_total{reason}           counter   Packets/bytes dropped: decode|non_tcp|cap_exceeded|gap|event_overflow
ja4proxy_tap_active_streams                          gauge     TCP connections currently tracked by the reassembler
ja4proxy_tap_handshakes_extracted_total{kind}        counter   TLS handshakes extracted: clienthello|serverhello|connection
ja4proxy_tap_fingerprints_written_total{result}      counter   Passive OS classes (316b): written|skipped_unknown|error
ja4proxy_tap_ja4t_written_total{result}              counter   Passive JA4T fingerprints (316c): written|skipped_unknown|error
ja4proxy_tap_enforcement_actions_total{result}       counter   Out-of-band enforcement (316d): skipped|watchlist|banned|error
ja4proxy_tap_enforcement_armed                       gauge     1 when armed to write enforceable ban:{ip} keys (316d); 0 = advisory-only (default)
```

#### Redis & config
```
ja4proxy_redis_health{status}                        gauge     Redis health status (1=current, 0=stale). Labels: status=ok|error.
ja4proxy_redis_operations_total{command,result}      counter   Redis operations performed by the proxy
ja4proxy_redis_acl_enabled                           gauge     1 if per-service Redis ACL users are in use, 0 if the proxy connects as the unrestricted default user (JA4PROXY-2026-0050).
ja4proxy_redis_script_reloads_total{result}          counter   Count of sliding_window.lua reloads after Redis restart/flush. Labels: result=ok|error.
ja4proxy_config_reloads_total                        counter   Total config reloads
ja4proxy_config_reload_failures_total                counter   Failed config reloads
```

#### Analytics stream & write buffer
```
ja4proxy_stream_event_queue_depth                    gauge     Current depth of the bounded XADD event queue (JA4PROXY-2026-0031).
ja4proxy_stream_event_drops_total                    counter   XADD events dropped because the bounded queue was full (JA4PROXY-2026-0031).
ja4proxy_stream_event_write_errors_total{reason}     counter   XADD worker failures by reason (JA4PROXY-2026-0031).
ja4proxy_write_buffer_queue_depth                    gauge     Current event buffer depth
ja4proxy_write_buffer_dropped_total                  counter   Total dropped events
```

#### Cross-DC sync
```
ja4proxy_sync_wan_connected{peer}                    gauge     WAN connection status to peers (1=connected, 0=disconnected)
ja4proxy_sync_replication_lag_seconds{stream}        gauge     Cross-DC state replication lag
ja4proxy_sync_peer_skew_seconds{peer}                gauge     Clock skew relative to peer DC
ja4proxy_sync_clock_drift_seconds                    gauge     NTP clock drift in seconds
ja4proxy_sync_events_processed_total{op,dc}          counter   Total sync events applied locally
ja4proxy_sync_errors_total{type}                     counter   Total sync failures
ja4proxy_signal_drift_total{source,type}             counter   Total detected scoring drift events between nodes or sources
```

#### NetBox integration
```
ja4proxy_netbox_cidrs_loaded{status}                 counter   NetBox CIDR fetch results (phase-94i2)
```

#### Health / runtime
```
ja4proxy_health_check_panics_total                   counter   Health check goroutine panics recovered
ja4proxy_rdap_enrichment_queue_depth                 gauge     RDAP enrichment queue depth
```

#### Analytics service (Python `src/`)
```
ja4proxy_analytics_calibration_check_duration        histogram Duration of calibration checks
ja4proxy_analytics_calibration_issue                 gauge     1 if calibration issue detected, 0 otherwise
ja4proxy_analytics_distribution_check_duration       histogram Duration of distribution analysis checks
ja4proxy_analytics_distribution_shift                gauge     1 if score distribution shifted significantly
ja4proxy_analytics_drift_check_duration              histogram Duration of drift detection checks
ja4proxy_analytics_ml_anomalies_detected             gauge     Number of anomalies detected by ML model
ja4proxy_analytics_ml_detection_duration             histogram Duration of ML anomaly detection
ja4proxy_analytics_ml_model_version                  gauge     Current ML model version
ja4proxy_analytics_score_drift_detected              gauge     1 if score drift detected, 0 otherwise
ja4proxy_analytics_score_median                      gauge     Current median risk score
ja4proxy_analytics_shadow_score_median               gauge     Current median shadow score for known-good traffic
ja4proxy_analytics_stream_lag_seconds                gauge     Seconds between the latest processed stream event and now
ja4proxy_ti_feed_caps_hit_total{feed_id,kind}        counter   Number of times a safety cap was hit
ja4proxy_ti_feed_circuit_state{feed_id}              gauge     TI feed circuit breaker state (0=closed, 1=half_open, 2=open)
ja4proxy_ti_feed_cleanup_removals_total{feed_id}     counter   Indicators removed by TI feed differential cleanup
ja4proxy_ti_feed_fp_blocked_total{feed_id}           counter   Number of JA4 fingerprints blocked as false positives
ja4proxy_ti_feed_indicators_managed{feed_id}         gauge     Current number of indicators managed by a TI feed
ja4proxy_ti_feed_indicators_processed_total{feed_id,outcome} counter   Per-indicator outcomes inside a TI feed poll
ja4proxy_ti_feed_last_success_timestamp_seconds{feed_id} gauge     Unix timestamp of the last successful TI feed poll
ja4proxy_ti_feed_mgmt_api_errors_total{feed_id,status_code} counter   Management API errors observed by the TI feed runner
ja4proxy_ti_feed_poll_duration_seconds{feed_id}      histogram Wall-clock time per TI feed poll
ja4proxy_ti_feed_poll_total{feed_id,result}          counter   TI feed poll outcomes
ja4proxy_ti_feed_seed_file_entries_total{feed_id,outcome} counter   Seed-file fingerprint entries loaded per outcome
```

#### Load Testing (`ja4proxy_loadtest_*`)

Emitted by the load-test tooling (`ja4p test benchmark` / the load harness), not
by the proxy or analytics service. Present only while a benchmark is running.

```
ja4proxy_loadtest_connections_attempted_total       counter   Connections the load test attempted to open
ja4proxy_loadtest_connections_completed_total        counter   Connections that completed successfully
ja4proxy_loadtest_errors_total                       counter   Connection errors during the load test
ja4proxy_loadtest_latency_seconds                    histogram Per-connection latency distribution
ja4proxy_loadtest_throughput_cps                     gauge     Achieved throughput (connections per second)
```

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

Alert rules are organized into multiple files in `deploy/monitoring/alertmanager/rules/`:

| File | Covers |
|------|--------|
| `deploy/monitoring/alertmanager/rules/proxy.rules.yml` | Active connections, block rate, latency, dial anomalies |
| `deploy/monitoring/alertmanager/rules/redis.rules.yml` | Redis availability, memory, command latency |
| `deploy/monitoring/alertmanager/rules/security.rules.yml` | High score rate, bypass disabled, blacklist size anomalies |
| `deploy/monitoring/alertmanager/rules/backup.rules.yml` | Backup failures, retention violations |
| `deploy/monitoring/alertmanager/rules/management_ui_rules.yml` | Management UI availability and errors (deferred until Phase 13) |

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
5. New alert rules go in the appropriate file in `deploy/monitoring/alertmanager/rules/` (§4) following the existing format.
6. Update `/health` component list (§5a) when adding a new dependency.
7. The observability acceptance criteria template (§7) must be present in every phase file that adds observable behaviour.
