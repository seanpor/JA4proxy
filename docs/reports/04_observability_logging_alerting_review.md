# Observability, Logging & Alerting Review

**Date:** 2026-04-08 (recalibrated 2026-04-08 v2)  
**Scope:** Prometheus rules, Alertmanager config, Grafana dashboards, telemetry, analytics, health checks, structured logging  
**Severity scale:** CRITICAL → HIGH → MEDIUM → LOW · **[Go-PROD]** = production gap · **[Python-deprecated]** = maintenance debt

> **Production context:** Go (`cmd/proxy/`, `internal/metrics/`) is production. Python is deprecated. Go-only gaps are production issues. Python-only logging violations are maintenance debt. Shared infrastructure (Prometheus, Alertmanager, Grafana, Helm, compose) applies equally.

## Findings Summary

| # | Severity | Category | Finding | Scope |
|---|----------|----------|---------|-------|
| 1a | MEDIUM | Metric Naming | Recording rules use `ja4:` prefix, not `ja4proxy_` | [Infra] |
| 1b | MEDIUM | Metric Naming | 15+ Python metric definitions lack `ja4proxy_` prefix | [Python-deprecated] |
| 2a | LOW | Logging/PII | f-string logging in 7 Python security modules (17 instances) | [Python-deprecated] |
| 2b | MEDIUM | Logging | Go health check logs at INFO for every check — noise at 15K+ conn/s | **[Go-PROD]** |
| 3a | MEDIUM | Health Depth | Go health check only tests Redis, no hysteresis | **[Go-PROD]** |
| 3b | MEDIUM | Health Depth | Go proxy has no `/ready` endpoint | **[Go-PROD]** |
| 4a | LOW | Alert Quality | Duplicate alert rules across two rule file sets | [Infra] |
| 4b | MEDIUM | Missing Alerts | No alert for enrichment queue depth backlog | [Infra] |
| 5a | **HIGH** | Blind Spot | `PipelineInternalError` alert references undefined metric | [Infra] |
| 5b | MEDIUM | Blind Spot | No alert for static allowlist bypass abuse | [Infra] |
| 5c | LOW | Blind Spot | No alert for country blacklist bypass under attack | [Infra] |
| 5d | MEDIUM | Missing Alerts | No alert for dial change rate exceeding limit | [Infra] |
| 6a | MEDIUM | Analytics | AggregationManager discards all data on window rotate | [Python-deprecated] |
| 6b | **HIGH** | Analytics | Shadow scoring uses ALPN-only for "known-good" traffic | [Infra] |
| 6c | MEDIUM | Analytics | Default HMAC secret is well-known string | [Python-deprecated] |
| 7a | **HIGH** | Metric Poisoning | Metrics endpoint unauthenticated, binds `0.0.0.0` | [Infra] |
| 7b | LOW | Metric Poisoning | Prometheus scrape targets not mTLS protected | [Infra] |
| 8a | MEDIUM | Structured Logging | `print()` calls bypass logging; mixed log formats | [Python-deprecated] |
| 9a | **HIGH** | Secrets | Hardcoded placeholder secrets in alertmanager.yml | [Infra] |
| 9b | LOW | Alert Routing | Default receiver is log-only, no human escalation | [Infra] |
| 10a | LOW | Dashboards | Analytics dashboard lacks actionable incident panels | [Infra] |
| 10b | LOW | Dashboards | No Grafana dashboard for backup operations | [Infra] |
| 11 | MEDIUM | SLOs | No SLO/SLI definitions in config or governance | [Infra] |

---

## Critical Findings

### Finding 2a — HIGH: f-String Logging Exposes PII

17 instances across 7 security modules use f-strings in logging calls, violating AGENTS.md standards and eagerly evaluating PII (IPs, fingerprints, SNIs) even when the log level is disabled:

| File | Instances |
|------|-----------|
| `src/security/virustotal.py` | 5 |
| `src/security/behavioral.py` | 3 |
| `src/security/greynoise.py` | 2 |
| `src/security/alienvault.py` | 2 |
| `src/security/misp.py` | 2 |
| `src/security/threatfox.py` | 2 |
| `src/security/attribution.py` | 1 |

**Remediation:** Replace with lazy formatting: `logger.warning("event=%s | ip=%s", event, ip)`

### Finding 5a — HIGH: Alert References Undefined Metric

`PipelineInternalError` alert (`monitoring/alertmanager/rules/security.rules.yml:20`) references `ja4proxy_pipeline_unexpected_errors_total`, but this metric is not defined in Go (`internal/metrics/metrics.go`) or any Python file found via grep.

### Finding 6b — HIGH: Shadow Scoring Uses ALPN-Only for "Known-Good"

**File:** `src/analytics/shadow_scoring.py`, lines 54-62

```python
def _is_known_good_traffic(self, event: Dict[str, Any]) -> bool:
    alpn = event.get("alpn", "")
    if alpn in self.known_good_alpn:
        return True
```

An attacker setting ALPN to `h2` pollutes the shadow score baseline, causing calibration checks to miss real issues.

### Finding 7a — HIGH: Metrics Endpoint Unauthenticated, Binds `0.0.0.0`

**File:** `config/proxy.yml`, lines 205-214

```yaml
metrics:
  authentication:
    enabled: false  # Set to true in production
  bind_host: "0.0.0.0"  # Override to 127.0.0.1 in production
```

Any container on the Docker network can read all metrics (information disclosure). Default `authentication.enabled` should be `true`.

### Finding 9a — HIGH: Hardcoded Placeholder Secrets in Alertmanager

**File:** `monitoring/alertmanager/alertmanager.yml`

- `smtp_auth_password: 'your-password-here'`
- Slack webhook URL is a placeholder
- PagerDuty service key is a placeholder
- SIEM password is `your-siem-password`

---

## Medium Findings

### Finding 1a — Recording Rules Use Wrong Prefix

All recording rules use `ja4:` prefix instead of `ja4proxy_` (e.g., `ja4:requests:rate1m` vs `ja4proxy_requests_rate1m`).

### Finding 1b — 15+ Python Metric Definitions Lack Prefix

Modules including `local_cache.py`, `config/loader.py`, `pubsub.py`, `backup/worker.py`, `backup/restorer.py`, `backup/cloud/s3_adapter.py`, `security/adaptive_cache.py`, `security/mtls.py`, `security/behavioral.py`, `security/tcp_analyzer.py`, `security/write_buffer.py`, `security/integrity_monitor.py`, `security/sni_analyzer.py`, `security/tls_enforcer.py`, `security/risk_scorer.py` — all define metrics without the `ja4proxy_` prefix.

### Finding 3a — Go Health Check Is Superficial

Only tests Redis connectivity. Does not check: GeoIP database presence, pipeline latency, active connection count vs capacity, tarpit saturation, or enrichment queue depths.

### Finding 4b — No Alert for Enrichment Queue Backlog

Multiple enrichment modules expose queue depth gauges, but no alert fires when they exceed a threshold. Queue saturation causes enrichment to silently fail open.

### Finding 5b — No Alert for Allowlist Bypass Abuse

Static allowlist completely bypasses the scoring pipeline. No alert for sudden spikes in `ja4proxy_static_allowlist_hits_total`.

### Finding 5d — No Alert for Dial Change Rate Exceeded

`max_dial_change_per_hour: 25` is defined but no alert fires when this rate is exceeded.

### Finding 6a — AggregationManager Discards All Data on Window Rotate

When the time window rotates, `aggregation_data.clear()` discards all state. Cross-instance signals miss events at window boundaries.

### Finding 6c — Default HMAC Secret Is Well-Known

**File:** `src/analytics/config.py`, line 27

```python
"hmac_secret": "default-secret-change-me"
```

If an operator forgets to override it, any attacker who reads this repo can forge events into the analytics stream.

### Finding 8a — `print()` Calls Bypass Logging

`src/analytics/stream_consumer.py` uses `print()` for error output (lines 127-129, 138, 173, 196, 199). These bypass the logging system entirely — no level filtering, no Loki ingestion, no timestamps.

### Finding 11 — No SLO/SLI Definitions

No explicit SLOs in `config/proxy.yml` or `src/governance/`. Only `ProxyAvailabilitySLOBurn` alert exists but SLO target, error budget, and burn rate windows are not documented.

---

## Low Findings

### Finding 3b — No `/ready` Endpoint on Go Proxy

Python serves `/health`, `/ready`, and `/metrics`. Go only serves `/health` and `/metrics`.

### Finding 4a — Duplicate Alert Rules

Same alert definitions exist in both `monitoring/prometheus/alerts.yml` and `monitoring/alertmanager/rules/`. The latter set is not referenced by `prometheus.yml`.

### Finding 5c — No Alert for Country Blacklist Bypass

Safe countries can override country blocks. No alert for unusual traffic from safe countries.

### Finding 7b — Prometheus Scrape Targets Not mTLS Protected

No `tls_config` on any scrape job. Metrics are scraped over plaintext HTTP.

### Finding 9b — Default Receiver Is Log-Only

Any alert not matching a specific route goes to `http://logger:8080/webhook` with no human notification.

### Finding 10a — Analytics Dashboard Lacks Incident Panels

No panels for per-subnet aggregation, campaign suspect leaderboard, slow-scan suspect table, or top JA4 fingerprints by block rate.

### Finding 10b — No Backup Operations Dashboard

Backup metrics and alerts exist but no Grafana dashboard.
