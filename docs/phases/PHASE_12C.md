# Phase 12c — Score Drift Monitoring & Observability

## Status: COMPLETE (2026-03-15)

Core drift detection algorithms exist and pass 14 tests. The main missing
deliverable is the Grafana dashboard that makes drift visible to operators.

---

## What Is Already Implemented

### Baseline Tracking (`src/analytics/baseline_monitor.py`)
- Hourly snapshots written to `analytics:baseline:hourly:{YYYY-MM-DD-HH}` (TTL 7 days) ✓
- Stores: median, mean, stddev, histogram, event count ✓

### Drift Detection (`src/analytics/drift_detector.py`)
- Z-score comparison: `|z| > 2.0` triggers alert ✓
- Alert written to `analytics:alerts:score_drift` (TTL 3600s, auto-clears) ✓
- Prometheus gauge `ja4proxy_analytics_score_drift_detected` ✓
- JSON log emitted on drift: `event=score_drift_detected` with z_score and medians ✓

### Distribution Analysis (`src/analytics/distribution_analyzer.py`)
- Manual KS-statistic approximation (max CDF difference) ✓
- **Note**: Does not use `scipy.stats.ks_2samp` — the approximation is acceptable
  for this use case. Revisit only if false positives become a problem in production.

### Shadow Scoring (`src/analytics/shadow_scoring.py`)
- Tracks h2/h1 ALPN (known-good) traffic separately as calibration signal ✓
- Alert written to `analytics:alerts:calibration_issue` when shadow median > threshold ✓

### Monitoring Integration (`src/analytics/monitoring.py`)
- `MonitoringSystem` orchestrates baseline capture, drift detection, shadow scoring ✓
- Prometheus metrics:
  - `ja4proxy_analytics_score_median` ✓
  - `ja4proxy_analytics_score_drift_detected` ✓
  - `ja4proxy_analytics_distribution_shift` ✓
  - `ja4proxy_analytics_drift_check_duration` ✓

---

## Gaps

### 1. Grafana dashboard (missing)
The "Score Health" panel described in PHASE_12.md does not exist. Required panels:

- Rolling 7-day median ± 1 stddev band, current 1-hour median overlaid
- `ja4proxy_analytics_score_drift_detected` gauge panel
- Stream lag (`ja4proxy_analytics_stream_lag_seconds`) graph
- Top attacking subnets table
- JA4 candidate count

Create `monitoring/grafana/dashboards/analytics.json` and add it to the
Grafana provisioning config.

### 2. Alertmanager rules (missing)
Add to `monitoring/alertmanager/alerts.yml`:

```yaml
- alert: ScoreDriftDetected
  expr: ja4proxy_analytics_score_drift_detected == 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Risk score median has drifted from 7-day baseline"

- alert: AnalyticsStreamLagHigh
  expr: ja4proxy_analytics_stream_lag_seconds > 60
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Analytics node is lagging behind the event stream"
```

### 3. Chaos test (missing)
- Baseline data missing/corrupted: drift detector returns no alert, logs warning, does not crash

---

## Out of Scope

The following items from the original 12c plan are **not required**:
- Alertmanager integration beyond the two rules above
- Slack/email/PagerDuty/JIRA notifications — that's an ops concern, not proxy code
- Incident response automation — Phase 14 territory

---

## Acceptance Criteria

### Functional
- [x] Hourly baseline snapshots captured and stored with 7-day TTL
- [x] Z-score drift detection: |z| > 2.0 → alert written
- [x] Alert auto-clears when drift resolves (TTL expires)
- [x] Distribution shift detection (approximated KS test)
- [x] Shadow scoring for known-good h2/h1 ALPN traffic
- [x] Calibration alert when shadow median rises unexpectedly

### Observability
- [x] Prometheus metrics for score health
- [x] Structured JSON logging for drift events
- [x] Grafana "Score Health" dashboard provisioned (`monitoring/grafana/dashboards/analytics.json`)
- [x] Alertmanager rules for drift and stream lag (`monitoring/prometheus/alerts.yml`)

### Testing
- [x] Unit tests: baseline capture (6 passing)
- [x] Unit tests: drift detection algorithm (8 passing)
- [x] Unit tests: distribution comparison
- [x] Unit tests: shadow scoring
- [x] Chaos test: baseline data corrupted/missing — no crash, WARN logged
  (`tests/chaos/test_drift_baseline.py` — 11 tests)
