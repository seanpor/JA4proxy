# Phase 12c — Score Drift Monitoring & Observability

## Goal
Implement comprehensive monitoring of scoring system health, including drift detection, anomaly identification, and enhanced observability.

## Score Drift Detection

### 12c.1 Baseline Tracking

**Hourly Snapshots:**
```python
def capture_baseline_snapshot():
    # Calculate current hour statistics
    current_hour = datetime.now().strftime("%Y-%m-%d-%H")
    
    stats = {
        "median_score": calculate_median_score(),
        "mean_score": calculate_mean_score(),
        "stddev_score": calculate_stddev(),
        "score_distribution": calculate_histogram(),
        "timestamp": time.time(),
        "event_count": get_event_count()
    }
    
    # Store in Redis with 7-day TTL
    redis.set(
        f"analytics:baseline:hourly:{current_hour}",
        json.dumps(stats),
        ex=604800  # 7 days
    )
```

**Redis Storage:**
- Key: `analytics:baseline:hourly:{YYYY-MM-DD-HH}`
- TTL: 604800 seconds (7 days)
- Retention: 168 hours (7 days)

### 12c.2 Drift Detection Algorithm

**Statistical Analysis:**
```python
def check_score_drift(current_stats, baseline_stats):
    # Calculate z-score for median comparison
    if baseline_stats["stddev_score"] > 0:
        z_score = (current_stats["median_score"] - baseline_stats["median_score"]) / baseline_stats["stddev_score"]
    else:
        z_score = 0
    
    # Check for significant drift
    if abs(z_score) > 2.0:  # Configurable threshold
        return {
            "drift_detected": True,
            "z_score": z_score,
            "current_median": current_stats["median_score"],
            "baseline_median": baseline_stats["median_score"],
            "severity": "high" if abs(z_score) > 3.0 else "medium"
        }
    
    return {"drift_detected": False}
```

**Alert Storage:**
- Key: `analytics:alerts:score_drift`
- Value: JSON alert details
- TTL: 3600 seconds (1 hour, auto-clears)

### 12c.3 Distribution Analysis

**Histogram Comparison:**
```python
def compare_distributions(current_dist, baseline_dist):
    # Kolmogorov-Smirnov test for distribution differences
    ks_statistic, p_value = ks_2samp(current_dist, baseline_dist)
    
    if p_value < 0.05:  # Significant difference
        return {
            "distribution_shift": True,
            "ks_statistic": ks_statistic,
            "p_value": p_value
        }
    
    return {"distribution_shift": False}
```

**Anomaly Patterns:**
- Bimodal distributions
- Sudden spikes/drops
- Unusual clustering
- Outlier proliferation

## Enhanced Observability

### 12c.4 Prometheus Metrics

**New Metrics:**
```python
# Score health metrics
ja4proxy_analytics_score_median = Gauge(
    "ja4proxy_analytics_score_median",
    "Current median risk score"
)

ja4proxy_analytics_score_drift_detected = Gauge(
    "ja4proxy_analytics_score_drift_detected",
    "1 if score drift detected, 0 otherwise"
)

ja4proxy_analytics_distribution_shift = Gauge(
    "ja4proxy_analytics_distribution_shift",
    "1 if score distribution shifted significantly"
)

# Performance metrics
ja4proxy_analytics_drift_check_duration = Histogram(
    "ja4proxy_analytics_drift_check_duration",
    "Duration of drift detection checks"
)
```

### 12c.5 Grafana Dashboards

**Score Health Panel:**
- Rolling 7-day median ± 1 stddev band
- Current 1-hour median overlaid
- Visual drift indicators
- Historical trend analysis

**Distribution Panel:**
- Score histogram comparison
- Current vs baseline overlay
- KS test results
- Anomaly flags

**Alert Panel:**
- Current active alerts
- Alert history
- Severity indicators
- Resolution tracking

### 12c.6 Enhanced Logging

**Structured Logs:**
```json
{
  "type": "monitoring",
  "level": "WARN",
  "subsystem": "analytics",
  "event": "score_drift_detected",
  "z_score": 2.45,
  "current_median": 45.2,
  "baseline_median": 38.7,
  "severity": "medium",
  "timestamp": "2024-03-15T14:30:45Z"
}

{
  "type": "monitoring",
  "level": "INFO",
  "subsystem": "analytics",
  "event": "baseline_captured",
  "hour": "2024-03-15-14",
  "median_score": 38.7,
  "event_count": 14567
}
```

## Shadow Scoring & Calibration

### 12c.7 Known-Good Traffic Monitoring

**Calibration Signal:**
```python
def track_shadow_scores():
    # Identify known-good traffic (h2/h1 ALPN)
    good_traffic = get_known_good_connections()
    
    # Calculate shadow scores
    shadow_stats = {
        "median": calculate_median(good_traffic),
        "mean": calculate_mean(good_traffic),
        "stddev": calculate_stddev(good_traffic),
        "count": len(good_traffic)
    }
    
    # Store for calibration
    redis.set(
        "analytics:shadow_scores:latest",
        json.dumps(shadow_stats),
        ex=3600  # 1 hour
    )
    
    # Check for calibration issues
    if shadow_stats["median"] > 10:  # Should be low
        log_calibration_issue(shadow_stats)
```

**Calibration Alerts:**
- Trigger when shadow scores rise unexpectedly
- Indicate signal module miscalibration
- Require manual review

## Configuration

```yaml
analytics_node:
  monitoring:
    enabled: true
    
    baseline:
      capture_interval_seconds: 3600  # Hourly
      retention_days: 7
      
    drift_detection:
      enabled: true
      z_score_threshold: 2.0
      check_interval_seconds: 60
      
    distribution_analysis:
      enabled: true
      ks_test_threshold: 0.05
      
    shadow_scoring:
      enabled: true
      known_good_alpn: ["h2", "h1"]
      calibration_alert_threshold: 10.0
      
    alerting:
      drift_alert_ttl_seconds: 3600
      severity_levels:
        low: 1.5
        medium: 2.0
        high: 3.0
```

## Integration with Monitoring Stack

### 12c.8 Alertmanager Integration

**Alert Rules:**
```yaml
- alert: ScoreDriftDetected
  expr: ja4proxy_analytics_score_drift_detected == 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Score drift detected in analytics system"
    description: "Risk score median has drifted significantly from baseline"

- alert: DistributionShiftDetected
  expr: ja4proxy_analytics_distribution_shift == 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Score distribution shift detected"
    description: "Risk score distribution has changed significantly"
```

### 12c.9 Incident Response Integration

**Automated Actions:**
- Create JIRA ticket on severe drift
- Page on-call for critical alerts
- Automated slack notifications
- Incident timeline creation

## Acceptance Criteria

### Functional
- [ ] Hourly baseline snapshots captured and stored
- [ ] Drift detection algorithm implemented
- [ ] Distribution analysis with KS test
- [ ] Shadow scoring for known-good traffic
- [ ] Alerts written to Redis with TTL
- [ ] Alert auto-clearance when resolved

### Observability
- [ ] Prometheus metrics for score health
- [ ] Grafana Score Health panel created
- [ ] Distribution comparison panel created
- [ ] Alert panel with history
- [ ] Structured JSON logging
- [ ] Health endpoints extended

### Integration
- [ ] Alertmanager rules configured
- [ ] Incident response integration
- [ ] Slack/email notifications working
- [ ] JIRA ticket creation (if configured)

### Testing
- [ ] Unit tests: baseline capture
- [ ] Unit tests: drift detection algorithm
- [ ] Unit tests: distribution comparison
- [ ] Unit tests: shadow scoring
- [ ] Integration test: full monitoring pipeline
- [ ] Chaos test: baseline data corruption
- [ ] Performance test: 1M events with monitoring

### Security
- [ ] Monitoring data access controlled
- [ ] Alert data sanitized
- [ ] Metrics endpoint secured
- [ ] Logging redaction for sensitive data

## Performance Considerations

**Optimizations:**
- Incremental statistics calculation
- Sliding window algorithms
- Memory-efficient histograms
- Batch processing of metrics

**Resource Limits:**
- Memory: < 200MB for monitoring data
- CPU: < 10% for drift checks
- Storage: < 50MB for 7-day baselines

## Next Steps
- Phase 12d: Security hardening
- Phase 13: Deployment and scaling