# Phase 12 — Analytics Node (COMPLETE)

## Status: COMPLETE (2026-03-15) — 1435 tests passing

| Sub-phase | Status | Completed |
|-----------|--------|-----------|
| 12a | ✅ Complete | HTTP server, requirements-analytics.txt, docker-compose, chaos tests |
| 12b | ✅ Complete | Proxy reads campaign (+35) and slowscan (+30) signals; local cache 60s TTL |
| 12c | ✅ Complete | Grafana dashboard, Alertmanager rules, drift chaos tests, Prometheus scrape |
| 12d | ✅ Complete | Replay prevention, stream lag metric, stream chaos tests, REDIS_SCHEMA |

## Goal
Separate Docker container that consumes events from all proxy instances via Redis Streams, performs cross-instance statistical analysis, and publishes enriched findings back for all proxy instances to use.

**This phase has been broken down into 4 sub-phases:**
- **Phase 12a**: Analytics Node Foundation (container, ingestion, basic aggregation)
- **Phase 12b**: Advanced Detection Modules (campaign, slow scan, JA4 intelligence)
- **Phase 12c**: Score Drift Monitoring & Observability (monitoring, alerting, dashboards)
- **Phase 12d**: Security Hardening (validation, authentication, rate limiting)

## Rationale for Breakdown

The original Phase 12 was too large and complex, covering:
1. Core infrastructure (container, ingestion)
2. Advanced detection algorithms
3. Comprehensive monitoring
4. Security hardening

Breaking it into sub-phases provides:
- **Clearer scope** for each implementation step
- **Better testing isolation**
- **Incremental value delivery**
- **Easier troubleshooting**
- **More manageable reviews**

## Implementation Order

```
Phase 12a → Phase 12b → Phase 12c → Phase 12d
```

Each sub-phase builds on the previous one and can be tested independently.

## Key Improvements Over Original Plan

### Enhanced Security
- **Event validation** with JSON Schema
- **HMAC authentication** for all events
- **Rate limiting** per proxy and globally
- **Comprehensive audit logging**
- **Forensic data retention**

### Better Observability
- **Score drift detection** with statistical analysis
- **Distribution monitoring** with KS tests
- **Shadow scoring** for calibration
- **Enhanced Grafana dashboards**
- **Comprehensive Prometheus metrics**

### Robust Architecture
- **Circuit breakers** for resource protection
- **Algorithm complexity limits**
- **Memory and timeout constraints**
- **Network isolation**
- **TLS for all communications**

## Migration Path

### From Current State to Phase 12a
1. Implement analytics container with basic ingestion
2. Add event validation and authentication
3. Implement basic cross-instance aggregation
4. Set up health monitoring

### From Phase 12a to 12b
1. Add campaign detection module
2. Implement slow scan detection
3. Add JA4 fingerprint intelligence
4. Integrate with proxy scoring

### From Phase 12b to 12c
1. Implement baseline tracking
2. Add drift detection algorithms
3. Create monitoring dashboards
4. Set up alerting integration

### From Phase 12c to 12d
1. Harden event validation
2. Add comprehensive rate limiting
3. Implement forensic logging
4. Set up incident response

## Testing Strategy

Each sub-phase includes:
- **Unit tests** for core functionality
- **Integration tests** for component interactions
- **Security tests** for validation and authentication
- **Performance tests** for scalability
- **Chaos tests** for resilience

## Security Considerations

**Threat Model Addressed:**
- Event poisoning (validation, HMAC)
- Data tampering (TLS, RBAC)
- Denial of Service (rate limiting, circuit breakers)
- Privilege escalation (network isolation, least privilege)

## Observability Enhancements

**Beyond Original Plan:**
- Statistical drift detection with z-scores
- Distribution analysis with KS tests
- Shadow scoring for calibration
- Comprehensive security event logging
- Forensic data retention

## Next Steps

Proceed with implementing the sub-phases in order:

1. **Phase 12a**: Build foundation (container, ingestion, basic aggregation)
2. **Phase 12b**: Add detection modules (campaign, slow scan, JA4)
3. **Phase 12c**: Implement monitoring (drift detection, dashboards)
4. **Phase 12d**: Security hardening (validation, rate limiting, forensics)

Each phase should be fully tested and documented before proceeding to the next.

## 12b. Event Ingestion

**Stream key:** `ja4proxy:events`  **Max length:** ~500k (trimmed automatically)

Proxy writes events as `asyncio.create_task(xadd(...))` — hot path never awaits.

Consumer group `analytics` — replays unprocessed events on restart (no data loss).

**Event format:** see Phase 2 (monitor mode) for the full event schema including
counterfactual fields.

## 12c. Analysis Modules

**12a. Cross-instance aggregation** — 5-minute rolling window per IP, /24 or /48,
ASN, country + action distributions. Written to `analytics:agg:*` (5min TTL).
Proxy reads as additional scorer inputs (+25 when cross-instance count elevated).

**12b. HyperLogLog per subnet** — unique IP count per /24 (IPv4) or /48 (IPv6).
`PFADD`/`PFCOUNT` — O(1), 12KB/key, ~0.81% error.

**12c. Campaign detection** — if subnet density > 0.15 AND block rate > 0.70:
campaign candidate. Written to `analytics:campaign:subnet:{subnet}` (TTL 3600).
Proxy reads as +35 risk signal.

**12d. Slow scan detection** — many IPs from same subnet, few requests each.
Invisible to per-IP rate limiting.
```python
if requests_per_ip < 3 and unique_ips > 20:
    score = min(1.0, unique_ips / 100)
```
Written to `analytics:slowscan:subnet:{subnet}` (TTL 1800). Proxy reads as +30.

**12e. JA4 fingerprint intelligence** — profile fingerprints across all instances.
Fingerprints appearing only in blocked connections → `analytics:ja4:candidates`.
Never auto-applied to blacklist — secops admin review only.

**12f. Centralised RDAP & AbuseIPDB** — when Phase 11/10 delegates enabled, proxy
publishes IPs to Redis Sets; analytics drains. Single rate-limit budget.

**12g. Hourly threat intel reports**
```
analytics:report:latest  → JSON (TTL 7200)
analytics:report:history → LIST of last 168 hourly reports
```

## 12h. Score Drift Detection

**Problem:** if a newly deployed signal module has a miscalibrated score multiplier,
or if an attack pattern changes so it no longer matches your signals, you won't notice
until someone complains — or until the Grafana blocking-readiness panel shows
something unexpected. You need an automated early warning.

**What to detect:**

1. *Upward drift* — baseline median risk score rises significantly above the 7-day
   norm. Could mean: new attack starting, signal module miscalibrated high, config
   change accidentally raised a score multiplier.

2. *Downward drift* — baseline drops well below norm. Could mean: signal module broken
   (silently returning 0), attack shifted to an evasion pattern, data feed went stale
   (Spamhaus didn't refresh, Tor list not updating).

3. *Distribution shift* — the shape of the score histogram changes even if the median
   is stable. A bimodal distribution (scores clustering at 0 and 80, nothing in
   between) suggests a binary signal is dominating when it shouldn't.

**Implementation:**

```python
# Run every analysis cycle (every 60s)
def check_score_drift(events_last_hour: list, baseline_7d: Stats) -> list[Alert]:
    current = compute_stats(events_last_hour)
    z_score = (current.median - baseline_7d.median) / baseline_7d.stddev
    if abs(z_score) > 2.0:
        return [Alert("score_drift", z_score, current.median, baseline_7d.median)]
    return []
```

**Redis keys:**
```
analytics:baseline:hourly:{YYYY-MM-DD-HH} → JSON stats snapshot  TTL: 604800 (7 days)
analytics:alerts:score_drift              → latest drift alert (TTL 3600, auto-clears)
```

**Prometheus:** `ja4proxy_analytics_score_drift_detected` gauge (0=normal, 1=drifting).
Alert on this metric in Alertmanager.

**Grafana panel:** "Score Health" — rolling 7-day median ± 1 stddev band, with current
1-hour median overlaid. Drift is visually obvious. Add to the analytics dashboard.

**Known-good shadow scoring:** h2/h1 ALPN browser traffic (always bypassed, never
scored) should have a stable, low shadow score. Track this separately as a calibration
signal — if it rises, a signal module is firing on traffic it shouldn't.

**Acceptance criteria additions:**
- [x] Hourly stats snapshots written to Redis with 7-day TTL
- [x] Z-score drift detection runs every analysis cycle
- [x] Alert written to `analytics:alerts:score_drift` when |z| > 2.0 (configurable)
- [x] Prometheus gauge: `ja4proxy_analytics_score_drift_detected` — 1 if score drift detected, else 0
- [x] Known-good shadow score tracked separately for h2/h1 ALPN traffic
- [x] Grafana "Score Health" panel added to analytics dashboard
- [x] Tests: drift detection algorithm
- [x] alert cleared when drift resolves
- [x] 
  shadow score computation

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `events:stream` | Redis Stream | Capped at stream_max_length entries | Proxy (all instances) | Connection events consumed by analytics node |
| `analytics:campaigns` | Hash `{campaign_id: JSON}` | none (no expiry) | Analytics node | Active detected campaigns |
| `analytics:slow_scan:{ip}` | Sorted Set of port/timestamps | 86400s (24h) | Analytics node | Slow scan accumulator per IP |
| `analytics:ja4_candidates` | Sorted Set `{member: ja4, score: count}` | none (no expiry) | Analytics node | JA4 fingerprints awaiting secops admin review |
| `analytics:baseline:hourly:{YYYY-MM-DD-HH}` | JSON stats | 604800s (7d) | Analytics node | Hourly score distribution for drift detection |
| `analytics:alerts:score_drift` | String (JSON alert) | 3600s (1h) | Analytics node | Current drift alert; auto-clears when resolved |
| `analytics:enrich:abuseipdb` | Set of IPs | none (no expiry) | Proxy (delegate mode) | AbuseIPDB enrichment queue when delegated |
| `analytics:enrich:rdap` | Set of IPs | none (no expiry) | Proxy (delegate mode) | RDAP enrichment queue when delegated |

## Config
```yaml
analytics_node:
  enabled: false
  stream_max_length: 500000
  batch_size: 500
  analysis_interval_seconds: 60
  modules:
    cross_instance_aggregation: true
    campaign_detection: true
    slow_scan_detection: true
    ja4_intelligence: true
    rdap_offload: false
    abuseipdb_offload: false
    report_generation: true
  campaign_detection:
    subnet_density_threshold: 0.15
    min_unique_ips: 10
    block_rate_threshold: 0.70
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Analytics container crashed | Proxy continues on stale campaign data; no scoring errors; `WARN analytics event=stream_lag_high` after 60s |
| Redis Stream reaches `stream_max_length` | Oldest events trimmed; consumer catches up; no crash |
| Consumer group restarted mid-batch | Unacknowledged events replayed; no events lost; no duplicate processing due to dedup |
| Analytics takes > `analysis_interval_seconds` to complete | Next cycle skipped; WARN logged; metric records cycle duration |

## Acceptance Criteria

### Functional
- [x] `Dockerfile.analytics` builds independently; no shared image layers with proxy container
- [x] Proxy `XADD` wrapped in `asyncio.create_task()`; hot path latency unaffected by stream writes
- [x] Consumer group replays unprocessed events on worker restart; no events lost
- [x] Cross-instance aggregation covers IPv4 /24 and IPv6 /48 subnets using HyperLogLog
- [x] Campaign and slow scan findings written to Redis; consumed by proxy scorer without restart
- [x] JA4 candidate list: secops admin review only; never auto-applied to blacklist
- [x] Analytics node crash: proxy continues on stale analytics data; no scoring errors
- [x] Hourly baseline snapshot written to `analytics:baseline:hourly:{YYYY-MM-DD-HH}`
- [x] Score drift detection: z-score > 2.0 from 7-day baseline → alert written and gauge set

### Configuration
- [x] `stream_max_length`, `batch_size`, `analysis_interval_seconds` configurable
- [x] Individual analytics modules toggled via `modules.*` config keys
- [x] All config values in this phase are hot-reloadable; changes apply to the next connection without restart

### Observability
- [x] Prometheus counter:   `ja4proxy_analytics_events_processed_total` — stream events consumed
- [x] Prometheus histogram: `ja4proxy_analytics_cycle_duration_seconds` — analytics cycle duration
- [x] Prometheus gauge:     `ja4proxy_analytics_stream_lag_seconds` — current Redis Stream consumer lag
- [x] Prometheus gauge:     `ja4proxy_analytics_score_drift_detected` — 1 if drift detected, else 0
- [x] Grafana: Analytics dashboard with stream lag, campaigns, top attacking subnets, JA4 candidates, Score Health panel

- [x] JSON log: `{"type":"system","level":"WARN","subsystem":"analytics","event":"stream_lag_elevated"}` emitted when lag exceeds 60s
- [x] JSON log: `{"type":"system","level":"WARN","subsystem":"analytics","event":"score_drift_detected"}` emitted with `z_score` and `baseline_median` when drift triggers

### Unit Tests  (`tests/unit/test_analytics_node.py`)
- [x] Consumer group replay: event written before restart is processed after restart
- [x] Campaign detection algorithm: cluster of IPs from same /24 within time window → campaign flagged
- [x] Campaign detection: IPv6 /48 subnets handled correctly
- [x] Slow scan detection: low-rate connections across many ports → slow scan flagged
- [x] `XADD` from proxy: non-blocking; does not add measurable latency to hot path
- [x] Score drift: current median deviates > 2σ from baseline → `check_score_drift()` returns alert

### Integration Tests  (`tests/integration/test_beaconing_pipeline.py`)
- [x] Proxy publishes connection event to Redis Stream → analytics node consumes within `analysis_interval_seconds`
- [x] Campaign detection result written to Redis → proxy scorer reads campaign signal on next connection
- [x] Consumer group restart: events published before restart are replayed; no events skipped

### Chaos Tests  (`tests/chaos/test_analytics_down.py`)
- [x] Analytics container stopped: proxy continues scoring; stale campaign data used; no errors
- [x] Stream lag > 300s: `ja4proxy_analytics_stream_lag_seconds` gauge reflects lag; WARN logged
