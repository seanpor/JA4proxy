# Phase 12 — Analytics Node

## Goal
Separate Docker container. Consumes events from all proxy instances via Redis Streams.
Performs cross-instance statistical analysis invisible per-node.
Publishes enriched findings back for all proxy instances to use.

The key insight: 200 req/s distributed across 8 proxy nodes = 25 req/s per node
(below every rate limit). The analytics node sees 200 req/s.

## 12a. Container: `analytics/`

Stays Python. Uses numpy, pandas, scipy — must NOT share layers with proxy container.

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
- [ ] Hourly stats snapshots written to Redis with 7-day TTL
- [ ] Z-score drift detection runs every analysis cycle
- [ ] Alert written to `analytics:alerts:score_drift` when |z| > 2.0 (configurable)
- [ ] Prometheus gauge: `ja4proxy_analytics_score_drift_detected` — 1 if score drift detected, else 0
- [ ] Known-good shadow score tracked separately for h2/h1 ALPN traffic
- [ ] Grafana "Score Health" panel added to analytics dashboard
- [ ] Tests: drift detection algorithm
- [ ] alert cleared when drift resolves
- [ ] 
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
- [ ] `Dockerfile.analytics` builds independently; no shared image layers with proxy container
- [ ] Proxy `XADD` wrapped in `asyncio.create_task()`; hot path latency unaffected by stream writes
- [ ] Consumer group replays unprocessed events on worker restart; no events lost
- [ ] Cross-instance aggregation covers IPv4 /24 and IPv6 /48 subnets using HyperLogLog
- [ ] Campaign and slow scan findings written to Redis; consumed by proxy scorer without restart
- [ ] JA4 candidate list: secops admin review only; never auto-applied to blacklist
- [ ] Analytics node crash: proxy continues on stale analytics data; no scoring errors
- [ ] Hourly baseline snapshot written to `analytics:baseline:hourly:{YYYY-MM-DD-HH}`
- [ ] Score drift detection: z-score > 2.0 from 7-day baseline → alert written and gauge set

### Configuration
- [ ] `stream_max_length`, `batch_size`, `analysis_interval_seconds` configurable
- [ ] Individual analytics modules toggled via `modules.*` config keys
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart

### Observability
- [ ] Prometheus counter:   `ja4proxy_analytics_events_processed_total` — stream events consumed
- [ ] Prometheus histogram: `ja4proxy_analytics_cycle_duration_seconds` — analytics cycle duration
- [ ] Prometheus gauge:     `ja4proxy_analytics_stream_lag_seconds` — current Redis Stream consumer lag
- [ ] Prometheus gauge:     `ja4proxy_analytics_score_drift_detected` — 1 if drift detected, else 0
- [ ] Grafana: Analytics dashboard with stream lag, campaigns, top attacking subnets, JA4 candidates, Score Health panel

- [ ] JSON log: `{"type":"system","level":"WARN","subsystem":"analytics","event":"stream_lag_elevated"}` emitted when lag exceeds 60s
- [ ] JSON log: `{"type":"system","level":"WARN","subsystem":"analytics","event":"score_drift_detected"}` emitted with `z_score` and `baseline_median` when drift triggers

### Unit Tests  (`tests/unit/test_analytics_node.py`)
- [ ] Consumer group replay: event written before restart is processed after restart
- [ ] Campaign detection algorithm: cluster of IPs from same /24 within time window → campaign flagged
- [ ] Campaign detection: IPv6 /48 subnets handled correctly
- [ ] Slow scan detection: low-rate connections across many ports → slow scan flagged
- [ ] `XADD` from proxy: non-blocking; does not add measurable latency to hot path
- [ ] Score drift: current median deviates > 2σ from baseline → `check_score_drift()` returns alert

### Integration Tests  (`tests/integration/test_beaconing_pipeline.py`)
- [ ] Proxy publishes connection event to Redis Stream → analytics node consumes within `analysis_interval_seconds`
- [ ] Campaign detection result written to Redis → proxy scorer reads campaign signal on next connection
- [ ] Consumer group restart: events published before restart are replayed; no events skipped

### Chaos Tests  (`tests/chaos/test_analytics_down.py`)
- [ ] Analytics container stopped: proxy continues scoring; stale campaign data used; no errors
- [ ] Stream lag > 300s: `ja4proxy_analytics_stream_lag_seconds` gauge reflects lag; WARN logged
