# Phase 9 — Beaconing Detection

## Goal

Detect Command-and-Control (C2) beacon patterns by analysing the timing of connections
from the same IP+JA4 fingerprint pair. Malware beacons home at regular intervals
(every 60s, every 5min, every hour) with remarkably consistent timing. Human browsing
is irregular. This distinction is mathematically measurable without inspecting any
content — purely from connection timestamps.

Zero external dependencies. Zero API calls. Uses the Sorted Set structure
established in Phase 0.

## 9a. Module: `src/security/beaconing_detector.py`

### 9a. The Statistical Foundation

**Inter-arrival time (IAT)** is the time gap between consecutive connections from the
same IP+JA4 pair. For a perfect beacon (e.g. C2 phone-home every 60 seconds), all
IATs are equal: `[60, 60, 60, 60, ...]`.

**Coefficient of Variation (CV)** measures the relative dispersion of a dataset:
```
CV = standard_deviation / mean
```

For perfect beacon: CV = 0.0 (no variation)
For jittered beacon (±10% randomisation, common in mature malware): CV ≈ 0.1–0.15
For human browsing: CV > 0.5 (highly irregular)

```python
import statistics

def coefficient_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return float('inf')  # Not enough data
    mean = statistics.mean(values)
    if mean == 0:
        return float('inf')
    stdev = statistics.stdev(values)
    return stdev / mean

def beacon_score(iats: list[float]) -> float:
    """
    Returns 0.0 (random/human) to 1.0 (highly regular = beacon).
    Never called with fewer than min_observations - 1 IATs.
    """
    cv = coefficient_of_variation(iats)
    if cv < 0.15:
        return 0.9   # Strong beacon
    elif cv < 0.40:
        return 0.5   # Moderate — could be periodic sync app
    elif cv < 0.70:
        return 0.2   # Somewhat regular — probably not malicious
    else:
        return 0.0   # Irregular — human-like
```

Risk contribution: `beacon_score * score_cap` (max 35 by default). See `score_cap` config key.

### 9b. Redis Sorted Set Per IP+JA4

Use the Sorted Set structure established in Phase 0. Score = timestamp float.

```python
async def record_connection(ip: str, ja4: str, timestamp: float) -> None:
    key = f"beacon:{ip}:{ja4}"
    uid = f"{timestamp:.6f}:{uuid.uuid4().hex[:8]}"  # Unique member

    async with redis.pipeline(transaction=False) as pipe:
        pipe.zadd(key, {uid: timestamp})
        pipe.zremrangebyscore(key, 0, timestamp - window_seconds)
        pipe.expire(key, window_seconds + 60)
        await pipe.execute()

async def get_timestamps(ip: str, ja4: str, window_seconds: int) -> list[float]:
    key = f"beacon:{ip}:{ja4}"
    now = time.time()
    members = await redis.zrangebyscore(
        key, now - window_seconds, now, withscores=True
    )
    return sorted([score for _, score in members])
```

The UUID suffix on member names prevents duplicate-timestamp collisions (two
connections in the same millisecond would otherwise overwrite each other in ZADD).

### 9c. IAT Computation from Timestamps

```python
def compute_iats(timestamps: list[float]) -> list[float]:
    """Convert sorted timestamp list to inter-arrival times."""
    if len(timestamps) < 2:
        return []
    return [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
```

Minimum IATs needed before scoring = `min_observations - 1`.
With `min_observations: 8`, need 7 IATs = 8 timestamps.

### 9d. Guards — Critical False Positive Prevention

**Guard 1: Minimum observations**
Never emit a beacon score with fewer than `min_observations` timestamps. A connection
that happens to occur twice in quick succession is not a beacon. With 8 required, the
probability of a false positive from coincidental timing is negligible.

**Guard 2: Never track ALPN whitelist IPs**
Browser IPs are in `LocalCache.whitelist_decisions` (Phase 0). Check this before
recording. Browsers make regular connections (keep-alive, prefetch, service workers) that
would produce false beacon scores.

```python
async def maybe_record(ip: str, ja4: str, alpn: str, action: str) -> None:
    # Guard 1: Never track browser ALPN
    if alpn in ("h2", "h1"):
        return
    # Guard 2: Skip already-whitelisted IPs
    if local_cache.whitelist_decisions.get(ip):
        return
    # Guard 3: Don't count connections that were themselves blocked
    # (blocked connections inflate apparent frequency, distorting CV)
    if action in ("block", "ban"):
        return
    await record_connection(ip, ja4, time.time())
```

**Guard 3: Exclude blocked connections from timing**
If every connection from an IP is being blocked, including those in the timing window
distorts the CV calculation. A bot that's being blocked on every attempt would appear
to beacon even if the blocking is working.

### 9e. Slow-burn Detection

Standard IAT analysis works well for C2 that beacons every 60 seconds to 30 minutes.
For C2 that beacons daily (e.g. some APT implants), the 1-hour window misses it.

Add a secondary long-window check:
```yaml
beaconing_detector:
  observation_window_seconds: 3600      # Primary: 1-hour window
  long_window_seconds: 86400            # Secondary: 24-hour window
  long_window_min_observations: 5       # Lower threshold (daily beacons are sparse)
  score: 20            # Lower score (less certainty)
```

Separate Redis key: `beacon:long:{ip}:{ja4}` — same structure, longer TTL.

### 9f. Integration with Beaconing Suspects List

Maintain a Redis Sorted Set of current suspected beaconers, scored by confidence:

```
beacon:suspects  →  Sorted Set {member: "ip:ja4", score: beacon_confidence}  TTL: none (no expiry)
```

This is consumed by:
- Phase 12 analytics node (cross-instance beaconing correlation)
- Phase 13 Management UI ("Beaconing Suspects" panel)

Update on each scored connection: `ZADD beacon:suspects {confidence} "{ip}:{ja4}"`
with TTL 3600s on each member (use score = last_seen timestamp for auto-eviction via
`ZREMRANGEBYSCORE ... -inf {cutoff}`).

---

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `beacon:{ip}:{ja4}` | Sorted Set (score=timestamp, member=uuid) | 3660s (1h + 60s buffer) | Proxy hot path | Short-window connection timestamps for IAT analysis |
| `beacon:long:{ip}:{ja4}` | Sorted Set (score=timestamp, member=uuid) | 86460s (24h + 1m buffer) | Proxy hot path | Long-window timestamps for slow-burn beaconing detection |
| `beacon:suspects` | Sorted Set (score=confidence, member=ip:ja4) | none (managed) | Beaconing detector | Current suspected beaconers; score is confidence 0–1 |

Add all to `docs/REDIS_SCHEMA.md`.

---

## Config

```yaml
beaconing_detector:
  enabled: true
  min_observations: 8              # Timestamps required before scoring
  window_size: 20                  # Max timestamps to keep per key
  cv_thresholds:
    strong_beacon: 0.15
    moderate_beacon: 0.40
    weak_signal: 0.70
  score: 35      # max contribution (multiplied by beacon_score 0–1)
  observation_window_seconds: 3600
  long_window:
    enabled: true
    window_seconds: 86400
    min_observations: 5
    score: 20
```

---

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Redis unavailable when recording | Skip recording silently; no beacon score emitted |
| Sorted Set evicted by `allkeys-lru` | Next connection has too few observations; no score (correct) |
| IP sends exactly `min_observations - 1` connections | No score emitted — minimum not met |
| Two connections same millisecond | UUID suffix prevents collision; both recorded |
| Beacon interval = 1 second (extremely fast) | Detected normally — CV still low |
| C2 with deliberate jitter >40% | CV >0.40; score ~0.5 (moderate) |

---

## Acceptance Criteria

### Functional
- [x] `beacon_score(iats: list[float]) -> float`: returns correct value for all CV ranges
- [x] `coefficient_of_variation(values)`: handles empty list, single value, all-equal values without error
- [x] Sorted Set per `{ip}:{ja4}` stores timestamps with UUID suffix as member; `window_size` trimming applied
- [x] Minimum observations guard: no signal emitted when fewer than `min_observations` timestamps present
- [x] Guard: h2/h1 ALPN connections never recorded in beaconing Sorted Set
- [x] Guard: IPs in Phase 0 whitelist LRU never recorded
- [x] Guard: blocked and banned connections excluded from timing records
- [x] Long-window secondary detection (24h) operates independently of short-window
- [x] `beacon:suspects` Sorted Set updated on every scored connection
- [x] Redis unavailable during record: fails silently; no crash; no signal emitted
- [x] Output: `RiskSignal(name="beaconing", score=N, reason="CV=X strength=Y")`

### Configuration
- [x] `cv_thresholds`, `score_cap`, `observation_window_seconds`, `min_observations` all configurable and hot-reloadable
- [x] Long window enabled/disabled independently via `long_window.enabled`

### Observability
- [x] Prometheus histogram: `ja4proxy_beaconing_score` — beacon score distribution; buckets [0,.1,.2,.3,.5,.7,.9,1]
- [x] Prometheus gauge:     `ja4proxy_beaconing_suspects` — current number of suspected beaconers
- [x] Prometheus counter:   `ja4proxy_beaconing_records_total` — connection timestamps recorded
- [x] `docs/REDIS_SCHEMA.md` updated with `beacon:{ip}:{ja4}`, `beacon:long:{ip}:{ja4}`, `beacon:suspects`

- [x] JSON log: beaconing signal appears in connection `signals` array as `{"name":"beaconing","score":N,"reason":"cv=0.12 over 47 observations"}` when emitted

### Unit Tests  (`tests/unit/test_beaconing_detector.py`)
- [x] `beacon_score()`: CV=0 (perfect beacon) → score=0.9
- [x] `beacon_score()`: CV=0.12 (jittered beacon) → score=0.9
- [x] `beacon_score()`: CV=0.25 (moderate) → score=0.5
- [x] `beacon_score()`: CV=0.55 (weak) → score=0.2
- [x] `beacon_score()`: CV=0.8 (human-like) → score=0.0
- [x] `beacon_score()`: empty IAT list → score=0.0 (not error)
- [x] `coefficient_of_variation()`: empty list → 0.0
- [x] `coefficient_of_variation()`: single value → 0.0
- [x] `coefficient_of_variation()`: all-equal values → 0.0
- [x] `maybe_record()`: h2 ALPN connection → not recorded
- [x] `maybe_record()`: whitelisted IP → not recorded
- [x] `maybe_record()`: blocked action → not recorded
- [x] `maybe_record()`: duplicate timestamp → UUID suffix prevents Sorted Set member collision
- [x] Signal not emitted when observations below `min_observations`

### Integration Tests  (`tests/integration/test_beaconing_pipeline.py`)
- [x] Simulated beaconing client (10 connections at 30s interval): `beacon_score` escalates to ≥ 0.9

### Chaos Tests  (`tests/chaos/test_redis_failure.py`)
- [x] Redis unavailable during `maybe_record()`: fails silently; no crash; no signal emitted
- [x] Sorted Set key evicted by `allkeys-lru`: next connection starts fresh; no error
