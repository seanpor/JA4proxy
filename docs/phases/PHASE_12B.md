# Phase 12b — Advanced Detection Modules

## Status: COMPLETE (2026-03-15)

Detection algorithms exist in `src/analytics/detection.py` and pass 13 tests.
The signals are written to Redis but the proxy scorer never reads them — they
produce no effect on blocking decisions until that wiring is added.

---

## What Is Already Implemented

### Campaign Detection (`detection.py` — `CampaignDetector`)
- Algorithm: `density > 0.15 AND block_rate > 0.70` ✓
- Written to `analytics:campaign:{subnet}` (TTL 3600s) ✓
- IPv4 /24 and IPv6 /48 subnet handling ✓

### Slow Scan Detection (`detection.py` — `SlowScanDetector`)
- Algorithm: `avg_requests_per_ip < 3 AND unique_ips > 20` ✓
- Written to `analytics:slowscan:{subnet}` (TTL 1800s) ✓

### JA4 Fingerprint Intelligence (`detection.py` — `JA4FingerprintIntelligence`)
- Profiles JA4 fingerprints across all proxy instances ✓
- Candidates written to `analytics:ja4:candidates` sorted set ✓
- **Never auto-applied to blacklist** — secops admin review only ✓
- Known bug: `get_subnet_stats()` references `self.subnet_data` which doesn't
  exist in this class (copy-paste error). Method is dead code — fix when encountered.

### Behavioral Clustering (12b.4)
Pseudo-code using DBSCAN exists but is not implemented. This section is marked
**experimental / out of scope** for Phase 12b. Remove the skeleton or keep it
disabled. Do not implement until there is a clear use case.

---

## Proxy Scorer Integration — DONE (2026-03-15)

`Pipeline._get_analytics_signals(ip)` added to `src/security/pipeline.py`:
- Computes subnet: IPv4 /24 or IPv6 /48
- Checks `LocalCache.analytics_signals` (60s TTL) before hitting Redis
- Reads `analytics:campaign:{subnet}` → `RiskSignal("analytics_campaign", +35)`
- Reads `analytics:slowscan:{subnet}` → `RiskSignal("analytics_slowscan", +30)`
- Fails open on any Redis exception; does not cache partial results on error
- Called at end of `_collect_signals()` as Phase 12 block
- Prometheus counter: `ja4proxy_analytics_signals_total{signal_type}`

`LocalCache.analytics_signals` LRU cache added (10k entries, 60s TTL, configurable).

---

## Acceptance Criteria

### Detection algorithms
- [x] Campaign detection identifies coordinated attacks
- [x] Slow scan detection catches distributed scanning
- [x] JA4 intelligence identifies malicious fingerprints
- [x] Detection results written to Redis with correct TTLs
- [x] Proxy reads and applies campaign signal (+35) into scoring
- [x] Proxy reads and applies slow-scan signal (+30) into scoring
- [x] Local cache (60s TTL) avoids per-connection Redis reads for analytics signals

### Integration
- [x] End-to-end: campaign written by analytics → proxy scores connection higher
- [x] Fail open: analytics Redis keys missing → zero signals, no error

### Testing
- [x] Unit tests: campaign detection algorithm (in test_detection.py)
- [x] Unit tests: slow scan detection (in test_detection.py)
- [x] Unit tests: JA4 candidate identification (in test_detection.py)
- [x] Unit tests: proxy signal reader (tests/unit/test_analytics_signals.py — 14 tests)
- [x] Chaos tests: analytics node down (tests/chaos/test_analytics_down.py — 11 tests)

### Out of scope for Phase 12b
- Behavioral clustering (DBSCAN) — experimental, no concrete use case yet
