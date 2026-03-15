# Phase 12b — Advanced Detection Modules

## Status: MOSTLY DONE — proxy scorer integration is the critical missing piece

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

## Critical Gap: Proxy Scorer Does Not Read Analytics Signals

The analytics node writes campaign and slow-scan findings to Redis. The proxy
`risk_scorer.py` never reads them. The entire value of Phase 12b depends on
fixing this.

**Required addition to `src/security/risk_scorer.py`** (or `pipeline.py`):

```python
async def _get_analytics_signals(self, ip: str) -> list[RiskSignal]:
    """Read cross-instance analytics findings for this connection's subnet."""
    signals: list[RiskSignal] = []
    subnet4 = _to_cidr24(ip)   # e.g. "192.0.2.0/24"
    subnet6 = _to_cidr48(ip)   # e.g. "2001:db8::/48"
    subnet = subnet6 if ":" in ip else subnet4

    try:
        campaign = await self._redis.get(f"analytics:campaign:{subnet}")
        if campaign:
            signals.append(RiskSignal(
                source="analytics_campaign", score=35,
                detail=f"subnet {subnet} in active campaign"
            ))

        slowscan = await self._redis.get(f"analytics:slowscan:{subnet}")
        if slowscan:
            signals.append(RiskSignal(
                source="analytics_slowscan", score=30,
                detail=f"subnet {subnet} slow-scan pattern"
            ))
    except Exception as exc:
        # Fail open — analytics unavailable must never affect scoring
        logger.debug("analytics_signals | event=read_failed | error=%s", exc)

    return signals
```

Call this from `_collect_signals()` (fire-and-forget is fine; it can be
`await`-ed since the hot path already awaits signal collection).

Results must be cached locally with a short TTL (e.g. 60s) to avoid one
Redis round-trip per connection.

---

## Acceptance Criteria

### Detection algorithms
- [x] Campaign detection identifies coordinated attacks
- [x] Slow scan detection catches distributed scanning
- [x] JA4 intelligence identifies malicious fingerprints
- [x] Detection results written to Redis with correct TTLs
- [ ] Proxy reads and applies campaign signal (+35) into scoring
- [ ] Proxy reads and applies slow-scan signal (+30) into scoring
- [ ] Local cache (≤60s TTL) avoids per-connection Redis reads for analytics signals

### Integration
- [ ] End-to-end: campaign written by analytics → proxy scores connection higher
- [ ] Fail open: analytics Redis keys missing → zero signals, no error

### Testing
- [x] Unit tests: campaign detection algorithm (in test_detection.py)
- [x] Unit tests: slow scan detection (in test_detection.py)
- [x] Unit tests: JA4 candidate identification (in test_detection.py)
- [ ] Integration test: analytics signal → proxy scoring pipeline
- [ ] Chaos test: analytics node down — proxy scorer returns zero analytics signals, no exception

### Out of scope for Phase 12b
- Behavioral clustering (DBSCAN) — experimental, no concrete use case yet
- Per-connection Redis round-trips without caching — use local cache

## Next Steps
- Fix proxy scorer integration first (blocking acceptance)
- Then Phase 12c (drift monitoring — also mostly done)
