# Phase 12b — Advanced Detection Modules

## Goal
Implement sophisticated threat detection algorithms that operate across all proxy instances.

## Detection Modules

### 12b.1 Campaign Detection

**Algorithm:**
```python
def detect_campaign(subnet, window_data):
    density = window_data["unique_ips"] / subnet_size(subnet)
    block_rate = window_data["blocked_connections"] / window_data["total_connections"]
    
    if density > 0.15 and block_rate > 0.70:
        return {
            "subnet": subnet,
            "density": density,
            "block_rate": block_rate,
            "severity": "high"
        }
    return None
```

**Redis Storage:**
- Key: `analytics:campaign:{subnet}`
- Value: JSON with detection metadata
- TTL: 3600 seconds (1 hour)

**Scoring Impact:** +35 risk points when detected

### 12b.2 Slow Scan Detection

**Algorithm:**
```python
def detect_slow_scan(subnet, window_data):
    if (window_data["avg_requests_per_ip"] < 3 and 
        window_data["unique_ips"] > 20):
        score = min(1.0, window_data["unique_ips"] / 100)
        return {
            "subnet": subnet,
            "unique_ips": window_data["unique_ips"],
            "score": score
        }
    return None
```

**Redis Storage:**
- Key: `analytics:slowscan:{subnet}`
- Value: JSON with scan details
- TTL: 1800 seconds (30 minutes)

**Scoring Impact:** +30 risk points when detected

### 12b.3 JA4 Fingerprint Intelligence

**Fingerprint Profiling:**
- Track JA4 fingerprints across all instances
- Identify fingerprints appearing only in blocked connections
- Calculate prevalence and block rate per fingerprint

**Candidate Selection:**
```python
def identify_ja4_candidates(fingerprints):
    candidates = []
    for ja4, stats in fingerprints.items():
        if stats["total_seen"] > 10:  # Minimum observations
            if stats["block_rate"] > 0.95:  # High block rate
                if stats["only_in_blocks"]:  # Only seen in blocked connections
                    candidates.append({
                        "ja4": ja4,
                        "block_rate": stats["block_rate"],
                        "first_seen": stats["first_seen"],
                        "last_seen": stats["last_seen"]
                    })
    return sorted(candidates, key=lambda x: x["block_rate"], reverse=True)
```

**Redis Storage:**
- Key: `analytics:ja4:candidates`
- Value: Sorted set by block rate
- **Important**: Never auto-applied to blacklist
- Requires secops admin review before action

### 12b.4 Behavioral Clustering

**Time-based Clustering:**
```python
def cluster_behavioral_patterns(events):
    # Group by time windows and behavior patterns
    clusters = dbscan(
        events,
        eps=300,  # 5-minute windows
        min_samples=5,
        metric="behavioral_distance"
    )
    
    # Identify anomalous clusters
    anomalous = []
    for cluster_id, cluster_events in clusters.items():
        if is_anomalous(cluster_events):
            anomalous.append({
                "cluster_id": cluster_id,
                "events": len(cluster_events),
                "pattern": identify_pattern(cluster_events)
            })
    
    return anomalous
```

**Pattern Identification:**
- Port scanning patterns
- Credential stuffing attempts
- Exploitation attempts
- Data exfiltration patterns

## Module Configuration

```yaml
analytics_node:
  modules:
    campaign_detection:
      enabled: true
      subnet_density_threshold: 0.15
      block_rate_threshold: 0.70
      min_unique_ips: 10
    
    slow_scan_detection:
      enabled: true
      max_requests_per_ip: 3
      min_unique_ips: 20
      score_cap: 1.0
    
    ja4_intelligence:
      enabled: true
      min_observations: 10
      block_rate_threshold: 0.95
      max_candidates: 1000
    
    behavioral_clustering:
      enabled: false  # Experimental
      time_window_seconds: 300
      min_cluster_size: 5
```

## Integration with Proxy

**Real-time Updates:**
- Analytics node writes detection results to Redis
- Proxy instances poll for updates every 60 seconds
- Results cached locally with 5-minute TTL

**Scoring Integration:**
```python
# In proxy scorer
async def get_analytics_signals(ip):
    subnet = get_subnet(ip)
    
    # Check for campaign detection
    campaign = await redis.get(f"analytics:campaign:{subnet}")
    if campaign:
        score += 35
        signals.append("analytics_campaign")
    
    # Check for slow scan
    slow_scan = await redis.get(f"analytics:slowscan:{subnet}")
    if slow_scan:
        score += 30
        signals.append("analytics_slow_scan")
    
    return score, signals
```

## Performance Optimization

**Batch Processing:**
- Process events in batches of 500
- Parallel processing where possible
- Memory-efficient data structures

**Caching:**
- Cache frequent subnet lookups
- Cache JA4 fingerprint metadata
- LRU cache for recent calculations

## Acceptance Criteria

### Functional
- [ ] Campaign detection identifies coordinated attacks
- [ ] Slow scan detection catches distributed scanning
- [ ] JA4 intelligence identifies malicious fingerprints
- [ ] Detection results written to Redis with proper TTL
- [ ] Proxy integrates detection signals into scoring
- [ ] Behavioral clustering (experimental) implemented

### Performance
- [ ] Batch processing handles 500 events/second
- [ ] Memory usage < 500MB with 1M events
- [ ] Detection algorithms complete within analysis window
- [ ] Redis operations optimized (pipeline, batch)

### Integration
- [ ] Proxy successfully reads and applies analytics signals
- [ ] Signal caching works correctly
- [ ] Stale data handling graceful
- [ ] Multiple detection signals combine correctly

### Testing
- [ ] Unit tests: campaign detection algorithm
- [ ] Unit tests: slow scan detection
- [ ] Unit tests: JA4 candidate identification
- [ ] Integration test: detection → Redis → proxy scoring
- [ ] Performance test: 10K events with all modules enabled
- [ ] Chaos test: analytics node restart during detection

## Security Considerations

**Input Validation:**
- All detection inputs validated
- Numeric ranges checked
- String lengths limited

**Rate Limiting:**
- Detection algorithms time-boxed
- Memory limits enforced
- Circuit breakers for resource exhaustion

**Audit Logging:**
- Detection events logged
- False positives tracked
- Performance metrics recorded

## Next Steps
- Phase 12c: Score drift monitoring
- Phase 12d: Security hardening