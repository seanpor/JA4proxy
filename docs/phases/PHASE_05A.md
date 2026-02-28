# Phase 5a — TCP & Connection Behavior Implementation Plan

## Current Status Analysis

### What's Complete
- ✅ Phase 0-4a foundation (pipeline, scoring, SNI analysis)
- ✅ Redis infrastructure for rate tracking
- ✅ Prometheus metrics framework
- ✅ Configuration hot reload system

### What's Needed for Phase 5
- ❌ `src/security/tcp_analyzer.py` - TCP behavior analysis
- ❌ `src/security/mtls.py` - mTLS client certificate handling
- ❌ PROXY protocol integration for JA4T extraction
- ❌ Redis schema extensions for new tracking keys
- ❌ Pipeline integration for TCP signals
- ❌ Comprehensive testing suite

## Phase 5a Implementation Plan

### Step 1: Create TCP Analyzer (`src/security/tcp_analyzer.py`)

```python
class TCPAnalyzer:
    def __init__(self, config: dict, redis_client: object):
        # Initialize all 6 detection modules
        self._ja4t_mismatch_score = config.get("tcp_analyzer", {}).get("tcp_fingerprinting", {}).get("score", 30)
        self._no_resumption_score = config.get("tcp_analyzer", {}).get("session_resumption", {}).get("score", 15)
        # ... other configurations
        self._redis = redis_client

    def analyze(self, ctx: ConnectionContext) -> list[RiskSignal]:
        signals = []
        
        # 1. JA4T fingerprinting
        if self._ja4t_enabled:
            signals.extend(self._check_ja4t_mismatch(ctx))
        
        # 2. Session resumption
        if self._resumption_enabled:
            signals.extend(self._check_session_resumption(ctx))
        
        # 3. Connection lifespan
        if self._lifespan_enabled:
            signals.extend(self._check_connection_lifespan(ctx))
        
        # 4. Concurrent connections
        if self._concurrent_enabled:
            signals.extend(self._check_concurrent_connections(ctx))
        
        # 5. Return visitor trust
        if self._return_visitor_enabled:
            signals.extend(self._check_return_visitor(ctx))
        
        # 6. TLS alerts
        if self._tls_alerts_enabled:
            signals.extend(self._check_tls_alerts(ctx))
        
        return signals
```

### Step 2: Create mTLS Handler (`src/security/mtls.py`)

```python
class MTLSHandler:
    def __init__(self, config: dict):
        self._enabled = config.get("mtls", {}).get("enabled", False)
        self._ca_cert_path = config.get("mtls", {}).get("ca_cert_path")
        self._require_client_cert = config.get("mtls", {}).get("require_client_cert", False)
        self._cert_cn_allowlist = set(config.get("mtls", {}).get("cert_cn_allowlist", []))
        self._ca_cert = self._load_ca_cert() if self._enabled else None

    def verify_client_cert(self, ctx: ConnectionContext) -> bool:
        """Return True if client cert is valid and should bypass scoring."""
        if not self._enabled or not ctx.has_valid_client_cert:
            return False
        
        # Verify cert against CA
        # Check CN against allowlist if specified
        # Return True if valid and should bypass
        return True
```

### Step 3: Update Pipeline Integration

```python
# In src/security/pipeline.py

# Add imports
from .tcp_analyzer import TCPAnalyzer
from .mtls import MTLSHandler

# Update __init__
def __init__(self, config, local_cache, redis_client):
    # ... existing code
    self._tcp_analyzer = TCPAnalyzer(config, redis_client)
    self._mtls_handler = MTLSHandler(config)

# Update _check_allow_bypasses to include mTLS
if self._mtls_handler.verify_client_cert(ctx):
    return PipelineResult(action="allow", score=0, signals=[], 
                        bypass="mtls", dial=self._cache.dial)

# Update _collect_signals to include TCP signals
signals.extend(self._tcp_analyzer.analyze(ctx))
```

### Step 4: Update ConnectionContext

```python
# Add TCP-level fields to ConnectionContext
tcp_ja4t: str = ""  # JA4T fingerprint from PROXY protocol
tcp_window_size: int = 0
tcp_ttl: int = 0
tcp_options: str = ""
connection_lifespan_ms: int = 0
tls_alerts: list[str] = field(default_factory=list)
```

### Step 5: Create Unit Tests

```python
# tests/unit/security/test_tcp_analyzer.py
class TestTCPAnalyzer:
    def test_ja4t_mismatch_signal(self):
        # Test OS fingerprint mismatch detection
        pass
    
    def test_session_resumption_signal(self):
        # Test zero resumption rate detection
        pass
    
    def test_connection_lifespan_signal(self):
        # Test short-lived connection detection
        pass
    
    def test_concurrent_connections_signal(self):
        # Test high concurrency detection
        pass
    
    def test_return_visitor_trust(self):
        # Test score reduction for trusted visitors
        pass
    
    def test_tls_alert_rate_signal(self):
        # Test excessive TLS alert detection
        pass

# tests/unit/security/test_mtls.py
class TestMTLSHandler:
    def test_valid_cert_bypass(self):
        # Test valid cert allows bypass
        pass
    
    def test_invalid_cert_rejected(self):
        # Test invalid cert handling
        pass
    
    def test_cn_allowlist_enforcement(self):
        # Test CN allowlist filtering
        pass
```

### Step 6: Create Integration Tests

```python
# tests/integration/test_tcp_pipeline.py
class TestTCPPipelineIntegration:
    async def test_mtls_bypass(self):
        # Test mTLS bypass in full pipeline
        pass
    
    async def test_tcp_signals_in_pipeline(self):
        # Test TCP signals affect scoring
        pass
    
    async def test_concurrent_counter_no_leak(self):
        # Test connection counter cleanup
        pass
```

### Step 7: Create Chaos Tests

```python
# tests/chaos/test_tcp_chaos.py
class TestTCPAnalyzerChaos:
    def test_redis_failure_during_counter_incr(self):
        # Test graceful degradation
        pass
    
    def test_abrupt_disconnect_counter_leak(self):
        # Test counter cleanup on disconnect
        pass
```

### Step 8: Update Configuration

```yaml
# Add to config/proxy.yml
tcp_analyzer:
  enabled: true
  tcp_fingerprinting:
    enabled: true
    score: 30
  session_resumption:
    enabled: true
    min_connections: 10
    score: 15
  connection_lifespan:
    enabled: true
    threshold_ms: 500
    min_connections: 5
    score: 20
  concurrent_connections:
    enabled: true
    thresholds: { moderate: 20, high: 50, severe: 100 }
    risk_scores: { moderate: 10, high: 25, severe: 40 }
  return_visitor:
    enabled: true
    trusted_days: 7
    trusted_allow_rate: 0.90
    score_reduction_pct: 20
  tls_alerts:
    enabled: true
    rate_threshold: 5
    score: 20

mtls:
  enabled: false
  ca_cert_path: "config/trusted_cas.pem"
  require_client_cert: false
  cert_cn_allowlist: []
```

### Step 9: Update Documentation

```markdown
# Add to docs/REDIS_SCHEMA.md

## Phase 5 Keys

### TCP Analyzer
- `session:ip:{ip}:ja4:{ja4}` - Hash {total, resumed} TTL: 3600s
- `lifespan:{ip}` - Sorted Set of durations TTL: 1800s
- `concurrent:{ip}` - Integer counter TTL: 60s
- `visitor:{ip}` - Hash {first_seen, last_seen, total, allowed, blocked} TTL: 604800s

### mTLS
- No additional Redis keys (in-process verification)
```

## Implementation Timeline

### Week 1: Core Implementation
- ✅ TCP analyzer skeleton
- ✅ JA4T fingerprinting module
- ✅ Session resumption tracking
- ✅ Connection lifespan analysis
- ✅ Basic unit tests

### Week 2: Advanced Features
- ✅ Concurrent connection tracking
- ✅ Return visitor trust system
- ✅ TLS alert monitoring
- ✅ mTLS handler implementation
- ✅ Pipeline integration

### Week 3: Testing & Validation
- ✅ Complete unit test suite
- ✅ Integration tests
- ✅ Chaos/resilience tests
- ✅ Performance benchmarking
- ✅ Documentation

## Acceptance Criteria

### Functional
- [ ] TCPAnalyzer.analyze() returns all 6 signal types
- [ ] mTLSHandler.verify_client_cert() works with real certificates
- [ ] All signals properly scored and weighted
- [ ] Trust reduction never makes score negative

### Testing
- [ ] 100% unit test coverage for new modules
- [ ] Integration tests with full pipeline
- [ ] Chaos tests for Redis failure scenarios
- [ ] Performance tests (target: < 1ms impact)

### Documentation
- [ ] Updated Redis schema
- [ ] Operational testing guide
- [ ] Configuration reference
- [ ] Troubleshooting section

## Risk Assessment

### High Risk
- **PROXY protocol dependency**: JA4T requires PROXY protocol v2
- **Mitigation**: Document limitation, provide fallback behavior

### Medium Risk
- **Redis load**: Additional keys may increase Redis pressure
- **Mitigation**: Use appropriate TTLs, monitor Redis performance

### Low Risk
- **mTLS complexity**: Certificate management
- **Mitigation**: Clear documentation, error handling

## Success Metrics

- **Test coverage**: 100% for new modules
- **Performance**: < 1ms latency impact
- **Detection rate**: > 90% for scanner/probe traffic
- **False positives**: < 5% on legitimate traffic
- **Redis efficiency**: < 10% increase in Redis operations

## Rollback Plan

If issues arise:
1. Disable tcp_analyzer in config: `tcp_analyzer.enabled: false`
2. Disable mTLS: `mtls.enabled: false`
3. Hot reload: `kill -HUP <proxy_pid>`
4. Monitor metrics for stabilization

## Next Steps

1. **Immediate**: Implement TCP analyzer core modules
2. **Short-term**: Add mTLS support and pipeline integration
3. **Long-term**: Monitor detection rates, adjust thresholds

## Resources Required

- **Development**: 3 weeks engineering time
- **Testing**: 1 week QA time
- **Documentation**: 3 days technical writing
- **Dependencies**: None (uses existing Redis, Prometheus)

## Success Criteria

Phase 5a is complete when:
- ✅ All TCP signals working in production
- ✅ mTLS bypass operational
- ✅ 100% test coverage achieved
- ✅ Documentation complete
- ✅ No performance regression
- ✅ Observability fully instrumented
