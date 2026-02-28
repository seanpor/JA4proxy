# Phase 4a — SNI Analysis Implementation & Testing

## Current Status Analysis

### What's Complete
- ✅ `src/security/sni_analyzer.py` - Full implementation with all 4 detection modules
- ✅ `proxy.py` - SNI parsing from TLS ClientHello (Phase 4 fields added)
- ✅ Core DGA detection algorithm with entropy analysis
- ✅ Prometheus metrics integration
- ✅ Configuration structure in `config/proxy.yml`

### What's Missing
- ❌ **Unit tests** - No `test_sni_analyzer.py` exists
- ❌ **Integration tests** - No pipeline integration tests for SNI signals
- ❌ **False-positive corpus tests** - No Tranco top-10k DGA FP rate validation
- ❌ **Chaos tests** - No Redis failure scenarios for SNI analysis
- ❌ **Pipeline integration** - SNIAnalyzer not wired into SecurityPipeline
- ❌ **Configuration validation** - No schema validation for sni_analyzer config
- ❌ **Documentation updates** - Missing operational docs and examples

## Phase 4a Plan

### Step 1: Create Unit Tests (`tests/unit/security/test_sni_analyzer.py`)

```python
# Test coverage needed:
- test_missing_sni_returns_signal()
- test_ip_literal_sni_returns_signal()
- test_dga_detection_known_dga()
- test_dga_detection_tranco_clean()
- test_unexpected_hostname_signal()
- test_empty_expected_hostnames_no_signal()
- test_config_hot_reload()
- test_dga_score_capping()
- test_privacy_no_sni_in_reason()
```

### Step 2: Create Integration Tests (`tests/integration/test_pipeline.py`)

```python
# Integration scenarios:
- test_pipeline_with_missing_sni()
- test_pipeline_with_ip_literal_sni()
- test_pipeline_with_dga_sni()
- test_pipeline_with_expected_hostname()
- test_pipeline_config_reload()
```

### Step 3: Create False-Positive Corpus Tests

```python
# Create tests/fp_corpus/test_dga_fp_rate.py
- Download Tranco top 10k domains
- Test DGA FP rate < 1%
- Test known DGA families detection > 95%
- Create test corpus in tests/fp_corpus/corpus/
```

### Step 4: Wire SNIAnalyzer into SecurityPipeline

```python
# In src/security/pipeline.py:
1. Add sni_analyzer to __init__
2. Call analyzer.analyze(ctx.sni) in process()
3. Merge signals into ctx.risk_signals
```

### Step 5: Create Chaos Tests

```python
# In tests/chaos/test_redis_failure.py:
- test_sni_analysis_without_redis()
- test_config_reload_during_sni_analysis()
```

### Step 6: Update Configuration Validation

```python
# In src/config/loader.py:
- Add sni_analyzer schema validation
- Validate score ranges (0-100)
- Validate entropy_threshold range
```

### Step 7: Update Documentation

```markdown
# Operational Documentation
- Add SNI analysis examples to SECURITY_TESTING.md
- Update POC_QUICKSTART.md with SNI testing
- Create SNI_ANALYSIS.md with real-world examples
- Update REDIS_SCHEMA.md with SNI metrics
```

### Step 8: Create Test Data

```bash
# Create test fixtures:
- tests/fixtures/sni_samples.json
- tests/fixtures/dga_corpus.txt
- tests/fixtures/tranco_top_100.txt
```

## Implementation Timeline

### Day 1: Core Testing
- ✅ Create unit tests (8 test methods)
- ✅ Create integration tests (5 scenarios)
- ✅ Wire into pipeline
- ✅ Basic validation

### Day 2: Advanced Testing
- ✅ False-positive corpus tests
- ✅ Chaos tests
- ✅ Configuration validation
- ✅ Test data fixtures

### Day 3: Documentation & Validation
- ✅ Update operational docs
- ✅ Create examples
- ✅ Run full test suite
- ✅ Validate 100% coverage

## Acceptance Criteria

### Functional
- [ ] SNIAnalyzer fully integrated into SecurityPipeline
- [ ] All 4 signal types working in production flow
- [ ] Configuration hot reload working
- [ ] Privacy: no raw SNI in logs or metrics

### Testing
- [ ] 100% unit test coverage for sni_analyzer.py
- [ ] Integration tests passing
- [ ] False-positive rate < 1% on Tranco corpus
- [ ] Chaos tests passing
- [ ] All tests pass in CI/CD

### Documentation
- [ ] SNI analysis operational guide
- [ ] Testing examples
- [ ] Configuration reference
- [ ] Troubleshooting guide

### Observability
- [ ] Prometheus metrics working
- [ ] Grafana dashboard updated
- [ ] Alerting rules configured

## Risk Assessment

### High Risk
- **False positives**: DGA detection flagging legitimate domains
- **Mitigation**: Comprehensive corpus testing, <1% FP requirement

### Medium Risk
- **Performance impact**: SNI analysis adding latency
- **Mitigation**: Benchmark before/after, optimize hot paths

### Low Risk
- **Configuration errors**: Invalid score ranges
- **Mitigation**: Schema validation, sensible defaults

## Success Metrics

- **Test coverage**: 100% for sni_analyzer.py
- **False positive rate**: < 1% on Tranco top 10k
- **Detection rate**: > 95% on known DGA families
- **Performance**: < 1ms added latency per request
- **Documentation**: Complete operational guide

## Rollback Plan

If issues arise:
1. Disable sni_analyzer in config: `sni_analyzer.enabled: false`
2. Hot reload config: `kill -HUP <proxy_pid>`
3. Monitor metrics for stabilization
4. Fix issues and redeploy

## Next Steps

1. **Immediate**: Create test files and implement tests
2. **Short-term**: Wire into pipeline and validate
3. **Long-term**: Monitor FP rate in production, adjust thresholds
