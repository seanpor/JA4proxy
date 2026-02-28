# Phase 4 — SNI Analysis

## Goal

Extract high-signal anomalies from the TLS ClientHello SNI field.
Zero external dependencies. Zero rate limits. Immediate detection improvement.

## 4a. Module: `src/security/sni_analyzer.py`

### 4a. Missing SNI (+30)
Modern browsers always send SNI. Missing SNI signals malware, C2 clients, scanners.

### 4b. IP-literal SNI (+25)
SNI containing a raw IP address. Common in scanners; rare in legitimate traffic.

### 4c. DGA Detection (0–40)
Domain Generation Algorithm likelihood using:
- Shannon entropy of label (high entropy = suspicious)
- Consonant/vowel ratio (DGA domains are consonant-heavy)
- Label length (DGA domains tend to be long)
- Numeric sequence presence

```python
def dga_score(hostname: str) -> float:
    # Returns 0.0 (clean) to 1.0 (likely DGA)
    # Deterministic and fast — no ML models
    # Must achieve < 1% FP rate on Tranco top 10k (verified by corpus test)
```

Risk contribution: `dga_score * 40` (max 40).

### 4d. Unexpected Hostname (+15)
If `expected_hostnames` is configured, flag SNI not in list. Catches scanners
probing your IP for other services.

## Redis Key Schema

Phase 4 adds no new Redis keys. SNI analysis is in-process only.

## Config

```yaml
sni_analyzer:
  enabled: true
  missing_sni:
    enabled: true
    score: 30              # Risk score when TLS ClientHello has no SNI extension. Default: 30.
  ip_literal_sni:
    enabled: true
    score: 25              # Risk score when SNI contains a raw IP address. Default: 25.
  dga_detection:
    enabled: true
    entropy_threshold: 3.8
    score_cap: 40
  expected_hostnames: []
  score: 15
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| SNI extension absent entirely | `missing_sni` signal emitted; no crash |
| SNI contains null bytes | Parsed safely; treated as ip_literal or flagged; no crash |
| SNI length > 253 characters | Truncated or treated as malformed; no crash |
| DGA model file missing at startup | FATAL error logged with file path; process exits cleanly |
| Config reload changes `expected_hostnames` | New list applies to next connection; no restart |

## Acceptance Criteria

### Functional
- [ ] `SNIAnalyzer.analyze(sni: str | None) -> list[RiskSignal]`
- [ ] Missing SNI (`None`): `RiskSignal(name="missing_sni")` with configured score
- [ ] IP-literal SNI (e.g. `192.168.1.1`): `RiskSignal(name="ip_literal_sni")` with configured score
- [ ] DGA detection: confidence 0–1 scaled by `score_cap`; `RiskSignal(name="dga")` emitted
- [ ] Expected hostname mismatch: `RiskSignal(name="unexpected_sni")` when configured list is non-empty
- [ ] All outputs are `RiskSignal` objects consumed by Phase 1 scorer
- [ ] SNI value never logged in cleartext (privacy)

### Configuration
- [ ] All score values and `score_cap` loaded from config; hot reload applies
- [ ] `expected_hostnames: []` disables hostname mismatch check (no signal emitted)

### Observability
- [ ] Prometheus counter:   `ja4proxy_sni_signal_total{signal}` — fires per signal name
- [ ] Prometheus histogram: `ja4proxy_sni_dga_score` — DGA confidence score distribution

### Unit Tests  (`tests/unit/test_sni_analyzer.py`)
- [ ] `SNIAnalyzer.analyze()`: None → missing_sni signal
- [ ] `SNIAnalyzer.analyze()`: valid hostname → no signal
- [ ] `SNIAnalyzer.analyze()`: IP string → ip_literal_sni signal
- [ ] `SNIAnalyzer.analyze()`: known DGA hostname → dga signal with score > 0
- [ ] `SNIAnalyzer.analyze()`: Tranco top-10 hostname → dga score near 0
- [ ] `SNIAnalyzer.analyze()`: hostname in `expected_hostnames` → no unexpected_sni signal
- [ ] `SNIAnalyzer.analyze()`: hostname not in `expected_hostnames` → unexpected_sni signal
- [ ] `SNIAnalyzer.analyze()`: `expected_hostnames: []` → no unexpected_sni signal regardless of SNI
- [ ] DGA score capped at `score_cap`; does not exceed 100

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [ ] Full pipeline with valid browser SNI (e.g. `www.google.com`) → no SNI signals emitted
- [ ] Full pipeline with `sni=None` → `missing_sni` signal reaches scorer; score elevated
- [ ] Hot reload changes `expected_hostnames` list → next connection applies new list; no restart

### Chaos Tests  (`tests/chaos/test_redis_failure.py`)
- [ ] Redis unavailable: SNI analysis runs in-process; no Redis dependency; no crash

### False-Positive Tests  (`tests/fp_corpus/test_dga_fp_rate.py`)
- [ ] DGA scorer: Tranco top 10k domains — FP rate < 1% (known-good domains not flagged)
- [ ] DGA scorer: known DGA families (Conficker, Mirai) — detection rate > 95%
