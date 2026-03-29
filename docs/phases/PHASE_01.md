# Phase 1 — Composite Risk Scorer Scaffold

Status: COMPLETE

## Goal

Build the **empty scoring framework** before adding any signals. All subsequent phases
output `RiskSignal` objects — the scaffold ensures they all have a consistent integration
point from day one. Build this before adding any signals so integration is clean.

## 1a. Module: `src/security/risk_scorer.py`

```python
@dataclass
class RiskSignal:
    name: str           # "abuseipdb", "missing_sni", "spamhaus_drop", etc.
    score: int          # 0–100 contribution
    reason: str         # Human-readable; shown in logs and UI
    weight: float = 1.0

@dataclass
class RiskAssessment:
    total_score: int            # Clamped 0–100
    signals: list[RiskSignal]   # All contributing signals
    recommended_action: str     # allow|flag|rate_limit|tarpit|block|ban
    explanation: str            # Top 3 signals as string for log output

class RiskScorer:
    def score(self, signals: list[RiskSignal]) -> RiskAssessment:
        ...
```

## 1b. Bypass Conditions (Configurable — See `security_policy` in CLAUDE.md)

These run before the scorer. If any active bypass matches, scorer is not called.
Which bypasses are active is determined entirely by `security_policy` config.

The scorer scaffold must be written to work correctly regardless of which bypasses
are enabled or disabled:
- If all ALLOW bypasses are disabled: h2/h1 ALPN traffic goes through scorer (it
  will likely score near 0, but it must not crash)
- If all BLOCK bypasses are disabled: known-bad JA4 traffic goes through scorer
  (it should score high enough to block via dial, but this is not guaranteed)

The scorer itself has no knowledge of bypass state. It scores whatever it receives.

## 1c. Configurable Thresholds

```yaml
risk_scorer:
  enabled: true
  thresholds:
    flag:       20    # Elevated logging, connection allowed
    rate_limit: 35    # Stricter per-IP limits
    tarpit:     55    # Slow drain
    block:      70    # Drop connection
    ban:        85    # Redis ban for ban_duration_seconds
  ban_duration_seconds: 300
```

## 1d. Score Contributions (filled as phases complete)

The `RiskSignal.name` column is the exact string used in code, config, and logs.
Human-readable descriptions are for documentation only — never use them in code.

| Phase | `RiskSignal.name` | Description | Max score |
|-------|-------------------|-------------|-----------|
| 3 | `tls_version` | TLS 1.0 or 1.1 connection | 40 |
| 4 | `missing_sni` | No SNI extension in ClientHello | 30 |
| 4 | `ip_literal_sni` | SNI is an IP address string | 25 |
| 4 | `dga` | DGA confidence score × cap | 0–40 |
| 4 | `unexpected_sni` | Hostname not in expected list | 15 |
| 5 | `ja4t_mismatch` | JA4T OS contradicts JA4 OS | 30 |
| 5 | `no_resumption` | Zero session resumption after min connections | 15 |
| 5 | `short_lived` | Median connection lifespan below threshold | 20 |
| 5 | `high_concurrency` | Concurrent connections from one IP above threshold | 10–40 |
| 5 | `tls_alert_rate` | TLS alert rate above threshold per minute | 20 |
| 5 | `return_visitor` | Long-term clean IP — trust reduction (negative) | −20 |
| 6 | `asn_tor` | ASN is a Tor exit node | 40 |
| 6 | `asn_datacenter` | ASN is a known datacenter / hosting provider | 20 |
| 6 | `asn_vpn` | ASN matches VPN provider pattern | 10 |
| 7 | `no_ptr` | No PTR record for IP | 15 |
| 7 | `fcrdns_failed` | PTR record does not forward-confirm | 20 |
| 7 | `residential_ptr` | PTR hostname matches residential pattern (negative) | −10 |
| 9 | `beaconing` | Regular timing pattern consistent with C2 beacon | 0–35 |
| 10 | `abuseipdb` | AbuseIPDB confidence score contribution | 0–40 |
| 11 | `rdap_known_bad_org` | IP netblock registered to known-bad organisation | 45 |
| 11 | `rdap_new_netblock` | IP netblock registered within `max_age_days` | 20 |
| 12 | `analytics_subnet` | Cross-instance subnet attack aggregate | 25 |
| 12 | `analytics_campaign` | Active campaign detection | 35 |
| 12 | `analytics_slow_scan` | Slow scan pattern detected | 30 |

Negative signals (`return_visitor`, `residential_ptr`) reduce the composite score.
The scorer clamps the result to 0 — composite score never goes below zero.

## 1e. Log Format

```
BLOCK    | 185.220.101.5 | score=78  | dial=75 | signals=[rdap_known_bad_org(+45), missing_sni(+30), asn_datacenter(+20)]
ALLOW    | 142.250.80.1  | score=12  | dial=75 | signals=[asn_unknown(+5), dga(+7)]
MONITOR  | 91.108.4.1    | score=61  | dial=0  | signals=[beaconing(+35), no_ptr(+15), asn_datacenter(+20)] | would=block@50
```

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `config:dial` | String (integer 0–100) | none (no expiry) | Management UI, config reload | Current dial value; read by every proxy instance on each connection |
| `ban:{ip}` | String (reason) | `ban_duration_seconds` | Proxy | Active IP ban; presence means IP is banned |

## Config

```yaml
risk_scorer:
  enabled: true
  thresholds:
    flag:       20          # Default: 20. Connection allowed; elevated logging.
    rate_limit: 35          # Default: 35. Connection rate-limited.
    tarpit:     55          # Default: 55. Connection slow-drained.
    block:      70          # Default: 70. Connection rejected with RST.
    ban:        85          # Default: 85. Rejected; IP banned for ban_duration_seconds.
  ban_duration_seconds: 300 # Default: 300 (5 minutes).
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Redis: connection refused when reading dial value | Last known dial used; WARN logged; connections continue |
| All signal modules return empty lists | Composite score = 0; action = allow; no crash |
| Signal with score > 100 | Clamped to 100; WARN logged in debug mode |
| Config reload changes threshold mid-traffic | New threshold applies to next connection; in-flight connection uses old threshold |

## Acceptance Criteria

### Functional
- [x] `RiskScorer.score(signals) -> RiskAssessment` with composite score clamped 0–100
- [x] Negative signal contributions supported; composite score never falls below 0
- [x] `RiskAssessment.recommended_action` matches the highest-triggered threshold
- [x] All bypass conditions exercised with bypass enabled AND disabled
- [x] Bypass disabled: connection reaches scorer, does not crash, produces a score
- [x] Log output format matches spec in `docs/STYLE_GUIDE.md §2a` exactly

### Configuration
- [x] Thresholds loaded from `config/proxy.yml`; documented defaults applied when absent
- [x] `ban_duration_seconds` loaded and passed to action decider
- [x] All config values in this phase are hot-reloadable; changes apply to the next connection without restart

### Observability
- [x] Prometheus histogram: `ja4proxy_risk_score` — score distribution; buckets [0,10,20,35,55,70,85,100]
- [x] Prometheus counter:   `ja4proxy_connections_total{action}` — connections by final action

- [x] JSON log: every connection produces one `{"type":"connection"}` line with `verb`, `ip`, `score`, `dial`, `action`, and `signals` fields
- [x] JSON log: bypass connections have `score: null` and `bypass` field set; `signals` array is empty

### Unit Tests  (`tests/unit/test_risk_scorer.py`, `tests/unit/test_action_decider.py`)
- [x] `RiskScorer.score()`: empty signal list → score=0, action=allow
- [x] `RiskScorer.score()`: single signal → correct score, correct action
- [x] `RiskScorer.score()`: score clamped at 100 when signals sum exceeds 100
- [x] `RiskScorer.score()`: negative signal reduces score; result never below 0
- [x] `ActionDecider.decide()`: at each threshold boundary (flag, rate_limit, tarpit, block, ban)
- [x] `ActionDecider.decide()`: one below each threshold → previous action returned
- [x] `ActionDecider.decide()`: dial=0 always returns allow regardless of score
- [x] All bypass conditions: bypass enabled → scorer not called; bypass disabled → scorer called

### Integration Tests  (`tests/integration/test_pipeline.py`)
- [x] Full pipeline: known-good JA4 fingerprint (h2 ALPN) → action=allow; bypass logged correctly
- [x] Full pipeline: known-bad JA4 fingerprint → action=block; signals list populated
- [x] All bypass conditions round-trip through Redis; pub/sub update propagates within 100ms

### Chaos Tests  (`tests/chaos/test_redis_failure.py`)
- [x] Redis unreachable: dial defaults to last known value; scoring continues; no crash
- [x] All signal modules return empty: score=0; action=allow; `ALLOW` log line emitted

### Performance Tests  (`tests/performance/bench_pipeline.py`)
- [x] `RiskScorer.score()`: p99 < 100µs with 10 signals
- [x] `ActionDecider.decide()`: p99 < 10µs; allocates no heap objects on hot path
