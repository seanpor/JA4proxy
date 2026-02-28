# Phase 2 — Monitor Mode & Progressive Blocking Dial ⚠️ HIGH PRIORITY

## Goal

Deploy safely. A global dial (0–100) controls how aggressively risk scores translate
into actions. At 0: pure monitor mode — all traffic passes, everything scored and
logged. At 100: full blocking at configured thresholds.

**Deploy at dial=0. Observe. Tune. Raise gradually.**

## 2a. Core Design: Score Always, Act Based on Dial

The scorer always computes a full 0–100 score. The dial only controls what score
triggers each action. This means all monitor-mode data is immediately useful when you
raise the dial.

## 2b. Threshold Scaling Formula

```python
def effective_threshold(configured: int, dial: int) -> int:
    """
    dial=0:   → 101 (unreachable — nothing ever triggers)
    dial=100: → configured (full aggression)
    Between:  → linear interpolation

    Example with configured block_threshold=70:
      dial=0   → 101  (monitor only)
      dial=10  → 97   (most egregious only)
      dial=25  → 93
      dial=50  → 86
      dial=75  → 78
      dial=100 → 70
    """
    if dial == 0:
        return 101
    return round(101 - (dial / 100) * (101 - configured))
```

ALLOW bypasses (when enabled via `security_policy` config) are not affected by the dial.
If an ALLOW bypass is disabled by the secops admin, those connections go through the scorer and dial normally.

## 2c. Counterfactual Logging

Every Stream event includes:
```python
{
    "risk_score":    "72",
    "action_taken":  "allow",      # What actually happened (at current dial)
    "action_at_50":  "tarpit",     # What would happen at dial=50
    "action_at_100": "block",      # What would happen at dial=100
    "dial_setting":  "30",
}
```

## 2d. Dial State

```
Redis key: config:dial  → Integer 0–100
Default: 0
TTL: none (no expiry)
```

Changes propagate via pub/sub `{"type": "dial_change", "value": N}`.
No restart required. Takes effect on next connection after pub/sub receipt.

## 2e. Safety Mechanisms

**Increment limit:** `max_dial_change_per_hour: 25` — rejects larger single changes
with a clear error. Prevents accidental jump from 0→100. Override with `force: true`
for emergencies.

**Acknowledgement guard:**
```yaml
monitor_mode:
  dial: 0
  blocking_acknowledged: false   # Proxy resets dial to 0 at startup if false
```

## 2f. Monitor Mode Log Format

```
MONITOR  | 185.220.101.5 | score=78  | dial=0  | signals=[missing_sni(+30), asn_datacenter(+20), abuseipdb(+26)] | would=block@50,ban@100
  Signals: [Missing SNI(+30), asn_datacenter(+20), abuseipdb(+26)]

MONITOR  | 91.108.4.1    | score=61  | dial=30 | signals=[beaconing(+35), no_ptr(+15), asn_datacenter(+20)] | would=tarpit@50
  (connection allowed by dial, would be tarpitted at higher setting)
```

## 2g. Module: `src/security/action_decider.py`

```python
class ActionDecider:
    def decide(self, assessment: RiskAssessment, dial: int) -> str:
        if dial == 0:
            return "allow"
        score = assessment.total_score
        t = self._effective_thresholds(dial)
        if score >= t["ban"]:        return "ban"
        elif score >= t["block"]:    return "block"
        elif score >= t["tarpit"]:   return "tarpit"
        elif score >= t["rate_limit"]: return "rate_limit"
        elif score >= t["flag"]:     return "flag"
        return "allow"
```

## 2h. Grafana: Blocking Readiness Panel

- **Current dial** (large gauge, green 0–30 / amber 31–70 / red 71–100)
- **Would block at dial=50/75/100**: N connections last hour (% of total)
- **Risk score distribution** histogram
- **Score p95 over time** — rises sharply during attacks

## Redis Key Schema

| Key | Type | TTL | Written by | Notes |
|-----|------|-----|------------|-------|
| `config:dial` | String (integer 0–100) | none (no expiry) | Management UI, config reload | Current dial value; default 0 |
| `config:dial:change_count:{YYYY-MM-DD-HH}` | Integer (INCR) | 3600s (1h) | Proxy, Management UI | Hourly dial change count for rate-limiting |

## Config

```yaml
monitor_mode:
  dial: 0
  blocking_acknowledged: false
  log_counterfactuals: true
  counterfactual_thresholds: [25, 50, 75, 100]
  max_dial_change_per_hour: 25
  alert_on_dial_change: true
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Redis: connection refused during dial read | Last known dial retained in-process; WARN logged; connections continue |
| Dial change arrives during high traffic | No connections dropped; new threshold applies to next connection without gap |
| `blocking_acknowledged: false` set mid-run | Dial resets to 0 on next config reload; WARN logged |
| Counterfactual threshold list empty | No `would=` field in MONITOR log; no crash |

## Acceptance Criteria

### Functional
- [ ] `config:dial` Redis key initialised to 0 with no TTL on startup
- [ ] `effective_threshold(configured, dial)` returns correct value at all boundary inputs
- [ ] dial=0: all non-bypassed connections allowed regardless of score
- [ ] dial=100: configured thresholds applied exactly
- [ ] ALLOW bypasses (when enabled) produce same outcome at any dial value
- [ ] ALLOW bypass disabled: connection scored and dial applied normally
- [ ] Dial changes propagated via pub/sub; new thresholds apply to next connection; no restart
- [ ] `max_dial_change_per_hour` enforced; change exceeding limit rejected with WARN logged
- [ ] `blocking_acknowledged: false`: dial resets to 0 at startup; WARN logged
- [ ] Counterfactual fields present in all Redis Stream events
- [ ] `log_counterfactuals: true`: MONITOR log line includes `would=` field

### Configuration
- [ ] `security_policy` config keys control which bypasses are active
- [ ] `counterfactual_thresholds` list configures which dial values appear in `would=` field
- [ ] All config values in this phase are hot-reloadable; changes apply to the next connection without restart

### Observability
- [ ] Prometheus gauge:   `ja4proxy_dial_current` — current dial value (0–100)
- [ ] Prometheus counter: `ja4proxy_monitor_counterfactual_total{action,dial}` — would-have-taken actions per dial setting
- [ ] Prometheus counter: `ja4proxy_dial_change_rejected_total` — dial changes rejected by increment limit
- [ ] Prometheus counter: `ja4proxy_dial_changes_total` — successful dial value changes
- [ ] Grafana: Blocking Readiness panel showing would-block percentages at dial 25/50/75/100

- [ ] JSON log: `{"type":"system","level":"INFO","subsystem":"dial","event":"dial_changed"}` emitted with `old_value` and `new_value` on every dial change
- [ ] JSON log: MONITOR connections include `counterfactual` object with `action_at_N` fields for each configured threshold

### Unit Tests  (`tests/unit/test_action_decider.py`)
- [ ] `effective_threshold()`: at every boundary combination of configured threshold and dial 0/25/50/75/100
- [ ] dial=0: score 100 → action=allow
- [ ] dial=100: score at each threshold → correct action
- [ ] `max_dial_change_per_hour`: change within limit accepted; change exceeding limit rejected
- [ ] `blocking_acknowledged: false`: dial set above 0 → rejected with clear error

### Integration Tests  (`tests/integration/test_dial_propagation.py`)
- [ ] Dial change via Redis SET + pub/sub → new thresholds apply within 100ms
- [ ] Two instances: dial change on one propagates to both via pub/sub

### Chaos Tests  (`tests/chaos/test_dial_change_chaos.py`)
- [ ] Redis unreachable during dial change: last known dial retained; WARN logged
- [ ] Dial change arrives mid-connection: no connections dropped; new threshold applies to next connection
