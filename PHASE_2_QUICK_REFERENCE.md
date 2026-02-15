# Phase 2 Quick Reference

**Quick Start:** Understanding what Phase 2 adds to the JA4 Proxy system

---

## What Phase 2 Does

Phase 2 adds **intelligent threat classification** on top of Phase 1's rate tracking. It takes connection rate data and determines what action should be taken.

### Simple Example

```python
# Phase 1 tracks: "This IP+JA4 pair made 6 connections in 1 second"
# Phase 2 decides: "6 conn/sec exceeds threshold of 5 → BLOCK tier → Apply TARPIT"
```

---

## Core Concepts

### 1. Threat Tiers (Escalation Levels)

| Tier | Threshold | Action | Example |
|------|-----------|--------|---------|
| **NORMAL** | ≤1 conn/sec | Allow | Regular user browsing |
| **SUSPICIOUS** | 1-5 conn/sec | Log + Allow | Aggressive client, watch it |
| **BLOCK** | 5-10 conn/sec | TARPIT or Block | Likely attack, slow down |
| **BANNED** | >10 conn/sec | Ban temporarily | Definite attack, block it |

### 2. Multi-Strategy Policies

**ANY Policy** (default, most protective):
```
If ANY strategy detects a threat → Take action
Example: IP is normal (1/sec), but IP+JA4 pair is high (6/sec) → BLOCK
```

**ALL Policy** (most permissive):
```
Only if ALL strategies detect threats → Take action
Example: Both IP and IP+JA4 pair must be high → BLOCK
```

**MAJORITY Policy** (balanced):
```
If majority of strategies detect threats → Take action
Example: 2 out of 3 strategies detect threats → BLOCK
```

---

## Usage Examples

### Example 1: Basic Usage

```python
from src.security import (
    MultiStrategyRateTracker,
    ThreatEvaluator,
    ThreatTier,
)

# Phase 1: Track connection rates
rate_tracker = MultiStrategyRateTracker(redis_client, config)
rate_results = rate_tracker.track_connection(ja4, client_ip)

# Phase 2: Evaluate threat level
evaluator = ThreatEvaluator.from_config(config)
evaluations = evaluator.evaluate_multi_strategy(rate_results)

# Check if action needed
if evaluator.should_apply_action(evaluations):
    tier = evaluator.get_most_severe_tier(evaluations)
    
    if tier == ThreatTier.SUSPICIOUS:
        logger.warning(f"Suspicious: {client_ip}")
    elif tier == ThreatTier.BLOCK:
        apply_tarpit(client_ip)
    elif tier == ThreatTier.BANNED:
        apply_ban(client_ip)
```

### Example 2: Understanding Evaluations

```python
# Get detailed evaluation results
evaluations = evaluator.evaluate_multi_strategy(rate_results)

for strategy, evaluation in evaluations.items():
    print(f"Strategy: {strategy.value}")
    print(f"  Tier: {evaluation.tier.name}")
    print(f"  Rate: {evaluation.rate}/sec")
    print(f"  Threshold: {evaluation.threshold_exceeded}/sec")

# Example output:
# Strategy: by_ip
#   Tier: NORMAL
#   Rate: 2/sec
#   Threshold: 0/sec
#
# Strategy: by_ip_ja4_pair
#   Tier: BLOCK
#   Rate: 6/sec
#   Threshold: 5/sec
```

### Example 3: Configuration

```yaml
security:
  # Global thresholds (used if strategy doesn't specify)
  thresholds:
    suspicious: 1
    block: 5
    ban: 10
  
  # Strategy-specific configurations
  rate_limit_strategies:
    by_ip_ja4_pair:
      enabled: true
      thresholds:
        suspicious: 1    # Override global for this strategy
        block: 5
        ban: 10
      action: "tarpit"
  
  # Policy for combining strategies
  multi_strategy_policy: "any"  # any, all, or majority
```

---

## Attack Scenario Examples

### Scenario 1: Simple DDoS

```
Attack: Single IP floods server (50 conn/sec)

Phase 1 Tracking:
  BY_IP: 50/sec
  BY_IP_JA4_PAIR: 2-3/sec per pair (using different tools)

Phase 2 Evaluation:
  BY_IP: 50/sec → BANNED (threshold: 20)
  BY_IP_JA4_PAIR: 2-3/sec → SUSPICIOUS

Policy (ANY): Take action because BY_IP triggered
Action: Block the IP address
```

### Scenario 2: Botnet

```
Attack: 1000 IPs using same tool (1 conn/sec each)

Phase 1 Tracking:
  BY_IP: 1/sec per IP
  BY_JA4: 1000/sec total for this JA4
  BY_IP_JA4_PAIR: 1/sec per pair

Phase 2 Evaluation:
  BY_IP: NORMAL
  BY_JA4: BANNED (threshold: 50)
  BY_IP_JA4_PAIR: SUSPICIOUS

Policy (ANY): Take action because BY_JA4 triggered
Action: Log the JA4 for investigation (botnet detected)
```

### Scenario 3: Aggressive Client

```
Attack: Misconfigured legitimate tool (10 conn/sec)

Phase 1 Tracking:
  BY_IP: 10/sec
  BY_JA4: 10/sec (only this IP using this tool)
  BY_IP_JA4_PAIR: 10/sec

Phase 2 Evaluation:
  BY_IP: SUSPICIOUS (threshold: 2)
  BY_JA4: NORMAL (threshold: 25)
  BY_IP_JA4_PAIR: BANNED (threshold: 10)

Policy (ANY): Take action because BY_IP_JA4_PAIR triggered
Action: TARPIT to slow down this specific client
```

---

## Key Classes

### ThreatTier (Enum)

```python
from src.security import ThreatTier

# Check tier level
if tier >= ThreatTier.BLOCK:
    # Connection should be blocked
    
# Get action name
action = tier.get_action_name()  # "allow", "log", "block", "ban"

# Get severity
severity = tier.get_severity_level()  # "info", "warning", "error", "critical"

# Check if should block
should_block = tier.should_block_connection()  # False for NORMAL/SUSPICIOUS
```

### ThreatEvaluation (Immutable Result)

```python
# Created automatically by ThreatEvaluator
evaluation = ThreatEvaluation(
    strategy=RateLimitStrategy.BY_IP,
    tier=ThreatTier.BLOCK,
    rate=6,
    threshold_exceeded=5,
    entity_id="192.168.1.100",
)

# Access properties
print(evaluation.tier)       # ThreatTier.BLOCK
print(evaluation.rate)       # 6
print(evaluation.strategy)   # RateLimitStrategy.BY_IP

# Immutable - cannot modify
# evaluation.tier = ThreatTier.BANNED  # ERROR!
```

### ThreatEvaluator (Main Engine)

```python
from src.security import ThreatEvaluator, MultiStrategyPolicy

# Create from config
evaluator = ThreatEvaluator.from_config(config)

# Or create manually
evaluator = ThreatEvaluator(
    tier_config=tier_config,
    strategy_configs=strategy_configs,
    policy=MultiStrategyPolicy.ANY,
)

# Evaluate threats
evaluations = evaluator.evaluate_multi_strategy(rate_results)

# Check if action needed
if evaluator.should_apply_action(evaluations):
    # Get details
    most_severe = evaluator.get_most_severe_tier(evaluations)
    triggering = evaluator.get_triggering_strategy(evaluations, most_severe)
    
    # Get summary for logging
    summary = evaluator.get_evaluation_summary(evaluations)
```

---

## Common Patterns

### Pattern 1: Check and Act

```python
rate_results = rate_tracker.track_connection(ja4, ip)
evaluations = evaluator.evaluate_multi_strategy(rate_results)

if evaluator.should_apply_action(evaluations):
    tier = evaluator.get_most_severe_tier(evaluations)
    apply_action_for_tier(tier, ja4, ip)
```

### Pattern 2: Log All Evaluations

```python
evaluations = evaluator.evaluate_multi_strategy(rate_results)

for strategy, evaluation in evaluations.items():
    if evaluation.tier != ThreatTier.NORMAL:
        logger.warning(
            f"Threat: {strategy.value} "
            f"tier={evaluation.tier.name} "
            f"rate={evaluation.rate}/sec"
        )
```

### Pattern 3: Get Detailed Summary

```python
summary = evaluator.get_evaluation_summary(evaluations)

# Summary contains:
# {
#   'total_strategies': 2,
#   'threats_detected': 1,
#   'most_severe_tier': 'BLOCK',
#   'policy': 'any',
#   'action_triggered': True,
#   'evaluations': [...]
# }

logger.info(f"Evaluation: {summary}")
```

---

## Testing

```bash
# Run Phase 2 tests
python3 -m pytest tests/unit/security/test_threat_tier.py -v
python3 -m pytest tests/unit/security/test_threat_evaluator.py -v

# Run all security tests (Phase 1 + 2)
python3 -m pytest tests/unit/security/ -v

# Expected: 108 tests, 100% pass rate
```

---

## Configuration Reference

### Minimal Configuration

```yaml
security:
  thresholds:
    suspicious: 1
    block: 5
    ban: 10
  
  rate_limit_strategies:
    by_ip_ja4_pair:
      enabled: true
  
  multi_strategy_policy: "any"
```

### Recommended Production Configuration

```yaml
security:
  thresholds:
    suspicious: 1
    block: 5
    ban: 10
  
  ban_durations:
    suspicious: 300
    block: 3600
    ban: 604800
  
  rate_limit_strategies:
    by_ip:
      enabled: true
      thresholds: {suspicious: 2, block: 10, ban: 20}
      action: "block"
    
    by_ja4:
      enabled: true
      thresholds: {suspicious: 5, block: 25, ban: 50}
      action: "log"
    
    by_ip_ja4_pair:
      enabled: true
      thresholds: {suspicious: 1, block: 5, ban: 10}
      action: "tarpit"
  
  multi_strategy_policy: "any"
```

---

## Troubleshooting

### Issue: Too many false positives

**Solution:** Increase thresholds or use "all" or "majority" policy

```yaml
multi_strategy_policy: "majority"  # Require majority agreement

# Or increase thresholds
rate_limit_strategies:
  by_ip_ja4_pair:
    thresholds:
      suspicious: 2    # Was 1
      block: 10        # Was 5
      ban: 20          # Was 10
```

### Issue: Missing attacks

**Solution:** Use "any" policy and enable multiple strategies

```yaml
multi_strategy_policy: "any"  # Block on any threat

rate_limit_strategies:
  by_ip:
    enabled: true       # Enable all strategies
  by_ja4:
    enabled: true
  by_ip_ja4_pair:
    enabled: true
```

### Issue: Want different actions per strategy

**Solution:** Configure action per strategy (Phase 3)

```yaml
rate_limit_strategies:
  by_ip:
    action: "block"     # Hard block IPs
  by_ja4:
    action: "log"       # Just log botnets
  by_ip_ja4_pair:
    action: "tarpit"    # Slow down specific clients
```

---

## Next Phase Preview

**Phase 3** will implement the actual enforcement actions:

- Apply TARPIT delays
- Store blocks/bans in Redis
- Manual override and unban
- Prometheus metrics
- Action history tracking

Stay tuned for `PHASE_3_COMPLETE.md`!

---

## Quick Links

- Full details: `PHASE_2_COMPLETE.md`
- Overall progress: `IMPLEMENTATION_PROGRESS.md`
- Phase 1 details: `PHASE_1_COMPLETE.md`
- Implementation roadmap: `IMPLEMENTATION_GAP_ANALYSIS.md`
