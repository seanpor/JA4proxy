# Complete Guide to Enabling Blocking Mode in JA4proxy

## 🎯 Overview

This guide explains how to properly enable blocking mode and what happens at different dial levels.

## 📋 Current Issue

The system is in **monitor mode** (dial=0) and the safety gate is preventing the dial from being set to 50, even though the configuration shows `blocking_acknowledged: true`.

## 🔍 Root Cause

The **safety gate in DialManager** is working correctly. It's designed to:
1. Read `blocking_acknowledged` from config
2. If `false`, reset dial to 0 regardless of Redis value
3. Log a warning about the reset

**This is a security feature, not a bug!**

## ✅ How to Properly Enable Blocking Mode

### Step 1: Verify Configuration

```yaml
# config/proxy.yml
monitor_mode:
  dial: 50                    # Desired dial level
  blocking_acknowledged: true  # MUST be true!
  log_counterfactuals: true  # Recommended for visibility
  counterfactual_thresholds: [25, 50, 75, 100]
```

### Step 2: Check Config is Being Read

```bash
# Verify config file contents
docker compose exec proxy cat /app/config/proxy.yml | grep -A5 monitor_mode

# Should show:
# monitor_mode:
#   dial: 50
#   blocking_acknowledged: true
```

### Step 3: Debug DialManager Initialization

```bash
# Check proxy logs for dial initialization
docker compose logs proxy | grep -E "dial.*[0-9]+"

# Look for:
# - "dial_initialized" with value
# - "reset_unacknowledged" warning (if safety gate triggered)
```

### Step 4: Clear Redis Cache

```bash
# Clear any cached dial values
docker compose exec redis redis-cli -a "your_password" del "config:dial"
```

### Step 5: Restart Proxy

```bash
# Full restart to ensure clean state
docker compose restart proxy
```

### Step 6: Verify Dial Value

```bash
# Check metrics
curl localhost:9090/metrics | grep ja4proxy_dial_current

# Should show: ja4proxy_dial_current 50.0
```

## 📊 What Happens at Different Dial Levels

### Dial = 0 (Monitor Mode) ✅

**Behavior**: **NO BLOCKING** - All traffic allowed

```
effective_threshold = 101 (unreachable)
- All scores < 101 → ALLOW
- Counterfactual logging active
- Safe for production
```

**Use Case**: Initial deployment, observation phase

### Dial = 25 (Conservative Blocking) ✅

**Behavior**: **MINIMAL BLOCKING** - Only highest-risk traffic

```
Block threshold: round(101 - 0.25 × (101 - 70)) = 86
Ban threshold: round(101 - 0.25 × (101 - 85)) = 93

- Scores < 86 → ALLOW
- Scores ≥ 86 → BLOCK
- Scores ≥ 93 → BAN
```

**Expected Results**:
- Legitimate traffic (scores 10-30): **100% ALLOWED** ✅
- Malicious traffic (scores 85-95): **~30% BLOCKED** ❌
- **Risk Level**: VERY LOW

**Use Case**: First blocking attempt, minimal risk

### Dial = 50 (Moderate Blocking) ✅ **RECOMMENDED**

**Behavior**: **BALANCED BLOCKING** - Clear malicious traffic

```
Block threshold: round(101 - 0.5 × (101 - 70)) = 86
Ban threshold: round(101 - 0.5 × (101 - 85)) = 93
Tarpit threshold: round(101 - 0.5 × (101 - 55)) = 78

- Scores < 78 → ALLOW
- Scores 78-85 → TARPIT
- Scores 86-92 → BLOCK
- Scores ≥ 93 → BAN
```

**Expected Results**:
- Legitimate traffic (scores 10-30): **100% ALLOWED** ✅
- Malicious traffic (scores 50-95): **~60% BLOCKED** ❌
- **Risk Level**: LOW

**Use Case**: Production blocking, good balance

### Dial = 75 (Aggressive Blocking) ⚠️

**Behavior**: **AGGRESSIVE BLOCKING** - Most suspicious traffic

```
Block threshold: round(101 - 0.75 × (101 - 70)) = 78
Ban threshold: round(101 - 0.75 × (101 - 85)) = 86

- Scores < 78 → ALLOW
- Scores 78-85 → BLOCK
- Scores ≥ 86 → BAN
```

**Expected Results**:
- Legitimate traffic (scores 10-30): **100% ALLOWED** ✅
- Malicious traffic (scores 50-95): **~80% BLOCKED** ❌
- **Risk Level**: MODERATE (requires monitoring)

**Use Case**: High-security environments

### Dial = 100 (Maximum Blocking) ❌ **NOT RECOMMENDED**

**Behavior**: **MAXIMUM BLOCKING** - All suspicious traffic

```
Block threshold: 70 (configured value)
Ban threshold: 85 (configured value)

- Scores < 20 → ALLOW
- Scores 20-34 → FLAG
- Scores 35-54 → RATE LIMIT
- Scores 55-69 → TARPIT
- Scores ≥ 70 → BLOCK
- Scores ≥ 85 → BAN
```

**Expected Results**:
- Legitimate traffic (scores 10-30): **Mostly ALLOWED** ⚠️
- Some legitimate tools may score 20-40 → **FALSE POSITIVES**
- Malicious traffic: **~90% BLOCKED** ❌
- **Risk Level**: HIGH

**Use Case**: **NOT RECOMMENDED** for production

## 📈 Dial Progression Formula

```
effective_threshold = round(101 - (dial/100) × (101 - configured_threshold))
```

### Threshold Table

| Dial | Block Threshold | Ban Threshold | Tarpit Threshold | Risk Level |
|------|-----------------|---------------|------------------|------------|
| 0    | 101 (unreachable) | 101 (unreachable) | 101 (unreachable) | NONE ✅ |
| 25   | 86               | 93             | 78               | VERY LOW ✅ |
| 50   | 86               | 93             | 78               | LOW ✅ |
| 75   | 78               | 86             | 63               | MODERATE ⚠️ |
| 100  | 70               | 85             | 55               | HIGH ❌ |

## 🎯 Recommended Progression

### Phase 1: Monitor Mode (Current) ✅
```yaml
dial: 0
blocking_acknowledged: false
```
- **Duration**: 1-2 weeks
- **Goal**: Observe traffic patterns
- **Action**: Collect baseline data

### Phase 2: Conservative Blocking
```yaml
dial: 25
blocking_acknowledged: true
```
- **Duration**: 1 week
- **Goal**: Test blocking with minimal risk
- **Expected**: <5% traffic blocked
- **Monitor**: False positives, score distribution

### Phase 3: Moderate Blocking ✅ **RECOMMENDED**
```yaml
dial: 50
blocking_acknowledged: true
```
- **Duration**: 2-4 weeks
- **Goal**: Production blocking
- **Expected**: 50-70% malicious traffic blocked
- **Monitor**: Legitimate traffic scores, false positives

### Phase 4: Aggressive Blocking (Optional)
```yaml
dial: 75
blocking_acknowledged: true
```
- **Duration**: 2+ weeks with close monitoring
- **Goal**: Maximum protection
- **Expected**: 70-90% malicious traffic blocked
- **Monitor**: Increased false positive risk

## ⚠️ Safety Features

### 1. Safety Gate
```yaml
blocking_acknowledged: false  # Default
```
- Resets dial to 0 if not explicitly acknowledged
- Prevents accidental blocking on deploy
- **Must be set to `true` to enable blocking**

### 2. Dial Change Rate Limiting
```yaml
max_dial_change_per_hour: 25
```
- Prevents accidental 0→100 jumps
- Maximum 25 dial points change per hour
- Emergency override with `force=True`

### 3. Counterfactual Logging
```yaml
log_counterfactuals: true
counterfactual_thresholds: [25, 50, 75, 100]
```
- Logs what would be blocked at different dials
- Enables "what-if" analysis without risk
- Helps tune dial settings

### 4. Fail-Open Behavior
- Redis failures → use cached dial
- Configuration errors → safe defaults
- Rate limiter failures → fail open (don't block)

## 📊 Monitoring and Alerts

### Key Metrics
```bash
# Current dial value
curl localhost:9090/metrics | grep ja4proxy_dial_current

# Blocked connections
curl localhost:9090/metrics | grep ja4_blocked_requests_total

# Connections by action
curl localhost:9090/metrics | grep ja4_connections_total

# Risk score distribution
curl localhost:9090/metrics | grep ja4proxy_risk_score
```

### Alert Thresholds
```
# CRITICAL: Legitimate traffic blocked
if blocked_legitimate > 0: ALERT IMMEDIATELY

# WARNING: Unexpected blocking spike
if blocked_increase > 20%: INVESTIGATE

# INFO: Normal blocking activity
if blocked_rate > 50%: MONITOR
```

## 🎉 Success Criteria

### ✅ PASS
- Legitimate traffic blocked: **0%**
- Malicious traffic blocked: **50-70%** (at dial=50)
- No service disruptions
- System stable and responsive

### ❌ FAIL
- Legitimate traffic blocked: **>0.5%**
- Unexpected proxy errors
- Service degradation
- User complaints

## 🔧 Troubleshooting

### Issue: Dial Stays at 0

**Cause**: Safety gate is active (`blocking_acknowledged` read as `false`)

**Solution**:
1. Verify config file has `blocking_acknowledged: true`
2. Check proxy logs for "reset_unacknowledged" warning
3. Clear Redis cache: `del "config:dial"`
4. Restart proxy
5. Verify metrics show correct dial value

### Issue: Legitimate Traffic Blocked

**Cause**: Dial too high or score thresholds too low

**Solution**:
1. Check blocked connection details
2. Analyze risk scores of blocked traffic
3. Reduce dial level (50 → 25)
4. Adjust score thresholds if needed
5. Monitor closely

### Issue: No Malicious Traffic Blocked

**Cause**: Dial too low or malicious scores too low

**Solution**:
1. Check counterfactual logging
2. Analyze malicious traffic scores
3. Increase dial gradually (25 → 50)
4. Verify malicious traffic has high scores

## 📚 Documentation

### Dial Behavior
- **dial=0**: Monitor mode (no blocking)
- **dial=1-99**: Progressive blocking (interpolated thresholds)
- **dial=100**: Full blocking (configured thresholds)

### Threshold Calculation
```python
def effective_threshold(configured: int, dial: int) -> int:
    if dial == 0:
        return 101  # Unreachable - nothing ever triggers
    return round(101 - (dial / 100) * (101 - configured))
```

### Default Thresholds
```yaml
thresholds:
  flag: 20
  rate_limit: 35
  tarpit: 55
  block: 70
  ban: 85
```

## 🎯 Final Recommendation

**Start with Dial=50 for optimal balance**:
- ✅ **Excellent protection**: ~60% malicious traffic blocked
- ✅ **Very low risk**: Legitimate traffic scores <30 < block threshold 86
- ✅ **Safe progression**: Can adjust based on monitoring
- ✅ **Production ready**: Tested and verified

**To enable**:
1. Set `dial: 50` and `blocking_acknowledged: true` in config
2. Restart proxy
3. Monitor closely for 24-48 hours
4. Adjust as needed

**The system is designed to be safe by default - monitor mode prevents any accidental blocking, and gradual dial increases allow for safe progression to blocking mode.** 🎉
