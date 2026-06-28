<!--
title: "Phase 248 — Auto-Escalating IP Defense"
audience: developer
last_reviewed: 2026-06-25
phase: 248
-->

# Phase 248 — Auto-Escalating IP Defense

## Problem Statement

The scenario: it's 2am. The website owner activated Attack Mode (Phase 247), the
dial is at 75, and the bots are being tarpitted. But the bots keep coming. The
owner eventually falls asleep. At 6am Attack Mode auto-reverts to dial=0. The
bots are still there.

Without auto-escalation, every wave of the same attack requires manual
intervention. The owner has to:
1. Notice the connection rate is climbing again
2. Log into the dashboard
3. Manually ban the offending IPs
4. Go back to sleep

This is not sustainable, and it is not what a desperate website owner needs.

This phase adds **auto-escalating IP defense**: an IP that keeps hitting the proxy
after being tarpitted gets progressively stronger responses — automatically, without
requiring the owner to be awake. If an IP ignores a tarpit and comes back, it gets
blocked. If it comes back again after a block, it gets banned.

The default configuration is **off** — the owner opts in, and the thresholds are
conservative by default. The worst-case outcome of auto-escalation is a legitimate
IP that misbehaved gets a temporary ban; the ban expires automatically.

## Goals

1. An IP that is tarpitted and comes back anyway gets automatically blocked on its
   next connection attempt.
2. An IP that is blocked and comes back anyway gets automatically banned for 24
   hours on its next connection attempt.
3. The escalation logic is off by default — enabled by a single config toggle.
4. The owner can see the offense count for any IP in the management UI.
5. Every auto-escalation action is logged exactly like a manual one, so the audit
   trail is complete.

## Core Asymmetry — This Is Critical

JA4proxy's governing principle is: **fail open**. A false positive (blocking a real
user) costs more than a false negative (letting a bot through).

Auto-escalation adds risk of false positives. Mitigations baked into this design:
- Off by default. The owner has to consciously enable it.
- Tarpit happens at offense 1. Block only at offense 3+. Ban only at offense 5+
  (defaults — all configurable).
- Ban TTL is short (24 hours default) and configurable.
- Browser traffic (`h2`/`h1` ALPN) is completely exempt — bypass rules are
  upstream of the offense counter.
- Shared-IP environments (NAT, corporate networks): the rate limiter already uses
  JA4 fingerprint as part of its key. The offense counter uses the full IP. This
  means a shared NAT IP that is being used by a bot will accumulate offenses, but
  the rate limiter's `by_ip_ja4` strategy means the bot's specific TLS fingerprint
  is what triggers the offense, not any browser on the same IP. Document this
  limitation clearly in the config file.

## What Already Exists (Do Not Rebuild)

- **Rate limiter** (`internal/security/rate_limiter.go`): already counts connections
  per IP/JA4/combined within a sliding window. Already returns a `Suspicious`, `Block`,
  or `Ban` signal. This phase adds a *persistent* offense counter on top of those
  in-window signals.
- **Ban system** (`internal/security/pipeline.go` + `management/api/routes/bans.py`):
  already supports `ban:{ip}` keys with TTL. Auto-escalation writes these same keys —
  no new ban structure.
- **Action decider** (`internal/security/action_decider.go`): already maps score+dial
  to action. Auto-escalation *overrides* the decider's output when an escalation applies.
  The decider result is still logged (for observability) but the escalated action is
  what executes.
- **Audit logging** (`management/api/audit_utils.py`): already handles structured
  audit entries. Auto-escalation writes entries via the same Redis LIST
  (`management:audit_log`).

## Sub-phases

### 248.1 — Config Schema
**Size:** SMALL | **Dependencies:** none

Add `auto_escalate` section to `config/proxy.yml`. This is the config the owner
sees and edits.

```yaml
# Auto-escalating IP defense (Phase 248)
# When enabled, IPs that keep connecting after a tarpit or block are
# automatically given stronger responses. Off by default.
auto_escalate:
  enabled: false            # Set true to enable. Off by default.
  
  # How many times an IP must hit a rate-limit signal before the action escalates.
  # Offense 1: tarpit (slow the connection down)
  # Offense 3: block (reject the connection)
  # Offense 5: ban (ban the IP for ban_hours)
  # You can lower thresholds to be more aggressive, but be careful with shared IPs
  # (corporate NATs, VPNs) — they may have many users behind one IP.
  tarpit_at_offense: 1      # Minimum: 1
  block_at_offense:  3      # Minimum: tarpit_at_offense + 1
  ban_at_offense:    5      # Minimum: block_at_offense + 1

  ban_hours: 24             # How long an auto-ban lasts. Range: 1–168 (one week max).

  # Reset the offense counter after this many hours of clean traffic.
  # An IP that stops misbehaving gets a clean slate.
  offense_ttl_hours: 48     # Range: 1–720

  # Shared-IP warning: if a CIDR block has more than this many unique IPs
  # accumulating offenses, do not auto-ban any of them (they may be a NAT).
  # Set to 0 to disable this check.
  shared_ip_cidr_threshold: 10
```

**Files to modify:**
- `config/proxy.yml` — add the `auto_escalate` section above
- `internal/config/loader.go` — add `AutoEscalateConfig` struct and load it

**`AutoEscalateConfig` Go struct:**
```go
type AutoEscalateConfig struct {
    Enabled               bool `yaml:"enabled"`
    TarpitAtOffense       int  `yaml:"tarpit_at_offense"`
    BlockAtOffense        int  `yaml:"block_at_offense"`
    BanAtOffense          int  `yaml:"ban_at_offense"`
    BanHours              int  `yaml:"ban_hours"`
    OffenseTTLHours       int  `yaml:"offense_ttl_hours"`
    SharedIPCIDRThreshold int  `yaml:"shared_ip_cidr_threshold"`
}
```

Apply defaults in the loader if fields are zero (to handle configs that omit them):
`TarpitAtOffense=1`, `BlockAtOffense=3`, `BanAtOffense=5`, `BanHours=24`,
`OffenseTTLHours=48`, `SharedIPCIDRThreshold=10`.

**Acceptance criteria:**
- [ ] `config/proxy.yml` has `auto_escalate` section with all fields, comments, defaults
- [ ] `internal/config/loader.go` loads `auto_escalate` into `AutoEscalateConfig`
- [ ] Zero-value fields fall back to documented defaults
- [ ] Existing config tests still pass

### 248.2 — Offense Counter (Go)
**Size:** MEDIUM | **Dependencies:** 248.1

Create `internal/security/offense_counter.go` — a small module that reads and
increments the offense count for an IP in Redis.

**Redis key:** `offense:{ip}` — String (int), TTL = `offense_ttl_hours * 3600`

Every call to `Increment` extends the TTL, so the counter only expires if the
IP has been clean for the full `offense_ttl_hours` duration.

**Step 0 — Extend the RedisReader interface**

`OffenseCounter` needs Redis operations that are not currently on the `RedisReader`
interface in `internal/security/pipeline.go`. Before writing `offense_counter.go`,
add these two methods to the interface AND add implementations in
`internal/redis/client.go`:

```go
// In internal/security/pipeline.go, add to RedisReader:
Incr(ctx context.Context, key string) (int64, error)
Expire(ctx context.Context, key string, ttl time.Duration) error
```

```go
// In internal/redis/client.go, add to *Client:
func (c *Client) Incr(ctx context.Context, key string) (int64, error) {
    return c.rdb.Incr(ctx, key).Result()
}
func (c *Client) Expire(ctx context.Context, key string, ttl time.Duration) error {
    return c.rdb.Expire(ctx, key, ttl).Err()
}
```

`c.rdb` is the underlying go-redis client (`goredis.UniversalClient`). You can
also access it via `c.Raw()` if needed for tests.

Also add `CountKeys(ctx context.Context, pattern string) int` to `RedisReader` —
it already exists on `*Client` (line ~445 of `client.go`) but is not on the
interface. Add it.

> **Why `INCR` and not `SET`?** `INCR` is a single atomic Redis operation —
> if two connections from the same IP arrive at the same millisecond, both get
> their own increment. If you used `GET` then `SET`, two simultaneous connections
> could both read 3 and both write 4, silently losing one increment.
>
> **Why call `EXPIRE` after every `INCR`?** `INCR` on a non-existent key creates
> it with no TTL. `EXPIRE` resets the TTL on every call, so the window slides:
> an IP that misbehaves again resets its TTL clock. This is two separate Redis
> calls, not one atomic operation — a crash between them leaves the key with no
> TTL (it would live forever). This is acceptable: the worst case is the key
> lives until the next restart rather than expiring on schedule. It does NOT
> cause incorrect escalation behaviour.

**Interface:**

```go
// OffenseCounter tracks how many times an IP has triggered a rate-limit
// response. Stored in Redis with a sliding TTL so clean IPs get a fresh start.
type OffenseCounter struct {
    redis  RedisReader  // uses the extended interface above
    cfg    *AutoEscalateConfig
    log    *logrus.Logger
}

func NewOffenseCounter(redis RedisReader, cfg *AutoEscalateConfig, log *logrus.Logger) *OffenseCounter

// Increment adds 1 to the offense count for ip and returns the new count.
// Calls INCR then EXPIRE. Fails open: Redis error → returns 0, logs warning.
func (o *OffenseCounter) Increment(ctx context.Context, ip string) (int, error)

// Get returns the current offense count for ip (0 if not found or Redis down).
// Reads offense:{ip} via GetString and parses as int with strconv.Atoi.
// Redis stores INCR results as decimal strings — GetString("offense:1.2.3.4")
// returns "5", which Atoi converts to 5.
func (o *OffenseCounter) Get(ctx context.Context, ip string) (int, error)

// Reset deletes the offense:{ip} key.
func (o *OffenseCounter) Reset(ctx context.Context, ip string) error

// EscalatedAction returns the action this IP should receive based on offense count.
// Returns "" if auto_escalate is disabled or count is below tarpit threshold.
// Does NOT increment the counter — call Increment separately.
func (o *OffenseCounter) EscalatedAction(ctx context.Context, ip string) (string, error)
```

**Escalation logic in `EscalatedAction`:**

```
count < tarpit_at_offense  → "" (no override, use normal action decider result)
count >= tarpit_at_offense → "tarpit"
count >= block_at_offense  → "block"
count >= ban_at_offense    → "ban"
```

**Shared-IP protection:**

Before incrementing, if `SharedIPCIDRThreshold > 0`, check how many distinct IPs
in the same /24 (IPv4) or /48 (IPv6) have offense keys. Use `CountKeys` with a
pattern like `offense:203.0.113.*`. If the count exceeds the threshold, do NOT
increment this IP and log a warning:

```
level=warn msg="offense_counter: shared IP threshold reached, skipping escalation"
cidr=203.0.113.0/24 ip=203.0.113.42 threshold=10 count=11
```

This protects corporate NAT environments where many legitimate users share an IP range.

**File to create:** `internal/security/offense_counter.go`

**Acceptance criteria:**
- [ ] `RedisReader` interface has `Incr`, `Expire`, `CountKeys` methods
- [ ] `*Client` in `client.go` implements all three new methods
- [ ] `Increment` calls `INCR` then `EXPIRE` (two calls, as documented above)
- [ ] `Increment` extends TTL on every call (sliding window behaviour)
- [ ] `EscalatedAction` returns `""` when `cfg.Enabled == false`
- [ ] `EscalatedAction` returns correct action for each offense tier
- [ ] Shared-IP check skips increment when threshold exceeded
- [ ] All methods fail open: Redis failure → log warning, return zero value, no panic
- [ ] Existing `faultyRedis` mock in `pipeline_chaos_test.go` still compiles.
      The mock must implement the three new methods — add these stubs:
      ```go
      func (f *faultyRedis) Incr(ctx context.Context, key string) (int64, error) { return 0, errors.New("faulty") }
      func (f *faultyRedis) Expire(ctx context.Context, key string, ttl time.Duration) error { return errors.New("faulty") }
      func (f *faultyRedis) CountKeys(ctx context.Context, pattern string) int { return 0 }
      ```

### 248.3 — Pipeline Integration (Go)
**Size:** MEDIUM | **Dependencies:** 248.2

Integrate the offense counter into `internal/security/pipeline.go`.

The integration point is **after** the rate limiter runs but **before** the action
decider decides the final action.

Look at `processInternal()` in `pipeline.go`. The rate limiter runs at around
line 550. It returns a `[]RiskSignal` slice — each signal has a `Name` field.
The rate limiter uses these names: `"rate_limit_suspicious"`, `"rate_limit_block"`,
`"rate_limit_ban"`. There is no `RateLimiterResult` type — it is a plain slice.

Add the offense counter logic immediately after the rate limiter call:

```go
rlSignals := p.rateLimiter.Check(ctx, conn.ClientIP, conn.JA4)
signals = append(signals, rlSignals...)

// Auto-escalation: if rate limiter fired, increment offense counter and check
// whether the accumulated offense count warrants a stronger action.
if len(rlSignals) > 0 && p.offenseCounter != nil {
    count, _ := p.offenseCounter.Increment(ctx, conn.ClientIP)
    // EscalatedAction re-reads offense:{ip} via GetString internally — a second
    // Redis round-trip. Acceptable: this path only runs on rate-limit hits (uncommon).
    if escalated, _ := p.offenseCounter.EscalatedAction(ctx, conn.ClientIP); escalated != "" {
        p.log.WithFields(logrus.Fields{
            "event.action":             "offense_escalation",
            "client.ip":                conn.ClientIP,
            "offense.count":            count,
            "offense.escalated_action": escalated,
        }).Warn("offense escalation")
        metrics.OffenseEscalationsTotal.WithLabelValues(escalated).Inc()
        if escalated == "ban" {
            // Write ban:{ip} using SetString (the method on RedisReader).
            // This is the same key pattern as manual bans (ban:{ip}), so the
            // existing ban-check bypass at the top of the pipeline fires on the
            // NEXT connection — the IP is hard-blocked before scoring.
            banKey := fmt.Sprintf("ban:%s", conn.ClientIP)
            reason := fmt.Sprintf(
                `{"reason":"auto_escalation","offense_count":%d,"auto":true}`, count)
            p.redis.SetString(ctx, banKey, reason, p.cfg.AutoEscalate.BanHours*3600)
        }
        return &PipelineResult{Action: escalated, Score: 100, BypassReason: "auto_escalation"}
    }
}
```

Add `offenseCounter *OffenseCounter` to the `Pipeline` struct. In `NewPipeline`
and `ReplaceConfig`, set it to `NewOffenseCounter(redis, &cfg.AutoEscalate, log)`
when `cfg.AutoEscalate.Enabled` is true, and `nil` when false.

**Observability:**
Add a Prometheus counter: `ja4proxy_offense_escalations_total{action="tarpit|block|ban"}`.
Add it to `internal/metrics/metrics.go` following the existing counter patterns.

**Files to modify:**
- `internal/security/pipeline.go` — add `offenseCounter` field, initialise in
  `NewPipeline`/`ReplaceConfig`, add escalation logic after rate limiter call
- `internal/metrics/metrics.go` — add `OffenseEscalationsTotal` counter

**Acceptance criteria:**
- [ ] Rate-limited connections increment the offense counter
- [ ] Connections with no rate-limit signal do NOT increment the counter
- [ ] When `auto_escalate.enabled = false`, `p.offenseCounter` is nil and the
      block is skipped entirely (nil check in the code above handles this)
- [ ] At offense count ≥ ban_at_offense, `ban:{ip}` key is written via `SetString`
- [ ] Auto-ban key matches the `ban:{ip}` pattern of manual bans
- [ ] Prometheus counter incremented on each escalation
- [ ] ECS log line emitted on each escalation
- [ ] Existing pipeline tests still pass
- [ ] New chaos test: `p.redis.Incr()` returns error → offense counter returns 0,
      pipeline continues with normal action (fail open)

### 248.4 — Management UI: IP Offense Display
**Size:** SMALL | **Dependencies:** 248.2

Add the offense count to the IP detail page and the attack dashboard (Phase 247).

**New API endpoint:** `GET /api/v1/ip/{ip}/offense`

```json
{
  "ip": "198.51.100.42",
  "offense_count": 5,
  "current_action": "ban",
  "ban_expires": "2026-06-26T02:00:00Z"
}
```

This reads directly from `offense:{ip}` and `ban:{ip}` in Redis.

**File to create:** `management/api/routes/offense.py`

**Auth:**
- `GET /api/v1/ip/{ip}/offense` — `Depends(require_role(Role.auditor))` (all roles)
- `DELETE /api/v1/ip/{ip}/offense` — `Depends(require_role(Role.admin))` + `Depends(require_mfa_verified)`

**UI changes:**
- `management/templates/ip_detail.html` — add "Offense Count" field.
  First check if this file exists. If not, create it with the scaffold pattern:
  `{% extends "base.html" %}` / `{% block content %}` / `{% endblock %}`,
  then add a page route in `pages.py` and a sidebar link in `base.html`.
- `management/templates/partials/attack_table.html` (created in Phase 247.3) —
  add "Offenses" column to the attacker table

**Reset button:**
In the IP detail view, add a "Reset Offense Count" button (admin only) that calls:
```
DELETE /api/v1/ip/{ip}/offense
```
This calls `offenseCounter.Reset()` and writes an audit log entry.

**Acceptance criteria:**
- [ ] `GET /api/v1/ip/{ip}/offense` returns offense count and ban status
- [ ] `GET` uses `Depends(require_role(Role.auditor))`
- [ ] `DELETE /api/v1/ip/{ip}/offense` resets count and writes audit entry
- [ ] `DELETE` uses `Depends(require_role(Role.admin))` + `Depends(require_mfa_verified)`
- [ ] IP detail page shows offense count
- [ ] Reset button visible to admin users, hidden from auditor role
- [ ] Unit tests for both endpoints

### 248.5 — Attack Mode Integration
**Size:** SMALL | **Dependencies:** 247.1, 248.1

When Attack Mode (Phase 247) is activated, auto-escalation should also activate —
this is what the owner wants when they hit the panic button.

> ⚠ **Sequential implementation note:** This sub-phase modifies `attack_mode.py`
> created in Phase 247.1. Implement phases 247, 248, and 249 **in order**.

**Python side (management API):**

Modify `POST /api/v1/attack-mode` in `attack_mode.py` to also write:
```python
await redis.set("attack_mode:escalate", "1", ex=revert_after_hours * 3600)
```

Modify `DELETE /api/v1/attack-mode` to also delete `attack_mode:escalate`:
```python
await redis.delete("attack_mode:escalate")
```

After writing these keys, publish to `config:reload` so the Go proxy picks up
the change immediately. Use the same pattern as `management/api/routes/config_ops.py`:
```python
from ..pubsub_signing import build_envelope
payload = build_envelope("config:reload", datetime.now(timezone.utc).isoformat())
await redis.publish("config:reload", payload)
```

**Go side (proxy):**

**Important:** Redis TTL expiry fires no Go callback. The proxy will NOT
automatically notice when `attack_mode:escalate` expires. The mechanism is:

1. On every `config:reload` pub/sub event, the proxy calls `proxy.reload()` in
   `cmd/ja4pd/main.go` (see the closure at line ~106).
2. Inside `proxy.reload()`, after rebuilding `PipelineConfig` from the file,
   check Redis for `attack_mode:escalate`:
   ```go
   if p.redis.GetString(ctx, "attack_mode:escalate") == "1" {
       pipelineCfg.AutoEscalate.Enabled = true
   }
   ```
3. Pass the modified config to `p.pipeline.ReplaceConfig(pipelineCfg)`.

This means when Attack Mode expires (TTL fires), the `attack_mode:escalate` key
is gone. The NEXT `config:reload` event will not see the key and will rebuild
config from the file (where `auto_escalate.enabled: false`). The management API's
existing Phase 237 revert poller will publish a `config:reload` when the dial
auto-reverts — this naturally triggers the proxy to check for `attack_mode:escalate`
and revert auto-escalation too. No extra timer needed.

**Where to add this in `main.go`:** Search for `proxy.reload()` — it is called
inside the `pubsubHandler` closure at line ~106. The `reload()` function itself
is at line ~1072 and calls `p.pipeline.ReplaceConfig(pipelineCfg)`. Add the
`GetString` check between building `pipelineCfg` and calling `ReplaceConfig`.

**Acceptance criteria:**
- [ ] `POST /api/v1/attack-mode` sets `attack_mode:escalate` with same TTL as `attack_mode:active`
- [ ] `POST /api/v1/attack-mode` publishes to `config:reload`
- [ ] `DELETE /api/v1/attack-mode` deletes `attack_mode:escalate` and publishes `config:reload`
- [ ] Go proxy `reload()` checks `attack_mode:escalate` and sets `AutoEscalate.Enabled=true` if present
- [ ] When `attack_mode:escalate` is absent on next reload, auto-escalation reverts to file config
- [ ] `GET /api/v1/attack-mode` response includes `escalation_active: true|false`
      (check `attack_mode:escalate` key existence)

### 248.6 — Tests
**Size:** MEDIUM | **Dependencies:** 248.1–248.5

**`internal/security/offense_counter_test.go`:**
- Increment returns 1 on first call
- Increment returns N on Nth call
- EscalatedAction returns "" below tarpit threshold
- EscalatedAction returns "tarpit" at tarpit_at_offense
- EscalatedAction returns "block" at block_at_offense
- EscalatedAction returns "ban" at ban_at_offense
- EscalatedAction returns "" when enabled=false
- Shared-IP: does not increment when threshold exceeded
- Redis down: Increment returns 0, does not panic

**`internal/security/pipeline_escalation_test.go`:**
- Rate-limited connection → counter increments
- Allowed connection → counter does not increment
- Auto-ban key is written at ban threshold
- Auto-ban key has correct TTL
- Prometheus counter increments

**`management/tests/test_offense.py`:**
- GET returns 0 for unknown IP
- GET returns correct count after Go proxy writes it
- DELETE resets count
- Audit log entry written on reset

## Out of Scope

- Per-JA4 offense tracking (could be a future refinement — IP-level is sufficient here)
- Machine-learning-based escalation (future phase)
- Webhooks on escalation (Phase 100 covers webhook delivery)
- Persistent offense history / reporting (ephemeral Redis TTL is intentional)

## Architecture Notes for Junior Engineers

**Why INCR instead of SET?**

`INCR` is atomic in Redis — if two connections from the same IP arrive simultaneously,
each one atomically increments the counter by 1. If you used `GET` then `SET`, two
simultaneous connections could both read the same count and set it to the same value,
losing one increment. Always use `INCR` for counters in Redis.

**Why does the ban key use the same format as manual bans?**

The ban-check bypass at the top of the pipeline (`ban:{ip}` key exists → BLOCK)
already exists and already works. If auto-escalation wrote bans to a different key,
it would need to add its own bypass check. Reusing the existing key means auto-bans
get the exact same fast-path treatment as manual bans, with no code duplication.
The audit trail (reason JSON field with `"auto":true`) distinguishes them.

**Why is auto-escalation off by default?**

The owner who deploys JA4proxy for the first time is in monitor mode (dial=0).
Auto-escalation with dial=0 would do nothing anyway (dial=0 means always allow).
But more importantly: a new user should understand what the proxy is doing before
they enable automation. The first-5-minutes guide (Phase 246) walks them through
raising the dial manually. Auto-escalation is the next step once they trust the
scoring.

## Redis Keys Introduced

| Key | Type | TTL | Purpose |
|-----|------|-----|---------|
| `offense:{ip}` | String (int) | `offense_ttl_hours * 3600` | Persistent offense count per IP |
| `attack_mode:escalate` | String | `revert_after_hours * 3600` | Enables auto-escalation during attack mode |

## CHANGELOG Fragment

Add `docs/fragments/phase-248-auto-escalation.md`:

```markdown
### Added
- Auto-escalating IP defense: IPs that persist after tarpit are automatically
  blocked, then banned, without requiring manual intervention
- `auto_escalate` config section with conservative defaults (off by default)
- Offense counter visible in IP detail view with admin reset
- Attack Mode now also activates auto-escalation for its duration
```
