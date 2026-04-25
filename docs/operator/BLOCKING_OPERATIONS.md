<!--
title: "Blocking Operations — Operator Reference"
audience: operators
last_reviewed: 2026-04-25
phase: 105
-->

# Blocking Operations — Operator Reference

> One canonical reference for how JA4proxy decides to block, what knobs you
> have, and how to investigate a block in production. Replaces (and
> consolidates) the four pre-Phase-105 blocking docs — see "Provenance" at
> the bottom.

This document is the single source of truth for operator-facing blocking
behaviour. The proxy's *internal* design — risk signals, scorer composition,
ADRs — is documented under `docs/for-architects/` and `docs/decisions/`.
This page is for the engineer who needs to enable blocking, raise the dial,
or explain why a particular connection was dropped.

---

## When JA4proxy Blocks

JA4proxy decides to drop, tarpit, or ban a TCP connection at exactly two
points in the pipeline:

1. **Hard bypass blocks** — happen before any scoring runs. They short-circuit
   the pipeline with an immediate RST. Only a small, deliberate set of
   conditions trigger them (see "Block Categories" below). They are
   **unaffected by the dial**.
2. **Scored blocks** — every connection that survives the bypass stage is
   scored by the composite risk scorer. The score (0–100) is compared against
   five effective thresholds (`flag`, `rate_limit`, `tarpit`, `block`, `ban`),
   each of which is interpolated from the dial (see "Operator Knobs"). If the
   score meets or exceeds the `block` (or `ban`) threshold, the action is
   taken.

Allow-bypasses (h2/h1 ALPN, JA4 whitelist, mTLS) **always win**. They cannot
be overridden by score or by the dial — by design. To score traffic that
would otherwise allow-bypass, disable the corresponding bypass in
`config/proxy.yml` rather than raising the dial.

---

## Block Categories

There are two distinct categories of blocking. Understand which one you are
operating before tuning anything.

### Hard bypass blocks (pre-scorer, dial-independent)

| Condition | Source | Notes |
|-----------|--------|-------|
| JA4 in **blacklist** | Redis SET `ja4:blacklist` + in-process mirror | O(1) match. Loaded at startup; updated via pub/sub. |
| Country in blacklist | MaxMind GeoLite2-Country mmap | Edge case — used sparingly. |
| Spamhaus DROP / EDROP CIDR match | Pytricia trie (Phase 8) | Updated by leader-elected feed manager; ETag-cached. |

Hard blocks send an immediate TCP RST and never reach the scorer. They have
no concept of "dial" — they are absolute. To disable any of them, set the
corresponding key under `security_policy` in `config/proxy.yml` and reload.

### Scored blocks (dial-aware, threshold-based)

The scorer aggregates risk signals from the modules listed in `CLAUDE.md`'s
pipeline (TLS, SNI, TCP/conn, ASN, FCrDNS, beaconing, AbuseIPDB, RDAP,
analytics) into a single score 0–100. The `ActionDecider` then maps the
score to one of five actions using the **effective thresholds** at the
current dial.

The five default configured thresholds (at dial=100) are:

```yaml
risk_scorer:
  thresholds:
    flag: 20          # Connection allowed; elevated logging.
    rate_limit: 35    # Connection rate-limited.
    tarpit: 55        # Connection slow-drained.
    block: 70         # Connection rejected with RST.
    ban: 85           # Rejected; IP banned for ban_duration_seconds.
  ban_duration_seconds: 300  # 5 min default
```

(From `config/proxy.yml`. These can be tuned, but are very rarely changed —
the dial is the operator's primary lever.)

---

## Operator Knobs

### The dial: 0 → 100

The dial is the single most important operator-facing setting. It scales
all five action thresholds simultaneously via the **interpolation formula**:

```
effective_threshold = round(101 - (dial/100) × (101 - configured_threshold))
```

(Banker's rounding — Python's `round()` and Go's `math.RoundToEven`. Both
implementations produce byte-identical results; this is verified by parity
tests in `internal/security/action_decider_test.go`.)

At `dial=0`, every effective threshold is **101 — unreachable.** Nothing is
ever blocked, regardless of score. This is monitor mode.

At `dial=100`, the effective thresholds equal the configured thresholds:
`block=70`, `ban=85`, etc.

In between, all five thresholds slide linearly toward the configured values
as the dial rises.

### Effective threshold table (canonical)

> The four pre-Phase-105 source docs each contained a different — and in
> several cases, **incorrect** — version of this table. The values below are
> computed directly from the formula in `src/security/action_decider.py`
> (`effective_threshold()`) and `internal/security/action_decider.go`
> (`EffectiveThreshold()`). If you spot a divergent table elsewhere in the
> repo, treat *this* table as authoritative and open an issue.

| Dial | Flag | Rate-limit | Tarpit | Block | Ban  |
|------|------|------------|--------|-------|------|
| 0    | 101  | 101        | 101    | 101   | 101  |
| 25   |  81  |  84        |  90    |  93   |  97  |
| 50   |  60  |  68        |  78    |  86   |  93  |
| 75   |  40  |  52        |  66    |  78   |  89  |
| 100  |  20  |  35        |  55    |  70   |  85  |

Worked examples (from the Python and Go docstrings):

- `effective_threshold(70, 50)` → `round(101 − 0.5 × 31)` = `round(85.5)` = **86**
- `effective_threshold(20, 50)` → `round(101 − 0.5 × 81)` = `round(60.5)` = **60**

### `monitor_mode` config block

```yaml
monitor_mode:
  dial: 0                              # 0 = monitor only. 100 = full blocking.
  blocking_acknowledged: false         # Safety gate. Must be true for dial > 0 to take effect.
  log_counterfactuals: true            # Include "would=action@dial" in MONITOR log lines.
  counterfactual_thresholds: [25, 50, 75, 100]
  max_dial_change_per_hour: 25         # Rate-limit dial changes (prevents 0→100 jumps).
  alert_on_dial_change: true           # Emit structured log on every dial change.
```

(Source: `config/proxy.yml` lines ~401–415.)

### Three independent safety features

These are **not redundant** — disabling any one removes a guarantee.

1. **The safety gate (`blocking_acknowledged`).**
   `DialManager.initialize()` reads the dial from Redis at startup. If
   `blocking_acknowledged: false`, it overrides any non-zero dial and resets
   to 0, logging a `dial | event=reset_unacknowledged` warning. **This means
   you cannot enable blocking by writing `config:dial = 50` in Redis alone.**
   You must also flip `blocking_acknowledged` in `config/proxy.yml` (or via
   the Management UI).
   (Originally documented in `BLOCKING_ANALYSIS.md` and
   `FINAL_BLOCKING_TEST_SUMMARY.md`; both attempted Redis-only changes and
   discovered the gate the hard way.)
2. **Dial-change rate limit (`max_dial_change_per_hour: 25`).**
   Prevents accidental 0→100 jumps via a fat-fingered config change or a
   misconfigured automation. Emergency override via `force=True` when calling
   the dial-change API.
3. **Fail-open behaviour.**
   - Redis unreachable → use the locally cached dial.
   - Configuration parse error → fall back to safe defaults.
   - Rate limiter unavailable → fail open (no block).

### Hot-reloadable vs not

**Hot-reloadable** (SIGHUP or Redis pub/sub `config_reload`):

- `monitor_mode.dial`
- `monitor_mode.blocking_acknowledged`
- `risk_scorer.thresholds.*`
- All `security_policy` bypass toggles
- `tarpit.drain_timeout_seconds`

**Restart required:**

- Listen port
- Redis URL
- TLS certificate paths
- `abuseipdb.worker_count` and `abuseipdb.queue_size` (Phase 10 — WARN logged
  if changed without restart)
- `enabled` flips on background-service modules (e.g. AbuseIPDB) where the
  service must be started/stopped.

---

## How to Change the Dial

There are three supported methods. Method 2 is recommended.

### Method 1 — Configuration file (requires SIGHUP or restart)

```yaml
# config/proxy.yml
monitor_mode:
  dial: 50
  blocking_acknowledged: true
```

Then trigger reload:

```bash
# Hot reload via SIGHUP (zero-traffic-gap):
docker compose kill -s HUP proxy

# OR full restart (causes brief disconnect):
docker compose restart proxy
```

### Method 2 — Pub/Sub (recommended, zero downtime)

```bash
# config/proxy.yml must already have blocking_acknowledged: true.
python3 set_dial.py 50
```

This publishes a `dial_change` message on Redis pub/sub. All proxy
instances pick up the new dial within ~50 ms. The change is also persisted
to `config:dial` so a restart will retain the value.

### Method 3 — Redis direct (immediate, but bypasses pub/sub fan-out)

```bash
docker compose exec redis redis-cli -a "${REDIS_PASSWORD}" set "config:dial" 50
```

> **Caveat:** the safety gate still applies. If `blocking_acknowledged` is
> `false` in `config/proxy.yml`, the proxy will reset the dial back to 0 on
> its next initialization. Use this method only when the gate is already
> open. (See "What we tried that did not work" below.)

### Recommended progression

A first-deploy progression learned from real DMZ rollouts:

| Phase | Dial | Duration | Goal |
|-------|------|----------|------|
| 1. Baseline | 0    | 1–2 weeks | Observe traffic patterns and score distribution. Counterfactual logs tell you what *would* be blocked. |
| 2. Conservative | 25 | 1 week | Block the very-highest-risk traffic only. Effective `block ≥ 93`, so legitimate browser traffic (typical scores 10–30) is untouched. |
| 3. Moderate | 50 | 2–4 weeks | Production-grade blocking. Effective `block ≥ 86`. Recommended end-state for most deployments. |
| 4. Aggressive | 75 | 2+ weeks, close monitoring | High-security environments only. Effective `block ≥ 78` — borderline cases get caught, FP risk rises. |
| 5. Maximum | 100 | Generally avoid | All configured thresholds active. FP risk significant; only used when the score distribution is well-understood. |

(Originally from `blocking-guide.md` and `BLOCKING_ANALYSIS.md` — they agreed
on the progression, even where their threshold tables disagreed.)

---

## Investigating a Block — the Runbook

When an alert fires or a user reports being blocked, work through these
steps in order.

### Step 1 — Capture the connection identifiers

You need at least one of:

- **Source IP** (full IPv4 or canonical IPv6 — never abbreviate)
- **JA4 fingerprint** (`t13d1516h2_aabbccddeeff_aabbccddeeff` shape)
- **Connection ID** (from access log line)

### Step 2 — Determine which category triggered the block

```bash
# Was it a hard bypass block?
docker compose exec redis redis-cli -a "${REDIS_PASSWORD}" SISMEMBER ja4:blacklist <ja4>
docker compose exec redis redis-cli -a "${REDIS_PASSWORD}" KEYS "ban:ip:<ip>"

# Was it scored?
docker compose logs proxy | grep "<connection_id>" | grep -E "score=|action="
```

A hard-bypass block log line looks like:

```
BLOCK | category=hard_bypass | reason=ja4_blacklist | ja4=t13...
```

A scored block log line looks like:

```
BLOCK | category=scored | score=87 | action=block | dial=50 | signals=[tcp_burst,asn_datacenter,...]
```

### Step 3 — If scored: dump the contributing signals

Look for the `signals=[...]` field in the block log line. Each signal name
maps to a signal module in `src/security/` (Python prototype) or
`internal/signals/` (Go production). The block reason is **the sum of all
signals**, so identify the top contributors.

```bash
# The score breakdown is in the structured JSON log:
docker compose logs proxy --tail=1000 | grep "<connection_id>" | jq '.signals'
```

### Step 4 — If hard-bypass: confirm the source feed

```bash
# Spamhaus DROP/EDROP — check feed freshness:
curl -s localhost:9090/metrics | grep ja4proxy_blocklist_last_update_seconds

# JA4 blacklist — when was this entry added?
docker compose exec redis redis-cli ZSCORE ja4:blacklist:audit <ja4>
```

### Step 5 — Validate against bypass rules

- Did the connection have `h2`/`h1` ALPN? If yes, it should never have been
  scored. Check `security_policy.bypass.h2_alpn` is still enabled.
- Was the JA4 in the whitelist? Whitelist always wins.
- Was mTLS verified? If the client presented a valid cert, the connection
  should bypass scoring entirely.

### Step 6 — Decide

If the block is a **true positive**: log the case, optionally add the source
to the JA4 blacklist for hard-block status.

If the block is a **false positive**:

- Add the JA4 to the whitelist (immediate ALLOW bypass): persists across
  restarts, propagated by pub/sub.
- If the FP is broader than one JA4, consider lowering the dial.
- Open an issue tagged `false-positive` with the score breakdown so the
  signal weights can be re-tuned in a future phase.

---

## Validating a Block Rule

Before raising the dial in production, validate against your traffic.

### Counterfactual analysis (preferred — zero risk)

Set `monitor_mode.log_counterfactuals: true`. The proxy still allows every
connection but logs `would=block@dial=50` annotations. Aggregate over a
representative window (24 h minimum):

```bash
# How many connections would be blocked at each candidate dial?
curl localhost:9090/metrics | grep ja4proxy_monitor_counterfactual_total

# Example shape:
# ja4proxy_monitor_counterfactual_total{action="block",dial="50"} 1042
# ja4proxy_monitor_counterfactual_total{action="block",dial="75"} 2870
```

Compare the would-be-blocked counts to your known-legitimate traffic. If
`block@dial=50` includes any of your real users' JA4 fingerprints, you have
a false-positive problem to solve before raising the dial.

### FP corpus (during development of new signals)

Phase 16 introduced an FP corpus: `tests/adversarial/test_fp_corpus.py`
runs scored signals against the Tranco top-10 000 list. Any new signal
**must** pass this gate before being merged. (See `docs/TESTING_STRATEGY.md`.)

### Score distribution

```bash
# Histogram — looks for bimodality (legit cluster <30, malicious cluster >50)
curl localhost:9090/metrics | grep ja4proxy_risk_score_distribution_bucket
```

Healthy distribution: clear separation between the legit and malicious
clusters, with a sparsely populated middle band. If your distribution is
unimodal or has a heavy middle, the dial cannot cleanly separate good from
bad — you need better signals before raising the dial.

---

## Common Blocking Mistakes

These are the FP traps that have actually bitten operators in past
deployments. Read them once.

### "I set `config:dial = 50` in Redis but blocking didn't activate."

You forgot the safety gate. The safety gate is not a bug — it deliberately
ignores Redis if `blocking_acknowledged` is `false` in `config/proxy.yml`.
Fix:

1. Edit `config/proxy.yml`: set `monitor_mode.blocking_acknowledged: true`.
2. SIGHUP or restart the proxy.
3. Look for `dial | event=reset_unacknowledged` in logs — its **absence**
   confirms the gate is open.

(Originally documented across `blocking-test-analysis.md` and
`FINAL_BLOCKING_TEST_SUMMARY.md`. Both authors burned hours on it.)

### "I expanded a /16 RDAP CIDR and took out an entire ISP's customers."

RDAP block expansion is **off by default** for exactly this reason. When
enabled, never allow expansion beyond `/24` (IPv4) or `/48` (IPv6). The
hourly cap (`rdap.expansion.hourly_cap`, default 10) is a circuit breaker —
do not raise it without a written rationale.

### "The dial jumped from 0 to 100 because of a config-management glitch."

`max_dial_change_per_hour: 25` exists for this. Do not disable it. If your
automation needs faster ramping, send four discrete pub/sub messages
spaced 60 minutes apart, not one big jump.

### "Legitimate traffic is being blocked but the JA4 is not in any list."

It's a scored block, not a hard block. Check:

- The score breakdown — what signals contributed?
- Was mTLS or ALPN bypass disabled? (If yes, was that intentional?)
- Is the dial too high for your observed score distribution? Most operators
  start with `dial=25` for at least a week before moving to `dial=50`.

### "I disabled the h2/h1 ALPN bypass to score browser traffic."

You can do this — but be aware that **every browser connection** will then
be scored. The risk-signal modules were not designed under that assumption;
many of them assume browsers are pre-cleared. Do not do this in production
without first running the FP corpus against your traffic.

### "I'm using `dial=100`."

Don't, except for very specific high-security deployments where you have
already proven the score distribution is bimodal. The recommended end-state
is `dial=50`. The combination of `dial=100` + default thresholds is known
to produce false positives on legitimate "power-user" traffic (curl, wget,
some CI runners) that score in the 20–40 range.

---

## Monitoring and Alerts

### Key Prometheus metrics

```bash
# Current dial value (gauge)
curl localhost:9090/metrics | grep ja4proxy_dial_current

# Blocked connections (counter, by action and reason)
curl localhost:9090/metrics | grep ja4proxy_blocked_total

# Action breakdown (counter)
curl localhost:9090/metrics | grep ja4proxy_action_total

# Score distribution (histogram)
curl localhost:9090/metrics | grep ja4proxy_risk_score

# Counterfactual ledger (counter — only populated when log_counterfactuals=true)
curl localhost:9090/metrics | grep ja4proxy_monitor_counterfactual_total
```

(Exact metric names are documented in `docs/OBSERVABILITY_STANDARDS.md`. If
you see `ja4_*` rather than `ja4proxy_*` in the wild, those are
pre-Phase-14e names — they were renamed during the Phase 14e observability
audit.)

### Alert thresholds (suggested)

| Severity | Condition | Action |
|----------|-----------|--------|
| CRITICAL | Any legitimate-tagged JA4 in the blocked stream | Page immediately. |
| WARNING  | Block rate increases by >20 % in 5 min | Investigate. |
| WARNING  | Dial changes unexpectedly (no operator action) | Investigate. |
| INFO     | Block rate sustained >50 % | Monitor — could be an active attack. |

(See `docs/runbooks/ja4proxy_block_rate_high.md` for the per-alert
playbook.)

### Success vs failure criteria for a blocking rollout

**PASS:**

- 0 % legitimate traffic blocked.
- 50–70 % of malicious traffic blocked at `dial=50` (typical baseline).
- No service disruption.
- System stable and within p99 latency budget.

**FAIL — rollback to `dial=0` immediately:**

- >0.5 % legitimate traffic blocked.
- Any unexpected proxy errors or crash loops.
- Backend latency degradation.
- User-reported breakage.

---

## Historical Context

The four pre-Phase-105 source docs were all written during a single Phase-21
sprint that attempted to enable blocking mode on a test cluster. The sprint
discovered the safety gate (working as designed), produced the
counterfactual analysis, and validated that the threshold formula is
internally consistent across the Python prototype and (then-emerging) Go
production proxy. The findings were ultimately consolidated into the
working safety procedures above — there is nothing additional in the
sprint summaries that an operator needs day-to-day. The historical
artefacts remain in git history (`git log --oneline -- docs/operator/`) for
anyone reconstructing how the safety gate was discovered.

---

## Provenance

This document consolidates four pre-Phase-105 sources, all retained in git
history:

- `docs/operator/blocking-guide.md` — Phase-14-era operator how-to
  (step-by-step config-and-restart procedure, dial progression). Its
  threshold table for `dial=25`/`75` was incorrect; the canonical formula
  is now reproduced above.
- `docs/operator/BLOCKING_ANALYSIS.md` — analysis of decision flow at each
  dial level. Its threshold table was incorrect (used the wrong formula);
  superseded by the table above.
- `docs/operator/blocking-test-analysis.md` — test-coverage gap analysis
  from the Phase-21 blocking sprint, including a forensic walk-through of
  the safety-gate symptoms.
- `docs/operator/FINAL_BLOCKING_TEST_SUMMARY.md` — closing summary of the
  same sprint. Mostly historical; reduced to one paragraph in "Historical
  Context" above.

For the underlying invariants ("when in doubt, fail open"; "ALLOW bypasses
ignore the dial"; etc.) see the **Core Asymmetry** and **Cross-Cutting
Requirements** sections of `CLAUDE.md`.
