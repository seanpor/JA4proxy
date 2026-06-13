# PHASE 316d — TAP Out-of-Band Enforcement Bridge (advisory by default)

> **STATUS: PROPOSED — OUTLINE. Depends on 316a–316c.**
> Detailed plan to be written before start. Security-sensitive — review §"Safety".

## Goal

Let the passive sensor *act* on what it sees — out of band (it is never inline) —
via the same ban channel and external blockers the project already uses.

## Scope

- Publish ban intents to the existing `ja4proxy:bans` pub/sub.
- Optional out-of-band blockers, each isolated and fail-open: iptables/ipset, a
  BGP blackhole named-pipe, and an HMAC-SHA256 webhook.
- Metric `ja4proxy_tap_enforcement_errors_total`.

## Safety (this is the whole point — non-negotiable)

The core asymmetry says a blocked real user is the expensive error, and a passive
sensor classifies traffic with no handshake confirmation and a mirror-only view.
Therefore:

- **Advisory-only by default.** Out of the box the sensor writes to a
  watchlist / counterfactual stream, **not** `ja4proxy:bans`. Active blocking is
  **off by default** and must be consciously enabled.
- **Dial-gated + monitor-first**, exactly like every other enforcement path; emit
  the startup WARN + Prometheus gauge that other high-risk bypasses do when armed.
- **Fail-open:** a capture or Redis failure must never *produce* a ban.
- **Expansion guards:** auto-expansion never exceeds `/24` (v4) or `/48` (v6),
  matching the existing RDAP/block-expansion invariant.

## Key decisions / to detail before start

Per-blocker fail-open contract (log + counter + neutral return for *each* of
iptables/BGP/webhook), the watchlist schema, the opt-in/arming UX + audit trail,
and a full test matrix incl. a "passive misclassification never blocks by default"
acceptance test.
