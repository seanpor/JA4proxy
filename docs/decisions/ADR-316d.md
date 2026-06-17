# ADR-316d: TAP enforcement reuses the `ban:{ip}` key, not pub/sub or external blockers

**Status:** Accepted
**Date:** 2026-06-17
**Phase:** 316 (Go TAP/SPAN passive sensor — sub-phase 316d)

---

## Context

Phase 316d lets the passive sensor *act* on what it observes. The original 316d
outline — inherited from the archived Python sensor (`5afeba26`) — proposed
publishing ban intents to a `ja4proxy:bans` pub/sub channel and driving
out-of-band blockers directly from the sensor: iptables/ipset, a BGP
blackhole named-pipe, and an HMAC-SHA256 webhook.

A critical review before implementation found that design is wrong for the
current Go architecture:

1. **`ja4proxy:bans` has no consumer.** Nothing in the Go codebase subscribes to
   it. Writing to it would be a dead channel — the same "writes a key nobody
   reads" defect caught and fixed in 316c.
2. **The external blockers are the wrong surface for this binary.** The sensor
   is deliberately least-privilege: `CAP_NET_RAW` for capture and a Redis ACL of
   `~fp:* +set +expire -@all` (ADR-316a, runbook). Wiring it to mutate the host
   firewall, speak BGP, or call external endpoints is a large privilege and
   blast-radius expansion that contradicts the standalone design. Those are
   external-integration concerns — Phase 316e (exporters) or a dedicated
   appliance, not the passive sensor.
3. **The inline proxy already has a live ban channel.** `internal/security/
   pipeline.go` (Phase 231a) hard-blocks on `EXISTS ban:{ip}`, evaluated before
   the dial. That is the project's actual ban mechanism in Go.

## Decision

The sensor enforces by writing the canonical **`ban:{ip}`** key the inline proxy
already reads — nothing more — and it does so in two tiers:

- **Advisory (default):** a blocklisted JA4T is recorded to
  `fp:ban_intent:ip:{ip}` (under the existing `~fp:*` ACL). Nothing blocks; this
  is the monitor-first surface.
- **Armed (opt-in):** with `--enforce` **and** a widened ACL (`~ban:*`), a match
  also writes a short-TTL `ban:{ip}` (provenance value `tap_enforce:ja4t=…`).
  The inline proxy blocks the client's *next* connection.

The `ja4proxy:bans` pub/sub and the iptables/BGP/webhook blockers are **dropped**
from 316d. CIDR auto-expansion is **out of scope** (single-IP only).

## Consequences

- **No dead writes.** The enforcement path targets a consumer that already
  exists and is exercised by the manual-ban tests.
- **Least-privilege preserved by default.** Active blocking requires a conscious
  two-step (flag + ACL grant); the default ACL physically prevents a `ban:`
  write, so misconfiguration fails safe.
- **Fail-open and self-healing.** Any Redis error drops the action; the ban TTL
  is short (default 5m) so a misfire on a passively-guessed fingerprint expires
  quickly — consistent with the core asymmetry.
- **Provenance over a dedicated key.** The inline `EXISTS` check ignores the
  value, so encoding origin (`tap_enforce:…`) in the value gives attribution and
  redaction without a second hot-path lookup.
- **Metric rename.** The outline's `ja4proxy_tap_enforcement_errors_total` is
  folded into `ja4proxy_tap_enforcement_actions_total{result="error"}` — one
  counter, one taxonomy (`skipped|watchlist|banned|error`).
- External/network-level blocking, if ever wanted, is a separate decision under
  316e — not silently bundled into the sensor.
