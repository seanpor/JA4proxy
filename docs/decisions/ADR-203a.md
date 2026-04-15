# ADR-203a: Go Inline Proxy Consumes Phase-20 TAP JA4T from Redis (Does Not Compute It)

**Status:** Accepted
**Date:** 2026-04-15
**Phase:** 203 (Go Missing Signals — sub-phase 203a)

---

## Context

Phase 203a calls for a JA4T-derived OS-class mismatch signal
(`tap_os_mismatch`) in the Go production proxy. The original phase-doc draft
proposed computing JA4T directly inside `handleConnection()` by reading socket
options after `accept()`. The critical review
(`docs/phases/PHASE_203_review.md`) found that premise unsound on three
independent grounds:

1. **Format mismatch.** The draft's proposed string
   (`{ttl}_{mss}_{window_size}_{options_hash[:8]}`) disagrees with the
   authoritative JA4T format implemented in
   `src/tap/fingerprints/ja4t.py:32-44`:
   `{window_size}_{mss}_{options_order}_{window_scale}`.
2. **Impossible from `accept()`.** By the time a Go listener's `accept()`
   returns, the kernel has consumed the client's SYN and completed the
   three-way handshake. `syscall.GetsockoptInt(fd, SOL_TCP, …)` returns the
   proxy's *send-side* parameters of the *negotiated* connection, not the
   client's original SYN options. Window scale, options order, and MSS as
   offered by the client are unrecoverable at this layer.
3. **Three conflicting definitions of "JA4T" already exist** in the repo:
   the TAP-node definition (authoritative), the existing Go stub
   `internal/tls/ja4t.go` (a TLS-alert-codes function that isn't JA4T at
   all), and the phase-doc draft's TTL-hash definition. Any of the three
   would compile; at most one is correct.

A live inline TCP listener has exactly three mechanisms by which the client's
SYN-level state can be recovered. This ADR enumerates them and picks one.

---

## Options Considered

### Option A — eBPF / XDP hook before the kernel handshake

An eBPF/XDP program attached to the ingress netdev can observe the SYN packet
before the kernel processes it, extract window-scale / MSS / options-order,
and pass the result to user-space (e.g. via BPF maps). This is the
highest-fidelity option.

**Rejected for Phase 203a:**
- Large project on its own (program authoring, loader, verifier, privileged
  deployment, kernel-version matrix).
- Requires `CAP_BPF` (or `CAP_SYS_ADMIN` pre-5.8) on the proxy container —
  contradicts the project's "Go proxy runs unprivileged" posture.
- Out of scope for a five-sub-phase defensive-parity phase.

### Option B — PROXY-protocol v2 TLVs from an upstream LB

If the upstream load balancer captures the client SYN and forwards the
extracted fields as PROXY-protocol v2 TLVs, the Go proxy can read them from
the PROXY header on the accepted TCP connection (no raw-socket access
required).

**Rejected for Phase 203a:**
- PROXY-v2 TLV handling is a planned but unshipped feature (Phase 200 is
  listed as a dependency in `docs/phases/manifest.yaml` but has not landed).
- Requires an upstream LB that actually populates the TLVs. Most L4 LBs
  (HAProxy, NGINX stream, AWS NLB with client-IP preservation) do not today.
- Deploying 203a behind this option would indefinitely block the signal on
  a cross-phase dependency that is not guaranteed to land soon.

### Option C — Consume Phase-20 TAP fingerprints from Redis (chosen)

Phase 20 already ships a Python TAP/SPAN-port listener that captures raw
packets via AF_PACKET, computes JA4T per connection, and writes the result
to Redis under well-documented keys (`fp:conn:{id}` Hash; `fp:os:ip:{ip}`
String). The Go inline proxy can **read** those keys on the hot path and
emit a mismatch signal without ever touching raw sockets itself.

This preserves the project's `Go-is-production / Python-is-prototype`
split (see `CLAUDE.md`): the Python TAP node is a legitimate long-lived
Python service because it **is not the proxy** — it is an out-of-band
signal-enrichment service, which CLAUDE.md explicitly permits Python for.

### Option D — Sidecar raw-socket capture co-located with each proxy

A per-proxy sidecar running AF_PACKET would compute JA4T for the local
traffic and hand it to the proxy via a local Unix socket or shared memory.

**Rejected:**
- Duplicates what Phase 20's TAP node already does, at a finer granularity
  that is operationally more complex (one extra privileged container per
  proxy replica vs. a single TAP node per SPAN port).
- `CAP_NET_RAW` on every proxy host defeats the unprivileged-proxy posture.
- No deployment precedent in this repo; Phase 20 is the precedent.

---

## Decision

**Go proxy consumes Phase-20 TAP-produced JA4T / OS-class data from Redis
and does not compute JA4T itself.**

Concrete design (full spec in `docs/phases/PHASE_203.md` sub-phase 203a):

- A new `TapConsumer` (`internal/security/tap_consumer.go`) exposes
  `GetSignal(ctx, clientIP, ja4) *RiskSignal`.
- On each non-bypassed connection, after JA4 is computed and bypass checks
  have not fired, `TapConsumer` computes `claimed := ja4OSClass(ja4)`,
  reads `GET fp:os:ip:{clientIP}` from Redis (with a 50 ms timeout and a
  short-lived `LocalCache` in front), compares to `observed`, and emits
  a `tap_os_mismatch` `RiskSignal` (score 30, capped 30) iff they differ.
- No new Redis keys are introduced — this is a pure read against Phase 20's
  existing schema.
- Default configuration is `tap_consumer.enabled: false`: with the TAP node
  absent, every lookup misses, no signal is ever emitted, and the proxy
  behaves exactly as it does today (fail-open preserved).

The existing dead stub `internal/tls/ja4t.go` (`ComputeJA4T(alertCodes
[]uint8) string`) is **withdrawn** as unrelated dead code and deleted
during 203a implementation.

---

## Consequences

**Positive**

- Clean runtime split: the privileged, raw-socket work stays in the Python
  TAP node where it already lives and is well-tested; the Go proxy stays
  inline, fast, and unprivileged (no `CAP_NET_RAW`, no eBPF, no kernel
  version matrix).
- No new Redis schema; reads only keys Phase 20 already writes.
- Fail-open by default and by design. TAP absent → lookup miss → no signal
  → connection handled exactly as today. TAP present but Redis unreachable
  → 50 ms timeout, no signal, existing fail-open Redis path already handles
  this.
- Hot-path cost is bounded: one `GET` per non-bypassed connection, fronted
  by a 60-second `LocalCache` LRU. Sub-millisecond with local Redis,
  sub-microsecond on cache hits.

**Negative**

- The signal only fires when the Phase-20 TAP node is deployed alongside
  the proxy. Operators who want `tap_os_mismatch` must stand up Phase 20
  (documented in `docs/runbooks/go_proxy_operations.md`).
- The JA4-to-OS mapping table (`ja4OSClass`) is a starter set (5–10
  entries) — gaps are intentional fail-open, not misses. A follow-up
  signal-quality phase will widen it once production telemetry exists.
- Stale TAP fingerprints (e.g. long-lived NAT pools where the current
  client at a given IP is not the one TAP last observed) could produce
  false mismatches. Bounded by `tap_consumer.max_age_seconds: 300` and
  the signal's low score (30, capped 30 — never hard-blocking on its own).

**Withdrawn / not done in this ADR**

- In-proxy JA4T computation via `syscall.GetsockoptInt` — architecturally
  impossible on an accept()'d socket; the existing `internal/tls/ja4t.go`
  stub is deleted during implementation.
- eBPF/XDP packet capture inside the Go proxy — large separate project;
  revisit only if 203a's TAP-consume approach proves insufficient.
- In-proxy AF_PACKET capture / raw-socket sidecar — duplicates Phase 20
  at worse operational cost.
- Expanding the JA4-to-OS mapping table beyond the starter set — deferred
  to a signal-quality follow-up phase informed by production data.

## Revisit if…

- **Phase 200 lands** and the upstream LB fleet gains PROXY-v2 TLV support:
  at that point, the Go proxy can read JA4T-input fields from the PROXY
  header directly, with no TAP-node dependency. A follow-up ADR would
  supersede this one's TAP-consumer decision for deployments where a
  capable LB exists.
- **The JA4-to-OS mapping table** grows past a dozen entries or needs to be
  data-driven (loaded from YAML rather than a static Go map): revisit
  `ja4OSClass`'s implementation in a signal-quality phase.
- **Redis hot-path cost** becomes measurable under benchmark (it should
  not — one `GET` behind a 60 s LRU is cheap): introduce a bloom filter or
  raise `cache_ttl_seconds`, and revisit this ADR only if those fail.

---

## Implementation notes (2026-04-15)

This ADR's decision shipped in commit `03db36e` (phase-203a) on branch
`claude/phase-203-go-signals`. The realised API and fail-open surfaces
follow.

### Public API

```go
// internal/security/tap_consumer.go

type TapConsumerConfig struct {
    Enabled      bool
    SignalScore  int           // default 30 when zero
    RedisTimeout time.Duration // default 50 ms when zero
    CacheTTL     time.Duration // default 60 s when zero
    MaxAge       time.Duration // discard older TAP entries
}

func NewTapConsumer(cfg *TapConsumerConfig, r redisGetter, log *logrus.Logger) *TapConsumer

func (t *TapConsumer) GetSignal(ctx context.Context, clientIP, ja4 string) *RiskSignal
```

`redisGetter` is a narrow interface (`Get(ctx, key) (string, error)`) that
`*redis.Client` satisfies directly and that tests stub trivially.

### Fail-open surfaces (all return `nil` from `GetSignal`)

1. `t == nil` or `cfg == nil` or `!cfg.Enabled`.
2. Empty `ja4` or empty `clientIP`.
3. `ja4OSClass(ja4) == ""` — JA4 prefix not in the starter mapping.
4. Redis `GET` returns an error (timeout, transport, auth) —
   `ja4proxy_tap_lookups_total{result="error"}` increments.
5. Redis `GET` returns empty/nil — `…{result="miss"}` increments.
6. LocalCache hit with empty observed value — short-circuits without a
   Redis round trip.
7. `observed == claimed` — `…{result="hit_match"}` increments, no signal.

Only case 7's inverse (`observed != claimed`, both non-empty) emits a
`tap_os_mismatch` signal (`…{result="hit_mismatch"}` plus
`ja4proxy_tap_signal_total{action="flag"}`).

### JA4 → OS starter mapping (7 entries)

```
t13d1516h2 → windows   (Chrome/Edge on Windows, modern)
t13d1517h2 → macos     (Chrome on macOS)
t13d1715h2 → linux     (Firefox on Linux)
t13d3112h2 → macos     (Safari on macOS)
t13d3113h2 → ios       (Safari on iOS)
t13d0310h2 → linux     (curl / CLI TLS, Linux default)
t13d1314h1 → linux     (Go http.Client on Linux)
```

Unknown prefixes return `""` and the caller emits no signal (fail-open).
A follow-up signal-quality phase, informed by production telemetry, will
widen this table.

### Metrics emitted

- `ja4proxy_tap_lookups_total{result}` — `hit_match` | `hit_mismatch` |
  `miss` | `error`.
- `ja4proxy_tap_signal_total{action}` — action taken by the pipeline when
  the signal fires (`flag` in this phase's default scoring).

Both are standard `CounterVec`s registered via the existing
`MustRegister` pattern in `internal/metrics/metrics.go`.
