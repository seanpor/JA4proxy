# PHASE 316d — TAP Out-of-Band Enforcement Bridge (advisory by default)

> **STATUS: APPROVED / IN PROGRESS.** Depends on 316a–316c.
> Re-scoped after critical review (see §1). Security-sensitive — §"Safety" is
> non-negotiable. See `docs/decisions/ADR-316d.md`.

## 1. Critical review of the original outline

The original 316d outline was inherited from the archived Python sensor and does
not fit the current Go architecture. Findings:

- **`ja4proxy:bans` pub/sub has no Go consumer.** Nothing subscribes to it;
  writing to it would be a dead channel — the same dead-key defect fixed in 316c.
- **iptables/ipset + BGP named-pipe + HMAC webhook are the wrong surface for
  this binary.** The sensor is least-privilege by design (`CAP_NET_RAW` +
  Redis ACL `~fp:* +set +expire -@all`, ADR-316a). Driving host firewall / BGP /
  external endpoints from it is a large privilege and blast-radius expansion.
  These belong to Phase 316e (exporters) or a dedicated appliance.
- **The feasible design already has a live consumer.** The inline proxy
  hard-blocks on `EXISTS ban:{ip}` (`internal/security/pipeline.go`, Phase 231a),
  before the dial. That is the project's real ban channel — and exactly what the
  316d *manifest summary* described.

Decision (ADR-316d): the sensor enforces by writing `ban:{ip}` — and only that —
in two tiers. Pub/sub and external blockers are dropped; CIDR expansion is out of
scope.

## 2. Goal

Let the passive sensor act, out of band, on a client whose JA4T is on an
operator-defined enforcement blocklist — by reusing the existing `ban:{ip}`
channel the inline proxy already enforces. Off (advisory) by default.

## 3. Scope

**In:**

- `internal/tap/enforcement.go` — `Enforcer` with a JA4T-blocklist trigger,
  fail-open in every branch.
  - **Advisory (default):** write `fp:ban_intent:ip:{ip}` (provenance
    `ja4t=…`, default 1h TTL). Nothing blocks. Under the existing `~fp:*` ACL.
  - **Armed (`--enforce` + ACL `~ban:*`):** also write `ban:{ip}` (provenance
    `tap_enforce:ja4t=…`, short default 5m TTL). Inline proxy blocks the next
    connection.
- Metrics `ja4proxy_tap_enforcement_actions_total{result=skipped|watchlist|banned|error}`
  and gauge `ja4proxy_tap_enforcement_armed`.
- `cmd/ja4-tap` flags: `--enforce`, `--ja4t-blocklist`, `--ban-ttl`,
  `--intent-ttl`; startup WARN + foot-gun warnings; wired into the drive loop
  under the existing shared write deadline.
- Docs: REDIS_SCHEMA (`fp:ban_intent:ip` + tap-written `ban:{ip}` note),
  OBSERVABILITY, runbook (arming UX + widened ACL + safety invariants),
  ADR-316d, `gdpr_delete.py` coverage.

**Out / deferred:**

- `ja4proxy:bans` pub/sub (no consumer) — dropped.
- iptables/ipset, BGP blackhole, HMAC webhook — deferred to 316e.
- CIDR auto-expansion (/24, /48) — out of scope; expansion is RDAP's domain.
- Composite "bot-JA4 + OS-mismatch" verdict — the sensor does not compute TLS
  JA4 yet; deferred to its own slice.

## 4. Key decisions

- **Reuse `ban:{ip}`, don't invent a channel** — it has a live inline consumer
  (231a); provenance lives in the value, which the `EXISTS` check ignores.
- **Two-step arming** — `--enforce` *and* a widened ACL. The default ACL
  physically prevents a `ban:` write, so misconfiguration fails safe; `--enforce`
  alone is a logged no-op.
- **Empty blocklist ⇒ provably inert** — same zero-FP-by-default guarantee as the
  316c consumer.
- **Short ban TTL** — a misfire on a passive guess self-heals (core asymmetry).
- **Failed watchlist write never escalates to a ban** — a sick Redis must not
  start blocking real users.
- **Metric rename** — the outline's `…_enforcement_errors_total` is folded into
  the actions counter's `result="error"` label.

## 5. Tests

- `internal/tap/enforcement_test.go` — unarmed→watchlist-only; armed→intent then
  ban; non-match / empty-blocklist / empty-JA4T short-circuits; unparsable IP →
  error; nil backend → skipped; watchlist-error aborts before ban; ban-error
  fails open; IP canonicalisation (v4/v6/bracketed/zoned); armed gauge; nil
  receiver; zero-TTL defaulting.
- `internal/tap/enforcement_roundtrip_test.go` — miniredis closed loop: armed +
  blocklisted JA4T → `ban:{ip}` EXISTS with the configured TTL (the exact key the
  inline proxy reads); unarmed → only `fp:ban_intent:ip`, never `ban:`.

## 6. Acceptance

- `go build ./...`, `go vet`, and `go test ./internal/... ./cmd/...` green.
- Default run writes no `ban:` key (proven by the unarmed roundtrip test).
- A passive misclassification cannot block by default (empty-blocklist
  short-circuit + unarmed advisory-only).
