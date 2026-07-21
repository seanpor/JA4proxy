# Phase 316d notes — TAP Out-of-Band Enforcement Bridge

## What shipped

The standalone TAP sensor (`cmd/ja4-tap`) can now act, out of band, on a client
whose passively-observed JA4T is on an operator-defined enforcement blocklist —
by reusing the existing `ban:{ip}` channel the inline proxy already enforces.
Advisory by default; active blocking requires a conscious two-step.

- `internal/tap/enforcement.go` — `Enforcer` / `EnforcerConfig` / `NewEnforcer` /
  `Consider`. Two tiers:
  - default: write `fp:ban_intent:ip:{ip}` (provenance `ja4t=…`, 1h) — nothing blocks.
  - armed (`Armed` + ACL `~ban:*`): also write `ban:{ip}` (`tap_enforce:ja4t=…`, 5m).
- `internal/tap/metrics.go` — `EnforcementActionsTotal{result}` +
  `EnforcementArmed` gauge, registered in `Collectors()`. Result vocabulary
  `skipped|watchlist|banned|error`.
- `cmd/ja4-tap/main.go` — flags `--enforce`, `--ja4t-blocklist`, `--ban-ttl`,
  `--intent-ttl`; `parseBlocklist`; `warnEnforcementPosture` (armed WARN +
  no-redis / empty-blocklist foot-gun warnings); `buildStore`→`buildBackends`
  (Store + Enforcer share one Redis client); `Consider` called in the drive loop
  under the existing `storeWriteTimeout` deadline.

## Why this shape (critical review → ADR-316d)

The original outline was ported from the deleted Python sensor and was infeasible:
- `ja4proxy:bans` pub/sub has **no Go consumer** — dead write.
- iptables/ipset/BGP/HMAC-webhook blockers break the sensor's least-privilege
  design (`CAP_NET_RAW` + `~fp:*` ACL) — deferred to 316e.

The inline proxy already hard-blocks on `EXISTS ban:{ip}` (pipeline.go, 231a), so
that is the project's real ban channel. Sensor writes it; proxy enforces on the
*next* connection (passive one-strike).

## Safety invariants (enforced by tests)

- Empty blocklist short-circuits before any write — default config can't ban.
- Two-step arming: `--enforce` alone is a no-op under the default ACL (`ban:`
  write is rejected server-side and counted `error`).
- Fail-open: unparsable IP / nil backend / Redis error all count and stop; a
  failed *watchlist* write never escalates to a ban.
- Short ban TTL (5m default) so a misfire self-heals.
- Single-IP only — no CIDR expansion.

## Privilege / ops note

The default least-privilege ACL stays `~fp:* +set +expire` (covers
`fp:ban_intent:ip`). Arming requires widening it to `~fp:* ~ban:* +set +expire`.
`scripts/gdpr_delete.py` erases both `fp:ban_intent:ip` and (already) `ban:`.

## Tests

`internal/tap/enforcement_test.go` (15 cases) + `enforcement_roundtrip_test.go`
(miniredis: armed→`ban:{ip}` with TTL; unarmed→watchlist-only). Full
`go build / vet / test ./internal/... ./cmd/...` green.

## Deferred

JA4S / JA4L / JA4X(≤TLS1.2) / QUIC fingerprint slices; external blockers + the
exporter surface (316e); composite "bot-JA4 + OS-mismatch" verdict (sensor does
not compute TLS JA4 yet).
