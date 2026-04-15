# Phase 201 — Implementation Notes

**Branch:** `claude/phase-201-redis-tls-hardening`
**Status:** COMPLETE (201a–201d merged; 201e close-out in this commit)
**Date:** 2026-04-15

Consolidated notes from all sub-phases. See `PHASE_201.md` for the spec and
`PHASE_201_review.md` for the original critical review.

---

## 201a — Go Redis TLS + Username

**Files:** `internal/redis/client.go`, `internal/config/loader.go`,
`config/proxy.yml`, `cmd/proxy/main.go`, `cmd/syncagent/main.go`,
`internal/redis/{client_tls_test.go,tls_harness_test.go}`,
`docs/decisions/ADR-201a.md`.

Decisions:
- TLS 1.2 minimum, system CA pool only — see ADR-201a.
- `Username` plumbed to both standalone and Sentinel/failover paths.
- TLS sanity ping (2s) on `New()`: failure is **WARN/ERROR + fail-open**,
  not a startup abort. `New()` always returns a non-nil `*Client`.
- Dial-option construction extracted into `buildStandaloneOptions` and
  `buildFailoverOptions` to keep `New()` testable and small.
- Test seam: `newFromOptions(opts, log)` is the unit-test entry point;
  TLS tests construct `*goredis.Options` directly without going through
  config-file plumbing.

Test harness:
- `tls_harness_test.go` wraps `miniredis` behind an in-process
  `tls.NewListener` so we get a **real TLS handshake** in unit tests
  (miniredis itself has no TLS support). Self-signed RSA-2048 cert with SANs
  for `127.0.0.1` and `::1`.
- Bidirectional `io.Copy` pipe goroutines bound by a `WaitGroup` so test
  cleanup is deterministic.
- Coder modified the harness during 201a (3 fixes: pipe close ordering,
  `isClosedErr` recognising TLS-side error patterns, restart-before-close
  to avoid bind-port races). QA reviewed; none mask real bugs.

---

## 201b — ZRemRangeByScore Error Logging

**Files:** `internal/redis/client.go`.

`ZRemRangeByScore` previously swallowed errors silently (used to GC sliding-
window sorted sets). Now logs WARN with the key and error, and increments no
metric (this is best-effort GC; counting it as a Redis error would skew the
new health gauge). Fail-open behaviour unchanged — the next sliding-window
write will rebuild state.

---

## 201c — Redis Health Check Goroutine + Script Reload

**Files:** `internal/redis/client.go`, `internal/metrics/metrics.go`,
`cmd/proxy/main.go`, `internal/redis/health_check_test.go`.

- New method `HealthCheck(ctx)` runs PING + EVALSHA-on-cached-SHA. On
  `NOSCRIPT` it reloads the Lua script (double-checked `RLock → Lock`
  pattern using `scriptMu sync.RWMutex` — **not** `sync.Once`, because
  reload must be repeatable across the lifetime of the client).
- `loadScripts` split into public `loadScripts()` (takes write lock) +
  internal `loadScriptsLocked()` (assumes lock held) so `HealthCheck` can
  reload without re-entering the mutex.
- New metrics: `ja4proxy_redis_health{status="ok|error"}` (Gauge) and
  `ja4proxy_redis_script_reloads_total{result="ok|error"}` (Counter).
- 30s ticker goroutine started from `cmd/proxy/main.go` using the existing
  `ctx` from line 67; cancelled on shutdown.
- **Sync-agent intentionally does NOT run this goroutine** — see ADR-201a
  "Sync-agent divergence" note. The sync-agent is short-lived ETL, not a
  long-running daemon; a periodic gauge would be noise.

Test seam: `SlidingWinSHAForTest()` and `ZeroSlidingWinSHAForTest()` allow
forcing NOSCRIPT-recovery paths without touching unexported fields.

---

## 201d — Rate Limiter Input Validation

**Files:** `internal/security/rate_limiter.go`.

`Check(clientIP, ja4)` previously trusted both inputs. New `sanitizeKey`
helper:
- Validates `clientIP` via `netip.ParseAddr` (handles IPv4 and IPv6
  uniformly — earlier draft used a "no colons" rule that would have
  rejected all IPv6).
- Validates `ja4` against the canonical 36-char alphanumeric+underscore
  pattern.
- On failure: WARN log with `ip_hash` (sha256[:16] of the raw input — never
  the raw IP) and the substring `"fail-open"`, then returns `nil` **before
  any Redis call**. This preserves the core asymmetry (false positive cost
  > false negative cost) when an upstream component sends garbage.

---

## 201e — Close-out

- Manifest updated: status PROPOSED → COMPLETE; sub-phase list rewritten to
  match the actual 201a–e structure (the original "signal score drift fix"
  premise was withdrawn — see PHASE_201_review.md).
- IPv6 SAN (`IP.2 = ::1`) added to the redis-tls cert generator for parity
  with the in-process test harness.
- `make test-go-redis-tls` target added: generates certs, brings up
  `docker-compose.redis-tls.yml`, runs `go test -race -count=1
  ./internal/redis/... -run 'TLS|HealthCheck'`, tears down on EXIT.
- ADR-201a annotated with the syncagent intentional-divergence note.

Architect findings deferred to follow-up work (none are blockers):
- Prometheus alert rule on `ja4proxy_redis_health{status="error"}` —
  belongs in the alerting bundle phase, not here.

---

## Test results at close

```
go test -race ./...           # 17/17 pass
make test                     # 5380 tests, 92.95% coverage
make check-scores             # exit 0
go vet ./...                  # clean
gofmt -l .                    # clean
```
