# Phase 201 — Go Redis TLS + Silent-Failure Hardening

> **Status:** IMPLEMENTATION COMPLETE (201a–201d merged; 201e close-out pending)
> **Parent Size:** MEDIUM
> **Last revised:** 2026-04-15 (rewritten after critical review — see `PHASE_201_review.md`)
> **Target runtime:** Go (production). Python is not touched.

## What changed in this rewrite

The previous revision proposed a "signal score drift fix" (201a) claiming 4 Go
scores diverged from `config/signal_scores.yml`. **That premise was false** —
`make check-scores` exits 0 and the Go scores already match the registry
exactly. Applying the previous 201a would have INTRODUCED drift. It has been
removed. Other sub-phases have been corrected (file paths, IPv6 rule,
concurrency model, test harness). See `PHASE_201_review.md` for the full audit.

## Goal

Close three production-critical gaps in the **Go** Redis client:

1. `redis.ssl: true` in `config/proxy.yml` is **silently ignored** — credentials
   and all security state are sent in cleartext. Python honours this flag
   (`proxy.py:1635-1678`); Go does not.
2. `loadScripts` is only ever called once at startup; if Redis restarts or
   `SCRIPT FLUSH` runs, the Go rate limiter breaks silently.
3. The Go rate limiter passes unvalidated strings (`clientIP`, `ja4`) straight
   into Redis key names, creating collision / log-injection surface.

Plus one small correctness fix:

4. `ZRemRangeByScore` swallows errors with only a metric increment, inconsistent
   with every other write method in the same file. One-line fix.

## Non-goals

- Redis ACL provisioning scripts (infrastructure, not proxy code).
- Custom CA bundles / client-certificate auth (`ssl_ca_certs`, `ssl_certfile`).
  System CA pool with `MinVersion: TLS 1.2` is the bar for this phase. A
  follow-up phase can add custom CAs if operators need them.
- Python changes — Python already supports all of the above.
- Rate-limiter algorithm changes.
- Full deep health-check endpoint (deferred to Phase 203-E).

---

## Sub-phase index

| ID | Title | Repo area | Size | Depends on |
|---|---|---|---|---|
| **201a** | TLS + Username in Go Redis client | `internal/redis`, `internal/config`, `cmd/proxy` | S (3 h) | none |
| **201b** | `ZRemRangeByScore` error logging | `internal/redis/client.go` | XS (30 min) | none |
| **201c** | Redis health-check goroutine + script reload | `internal/redis`, `internal/metrics`, `cmd/proxy` | M (4 h) | 201a |
| **201d** | Rate-limiter input validation (IPv4/IPv6 safe) | `internal/security/rate_limiter.go` | S (2 h) | none |
| **201e** | Docs, runbook, ADR, CHANGELOG close-out | `docs/`, `CHANGELOG.md`, `manifest.yaml` | XS (45 min) | 201a–201d |

**Parallelism:** 201a, 201b, 201d can all run in parallel (different packages
and lines). 201c depends on 201a (needs the TLS config path to exist).
201e is last.

---

## Sub-phase 201a — TLS + Username support in Go Redis client

**Size:** S (~3 h) · **Depends on:** none

### Why

Operators enabling `ssl: true` in `config/proxy.yml` expect their Redis password
and security state to be encrypted in transit. Today the flag is parsed
(`internal/config/loader.go:407`) but then dropped — never read by
`cmd/proxy/main.go:139-147` when constructing `redisclient.Config`, and the
struct at `internal/redis/client.go:31-43` has no TLS field at all.

### Files to touch

- `internal/redis/client.go` — add fields and wire into dial options
- `internal/config/loader.go` — add `username` YAML field
- `cmd/proxy/main.go:139-147` — pass SSL + Username into `redisclient.Config`
- `cmd/syncagent/main.go:44-53` — same (the sync agent also uses the client)
- `config/proxy.yml:32-44` — add `username: ""` line with `# phase-201a`
- `internal/redis/client_tls_test.go` — **new file**, co-located with code

### Steps

1. **Struct extension** (`internal/redis/client.go:31-43`)
   Add two fields, grouped with other auth settings; do not reorder existing
   fields (callers construct `Config{...}` by name, but struct tags / reflection
   users may exist):
   ```go
   Password string
   Username string  // phase-201a: Redis ACL username; empty = default user
   SSL      bool    // phase-201a: enable TLS to Redis (MinVersion 1.2)
   Timeout  time.Duration
   ```

2. **Dial options** (`internal/redis/client.go:54-81`)
   Import `crypto/tls`. In **both** branches (Sentinel at line 56,
   standalone at line 72), set:
   ```go
   opts.Username = cfg.Username
   if cfg.SSL {
       opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
   }
   ```
   `goredis.FailoverOptions` and `goredis.Options` both expose identical
   `Username` and `TLSConfig` fields — verified in `go-redis/v9`.

3. **Startup log** (after `rdb` is constructed, before `return c`)
   Add one `Info` line recording observed dial options. **Do not log the
   password.** Grep your diff for `Password` before committing.
   ```go
   log.WithFields(logrus.Fields{
       "ssl":      cfg.SSL,
       "username": cfg.Username != "",  // bool, not the value
   }).Info("redis: dial options configured")
   ```

4. **TLS sanity ping**
   Immediately after `loadScripts()`, call `rdb.Ping(ctx)` with a 2-second
   timeout. If `cfg.SSL` was set and the ping fails, log an `ERROR` but **do
   not return an error** — fail-open is preserved (callers continue with local
   cache). The ERROR line makes misconfiguration loud without crashing prod.

5. **Config loader** (`internal/config/loader.go:400-408`)
   Add `Username string \`yaml:"username"\`` between `Password` and `Timeout`.

6. **Proxy wiring** (`cmd/proxy/main.go:139-147` and `cmd/syncagent/main.go:44-53`)
   Add the two new fields to the `redisclient.Config{...}` literal:
   ```go
   Username: cfg.Redis.Username,
   SSL:      cfg.Redis.SSL,
   ```

7. **Config example** (`config/proxy.yml` under the existing `redis:` block at
   line 32)
   ```yaml
     username: ""   # phase-201a: Redis 6+ ACL username (leave "" for default user)
     # ssl: false   # already present at line 44
   ```

8. **Unit tests** (`internal/redis/client_tls_test.go`, new file)

   **Test harness:** Build a real in-process TLS-wrapped RESP endpoint by
   layering `crypto/tls` in front of `miniredis` (v2.37.0 already in go.mod).
   This is a proper test harness — a real TLS handshake occurs, a real go-redis
   client dials through it, and real commands round-trip. No handshake-free
   shortcuts.

   Create a helper `newTLSMiniredis(t)` in a new file
   `internal/redis/tls_harness_test.go`:
   ```go
   // Generates a 2048-bit RSA self-signed cert for "127.0.0.1",
   // starts miniredis, wraps it behind tls.NewListener on a random port,
   // spawns a goroutine that accepts + pipes bytes between TLS conn and miniredis conn,
   // returns (addr string, caPool *x509.CertPool, cleanup func()).
   ```
   The goroutine uses `io.Copy` in both directions (client→backend and
   backend→client). Cleanup closes the listener, stops miniredis, and waits
   for goroutines via a `sync.WaitGroup`. Failures in the pipe goroutine are
   surfaced via `t.Errorf` through a channel — no silent test bugs.

   **Tests that must exist:**
   - `TestClient_TLS_RealHandshake_Succeeds`: `cfg.SSL=true` + cert's CA in
     `TLSConfig.RootCAs` → `rdb.Ping` succeeds, `Set`/`Get` round-trip works.
   - `TestClient_TLS_WrongCA_Fails`: `cfg.SSL=true` with empty `RootCAs` →
     ping returns a TLS verification error; proxy logs ERROR but `New()`
     still returns a non-nil `*Client` (fail-open preserved).
   - `TestClient_TLS_ClearRedisRejectsTLSClient`: start plain miniredis, dial
     with `SSL=true` → ping fails within 2 s; proxy logs ERROR; fail-open.
   - `TestClient_TLS_TLSRedisRejectsClearClient`: TLS harness + `SSL=false` →
     ping fails; fail-open.
   - `TestClient_Options_SentinelTLS`: Sentinel mode with `SSL=true` →
     `FailoverOptions.TLSConfig != nil` and `MinVersion == TLS 1.2`. (Pure
     options construction; no live Sentinel needed.)
   - `TestClient_Username_PassedThrough`: construct with `Username: "alice"`,
     assert `opts.Username == "alice"` via the exported `buildOptions` helper.
   - `TestClient_PasswordNeverLogged`: attach a `logrus_test.NullLogger`,
     construct client with `Password: "s3cret"`, assert no log entry contains
     the substring `"s3cret"`.

   **Refactor required:** Extract `buildStandaloneOptions(cfg) *goredis.Options`
   and `buildFailoverOptions(cfg) *goredis.FailoverOptions` as unexported
   helpers so tests can inspect option structs without a live connection.
   `New()` calls these helpers. This is the only refactor in 201a.

   **Integration smoke** (deferred to 201e close-out, not blocking 201a unit
   tests): add a `deploy/docker/docker-compose.redis-tls.yml` overlay that
   runs Redis 7 with `tls-port 6380`, a self-signed cert, and a mounted
   `redis.conf`. Add `make test-go-redis-tls` target that `go run`s the
   proxy briefly against it and asserts `/metrics` shows
   `ja4proxy_redis_health{status="ok"} == 1` and no `error` status. Tracked
   as acceptance criterion in 201e.

### Acceptance

- [x] `go build ./...` passes
- [x] `go test ./internal/redis/... -race` passes (including the 5 new tests)
- [x] `go vet ./...` clean
- [x] `grep -n "Password" internal/redis/client.go` shows no log line includes the password value
- [x] With `ssl: true` in `config/proxy.yml` pointing at a non-TLS Redis, the proxy logs an `ERROR "redis: TLS ping failed"` and continues serving (fail-open)
- [ ] `PHASE_201a_notes.md` written summarising work

### Watch out for

- `cmd/syncagent/main.go` uses the same `redisclient.Config` — if you only fix `cmd/proxy`, the sync agent silently keeps shipping cleartext. **Fix both.**
- Do not replace `context.Background()` in `SeedDialIfAbsent` — that's a separate concern.
- `logrus.Fields{"username": cfg.Username != ""}` — the `!= ""` is deliberate. Never log the username value itself; some deployments treat ACL usernames as secrets.

---

## Sub-phase 201b — ZRemRangeByScore error logging

**Size:** XS (~30 min) · **Depends on:** none

### Why

Every other write method in `internal/redis/client.go` logs on error
(audited: `Set:160`, `SAdd:195`, `SRem:206`, `ZAdd:348`, `XAdd:411`,
`SetArgs:442` all log). Only `ZRemRangeByScore` at line 355-362 does not.
Inconsistent error handling is how silent data loss hides.

### Files to touch

- `internal/redis/client.go` — one method at line 355-362
- `internal/redis/client_test.go` — one new test

### Steps

1. In `ZRemRangeByScore`, match the `ZAdd` pattern one method up:
   ```go
   if err := c.rdb.ZRemRangeByScore(ctx, key, ...).Err(); err != nil {
       observeOp("zremrangebyscore", "error")
       c.log.WithError(err).WithField("key", key).Warn("redis: ZREMRANGEBYSCORE failed")
       return
   }
   ```

2. Add a test `TestZRemRangeByScore_LogsOnError` in
   `internal/redis/client_test.go`:
   - Use `logrus_test.NewNullLogger()` (already used elsewhere — grep for it).
   - Force an error by calling `ZRemRangeByScore` on a key set to a **string**
     via miniredis (wrong type → WRONGTYPE error).
   - Assert `hook.LastEntry().Level == logrus.WarnLevel` and message contains
     `ZREMRANGEBYSCORE failed`.

### Acceptance

- [x] Test passes
- [x] `go test ./internal/redis/... -race` clean
- [ ] `PHASE_201b_notes.md` written

### Watch out for

- The existing `observeOp("zremrangebyscore", "error")` line stays. Keep it above the log line to match the ordering in `ZAdd`.
- No other call sites in `internal/redis/client.go` are silent (verified). Do not expand scope to other packages in this sub-phase.

---

## Sub-phase 201c — Redis health-check + script reload

**Size:** M (~4 h) · **Depends on:** 201a

### Why

`loadScripts` is called once in `New()` (line 84) and never again. A Redis
restart or manual `SCRIPT FLUSH` wipes `slidingWinSHA`'s server-side cache,
and every `EVALSHA` call after that fails until the proxy restarts. The
rate limiter breaks silently — exactly the failure Python's
`health_check_interval=30` prevents.

### Files to touch

- `internal/redis/client.go` — add mutex + public `HealthCheck(ctx) error`
- `internal/metrics/metrics.go` — register two new Prom series
- `cmd/proxy/main.go` — start one goroutine with the existing `ctx` at line 67
- `internal/redis/client_test.go` — health check tests
- `docs/runbooks/go_proxy_operations.md` — alert response entry

### Steps

1. **Metrics** (`internal/metrics/metrics.go` — find via
   `grep -l promauto internal/`)
   ```go
   RedisHealth = promauto.NewGaugeVec(prometheus.GaugeOpts{
       Name: "ja4proxy_redis_health",
       Help: "Redis health status (1=current, 0=stale). Labels: status=ok|degraded|error.",
   }, []string{"status"})
   RedisScriptReloadsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
       Name: "ja4proxy_redis_script_reloads_total",
       Help: "Count of sliding_window.lua reloads after Redis restart/flush.",
   }, []string{"result"})
   ```

2. **Client mutex** (`internal/redis/client.go` `Client` struct at line 20-28)
   ```go
   scriptMu sync.RWMutex  // protects slidingWinSHA
   ```
   Wrap every read of `c.slidingWinSHA` (lines 257, 293) in `RLock`/`RUnlock`.
   Wrap writes in `loadScripts` (line 136) in `Lock`/`Unlock`.

3. **Health method** (new, below `Ping` around line 272)
   ```go
   func (c *Client) HealthCheck(ctx context.Context) {
       ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
       defer cancel()
       if err := c.rdb.Ping(ctx).Err(); err != nil {
           metrics.RedisHealth.WithLabelValues("error").Set(1)
           metrics.RedisHealth.WithLabelValues("ok").Set(0)
           c.log.WithError(err).Warn("redis: health check ping failed")
           return
       }
       c.scriptMu.RLock()
       empty := c.slidingWinSHA == ""
       c.scriptMu.RUnlock()
       if empty {
           c.loadScripts()  // acquires Lock internally
           c.scriptMu.RLock()
           ok := c.slidingWinSHA != ""
           c.scriptMu.RUnlock()
           if ok {
               metrics.RedisScriptReloadsTotal.WithLabelValues("ok").Inc()
           } else {
               metrics.RedisScriptReloadsTotal.WithLabelValues("error").Inc()
           }
       }
       metrics.RedisHealth.WithLabelValues("ok").Set(1)
       metrics.RedisHealth.WithLabelValues("error").Set(0)
   }
   ```
   Rationale: **mutex, not `sync.Once`**. Reloads can happen many times over
   the proxy's lifetime. `RLock` for reads is fine — `loadScripts` runs rarely.

4. **Goroutine** (`cmd/proxy/main.go`, immediately after the existing
   `go redisclient.NewPubSubHandler(...)` at line 79)
   ```go
   go func() {
       t := time.NewTicker(30 * time.Second)
       defer t.Stop()
       for {
           select {
           case <-ctx.Done():
               return
           case <-t.C:
               proxy.redis.HealthCheck(ctx)
           }
       }
   }()
   ```
   Uses the existing cancellable `ctx` from line 67 — do **not** create a new
   `context.Background()`.

5. **Tests** (`internal/redis/client_test.go`)

   **Test harness:** Use real miniredis. Use `miniredis.Server.Close()` and
   re-start with `miniredis.RunAddr(addr)` on the SAME address to simulate
   a real Redis outage + restart — not a mutated private field. The restart
   must actually drop and re-accept the TCP connection so the go-redis
   connection pool sees a real reconnection.

   - `TestHealthCheck_ReloadsScriptAfterFlush`: start miniredis, construct
     client (scripts loaded), call `miniredis.FlushAll()` + force SCRIPT
     cache clear by stopping and restarting miniredis on the same port.
     Call `HealthCheck`. Assert (a) `EvalSha` fails with `NOSCRIPT` before
     the call, (b) `slidingWinSHA` is re-populated after the call, (c)
     `EvalSha` works after the call, (d)
     `RedisScriptReloadsTotal{result="ok"}` incremented by exactly 1.
   - `TestHealthCheck_ErrorOnPingFailure`: close miniredis (do not restart).
     Call `HealthCheck`. Assert `RedisHealth{status="error"} == 1`,
     `RedisHealth{status="ok"} == 0`, and a WARN log line was emitted.
   - `TestHealthCheck_RecoversAfterRestart`: close miniredis, call
     `HealthCheck` (observe error), restart miniredis on same addr, call
     `HealthCheck` again, assert `RedisHealth{status="ok"} == 1` and the
     script is reloaded.
   - `TestHealthCheck_Concurrent`: 50 goroutines call `HealthCheck` in
     parallel against a healthy miniredis. Run under `-race`. Force the
     "empty SHA → reload" path once by zeroing the SHA under lock before
     the barrier. Assert exactly one `loadScripts` invocation wins (use a
     counting `logrus.Hook` on the debug-level "sliding_window.lua loaded"
     message, or a test-only atomic counter incremented inside
     `loadScripts`).
   - `TestHealthCheck_GoroutineStopsOnContextCancel`: start the goroutine
     from `cmd/proxy/main.go` pattern in an isolated helper, cancel the
     ctx, assert the goroutine returns within 100 ms. Prevents leak
     regressions.

6. **Runbook** (`docs/runbooks/go_proxy_operations.md`)
   Append a section `## Alert: ja4proxy_redis_health{status="error"}`:
   - What it means (ping to Redis failing)
   - First check: is Redis up? `docker ps | grep redis`
   - Second check: TLS misconfig? `journalctl -u ja4proxy | grep "TLS ping failed"`
   - If proxy is still serving: fail-open is working; no emergency. Fix Redis.
   - Manual script reload: restart the proxy (no hot reload endpoint in this phase).

### Acceptance

- [x] `go test -race ./internal/redis/...` clean
- [x] `/metrics` exposes `ja4proxy_redis_health` and `ja4proxy_redis_script_reloads_total`
- [ ] Manual test: run proxy against miniredis, `SCRIPT FLUSH`, wait 30 s, check metric — reload counter increments
- [x] Runbook entry committed
- [ ] `PHASE_201c_notes.md` written

### Watch out for

- **Do not** use `sync.Once` — scripts must be reloadable many times.
- **Do not** create a new context — thread the existing `ctx` from `main.go:67`.
- `loadScripts` acquires `scriptMu.Lock()`; callers must not hold `scriptMu.RLock()` when calling it (deadlock). The health method above releases `RLock` before calling `loadScripts`.

---

## Sub-phase 201d — Rate-limiter input validation

**Size:** S (~2 h) · **Depends on:** none

### Why

`internal/security/rate_limiter.go:63` and `:77` format untrusted strings
straight into Redis key names:
```go
key := fmt.Sprintf("ratelimit:ip:%s", clientIP)
key := fmt.Sprintf("ratelimit:ip_ja4:%s:%s", clientIP, ja4)
```
If `clientIP` ever contains a newline, `*`, or Redis protocol bytes (because
upstream parsing regresses, or PROXY-protocol injection), the key space
corrupts and log output becomes injectable.

The previous phase doc proposed "reject strings containing colons in IP" —
**this rejects every IPv6 address**. The rule below uses `netip.ParseAddr`
as the oracle, which handles v4, v6, v6+zone, and malformed input correctly.

### Files to touch

- `internal/security/rate_limiter.go` (not `internal/rate_limiter/` — that
  directory does not exist)
- `internal/security/rate_limiter_test.go`

### Steps

1. Import `net/netip` and `crypto/sha256`.

2. Add a helper below the existing `RateLimiter` struct:
   ```go
   // sanitizeKey canonicalises clientIP via netip and caps ja4 length.
   // Returns false if the IP cannot be parsed; caller should skip rate limiting
   // (fail-open) and log a warning.
   func sanitizeKey(clientIP, ja4 string) (canonIP, safeJA4 string, ok bool) {
       addr, err := netip.ParseAddr(clientIP)
       if err != nil || !addr.IsValid() {
           return "", "", false
       }
       if len(ja4) > 256 {
           ja4 = ja4[:256]
       }
       return addr.String(), ja4, true
   }
   ```

3. In `Check` (line 49), first thing after entry:
   ```go
   canonIP, safeJA4, ok := sanitizeKey(clientIP, ja4)
   if !ok {
       // Log a hash of the raw input — never log raw bytes (log-injection risk).
       hash := fmt.Sprintf("%x", sha256.Sum256([]byte(clientIP)))[:16]
       r.log.WithField("ip_hash", hash).Warn("rate_limiter: rejected unparsable IP; skipping rate limit (fail-open)")
       return nil
   }
   clientIP, ja4 = canonIP, safeJA4
   ```
   Rest of `Check` is unchanged.

4. **Tests** (`internal/security/rate_limiter_test.go` — extend existing file)
   - `TestSanitizeKey_IPv4`: `"1.2.3.4"` → ok, canonical `"1.2.3.4"`.
   - `TestSanitizeKey_IPv6`: `"2001:db8::1"` → ok, canonical preserved.
   - `TestSanitizeKey_IPv6WithZone`: `"fe80::1%eth0"` → ok.
   - `TestSanitizeKey_Empty`: `""` → not ok.
   - `TestSanitizeKey_Garbage`: `"1.2.3.4\nSET evil x"` → not ok.
   - `TestSanitizeKey_OverlongJA4`: 1 KB JA4 → truncated to 256.
   - `TestSanitizeKey_OracleProperty`: 1 000 random 16-byte strings; for each,
     assert `sanitizeKey` returns ok iff `netip.ParseAddr` reports valid.
     Seed `rand.New(rand.NewSource(1))` for reproducibility.
   - `TestCheck_FailOpenOnBadIP`: call `RateLimiter.Check(ctx, "not-an-ip", "ja4")`;
     assert empty signals and a WARN log with `ip_hash` field (no raw IP in log).

### Acceptance

- [x] All 8 tests pass
- [x] `go test -race ./internal/security/... -count=5` stable
- [ ] `PHASE_201d_notes.md` written

### Watch out for

- **Never** hand-roll regex validation of IP addresses. `netip.ParseAddr` is the only correct oracle for v4 and v6.
- The fallback path returns `nil` signals (fail-open). Do **not** invent a synthetic key like `"ratelimit:ip:unknown"` — that would bucket all malformed requests into one limiter and defeat the purpose.
- Log the `sha256` hash prefix, **never** the raw input.

---

## Sub-phase 201e — Docs, runbook, ADR, CHANGELOG close-out

**Size:** XS (~45 min) · **Depends on:** 201a–201d all merged

### Files to touch

- `CHANGELOG.md` (prepend entry)
- `docs/phases/manifest.yaml` (set phase 201 `status: COMPLETE`)
- `docs/decisions/ADR-201a.md` (new — TLS MinVersion choice)
- `docs/reference/OBSERVABILITY_STANDARDS.md` (document the two new metrics)
- Auto-regenerated: `docs/phases/TODO.md`, `docs/reference/PROJECT_STATUS.md`

### Steps

1. **CHANGELOG** — one entry in the standard format, noting:
   - Go Redis client now honours `ssl: true` and supports ACL `username`.
   - `ZRemRangeByScore` errors now logged (previously silent).
   - Periodic Redis health check with automatic Lua-script reload.
   - Rate-limiter input validation (netip-based).
   - **Withdrawn:** the previously proposed "signal score drift fix" was
     based on a false premise (registry and code already agreed).

2. **ADR-201a** — "Go Redis client TLS MinVersion = 1.2, system CA pool only"
   - Context: Phase 201 added TLS to Go Redis client.
   - Decision: `MinVersion: tls.VersionTLS12`, no custom `RootCAs` (system pool).
   - Consequences: compatible with Redis Enterprise, AWS ElastiCache, stunnel
     terminators. Deployments using private-CA-issued Redis certs will need
     OS-level trust store updates until a follow-up phase adds
     `ssl_ca_certs` support (as Python has).

3. **OBSERVABILITY_STANDARDS.md** — add two rows to the metrics table:
   - `ja4proxy_redis_health{status}` — gauge, status=ok|error
   - `ja4proxy_redis_script_reloads_total{result}` — counter, result=ok|error

4. **Manifest** — `phases.201.status: PROPOSED → COMPLETE`, remove
   `sub_phases.201a` stale entry if still present.

5. Run `make sync` — regenerates TODO.md and PROJECT_STATUS.md.

### Acceptance

- [x] CHANGELOG prepended
- [x] ADR-201a present and linked from ADR index
- [ ] `make sync` run; generated docs committed
- [ ] `make check-scores` exits 0 (sanity check, not changed by this phase)
- [ ] `make test` and `make go-test` both pass
- [ ] Manifest phase 201 is `COMPLETE`

---

## Full-phase acceptance criteria

- [ ] All 5 sub-phases complete (201e close-out pending: `make sync`, manifest)
- [x] `go test -race ./...` passes
- [x] `go vet ./...` clean
- [ ] `make check-scores` exits 0 (unchanged baseline — not re-run by doc-late)
- [ ] `make test-go-redis-tls` (new target) passes against real Redis+TLS in compose — compose overlay exists (`deploy/docker/docker-compose.redis-tls.yml`) but the Make target has not been added
- [x] `grep -rn "Password.*log\|log.*Password" internal/redis/ cmd/` returns no matches that log a password value
- [x] `ssl: true` with a broken TLS config produces a loud ERROR log, not a silent cleartext connection
- [x] Rate limiter fuzz test (201d) stable under 5 repeated runs
- [x] In-process TLS harness test suite produces a REAL TLS handshake (verified by reading the harness source — no handshake-free shortcuts)

---

## Implementation notes (Doc-Late, 2026-04-15)

Implementation landed across four commits (b593f79 planning → b19786f final):

- **201a** (`9efa748`): `crypto/tls` import, `Username`/`SSL` fields on
  `redis.Config`, `buildStandaloneOptions`/`buildFailoverOptions` helpers,
  startup Info log `"redis: dial options configured"` (Booleans only — no
  password), and a 2 s TLS sanity ping that surfaces
  `"redis: TLS ping failed; continuing fail-open"` (Error) while keeping
  fail-open. `cmd/proxy/main.go` and `cmd/syncagent/main.go` both pass the
  two new fields through. `config/proxy.yml` gains `username: ""`.
- **201b** (`5e5d08f`): one-line fix in `ZRemRangeByScore` — Warn log on
  error, consistent with every other write method in the file.
- **201c** (`b19786f`): `Client.scriptMu sync.RWMutex` + split
  `loadScripts` (acquires lock) / `loadScriptsLocked` (caller holds lock).
  New `HealthCheck(ctx)` uses a double-checked `RLock → Lock` pattern to
  deduplicate concurrent reload attempts. Metrics `RedisHealth{status}` and
  `RedisScriptReloadsTotal{result}` registered in `internal/metrics/metrics.go`.
  A 30-second `time.Ticker` goroutine is wired in `cmd/proxy/main.go` using
  the existing cancellable `ctx` from line 67.
- **201d** (`174625a`): `sanitizeKey` helper in
  `internal/security/rate_limiter.go` uses `netip.ParseAddr` as the
  validation oracle; unparsable IPs fail-open with a
  `sha256[:16]`-hashed `ip_hash` field (never raw bytes).
  `ja4` is truncated to 256 bytes.

Work remaining for Phase 201e (out of doc-late scope):

- Per-sub-phase `PHASE_201{a,b,c,d}_notes.md` files.
- `make test-go-redis-tls` Make target driving the existing compose overlay.
- `manifest.yaml` phase 201 → `COMPLETE` + `make sync`.
- Final `make test` / `make go-test` / `make check-scores` run on the
  merge commit.

## Out of scope (reminder)

- Python Redis client (already correct)
- Redis ACL provisioning / user creation
- Custom CA bundles, client-cert mTLS to Redis
- Management API / analytics Redis TLS (separate phases)
- Rate-limiter algorithm changes
