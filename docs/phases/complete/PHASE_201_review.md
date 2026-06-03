# Phase 201 — Critical Review

**Reviewed:** 2026-04-15
**Phase doc:** `docs/phases/complete/PHASE_201.md`
**Target:** Go (production runtime)
**Dependencies:** Phase 15 (COMPLETE) ✅

---

## TL;DR / Critical Blockers

1. **🔴 CRITICAL — Sub-phase 201a premise is FALSE.** The phase doc claims 4 Go
   signal scores have drifted from `config/signal_scores.yml` and must be changed
   (`tls_version 40→10`, `weak_cipher 20→35`, `high_concurrency 25→40`,
   `moderate_concurrency 10→25`). **Verification shows the opposite:**
   - `make check-scores` exits 0 with "All signal scores consistent with registry."
   - Registry values are `tls_version=40`, `weak_cipher=20`, `high_concurrency=25`,
     `moderate_concurrency=10`.
   - Go source (`internal/security/tls_enforcer.go:68,85,119` and
     `internal/security/tcp_analyzer.go:122,130,138`) already uses those exact
     values.
   **Applying the phase doc's instructions would INTRODUCE drift, not fix it.**
   Either the review that produced the phase was done against a stale branch, or
   the numbers were transcribed backwards. **This sub-phase must be deleted or
   rewritten before any work begins.**

2. **🟠 HIGH — Sub-phase 201c is already half done.** `ZAdd` in
   `internal/redis/client.go:346-349` already logs on error with
   `c.log.WithError(err).WithField("key", key).Warn(...)`. Only
   `ZRemRangeByScore` (line 357-360) still swallows errors silently. The
   sub-phase should be narrowed to just that one method, or deleted if deemed
   too small.

3. **🟠 HIGH — `redis.ssl` field is parsed but never used.**
   `internal/config/loader.go:407` reads `ssl: bool` from YAML, but
   `internal/redis/client.go:31-43` Config struct has no TLS field and
   `goredis.Options` is built without `TLSConfig`. When operators set
   `ssl: true` in `config/proxy.yml:44`, the flag is **silently ignored** — no
   warning, no error. This is worse than a missing feature because it gives a
   false sense of security. 201b needs to (a) honour the flag and (b) log a
   startup ERROR if `ssl: true` fails to produce a TLS handshake.

4. **🟡 MEDIUM — Test file paths in 201b and 201e are wrong for Go.** Phase doc
   says `tests/unit/test_redis_client_tls.go` and
   `tests/unit/test_rate_limiter_validation.go`. Go tests live **next to**
   the code: `internal/redis/client_tls_test.go` and
   `internal/security/rate_limiter_test.go`. The `tests/unit/` directory is
   Python-only. A junior engineer following the doc verbatim will create
   files `go test` never runs.

---

## Step 2 — Six-Lens Review

### 2a. Security
| # | Finding | Sev |
|---|---|---|
| S1 | `redis.ssl=true` silently ignored in Go (see blocker #3) — credentials + all security state transit in cleartext | CRITICAL |
| S2 | No `Username` field in `Config` → cannot use Redis ACLs; must fall back to shared `requirepass` account | HIGH |
| S3 | Rate limiter accepts arbitrary `clientIP`/`ja4` strings into Redis key names (201e) — key collision / log-injection risk if upstream parsing regresses | MEDIUM |
| S4 | If 201a is applied as written, `tls_version` drops to score 10 — deprecated TLS would no longer trigger the `flag` threshold (20). Exactly the kind of false-negative regression the core asymmetry warns against (low cost) **but** it would mean production silently tolerates TLS 1.0/1.1. | HIGH (only if 201a applied as-written) |
| S5 | No check for Redis password / username presence in logs — verify 201b doesn't accidentally log `cfg` | LOW |

### 2b. DevOps
| # | Finding | Sev |
|---|---|---|
| D1 | `config/proxy.yml:44` already has `ssl: false` — 201b just needs to honour it, not add new keys. Phase doc suggests adding example with `# phase-201b` which is redundant | LOW |
| D2 | No Helm / Compose change required — TLS is a runtime toggle. Good. | INFO |
| D3 | Rollback is clean: all changes are additive struct fields with zero-value defaults matching current behaviour | INFO |
| D4 | `sub-phase 201d` adds a new Prometheus metric `ja4proxy_redis_health` — must be registered in the shared registry (`internal/metrics/`) per `docs/OBSERVABILITY_STANDARDS.md`, not in the Redis package | MEDIUM |

### 2c. SRE
| # | Finding | Sev |
|---|---|---|
| R1 | Health-check goroutine (201d) must use `context.Context` and respect shutdown — if it spins forever on `time.Sleep(30s)` after `main()` returns, `go test` will hang. Use `time.NewTicker` + `select { case <-ctx.Done() }` | HIGH |
| R2 | 201d says "detect empty SHA → reload" but `loadScripts()` is not concurrency-safe — two simultaneous reloads will race on `c.slidingWinSHA`. Needs a mutex or `sync.Once`-per-generation | HIGH |
| R3 | No SLI defined: "reload after outage" is a capability, not a measurement. Add `ja4proxy_redis_script_reloads_total{result="ok|error"}` counter | MEDIUM |
| R4 | Runbook entry needed in `docs/runbooks/go_proxy_operations.md` for "what to do when `ja4proxy_redis_health{status="error"}` alerts" | MEDIUM |
| R5 | Rate limiter "sanitized fallback key" (201e) must be deterministic — otherwise attackers get different buckets per request and rate limit is bypassed | HIGH |

### 2d. Architecture
| # | Finding | Sev |
|---|---|---|
| A1 | `internal/rate_limiter/` does not exist — rate limiter is at `internal/security/rate_limiter.go`. Phase doc path is wrong for 201e | HIGH |
| A2 | TLS config plumbing: loader already owns `SSL` → just add `SSL`, `Username` to `redis.Config` and pass through in `redis.New`. No interface refactor needed | INFO |
| A3 | IPv6: rate-limiter validation "≤45 chars" is correct (max IPv6 textual length = 45 incl. zone id omitted). "no colons in IP" rule is WRONG — IPv6 is all colons. Rule should be "no colons in the IP *field* of the key after canonicalisation" or "use `netip.ParseAddr` and reject on error" | CRITICAL for IPv6 |
| A4 | Phase doc proposes 5 independent sub-phases — 201b is a strict prerequisite only of 201d (which re-uses the TLS-enabled client). 201c and 201e are independent of 201b. Dependency graph in doc is too conservative; can be tightened | LOW |

### 2e. Testing
| # | Finding | Sev |
|---|---|---|
| T1 | Go test files in wrong location (see blocker #4) | HIGH |
| T2 | No chaos test proposed for Redis-TLS handshake failure → proxy must fail-open to local cache, not crash at startup | HIGH |
| T3 | No parity test: Python already supports TLS + Username; 201b should include a test that both clients reject the same malformed Redis URL | MEDIUM |
| T4 | 201d "test that health check recovers after Redis restart" needs `miniredis` or testcontainers — spell out which in the sub-task | MEDIUM |
| T5 | 201e missing the one test that matters most: fuzz-style property test using `netip.ParseAddr` as oracle. Without it "validation" is an arbitrary regex that will get holes | HIGH |

### 2f. Documentation
| # | Finding | Sev |
|---|---|---|
| DOC1 | Phase-level CHANGELOG entry missing from acceptance criteria (sub-phases each require one, but there's no roll-up) | LOW |
| DOC2 | ADR needed: "Why Go Redis client uses TLS MinVersion 1.2 and not 1.3" — this is a non-obvious security-vs-compat tradeoff | MEDIUM |
| DOC3 | `docs/REDIS_SCHEMA.md` doesn't need updates (no new keys), but the health-check metric should be added to `docs/OBSERVABILITY_STANDARDS.md` | MEDIUM |
| DOC4 | Phase doc "last revised 2026-04-11" but numbers don't match the code on `main` at 2026-04-15 — needs re-verification timestamp | INFO |

---

## Step 3 — Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| 1 | 201a premise inverted; applying as written creates drift | CRITICAL | Security/Correctness | **Delete 201a** from the phase, or rewrite with a fresh `make check-scores` diff |
| 2 | `redis.ssl` silently ignored | CRITICAL | Security | 201b is essential; add startup log line confirming TLS active |
| 3 | IPv6 "no colons" rule | CRITICAL | Architecture | Replace with `netip.ParseAddr` in 201e |
| 4 | Go test file paths wrong | HIGH | Testing | Use `internal/<pkg>/xxx_test.go` in all sub-phases |
| 5 | `loadScripts` race in 201d | HIGH | SRE | Add mutex or `sync.Once` |
| 6 | Rate limiter fallback key must be deterministic | HIGH | SRE | Use `sha256(raw)[:16]` fallback or reject outright |
| 7 | No Redis-TLS chaos test | HIGH | Testing | Add test: proxy starts, Redis TLS fails, proxy runs fail-open |
| 8 | 201c partially done already | HIGH | Correctness | Narrow 201c to just `ZRemRangeByScore`; verify no other callers swallow errors |
| 9 | `rate_limiter/` path doesn't exist | HIGH | Architecture | Fix path to `internal/security/rate_limiter.go` |
| 10 | `tls_version` score regression risk | HIGH | Security | Do NOT apply 201a |
| 11 | Username/ACL not supported | HIGH | Security | Add in 201b |
| 12 | Health-check metric must live in `internal/metrics` | MEDIUM | DevOps | Register centrally |
| 13 | No ADR on TLS MinVersion choice | MEDIUM | Docs | Add ADR-201a |
| 14 | No Go-vs-Python parity test for Redis URL parsing | MEDIUM | Testing | Add one small table-driven test |
| 15 | Runbook entry for health-check alert | MEDIUM | SRE | Append to `go_proxy_operations.md` |

---

## Step 4 — Junior-Engineer Sub-Task Breakdown

> All path and premise corrections from the review are already applied below.
> **Do not use the sub-phase numbering from the original phase doc verbatim.**

### Phase 1 — Correct the Plan (blocker)

#### Sub-task 1.1: Remove or rewrite 201a
**Size:** XS (≤30 min)
**Depends on:** none
**Parallel with:** none
**Files to touch:** `docs/phases/complete/PHASE_201.md`, `docs/phases/manifest.yaml`
**What to do:**
- Run `make check-scores`. Confirm exit 0.
- Open `docs/phases/complete/PHASE_201.md` and delete the entire "Sub-phase 201a" section.
- In `manifest.yaml` under phase 201 `sub_phases:`, remove `201a:` line.
- Update the phase doc "Sub-phase index" table accordingly.
**Done when:**
- [ ] `make check-scores` still exits 0 on `main`
- [ ] `grep -R "201a" docs/phases/` returns no results
**Watch out for:** Don't touch `config/signal_scores.yml` — it is the source of truth and is already correct.

---

### Phase 2 — Scaffolding (safe, parallelisable)

#### Sub-task 2.1: Add TLS + Username fields to redis.Config struct
**Size:** XS (30 min)
**Depends on:** 1.1
**Parallel with:** 2.2, 2.3
**Files to touch:** `internal/redis/client.go`
**What to do:**
- Extend struct at `internal/redis/client.go:31-43` with `SSL bool` and `Username string`.
- **Do not** wire them into `goredis.Options` yet. Just add the fields with zero-value defaults.
- Run `go build ./...` and `go test ./internal/redis/...` — both must pass unchanged.
**Done when:**
- [ ] `grep -n "SSL\s*bool" internal/redis/client.go` returns a hit
- [ ] `go build ./...` passes
**Watch out for:** Keep field order grouped (network, auth, timing). `gofmt` will rewrite the struct if you don't.

#### Sub-task 2.2: Register `ja4proxy_redis_health` metric
**Size:** XS (30 min)
**Depends on:** 1.1
**Parallel with:** 2.1, 2.3
**Files to touch:** `internal/metrics/metrics.go` (or wherever existing Prom metrics live — `grep -l "promauto\|prometheus.MustRegister" internal/`)
**What to do:**
- Add `RedisHealth = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "ja4proxy_redis_health", Help: "..."}, []string{"status"})`.
- Add `RedisScriptReloadsTotal = promauto.NewCounterVec(..., []string{"result"})`.
- Do **not** wire them into the client yet.
**Done when:**
- [ ] `go build ./...` passes
- [ ] `grep ja4proxy_redis_health internal/metrics/` returns a hit
**Watch out for:** Use `promauto` (auto-registers) consistent with existing metrics; do not call `MustRegister` manually.

#### Sub-task 2.3: Create failing tests for ZRemRangeByScore error logging
**Size:** XS (45 min)
**Depends on:** 1.1
**Parallel with:** 2.1, 2.2
**Files to touch:** `internal/redis/client_test.go`
**What to do:**
- Using `miniredis` (already in test deps — grep existing tests to confirm import path), write a test that forces `ZRemRangeByScore` to fail (e.g., pass a key of the wrong type).
- Use a `logrus.Hook` or `test.NewNullLogger()` to capture log output.
- Assert `WARN` line with `key` field is emitted.
- Test MUST fail until 3.2 is done.
**Done when:**
- [ ] `go test -run TestZRemRangeByScore_LogsOnError ./internal/redis/` fails with "no warn log emitted"
**Watch out for:** `miniredis` accepts many commands silently — use `.SetError()` to force failure, or an unexpected-type key.

---

### Phase 3 — Core Logic (sequential within file)

#### Sub-task 3.1: Wire TLS and Username into goredis.Options / FailoverOptions
**Size:** S (2 h)
**Depends on:** 2.1
**Parallel with:** 3.2 (different methods)
**Files to touch:** `internal/redis/client.go` (function `New`, both branches)
**What to do:**
- Import `crypto/tls`.
- In both the Sentinel and Single-Node branches, if `cfg.SSL` is true, set `opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}`.
- Pass `Username: cfg.Username` in both options.
- Add a startup log line: `log.WithFields{"ssl": cfg.SSL, "username": cfg.Username != ""}.Info("redis: dial options")`. **Do not** log the password.
- Ping the server within 2 s after `New` returns; if `cfg.SSL` was set but the ping fails with a TLS error, log an `ERROR` (don't fail — fail-open is preserved).
**Done when:**
- [ ] With `ssl: true` against a non-TLS Redis, proxy logs `ERROR` and continues in fail-open mode
- [ ] With `ssl: true` against a TLS-enabled Redis (miniredis TLS helper or stunnel), ping succeeds
- [ ] `go test ./internal/redis/...` passes
- [ ] `go vet ./...` clean
**Watch out for:**
- `goredis.FailoverOptions.TLSConfig` is the Sentinel field — same name, different struct. Set on both.
- Do NOT log `cfg.Password`. Grep your diff for `Password` before committing.

#### Sub-task 3.2: Add error logging to ZRemRangeByScore
**Size:** XS (15 min)
**Depends on:** 2.3
**Parallel with:** 3.1
**Files to touch:** `internal/redis/client.go:355-362`
**What to do:**
- Match the existing `ZAdd` pattern at line 348: add
  `c.log.WithError(err).WithField("key", key).Warn("redis: ZREMRANGEBYSCORE failed")`
  before `return`.
- Audit the rest of the file for other `.Err()` results that are discarded; for each, decide: log + observe, or document why silent is correct.
**Done when:**
- [ ] Test from 2.3 passes
- [ ] No `.Err()` call in `client.go` is discarded without a comment
**Watch out for:** `observeOp("zremrangebyscore", "error")` is already present — keep it.

#### Sub-task 3.3: Config loader wires username through
**Size:** XS (20 min)
**Depends on:** 2.1
**Parallel with:** 3.1, 3.2
**Files to touch:** `internal/config/loader.go` (struct at line 400; the place where `redis.Config` is constructed from the YAML struct)
**What to do:**
- Add `Username string \`yaml:"username"\`` to the YAML struct.
- Pass it into `redis.Config{SSL: ..., Username: ...}` at the construction site (find with `grep -n "redis.Config{" internal/`).
- `config/proxy.yml:32-44`: add `username: ""` line under the existing `redis:` block with a `# phase-201` inline comment.
**Done when:**
- [ ] `go build ./...` passes
- [ ] Setting `username: alice` in YAML + dumping parsed config shows `alice`
**Watch out for:** `redis.ssl` is already present and already plumbed into the YAML struct — confirm your code path actually reaches `goredis.Options`, don't assume.

---

### Phase 4 — Health Check (sequential — new goroutine)

#### Sub-task 4.1: Add thread-safe script reload
**Size:** S (1 h)
**Depends on:** 3.1
**Parallel with:** 4.3
**Files to touch:** `internal/redis/client.go`
**What to do:**
- Add `scriptMu sync.RWMutex` to `Client`.
- Wrap reads of `c.slidingWinSHA` in `RLock`, writes (in `loadScripts`) in `Lock`.
- Add public method `HealthCheck(ctx context.Context) error`:
  - `PING` Redis (2 s timeout).
  - On error: set metric `RedisHealth.WithLabelValues("error").Set(1)` and return.
  - On success with empty `slidingWinSHA`: call `loadScripts`, increment `RedisScriptReloadsTotal`.
  - On success: set `RedisHealth...("ok").Set(1)`.
**Done when:**
- [ ] `go test -race ./internal/redis/...` passes
- [ ] Calling `HealthCheck` twice concurrently cannot cause two `loadScripts` runs (verify via hook on `SCRIPT LOAD` call count in miniredis)
**Watch out for:** `sync.Once` is wrong here — scripts CAN need reloading more than once over the proxy lifetime. Use mutex + "if empty then reload" under lock.

#### Sub-task 4.2: Health-check goroutine in main
**Size:** S (1 h)
**Depends on:** 4.1
**Parallel with:** 4.3
**Files to touch:** `cmd/proxy/main.go`
**What to do:**
- In the existing startup goroutine block (grep for `go func()` after Redis init), add a new goroutine:
  ```go
  ticker := time.NewTicker(30 * time.Second)
  defer ticker.Stop()
  for {
      select {
      case <-ctx.Done(): return
      case <-ticker.C: redisClient.HealthCheck(ctx)
      }
  }
  ```
- The goroutine must receive the shutdown context, not `context.Background()`.
**Done when:**
- [ ] `go test ./cmd/proxy/...` passes (if tests exist; otherwise manual verify)
- [ ] `grep -n "HealthCheck(ctx)" cmd/proxy/main.go` returns a hit
- [ ] Running `bin/proxy` against Redis, killing and restarting Redis, then checking `/metrics` shows `ja4proxy_redis_script_reloads_total{result="ok"} >= 1` within 60 s
**Watch out for:** If `main.go` has no cancellable ctx today, create one with `signal.NotifyContext`. Don't leak the old `context.Background()`.

#### Sub-task 4.3: Runbook + ADR
**Size:** XS (30 min)
**Depends on:** 1.1
**Parallel with:** everything
**Files to touch:** `docs/runbooks/go_proxy_operations.md`, `docs/decisions/ADR-201a.md` (new)
**What to do:**
- Append a `## Redis health check alerts` section: what `ja4proxy_redis_health{status="error"}` means, what operators should check, how to force a script reload manually.
- New ADR-201a: "Redis TLS MinVersion=1.2 for Go client" — explain why not 1.3 (compat with Redis Enterprise, ELB terminators) and why not 1.0/1.1 (weak ciphers).
**Done when:**
- [ ] Runbook links from `/metrics` alert rules (if rules exist)
- [ ] ADR passes `make lint-docs` (if configured) or at minimum `markdownlint`

---

### Phase 5 — Rate Limiter Validation

#### Sub-task 5.1: Add netip-based IP validator
**Size:** S (1 h)
**Depends on:** 1.1
**Parallel with:** 3.x, 4.x
**Files to touch:** `internal/security/rate_limiter.go` (NOT `internal/rate_limiter/`)
**What to do:**
- Add a private helper:
  ```go
  func sanitizeKey(ip, ja4 string) (string, string, bool) {
      addr, err := netip.ParseAddr(ip)
      if err != nil || !addr.IsValid() { return "", "", false }
      canonIP := addr.String()
      if len(ja4) > 256 { ja4 = ja4[:256] }
      return canonIP, ja4, true
  }
  ```
- In `Check` (line 49), call `sanitizeKey` first. On false: log `Warn` with the raw input (sha256-hashed to avoid log-injection via weird bytes) and **return nil signals** (fail-open).
**Done when:**
- [ ] IPv6 addresses with zone IDs accepted (canonicalised)
- [ ] `netip.ParseAddr` oracle test: every input it accepts, `sanitizeKey` accepts; every one it rejects, `sanitizeKey` rejects
- [ ] `make go-test` passes
**Watch out for:**
- Do NOT use the "no colons" rule from the original phase doc — it rejects all IPv6.
- Log hash (`fmt.Sprintf("%x", sha256.Sum256([]byte(ip)))[:16]`) not the raw string — raw may contain `\n` etc.

#### Sub-task 5.2: Property test
**Size:** S (1 h)
**Depends on:** 5.1
**Parallel with:** none
**Files to touch:** `internal/security/rate_limiter_test.go`
**What to do:**
- Table-driven cases: valid v4, valid v6, v6-with-zone, empty, 1KB garbage, `"1.2.3.4\nSET evil"`, JA4 of 10KB.
- Plus a loop: 1 000 random 16-byte strings — assert `sanitizeKey` return matches `netip.ParseAddr(x).IsValid()`.
**Done when:**
- [ ] `go test -run TestSanitizeKey ./internal/security/ -count=10` stable
- [ ] Coverage of `sanitizeKey` ≥ 95 %

---

### Phase 6 — Roll-up / Docs

#### Sub-task 6.1: CHANGELOG and manifest close-out
**Size:** XS (20 min)
**Depends on:** 3.x, 4.x, 5.x all merged
**Files to touch:** `CHANGELOG.md`, `docs/phases/manifest.yaml`, `docs/PROJECT_STATUS.md` (regenerated)
**What to do:**
- Prepend CHANGELOG entry in standard format noting TLS + username support, ZRemRangeByScore logging, health check, rate-limiter validation. Mention that the "signal score drift" finding was withdrawn as invalid.
- Set `phases.201.status: COMPLETE` in manifest.
- Run `make sync`.
**Done when:**
- [ ] `git diff docs/phases/TODO.md` shows phase 201 no longer listed as open
- [ ] `make test` and `make go-test` both pass

---

## Step 5 — Summary

- **Sub-tasks:** 13 (down from 5 original sub-phases; finer-grained per junior-handoff requirement)
- **Estimated total:** ~11–12 hours of focused engineering
- **Critical blockers before any code is written:**
  1. **Delete or rewrite sub-phase 201a** — its premise is false; applying it introduces the drift it claims to fix. (Sub-task 1.1)
  2. **Correct all Go test file paths** in the phase doc (`tests/unit/*.go` → `internal/<pkg>/*_test.go`).
  3. **Fix the IPv6 "no colons" rule** in 201e before any code is written.
- **Unblocked next step:** Sub-task 1.1 can land immediately (docs-only); Phase 2 scaffolding (2.1, 2.2, 2.3) can then run in parallel.
