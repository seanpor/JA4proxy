# Security Remediation — Go Redis TLS + Signal Score Drift

> **Status:** PROPOSED
> **Parent Size:** MEDIUM — split into 5 SMALL sub-phases below.
> **Last revised:** 2026-04-11 (sub-phase breakdown for junior engineer handoff).

## Goal

Fix two production-critical Go gaps: (1) the Go Redis client omits TLS configuration
despite the config having an `ssl` field, exposing credentials and data on the wire
when Redis TLS is enabled, and (2) four signal scores in the Go proxy diverge from
the canonical `config/signal_scores.yml` registry, causing the production proxy to
make wrong scoring decisions.

---

## Sub-phase index

| ID | Sub-phase | Repo area | Size | Depends on |
|---|---|---|---|---|
| **201a** | Signal score drift fix (4 values) | `internal/security/` | XS | none |
| **201b** | TLS support in Go Redis client | `internal/redis/client.go` | S | none |
| **201c** | Error logging for silent failures | `internal/redis/client.go` | XS | 201b |
| **201d** | Health check / script reload | `cmd/proxy/main.go`, `internal/redis/` | S | 201b |
| **201e** | Rate limiter input validation | `internal/rate_limiter/` | S | 201b |

All sub-phases are **SMALL** or **XS**. Any can be picked up independently except
201c/201d/201e which depend on the TLS changes from 201b. 201a has no dependencies
and can be merged immediately.

---

## Sub-phase 201a — Signal score drift fix (XS)

**Goal:** Align 4 Go signal scores with `config/signal_scores.yml`.

**Why this matters:** The Go proxy assigns wrong risk scores, causing it to either
under-block (missing real threats) or over-block (false positives). This is a
single-commit fix.

**Files to modify:**
- `internal/security/tls_enforcer.go` — `tls_version` (40→10), `weak_cipher` (20→35)
- `internal/security/tcp_analyzer.go` — `high_concurrency` (25→40), `moderate_concurrency` (10→25)

**Steps:**
1. Run `make check-scores` and note the 4 failing scores.
2. Open `config/signal_scores.yml` and read the correct values:
   - `tls_version: 10`
   - `weak_cipher: 35`
   - `high_concurrency: 40`
   - `moderate_concurrency: 25`
3. Update the hardcoded scores in `tls_enforcer.go` and `tcp_analyzer.go`.
4. Run `make check-scores` — must exit 0.
5. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] `make check-scores` exits 0
- [ ] `make go-lint` passes with zero warnings
- [ ] CHANGELOG.md entry written
- [ ] PHASE_201a_notes.md written

**Out of scope:** Changing any other scores, changing Python scores, changing the registry file.

---

## Sub-phase 201b — TLS support in Go Redis client (S)

**Goal:** Add TLSConfig + username support to the Go Redis client so credentials
are not sent in cleartext when Redis TLS is enabled.

**Why this matters:** When `ssl: true` is set in config, the Go proxy connects to
Redis over plaintext — exposing the Redis password and all security data on the wire.

**Files to modify:**
- `internal/redis/client.go` — add `TLSConfig` + `Username` to Config struct and dial options
- `internal/config/loader.go` — wire `redis.username` from YAML config
- `tests/unit/test_redis_client_tls.go` — new TLS config unit tests

**Steps:**
1. Add `Username string` to the `Config` struct in `internal/redis/client.go`.
2. When `cfg.SSL` is true, set `opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}`.
3. Pass `Username: cfg.Username` to `goredis.Options`.
4. Wire `username` from the config loader (`internal/config/loader.go`) to read
   `redis.username` from YAML. Add to `config/proxy.yml` example with `# phase-201b` comment.
5. Write unit tests in `tests/unit/test_redis_client_tls.go`:
   - SSL=true → TLSConfig is set
   - SSL=false → TLSConfig is nil
   - Username is passed through
6. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] Go Redis client sets `TLSConfig` when `cfg.SSL` is true
- [ ] Go Redis client passes `Username` for ACL-based auth
- [ ] Unit tests cover SSL true/false + username passthrough
- [ ] `make go-test` passes
- [ ] `make go-lint` passes
- [ ] PHASE_201b_notes.md written

**Out of scope:** Redis ACL management, Redis TLS certificate generation, management API TLS.

---

## Sub-phase 201c — Error logging for silent failures (XS)

**Goal:** Add error logging to `ZAdd` and `ZRemRangeByScore` in the Go Redis client.

**Why this matters:** These methods currently swallow errors silently. If Redis is
unavailable or returns an error, the proxy continues as if the operation succeeded,
creating invisible data loss.

**Files to modify:**
- `internal/redis/client.go` — add error logging to `ZAdd` and `ZRemRangeByScore`

**Steps:**
1. Update `ZAdd` in `internal/redis/client.go` to log on error:
   ```go
   if err := c.rdb.ZAdd(ctx, key, goredis.Z{Score: score, Member: member}).Err(); err != nil {
       c.log.WithError(err).WithField("key", key).Warn("redis: ZADD failed")
   }
   ```
2. Same pattern for `ZRemRangeByScore`.
3. Write a test that mocks a Redis error and asserts the log line is emitted.
4. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] `ZAdd` logs errors instead of swallowing them
- [ ] `ZRemRangeByScore` logs errors instead of swallowing them
- [ ] Test verifies log output on error
- [ ] `make go-test` passes
- [ ] PHASE_201c_notes.md written

**Out of scope:** Retrying failed operations, circuit breakers (Phase 59 already covers this for TI feeds).

---

## Sub-phase 201d — Health check / script reload (S)

**Goal:** Add a periodic health check goroutine that re-loads Lua scripts after Redis outages.

**Why this matters:** If Redis restarts or evicts Lua scripts, the rate limiter breaks
silently. The proxy needs to detect this and re-load scripts without a restart.

**Files to modify:**
- `internal/redis/client.go` — add health check method
- `cmd/proxy/main.go` — wire health check goroutine at startup
- `internal/redis/client_test.go` — health check unit tests (new file)

**Steps:**
1. Add a periodic health check goroutine in the Go proxy startup that pings Redis
   every 30 seconds (matching Python's `health_check_interval=30`).
2. If `slidingWinSHA` is empty (script was lost/evicted), re-run `loadScripts()`
   to reload Lua scripts.
3. Add a Prometheus metric `ja4proxy_redis_health{status="ok|degraded|error"}`.
4. Write tests:
   - Health check detects empty script SHA and reloads
   - Health check recovers after simulated Redis restart
5. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] Periodic health check re-loads Lua scripts after Redis outage
- [ ] Prometheus metric `ja4proxy_redis_health` exposed
- [ ] Tests cover script reload after outage
- [ ] `make go-test` passes
- [ ] PHASE_201d_notes.md written

**Out of scope:** Full deep health-check endpoint (that's Phase 203-E), management API health endpoints.

---

## Sub-phase 201e — Rate limiter input validation (S)

**Goal:** Add input validation before constructing Redis keys in the rate limiter.

**Why this matters:** Malformed input (e.g., IPs with embedded colons or extremely
long strings) creates unexpected Redis key structures, potentially allowing key
collision attacks or Redis errors.

**Files to modify:**
- `internal/rate_limiter/rate_limiter.go` — add input validation
- `tests/unit/test_rate_limiter_validation.go` — new validation tests

**Steps:**
1. Add validation in `internal/rate_limiter/rate_limiter.go` before constructing Redis keys:
   - `len(clientIP) > 45` → reject (exceeds max IPv6 length)
   - `len(ja4) > 256` → truncate or reject
   - Reject strings containing colons in IP (would create unexpected key structure)
2. Log a warning and use a sanitized fallback key when input is invalid.
3. Write tests for each validation case:
   - Overlong IP rejected
   - Overlong JA4 truncated
   - IP with embedded colons rejected
   - Valid IPv4 and IPv6 accepted
4. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] Rate limiter validates IP (≤45 chars, no embedded colons) before key construction
- [ ] Rate limiter validates JA4 (≤256 chars) before key construction
- [ ] Warning logged on invalid input with sanitized fallback
- [ ] Tests cover all validation cases
- [ ] `make go-test` passes
- [ ] PHASE_201e_notes.md written

**Out of scope:** Rate limiting algorithm changes, Redis key naming convention changes.

---

## Full Phase Acceptance Criteria (all sub-phases)

- [ ] All 5 sub-phases complete (see individual acceptance criteria above)
- [ ] `make check-scores` exits 0 (all Go scores match registry)
- [ ] `make go-test` passes with zero failures
- [ ] `make go-lint` passes with zero warnings
- [ ] CHANGELOG.md entry written

## Out of Scope

- Changing the Python Redis client (it already supports TLS).
- Redis ACL management scripts (that's infrastructure, not proxy code).
- Adding Redis TLS to management API or analytics (separate phases).
