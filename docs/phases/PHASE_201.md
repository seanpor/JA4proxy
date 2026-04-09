# Security Remediation — Go Redis TLS + Signal Score Drift

## Goal

Fix two production-critical Go gaps: (1) the Go Redis client omits TLS configuration
despite the config having an `ssl` field, exposing credentials and data on the wire
when Redis TLS is enabled, and (2) four signal scores in the Go proxy diverge from
the canonical `config/signal_scores.yml` registry, causing the production proxy to
make wrong scoring decisions.

## Scope

Files to modify:
- `internal/redis/client.go` — add TLSConfig + username support
- `internal/redis/client.go` — add error logging to `ZAdd`/`ZRemRangeByScore`
- `internal/redis/client.go` — add health check / script reload after outage
- `internal/security/tls_enforcer.go` — fix `tls_version` and `weak_cipher` scores
- `internal/security/tcp_analyzer.go` — fix `high_concurrency` and `moderate_concurrency` scores
- `internal/rate_limiter/rate_limiter.go` — add input validation on IP/JA4 key construction
- `tests/unit/test_redis_client_tls.go` — TLS config unit tests
- `tests/unit/test_signal_scores_parity.go` — verify scores match registry

## Implementation Plan

### A — TLS support in Go Redis client

1. Add `Username string` to the `Config` struct in `internal/redis/client.go`.
2. When `cfg.SSL` is true, set `opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}`.
3. Pass `Username: cfg.Username` to `goredis.Options`.
4. Wire `username` from the config loader (`internal/config/loader.go`) to read
   `redis.username` from YAML.

### B — Error logging for silent failures

1. Update `ZAdd` in `internal/redis/client.go` to log on error:
   ```go
   if err := c.rdb.ZAdd(ctx, key, goredis.Z{Score: score, Member: member}).Err(); err != nil {
       c.log.WithError(err).WithField("key", key).Warn("redis: ZADD failed")
   }
   ```
2. Same pattern for `ZRemRangeByScore`.

### C — Health check / script reload

1. Add a periodic health check goroutine in the Go proxy startup that pings Redis
   every 30 seconds (matching Python's `health_check_interval=30`).
2. If `slidingWinSHA` is empty (script was lost/evicted), re-run `loadScripts()`
   to reload Lua scripts.
3. This ensures the rate limiter recovers automatically after Redis outages without
   requiring a proxy restart.

### D — Rate limiter input validation

1. Add validation in `internal/security/rate_limiter.go` before constructing Redis keys:
   - `len(clientIP) > 45` → reject (exceeds max IPv6 length)
   - `len(ja4) > 256` → truncate or reject
   - Reject strings containing colons in IP (would create unexpected key structure)
2. Log a warning and use a sanitized fallback key when input is invalid.

### E — Signal score drift fix

1. Read `config/signal_scores.yml` to get the correct values:
   - `tls_version: 10`
   - `weak_cipher: 35`
   - `high_concurrency: 40`
   - `moderate_concurrency: 25`
2. Update `internal/security/tls_enforcer.go`:
   - Change `tls_version` score from 40 → 10
   - Change `weak_cipher` score from 20 → 35
3. Update `internal/security/tcp_analyzer.go`:
   - Change `high_concurrency` score from 25 → 40
   - Change `moderate_concurrency` score from 10 → 25
4. Run `make check-scores` — must exit 0.

## Acceptance Criteria

- [ ] Go Redis client sets `TLSConfig` when `cfg.SSL` is true
- [ ] Go Redis client passes `Username` for ACL-based auth
- [ ] `ZAdd` and `ZRemRangeByScore` log errors instead of swallowing them
- [ ] Periodic health check re-loads Lua scripts after Redis outage
- [ ] Rate limiter validates IP (≤45 chars, no colons) and JA4 (≤256 chars) before key construction
- [ ] `make check-scores` exits 0 (all Go scores match registry)
- [ ] `make go-test` passes with zero failures
- [ ] `make go-lint` passes with zero warnings
- [ ] CHANGELOG.md entry written

## Out of Scope

- Changing the Python Redis client (it already supports TLS).
- Redis ACL management scripts (that's infrastructure, not proxy code).
- Adding Redis TLS to management API or analytics (separate phases).
