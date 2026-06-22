---
phase: 335
title: TAP Sensor Hardening — Phase 334 Findings Remediation
created: 2026-06-18
audience: [developer, security]
---

# TAP Sensor Hardening — Phase 334 Findings Remediation

## Goal

Fix the CRITICAL and HIGH findings from the Phase 334 expert code review of the 316* Go TAP/SPAN passive sensor series. The sensor is code-complete but has production-safety gaps that make it unsuitable for deployment: no panic recovery (goroutine leak on any crash), zero observability (no metrics endpoint, no health check), and a shutdown hang that ignores SIGTERM on idle SPAN ports.

## Scope

### P0 — CRITICAL (production safety — must fix)

| Finding | Description | Fix |
|---------|-------------|-----|
| F-022 | No panic recovery — sensor silently hangs on any nil-pointer/panic in gopacket decode | Add `recover()` in the sensor goroutine that closes `s.events` and sends error to `done` channel |
| F-023 | Zero observability — metrics never registered, no `/metrics` or `/health` endpoint | Register TAP metrics with Prometheus, add HTTP listener with `promhttp.Handler()` + `/health` endpoint |
| R-001 | Shutdown hang — `ReadPacketData` blocks forever on idle SPAN, SIGTERM ignored | Add `OptPollTimeout(1s)` to AF_PACKET handle so context cancellation is rechecked |

### P1 — HIGH (operational integrity)

| Finding | Description | Fix |
|---------|-------------|-----|
| F-014 | Busyloop on read error — 100% CPU burn on transient errors | Add `time.Sleep(100ms)` + consecutive-error counter on the error path |
| F-002 | Capability drop + seccomp not wired — full `CAP_NET_RAW` throughout lifetime | Post-socket `setuid/setgid` to nobody, load seccomp profile before capture loop |
| F-016 | Concurrent map read on `JA4TBlocklist` — latent data-race panic | Wrap with `sync.RWMutex` or switch to `sync.Map` |
| O-001 | No Makefile target to build `cmd/ja4-tap` | Add `tap-build` target + add to `build` chain |
| O-002 | Alert rules reference 5 non-existent/dead metrics | Fix metric names in `tap.yml` alert rules |
| O-003 | Grafana dashboard references 8 non-existent metrics | Fix metric names in `tap_sensor.json` dashboard panels |
| D-001 | Sensor bans overwrite admin bans with 5min TTL | Check existing ban value before overwriting; log provenance |

### P2 — MEDIUM (correctness, security hardening)

| Finding | Description | Fix |
|---------|-------------|-----|
| F-008 | TLS parser stalls on non-handshake record interleaved in fragmented handshake | Advance `i` past non-handshake record instead of `break` |
| F-019 | Duplicate `canonicalIP` in writer + consumer (silent drift risk) | Extract to `internal/netutil/ip.go` |
| D-002 | Consumer cache does not distinguish "not cached" from "cached empty" (60s blind window) | Use sentinel value for negative cache entries or shorter negative TTL |
| F-017 | Redis password in cleartext on command line | Add `--redis-password` flag read from env/file |
| F-018 | No TLS enforcement for Redis connection (cleartext fingerprints) | Add `--redis-tls` flag |
| R-012 | No Redis `Ping()` on startup — misconfigured Redis discovered on first event | Add startup connectivity check |
| F-007 | `dropEventOverflow` missing from metrics constants | Add constant |
| F-020 | Read error rate not tracked in metrics | Add `PacketsDroppedTotal{reason="read_error"}` on error path |
| G-001 | `StackFeatures.OptionOrder` slice aliasing across goroutines | Deep-copy at emit time |

### P3 — LOW (hygiene, packaging)

| Finding | Description | Fix |
|---------|-------------|-----|
| F-001 | 316a PROPOSED but code shipped under 316b | Mark 316a COMPLETE, fix action_plan path |
| F-006 | No `tap:` section in `config/proxy.yml` | Add disabled-by-default placeholder section |
| F-009/F-010 | Stale doc comments referencing Phase 20 Python TAP | Update to reference Phase 316 Go sensor |
| O-005 | No Dockerfile or docker-compose service for TAP sensor | Create `Dockerfile.ja4-tap` + compose service |
| O-006 | No Redis ACL user for TAP sensor in `config/redis_acl.conf` | Add `ja4tap` user entry |
| R-008 | No structured logging / log level flags | Add `--log-format` and `--log-level` flags |
| T-001 | ServerHello missed on HelloRetryRequest/HelloRequest | Fix `appendDir` to only set `done` on matching handshake type |
| T-002 | No protocol version validation in TLS record header | Add version field check |

### Deferred (future phase)

| Finding | Reason |
|---------|--------|
| F-003 | No `sync.Pool` usage | Capacity/throughput hardening phase |
| F-004 | No kernel BPF filter | Depends on F-002 being stable |
| F-005 | No watchdog | Covered by F-022 panic recovery; nice-to-have |
| F-025 | gopacket dependency CVE audit | Needs dedicated fuzzing phase |
| F-026 | `Fetch()` allocates attacker-controlled buffer | Bounded by existing limit; monitor |
| F-027 | No input validation on `--frame-size` | Acceptable risk; add bounds check if crashes seen |
| P-001–P-005 | GDPR/privacy documentation | Separate compliance phase |
| R-003–R-011 | Memory limits, rate limiting, sampling, etc. | Future capacity/operational phase |
| T-003–T-005 | Performance edge cases | Future optimization phase |
| G-002–G-003 | GC pressure, Go runtime config | Capacity planning phase |
| D-003 | Redis key prefixes hard-coded | Refactor with shared constants (future cleanup) |

## Implementation Plan

### Sub-phase A — Safety (P0)
1. `internal/tap/panic.go`: new file with `Recover()` helper that logs stack and closes events channel
2. `cmd/ja4-tap/main.go`: wrap `sensor.Run` goroutine with panic recovery; add `--metrics-addr` flag
3. `internal/tap/metrics.go`: add HTTP handler registration with `/metrics` and `/health` endpoints
4. `capture_linux.go`: add `afpacket.OptPollTimeout(time.Second)` to AF_PACKET options

### Sub-phase B — Operational Hardening (P1)
5. `cmd/ja4-tap/main.go`: add `dropCapabilities()` + `loadSeccompProfile()` before capture loop
6. `internal/tap/enforcement.go`: `sync.RWMutex` on `EnforcerConfig.JA4TBlocklist`
7. `Makefile`: add `tap-build` target, wire into `build` target
8. `deploy/monitoring/alertmanager/rules/tap.yml`: fix all metric names
9. `deploy/monitoring/grafana/dashboards/tap_sensor.json`: fix all metric names
10. `internal/tap/enforcement.go`: add `BanProvenance` check before overwriting existing ban

### Sub-phase C — Correctness (P2)
11. `internal/tap/tlsparse.go`: replace `break` with advancing past non-handshake record
12. `internal/netutil/ip.go`: new file with `CanonicalIP()` function
13. `internal/security/tap_consumer.go` + `internal/security/tap_ja4t_consumer.go`: use shared `CanonicalIP`, sentinel-based negative cache
14. `cmd/ja4-tap/main.go`: add `--redis-password` + `--redis-tls` flags
15. `cmd/ja4-tap/main.go`: add `rdb.Ping()` check after Redis client creation
16. `internal/tap/metrics.go`: add `dropEventOverflow` constant + `read_error` label value
17. `internal/tap/reassembler.go`: deep-copy `OptionOrder` at emit time

### Sub-phase D — Packaging & Hygiene (P3)
18. `config/proxy.yml`: add `tap:` section with disabled-by-default settings
19. `deploy/docker/Dockerfile.ja4-tap`: multi-stage build (Go → scratch)
20. `deploy/docker/docker-compose.prod.yml`: add `ja4-tap` service (commented out by default)
21. `config/redis_acl.conf`: add `ja4tap` user with minimal permissions
22. `cmd/ja4-tap/main.go`: add `--log-format` (text/json) + `--log-level` flags
23. `internal/tap/reassembler.go`: fix ServerHello edge case in `appendDir`
24. `internal/tap/tlsparse.go`: add TLS version validation in record header
25. `docs/phases/manifest.yaml`: mark Phase 316a COMPLETE, add Phase 335 entry

## Test Strategy

- Unit tests: `go test ./internal/tap/...` and `./cmd/ja4-tap/...`
- Panic recovery test: inject panic → verify `recover()` logs and channel closes
- Shutdown test: idle sensor + SIGTERM → exit within 2s
- Health check test: `/health` returns 200 after Redis connect
- CPU spin test: simulate read errors → verify `time.Sleep` prevents 100% CPU
- `make lint` — zero violations
- `make test` — no regressions  
- `make lint-phases` — phase docs valid
- `make preflight` — all gates green
- Docker build test: `make tap-build` → `docker build -f deploy/docker/Dockerfile.ja4-tap`

## Acceptance Criteria

1. Sensor recovers from a panic (test: inject panic in decode path → event channel closes → process exits gracefully)
2. Sensor shuts down cleanly on idle SPAN (SIGTERM → exit within 2s)
3. `/metrics` returns Prometheus text with TAP metrics; `/health` returns 200
4. Read errors are metered and bounded (no 100% CPU spin)
5. Capability drop + seccomp loaded before capture starts
6. `JA4TBlocklist` is safe for concurrent read+write
7. `make tap-build` produces `bin/ja4-tap` binary
8. Alert rules and dashboard show live data (metric names match code)
9. Admin bans not overwritten by sensor bans
10. Redis connection verified at startup; TLS and password configurable via flags
11. Phase 316a status set to COMPLETE in manifest
12. `make lint` + `make test` + `make lint-phases` + `make preflight` all green