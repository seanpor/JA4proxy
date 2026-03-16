# Phase 15 — Go Rewrite of Proxy Core

## Goal
Rewrite `proxy.py` and `src/security/` in Go. Eliminate Python GIL bottleneck.
Target: 10–50× throughput improvement per instance.

**Do this phase last.** The Python implementation proves the design and its test suite
defines correctness. Rewrite once, when the design is stable.

## 15a. Why Go, Not Rust

| Factor | Go | Rust |
|--------|-----|------|
| Throughput vs Python | 10–50× | 15–70× |
| GC pauses at this scale | <1ms, infrequent | None |
| Dev time vs Python | ~2× | ~4–5× |
| Redis client | go-redis/v9 — excellent | redis-rs — good |
| Verdict | ✅ Recommended | Not worth complexity delta |

## 15b. What Moves to Go
`proxy.py` — TCP listener, TLS ClientHello parser, connection dispatcher
`src/security/` — all pipeline modules
`src/cache/` — in-process LRU caches

## 15c. What Stays Python
`analytics/` (Phase 12) — scipy/pandas ecosystem; not performance-critical
`management/` (Phase 13) — FastAPI; not performance-critical

## 15d. Go Module Structure
```
cmd/proxy/main.go
internal/
  tls/{parser,ja4,ja4t}.go
  security/{pipeline,risk_scorer,action_decider,sni,tcp_analyzer,mtls,
            asn,dns,blocklists,beaconing,abuseipdb,rdap,tls_enforcer}.go
  cache/local.go
  redis/{client,lua,pubsub}.go
  config/loader.go              # Same proxy.yml YAML schema
```

## 15e. Performance Reality Check

| Condition | Bottleneck | Expected ceiling |
|-----------|-----------|-----------------|
| Warm cache (repeat IPs) | TLS parse + JA4 compute | ~5,000–15,000 conn/s per instance |
| Mixed traffic | Redis pipeline RTT | ~2,000–8,000 conn/s per instance |
| DDoS (all new IPs) | Redis ops/s | ~50,000 conn/s (Redis Stack ~200k ops/s + pipeline batching) |

## 15f. Migration Strategy
1. Go proxy reads same `config/proxy.yml` schema — no schema changes
2. Uses identical Redis key schema — Python and Go interoperable on same Redis
3. All Python tests that test behaviour (not implementation) have Go equivalents
4. Run Python and Go versions in parallel on different ports during validation
5. Switch HAProxy upstream to Go port after validation
6. Keep Python proxy in `legacy/` for 30 days then archive

## Redis Key Schema

Phase 15 adds no new Redis keys. The Go proxy reads and writes the same schema defined in Phases 00–14.

## Config

The Go proxy reads the same `config/proxy.yml` as the Python proxy. No new config
keys are introduced. The Go implementation must handle every existing config key
and produce identical decisions for identical inputs.

Build configuration:
```yaml
# config/build.yml  (new — Go build settings only)
go_proxy:
  binary_name: ja4proxy           # Output binary name.
  min_go_version: "1.22"          # Minimum Go version required.
  target_platforms:               # Build targets for release.
    - linux/amd64
    - linux/arm64
```

## Chaos Scenarios

| Scenario | Expected behaviour |
|----------|--------------------|
| Go proxy crashes | HAProxy routes to Python instance (if running in parallel); no traffic gap |
| Go proxy receives adversarial ClientHello | Parser handles without panic; connection rejected or scored normally |
| Redis connection fails mid-traffic | Same fail-open behaviour as Python proxy; verified by identical chaos test suite |
| Config file has unknown keys | Go proxy ignores unknown keys with DEBUG log; does not exit |

## Current Implementation State (as of 2026-03-16)

Initial scaffolding is committed. **Nothing is functional yet.** See `PHASE_15_subplan.md`
for the full breakdown of what exists and what is broken. Summary:

- `go.mod` exists but has the wrong redis import path (`go-redis/redis/v9` → fix to `redis/go-redis/v9`)
- `cmd/proxy/main.go` is a skeleton; references `NewProxy` / `config.Load` which don't exist
- `internal/tls/hello_info.go` has preliminary struct definitions
- `internal/tls/ja4.go` is a non-functional placeholder (wrong hash, hardcoded ALPN)
- All other `internal/` packages are empty

Start at Phase 0 in `PHASE_15_subplan.md` to begin the actual implementation.

## Acceptance Criteria

### Functional
- [ ] `Dockerfile.go` multi-stage build; runtime image ≤ 10MB
- [ ] Go proxy reads same `config/proxy.yml` without schema changes
- [ ] JA4 fingerprint output byte-for-byte identical to Python for all `tests/fixtures/clienthello/` fixtures
- [ ] TLS ClientHello parser handles all adversarial corpus cases without panic
- [ ] All Lua scripts loaded via EVALSHA; script content identical to Python version
- [ ] Pub/Sub subscriber handles all message types; dial changes propagate correctly
- [ ] Prometheus metric names and label sets identical to Python version
- [ ] Python analytics and management UI containers run unchanged alongside Go proxy

### Observability
- [ ] All Prometheus metric names verified identical to `docs/OBSERVABILITY_STANDARDS.md` registry
- [ ] Go proxy structured JSON log schema identical to Python (same field names and types)

### Unit Tests  (`tests/unit/` — Go test files)
- [ ] JA4 computation: each `tests/fixtures/clienthello/*.bin` → matches expected fingerprint in `fixtures/clienthello/README.md`
- [ ] TLS parser: each adversarial corpus file → no panic; returns in < 1ms

### Integration Tests  (`tests/integration/test_pipeline.py` — cross-language)
- [ ] Go proxy + Python analytics: full pipeline produces same actions as Python proxy for identical inputs

### Performance Tests  (`tests/performance/bench_pipeline.py`)
- [ ] Throughput: ≥ 5× connections/second versus Python proxy at equivalent Redis load
- [ ] Load test: 1,000 conn/s sustained 60s with false-positive rate < 0.1%
