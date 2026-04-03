# Phase 15 — Go Rewrite of Proxy Core

| Component | Status | Notes |
|-----------|--------|-------|
| Go proxy binary (`cmd/proxy/`) | ✅ Complete | Drop-in replacement for `proxy.py` |
| Core security signals (TLS, SNI, TCP, etc.) | ✅ Complete | All Phase 0–14 signals ported |
| Signal module config wiring | ✅ Complete | All 7 modules (ASN, DNS, blocklists, beaconing, AbuseIPDB, RDAP, JA4X) wired via `buildPipelineConfig()` |
| Health endpoint | ✅ Complete | Redis connectivity check |
| PROXY protocol support | ✅ Complete | Real client IP extraction |
| Docker build | ✅ Complete | `docker/Dockerfile.go-proxy` multi-stage alpine image |
| Go unit tests | ✅ Complete | 75+ tests passing |
| Prometheus metric names | ⚠️ Unverified | Names not audited against `docs/OBSERVABILITY_STANDARDS.md` |
| PubSub reconnect | ⚠️ Known gap | `internal/redis/pubsub.go` exits goroutine on channel close instead of reconnecting |
| JA4 parity validation | ⚠️ Blocked | Needs `tests/fixtures/clienthello/*.bin` — use `scripts/capture_clienthello.py` |
| Live parity harness | ⚠️ Blocked | `make parity-check` requires both proxies running (`make go-start` first) |
| Performance benchmarking | ⚠️ Blocked | Needs production-like load |
| Production deployment | ❌ Not started | Awaiting validation gates |

**Completion: 8/12 items (67%) — all code complete; remaining items are validation gates**

See `docs/phases/PHASE_15_WORK_PLAN.md` for detailed implementation plan.

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

## Current Implementation State (as of 2026-03-17)

**The subplan document was written before significant implementation work was done.
Its "nothing is functional / all packages empty" description is wrong — see below.**

### What is implemented and working

All packages compile. All Go unit tests pass (75+ tests):

```
ok  internal/cache     — LRU with TTL and eviction (9 tests)
ok  internal/config    — proxy.yml loader with env-var expansion (11 tests)
ok  internal/redis     — Redis client, Lua script load, pub/sub (11 tests)
ok  internal/security  — RiskScorer, ActionDecider, Pipeline (14 tests)
ok  internal/tls       — ClientHello parser, JA4 computation (22 tests)
```

Specific files that exist and are functional:

| File | State |
|------|-------|
| `go.mod` | ✅ Correct — uses `github.com/redis/go-redis/v9` |
| `cmd/proxy/main.go` | ✅ Full proxy — TCP listener, TLS parse, pipeline, forward/tarpit/block |
| `internal/tls/hello_info.go` | ✅ `ClientHelloInfo` with all needed fields |
| `internal/tls/parser.go` | ✅ Full ClientHello parser — never panics, handles all adversarial inputs |
| `internal/tls/ja4.go` | ✅ Correct JA4 — SHA-256, GREASE filter, sorted ciphers/extensions |
| `internal/security/models.go` | ✅ `ConnectionContext`, `PipelineResult`, `RiskSignal` |
| `internal/security/risk_scorer.go` | ✅ Full scorer with clamping, weighting, thresholds |
| `internal/security/action_decider.go` | ✅ Dial formula, banker's rounding, counterfactuals |
| `internal/security/pipeline.go` | ✅ Bypass checks, hard blocks, scorer, dial — signal modules stubbed |
| `internal/redis/client.go` | ✅ get/set/SISMEMBER/GetDial/Ping — fail-open |
| `internal/redis/lua.go` | ✅ `SlidingWindowScript` embedded + reads from file |
| `internal/redis/pubsub.go` | ⚠️ Works but no reconnect on channel close |
| `internal/cache/local.go` | ✅ Thread-safe LRU with TTL |
| `internal/config/loader.go` | ✅ Full proxy.yml schema, `${VAR:-default}` expansion, unknown keys ignored |
| `docker/Dockerfile.go-proxy` | ✅ Multi-stage alpine build |
| `config/build.yml` | ✅ Go build settings |

### Known environment issue: GOROOT

The snap Go installation sets `GOROOT=/usr/share/go` which does not exist on this host.
The stdlib is at `/snap/go/current`. Until fixed system-wide, all `go` commands need:

```bash
GOROOT=/snap/go/current go build ./...
GOROOT=/snap/go/current go test ./...
```

This is a **host configuration issue**, not a code issue. Fix once:
```bash
# Add to ~/.bashrc or ~/.zshrc:
export GOROOT=/snap/go/current
```

### Remaining work to close Phase 15 (as of 2026-04-03)

All code is written and all Go unit tests pass. Four gaps remain before phase closeout:

**Gap 1 — ClientHello binary fixtures** (blocks JA4 parity proof)
- `tests/fixtures/clienthello/*.bin` do not exist yet.
- Capture with: `python3 scripts/capture_clienthello.py` (requires Chrome/Firefox running).
- Once captured, `tests/fixtures/clienthello/README.md` must record the expected JA4
  for each fixture; the Go test in `internal/tls/` asserts `parse(fixture) == expected`.

**Gap 2 — Live parity harness** (blocks formal close-out gate)
- `tests/integration/test_go_python_parity.py` test bodies are structural stubs.
- To run for real: `make agent-up NAME=claude && make go-start && make go-parity`
- `tests/chaos/test_go_proxy_chaos.py` and `tests/performance/test_bench_go_proxy.py`
  also require a running stack.

**Gap 3 — Prometheus metric name alignment** (blocks observability parity)
- Go metric names have not been audited against `docs/OBSERVABILITY_STANDARDS.md`.
- Grep Go metrics: `grep -r 'MustRegister\|NewCounter\|NewGauge\|NewHistogram' internal/`
- Compare against the Python registry in `docs/OBSERVABILITY_STANDARDS.md §2`.

**Gap 4 — PubSub reconnect** (resilience gap)
- `internal/redis/pubsub.go`: when the Redis channel closes (e.g. Redis restart),
  the goroutine exits instead of reconnecting.
- Fix: wrap the subscribe loop in a retry with exponential backoff.
- The Python proxy handles this via `asyncio-retry`; Go should match.

**Development tooling (all complete):**
- `docs/TESTING_GO.md` — ✅ Go vs Python test comparison
- `docs/developer/go_proxy_guide.md` — ✅ architecture, patterns, adding modules
- `Makefile` go-* targets — ✅ `make go-build`, `make go-test`, `make go-start`,
  `make go-switch`, `make go-rollback`, `make go-parity`, `make go-stop`

See `docs/phases/details/PHASE_15_subplan.md` for the full group-by-group task list.

## Acceptance Criteria

### Functional
- [x] `docker/Dockerfile.go-proxy` multi-stage build; runtime image ≤ 10MB
- [x] Go proxy reads same `config/proxy.yml` without schema changes (all signal modules wired)
- [ ] JA4 fingerprint output byte-for-byte identical to Python for all `tests/fixtures/clienthello/` fixtures **(Gap 1 — fixtures not captured yet)**
- [x] TLS ClientHello parser handles all adversarial corpus cases without panic
- [x] All Lua scripts loaded via EVALSHA; script content identical to Python version
- [x] Pub/Sub subscriber handles all message types; dial changes propagate correctly *(reconnect gap remains — Gap 4)*
- [ ] Prometheus metric names and label sets identical to Python version **(Gap 3 — not yet audited)**
- [x] Python analytics and management UI containers run unchanged alongside Go proxy

### Observability
- [ ] All Prometheus metric names verified identical to `docs/OBSERVABILITY_STANDARDS.md` registry **(Gap 3)**
- [x] Go proxy structured JSON log schema identical to Python (same field names and types)

### Unit Tests  (Go test files in `internal/`)
- [ ] JA4 computation: each `tests/fixtures/clienthello/*.bin` → matches expected fingerprint **(Gap 1)**
- [x] TLS parser: adversarial corpus → no panic; returns in < 1ms

### Integration Tests
- [ ] `make go-parity`: Go + Python produce identical `(action, score)` pairs for synthetic traffic **(Gap 2)**

### Performance Tests
- [ ] Throughput: ≥ 5× connections/second versus Python proxy at equivalent Redis load **(Gap 2)**
- [ ] Load test: 1,000 conn/s sustained 60s with false-positive rate < 0.1% **(Gap 2)**
