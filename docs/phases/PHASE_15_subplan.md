# Phase 15 Go Rewrite — Execution Subplan

## Goal
Rewrite `proxy.py` and `src/security/` in Go. Target: ≥5× throughput vs Python at equivalent load.

---

## Plan Overview (7 Phases)

| Phase | Task | Acceptance |
|-------|------|------------|
| 0 | Foundation & design decisions | Module init, go.mod, build setup, design doc |
| 1 | Core TLS infrastructure | ClientHello parser, JA4 computation, JA4T extraction |
| 2 | Pipeline modules v1 | Risk scorer, action decider, all signal collectors wired in Go |
| 3 | Redis & Config layer | go-redis client, Lua scripts, hot reload handler |
| 4 | Test fixtures migration | All Python unit tests → Go equivalents pass |
| 5 | Integration & cross-lang validation | Go proxy + Python analytics produces same results |
| 6 | Performance validation | Benchmarks meet targets, load test sustained |
| 7 | Polish & deliverable | Dockerfile.go, README updates, CHANGELOG entry |

---

## Scaffolding State (as of 2026-03-16)

The following files were committed as initial scaffolding. They are **not functional** —
see the issues listed below before starting Phase 1.

### Files that exist

| File | State | Notes |
|------|-------|-------|
| `go.mod` | ⚠️ Wrong dependency | redis import path incorrect — see below |
| `cmd/proxy/main.go` | ⚠️ Skeleton only | Calls `NewProxy` and `config.Load` which don't exist yet |
| `internal/tls/hello_info.go` | 🟡 Struct definitions | `ClientHelloInfo` and `ClientHelloField` structs; field layout is preliminary |
| `internal/tls/ja4.go` | ⚠️ Non-functional placeholder | `hashValue()` sums uint16s instead of SHA256; ALPN hardcoded to `"h2"`; format string has wrong arg count — will not produce correct JA4 |

### Empty packages (contain no .go files)

- `internal/cache/`
- `internal/redis/`
- `internal/security/`
- `internal/config/`

### Known issues to fix before Phase 1

1. **`go.mod` wrong redis import path** — current: `github.com/go-redis/redis/v9`, correct: `github.com/redis/go-redis/v9`. Fix with:
   ```
   go get github.com/redis/go-redis/v9
   go mod tidy
   ```

2. **`internal/tls/ja4.go` is non-functional** — `hashValue()` must use SHA256 (not integer sum); ALPN extraction must parse the ALPN extension data (not return a hardcoded string); the `fmt.Sprintf` format string has wrong argument count. Delete and rewrite from spec.

3. **`cmd/proxy/main.go` references unimplemented types** — `NewProxy`, `config.Load`, `Proxy.Run()`, `Proxy.Close()` do not exist. This file will not compile until Phase 2/3 provide these.

4. **`internal/tls/hello_info.go` field layout is preliminary** — `ClientHelloInfo` contains single `CipherSuite uint16` but the JA4 spec requires the full cipher suite list. The struct will need to be revised in Phase 1 when the parser is written.

---

## Phase 0: Foundation (1 hour)

**Tasks:**
- [x] Create Go module (`go.mod` exists at repo root)
- [ ] Fix `go.mod` redis import path: replace `github.com/go-redis/redis/v9` with `github.com/redis/go-redis/v9`; run `go mod tidy`
- [ ] Add remaining dependencies: `github.com/sirupsen/logrus`, `gopkg.in/yaml.v3`
- [ ] Set up directory structure matching Phase 15d spec (empty package dirs already present)
- [ ] Create `config/build.yml` with Go build settings
- [ ] Write design doc: error handling strategy, fail-open behaviour

**Acceptance:**
- ✅ Module file exists
- ⬜ `go mod tidy` succeeds with correct import paths
- ⬜ Directory tree matches Phase 15d spec
- ⬜ Design decisions documented

---

## Phase 1: TLS Infrastructure (2 hours)

**Tasks:**
- [ ] `internal/tls/parser.go` — ClientHello frame parser
  - Read raw TCP buffer
  - Validate ClientHello vs other TLS messages
  - Extract version, cipher suite, extensions
  - Return structured `ClientHelloInfo` type
- [ ] `internal/tls/ja4.go` — JA4 computation
  - Implement algorithm per FoxIO spec
  - Handle all extension types in fixtures
  - Return hex string fingerprint
- [ ] `internal/tls/ja4t.go` — JA4T (TLS alerts) extraction
  - Track alert codes from handshake
  - Compute JA4T value
- [ ] Unit tests: parse each fixture binary → assert JA4 matches README

**Questions answered:**
- ClientHello validation: reject non-ClientHello (< 80 bytes or wrong type) before parsing
- JA4 order: extract all fields first, then compute fingerprint to support early abort on known-bypasses

**Acceptance:**
- ✅ All `.bin` fixtures parse without panic
- ✅ JA4 output matches Python for existing fingerprints
- ✅ Adversarial corpus returns results (not panics) in <1ms

---

## Phase 2: Pipeline Modules v1 (3 hours)

**Tasks:**
- [ ] Wire modules to `internal/security/pipeline.go`
  - risk_scorer.go
  - action_decider.go
  - sni_analyzer.go → new file (currently in pipeline.py as part of connection analysis? Need to check)
  - tcp_analyzer.go
  - mtls.go
  - asn_classifier.go
  - dns_enrichment.go
  - blocklists.go
  - beaconing_detector.go
  - abuseipdb.go
  - rdap_enrichment.go
- [ ] Ensure all error paths fail open (log + zero result)

**Acceptance:**
- ✅ Pipeline processes connection end-to-end
- ✅ All modules return `RiskSignals` compatible with Python schema
- ✅ Error handling verified: bad TLS → logged but doesn't crash proxy

---

## Phase 3: Redis & Config Layer (2 hours)

**Tasks:**
- [ ] `internal/redis/client.go` — Connection pool, pipeline batching
- [ ] `internal/redis/lua.go` — Export all Lua scripts as strings
  - Verify byte-identical to Python version using file diff
- [ ] `internal/redis/pubsub.go` — Subscribe to config_reload channel
- [ ] `internal/config/loader.go` — YAML → structs, hot reload handler
- [ ] Handle unknown config keys with DEBUG log (don't exit)

**Acceptance:**
- ✅ EVALSHA scripts loaded successfully
- ✅ Pub/sub subscriber handles message types correctly
- ✅ Hot reload triggers on pub/sub + SIGHUP without restart for hot-reloadable configs only
- ⬜ Config reload: listen port/Redis URL/TLS certs require manual restart (document)

---

## Phase 4: Test Migration (2 hours)

**Tasks:**
- [ ] For each Python test in `tests/unit/security/test_*.py`:
  - Create Go equivalent in `tests/unit/security_test/*.go`
  - Use testify for assertions
  - Mock Redis with go-redis + wiremock pattern
- [ ] Verify all fixtures work:
  - `tests/fixtures/clienthello/*.bin` → JA4 tests
  - `tests/adversarial/` → adversarial parser tests

**Acceptance:**
- ✅ All unit tests pass locally
- ✅ Test coverage ≥90% of Go code (same target as Python ~6K lines)

---

## Phase 5: Integration Validation (1 hour)

**Tasks:**
- [ ] `tests/integration/test_cross_language.go` — New integration tests
  - Start Go proxy on :8080, Python analytics on :9000
  - Send test traffic via socat or custom client
  - Verify action decisions match between implementations
- [ ] Run against full docker-compose stack
- [ ] Python analytics container runs unchanged alongside Go proxy

**Acceptance:**
- ✅ Go + Python analytics produce identical composite scores for same inputs
- ✅ Actions (allow/block/tarpit) match between implementations
- ✅ No schema drift in decision output

---

## Phase 6: Performance Validation (1 hour)

**Tasks:**
- [ ] `tests/performance/bench_pipeline.go`
  - Warm cache scenario: repeat IPs → measure TLS parse + JA4 throughput
  - Random traffic: simulate mixed load (adversarial vs legitimate)
  - DDoS scenario: all new IPs → measure Redis pipeline saturation point
- [ ] Target metrics:
  | Condition | Python baseline | Go target |
  |-----------|----------------|-----------|
  | Warm cache | ~300 conn/s | ≥1,500 conn/s (5×) |
  | Mixed traffic | ~600 conn/s | ≥3,000 conn/s (5×) |
  | DDoS new IPs | ~200 conn/s | ≥800 conn/s (4× minimum) |

- [ ] Load test: 1,000 conn/s sustained 60s with FP rate <0.1%

**Acceptance:**
- ✅ Throughput targets met across all scenarios
- ✅ No memory leaks over 5-min stress run
- ✅ GC pause <1ms at target load

---

## Phase 7: Polish & Deliver (30 min)

**Tasks:**
- [ ] Create `Dockerfile.go` multi-stage build
  - Build stage: alpine with Go toolchain
  - Runtime stage: alpine + binary + GeoLite2 DBs
  - Target: ≤10MB runtime image
- [ ] Update `cmd/proxy/main.go`:
  - Parse config from same `proxy.yml` schema
  - Emit identical structured JSON logs
  - Same Prometheus metric names/labels
- [ ] Write migration guide in README section
- [ ] Add CHANGELOG.md entry with performance numbers

**Acceptance:**
- ✅ Dockerfile builds without warnings
- ⬜ Runtime image ≤10MB (verify after first build)
- ⬜ Binary reads same config and handles all keys
- ⬜ Metrics names verified against OBSERVABILITY_STANDARDS.md registry

---

## Risk Register

| Risk | Mitigation |
|------|-----------|
| Adversarial ClientHello causes panic | Parser validates message type, returns zero values on malformed input |
| Redis Lua script differs byte-for-byte | Store scripts as strings in code; verify against Python files via diff tool |
| Unknown config keys cause crash | Use `map[string]interface{}` or viper-style unknown key handling; log DEBUG |
| GC pauses degrade throughput | Profile first run; tune GOGC if needed (default 100 should suffice) |

---

## Dependencies Checklist

- [ ] `github.com/redis/go-redis/v9` — Redis client with pipelining (**not** `github.com/go-redis/redis/v9` which is the old path)
- [ ] `github.com/oschwald/geoip2-golang` — GeoIP lookup (wraps maxminddb)
- [ ] `github.com/oschwald/maxminddb-golang` — MaxMind DB reader (already in go.mod)
- [ ] `gopkg.in/yaml.v3` — config parsing
- [ ] `github.com/sirupsen/logrus` — structured JSON logging (matches Python log schema)
- [ ] `github.com/golang/snappy` — only if Redis compression enabled; defer until needed

---

## Notes & Additions to Main Plan

From analysis of existing Python code and requirements:

1. **TLS version/cipher capture** — Parser must extract `Version` (uint8), `CipherSuite` (uint16 big-endian) from ClientHello for scoring layers that operate on these fields.

2. **SNI handling** — SNI appears in ServerName extension (hostname string field). Current pipeline processes SNI before JA4 computation; Go version should follow same order.

3. **Return visitor tracking** — Hash fields: `first_seen`, `total`, `allowed`, `blocked`. Go uses map[string]int64 equivalent structures.

4. **Beaconing keys** — `beacon:{ip}:{ja4}` with full IP string (no truncation). IPv6 addresses handled natively by net/netip.

5. **mTLS client cert validation** — Requires loading `config/trusted_cas.pem` at startup; verify signatures before bypass.

6. **Block expansion /48 for IPv6** — MaxMind GeoLite2-ASN covers both addresses; ensure prefix length check uses Go's ip.MaskSize() or equivalent.

---

## End of Subplan