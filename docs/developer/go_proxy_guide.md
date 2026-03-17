# Go Proxy — Developer Guide

This guide covers the architecture, key design decisions, and development workflow for
the Go proxy (`cmd/proxy/` + `internal/`). Read `docs/phases/PHASE_15.md` for the
migration context and acceptance criteria.

---

## Module Layout

```
cmd/proxy/main.go               Entry point — wires everything together
internal/
  tls/
    hello_info.go               ClientHelloInfo struct (all fields from TLS ClientHello)
    parser.go                   Raw TCP bytes → ClientHelloInfo (never panics)
    ja4.go                      ClientHelloInfo → JA4 fingerprint string
    ja4t.go                     Alert codes → JA4T stub (no TLS alert hook yet)
  security/
    models.go                   ConnectionContext, PipelineResult, RiskSignal
    pipeline.go                 Orchestrates all signal modules → action
    risk_scorer.go              []RiskSignal → composite score 0–100
    action_decider.go           Score + dial → action (allow/flag/tarpit/block/ban)
    tls_enforcer.go             TLS version / cipher signals
    sni_analyzer.go             Missing SNI / IP literal / DGA scoring
    rate_limiter.go             Sliding-window rate limiting (3 strategies)
    tcp_analyzer.go             Session resumption / lifespan / concurrency
    mtls.go                     mTLS client cert verification
    asn_classifier.go           Tor / datacenter / VPN ASN/org signals
    dns_enrichment.go           FCrDNS async enrichment
    blocklists.go               CIDR feed hard-block / soft-block
    beaconing_detector.go       Inter-arrival time CV from Redis sorted sets
    abuseipdb.go                AbuseIPDB score (LRU cache → Redis → HTTP)
    rdap_enrichment.go          RDAP org reputation + block expansion
    analytics_signals.go        Campaign / slow-scan findings from Redis
  redis/
    client.go                   go-redis/v9 wrapper with fail-open semantics
    lua.go                      EVALSHA loader for sliding window Lua script
    pubsub.go                   Config change subscriber with reconnect loop
  cache/
    local.go                    Thread-safe in-process LRU with TTL
  metrics/
    metrics.go                  All Prometheus metrics (ja4proxy_* names)
  proxy/
    proxy_protocol.go           PROXY protocol v1 parser
  config/
    loader.go                   proxy.yml → Config struct (${VAR:-default} expansion)
```

---

## Request Flow

```
TCP accept (main.go:handleConn)
    │
    ├── PROXY protocol header? → extract real client IP
    │
    ├── Read TLS ClientHello (tls/parser.go)
    │     Never panics. Returns empty ClientHelloInfo on any parse error.
    │
    ├── Compute JA4 (tls/ja4.go)
    │
    ├── GeoIP country lookup (geoip2)
    │
    ├── pipeline.Process(ctx, ConnectionContext) → PipelineResult
    │     │
    │     ├── Static IP allowlist? → ALLOW (bypass)
    │     ├── h2/h1 ALPN?          → ALLOW (bypass)
    │     ├── JA4 in whitelist?    → ALLOW (bypass)
    │     ├── mTLS cert valid?     → ALLOW (bypass)
    │     ├── JA4 in blacklist?    → BLOCK (bypass)
    │     ├── Country in blacklist?→ BLOCK (bypass)
    │     ├── Blocklist CIDR?      → BLOCK (bypass)
    │     │
    │     ├── TLS enforcer signals
    │     ├── SNI analyzer signals
    │     ├── Rate limiter signals
    │     ├── TCP analyzer signals
    │     ├── ASN classifier signals
    │     ├── DNS enrichment signal
    │     ├── Beaconing signal
    │     ├── AbuseIPDB signal
    │     ├── interim score (for RDAP trigger threshold)
    │     ├── RDAP signals
    │     ├── Analytics signals
    │     └── final score → action
    │
    └── Execute: forward / tarpit / block (RST)
```

---

## Key Design Decisions

### RedisReader interface (internal/security/pipeline.go)

All signal modules receive a `RedisReader` interface rather than a concrete `*redis.Client`.
This means:
- Tests inject a lightweight mock (`mockRedis` in `pipeline_test.go`) — no real Redis needed.
- The interface grew incrementally as each signal module was added. If you add a module
  that needs a new Redis operation, add it to `RedisReader` and add a stub to `mockRedis`.

### Fail-open everywhere

Every Redis call, GeoIP lookup, and external API call returns a zero/neutral result on
error. Nothing on the hot path ever returns an error that the caller must handle — errors
are logged and the pipeline continues as if the module wasn't there.

### Async enrichment (goroutines, not asyncio)

Python uses `asyncio.create_task()` for fire-and-forget enrichment tasks. Go uses
buffered channels + worker goroutines started at startup:

```go
// Hot path: non-blocking send
select {
case r.lookupCh <- clientIP:
default:
    // channel full — skip; fail open
}

// Background worker (started once in StartBackgroundWorkers)
go func() {
    for ip := range r.lookupCh {
        r.doLookup(ctx, ip)
    }
}()
```

The channel buffer acts as a load-shedding mechanism: if the worker is slower than
arrivals, new enrichment requests are dropped rather than accumulating memory.

### Two-phase scoring for RDAP

RDAP's decision to enqueue a lookup depends on the current risk score (only query RDAP
for high-risk connections, to avoid hammering the RDAP server). The pipeline computes an
interim score after all other signals, passes it to RDAP, then recomputes the final score:

```go
interim := p.scorer.Score(signals)      // score without RDAP
rdapSigs := p.rdap.GetSignals(ctx, conn, interim.Score)
signals = append(signals, rdapSigs...)
final := p.scorer.Score(signals)        // final score
```

### Injectable lookupFn (ASN classifier)

`ASNClassifier` accepts a `lookupFn func(ip string) (*geoip2.ASN, error)` at construction
time. In production this wraps the MaxMind DB. In tests it's a simple closure returning
canned data — no DB file required.

### GeoIP DB nil-safe

If no MaxMind DB path is configured, `geoIP` is nil throughout. All code that uses it
checks `if r.geoIP != nil` before calling. GeoIP absence is not an error; it degrades
gracefully (no country-based bypass checks, no ASN lookups).

---

## Testing

See `docs/TESTING_GO.md` for the full comparison of Go vs Python tests. Summary:

- Go unit tests live **alongside the code** (`*_test.go` in each package).
- Python unit tests live in `tests/unit/`.
- Both test the same behaviour; Go tests use table-driven patterns + mock injections.
- Integration / chaos / performance tests are **Python** because they test the running
  binary (Docker stack) and the Python analytics container together.

### Running Go tests

```bash
# All packages
GOROOT=/snap/go/current go test ./...

# Single package with verbose output
GOROOT=/snap/go/current go test -v ./internal/security/

# Single test by name
GOROOT=/snap/go/current go test -v -run TestRateLimiter_BanThreshold ./internal/security/

# With race detector (use in CI)
GOROOT=/snap/go/current go test -race ./...

# Build-only check (fast)
GOROOT=/snap/go/current go build ./...
```

### mockRedis

`pipeline_test.go` contains a `mockRedis` struct that implements the full `RedisReader`
interface. When you add a new method to `RedisReader`, you **must** add the corresponding
stub to `mockRedis` or the package will not compile.

The convention is:
```go
func (m *mockRedis) NewMethod(ctx context.Context, key string) ReturnType {
    // Return zero value by default; individual tests override via fields.
    return zeroValue
}
```

---

## Adding a New Signal Module

1. Create `internal/security/my_signal.go`:
   ```go
   package security

   type MySignalConfig struct {
       Enabled bool
       // ... thresholds
   }

   type MySignal struct {
       cfg *MySignalConfig
       // redis, log, etc.
   }

   func NewMySignal(cfg *MySignalConfig, redis RedisReader, log *logrus.Logger) *MySignal { ... }

   // GetSignal returns nil if disabled or no signal fires.
   func (m *MySignal) GetSignal(ctx context.Context, conn ConnectionContext) *RiskSignal { ... }
   ```

2. Add config struct to `internal/config/loader.go` under `PipelineConfig`.

3. Add the field to `Pipeline` in `pipeline.go` and wire it in `NewPipeline`.

4. Call it in `Pipeline.Process()`.

5. Add any new Redis operations to `RedisReader` and `mockRedis`.

6. Write `internal/security/my_signal_test.go` with table-driven tests.

---

## Environment Notes

The snap Go installation sets `GOROOT=/usr/share/go` (non-existent). All `go` commands
need the override until it's fixed system-wide:

```bash
# Add to ~/.bashrc:
export GOROOT=/snap/go/current

# Or per-command:
GOROOT=/snap/go/current go test ./...
```

The Makefile targets (`make go-build`, `make go-test`) handle this automatically via
the `GOROOT ?= /snap/go/current` variable.

---

## Prometheus Metrics

All metrics are defined in `internal/metrics/metrics.go` and registered once in
`main()` via `metrics.Register()`. Do not call `Register()` in tests — the package-level
vars are accessible directly.

Metric names follow the Python proxy exactly (`ja4proxy_*`) so that Grafana dashboards
work without modification after the cutover.

---

## Config Hot-Reload

The Go proxy supports the same hot-reload mechanism as Python:
- `SIGHUP` → reloads `proxy.yml` (implemented in `main.go`)
- Redis pub/sub `channel:config_reload` → triggers reload

Config sections that **cannot** be hot-reloaded (require restart):
- `listen_port`
- `redis.url`
- `tls.*` certificate paths
- `metrics.port`

---

## Binary Size

The multi-stage `Dockerfile-go` produces an Alpine runtime image. Verify after changes:

```bash
docker build -f Dockerfile-go -t ja4proxy-go:latest .
docker image inspect ja4proxy-go:latest --format '{{.Size}}' | numfmt --to=iec
# Target: ≤ 10MB
```
