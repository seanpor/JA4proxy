# JA4proxy Performance Benchmarks

> **Run the benchmark harness:** `make bench-hostnative` for real end-to-end
> throughput (host networking — see the section below for why this is the
> meaningful capacity number). `make bench` / `make bench-quick` run the
> bridge-port suite, which is fine for regression tracking but is capped by
> `docker-proxy`. Raw Go microbenchmarks live under `internal/tls/` and
> `cmd/proxy/` and can be run directly with `go test -bench=. ./...`.
>
> **Honesty note:** the numbers on this page were produced on a
> single developer workstation — they are **not production-representative**.
> They are published so that (a) the capacity calculator has measured
> anchor points instead of pure guesses, and (b) subsequent runs can be
> compared against a known baseline. They do **not** constitute a capacity
> claim. Real deployments must re-run the suite on target hardware.

## Reference Hardware

| Component | Specification |
|-----------|--------------|
| CPU | Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz (8 cores / 16 threads) |
| Cores | 16 (logical), 8 (physical) |
| RAM | 62 GiB |
| OS | Linux 6.17.9-76061709-generic x86_64 (Pop!_OS 22.04 LTS) |
| Redis | not exercised by the microbenchmarks below (see note) |
| Go | go1.26.2 linux/amd64 |
| Python | Python 3.10.12 |

**Redis:** no `redis-server` binary installed on this dev host, so the
end-to-end `make bench` suite (which spins up Redis in Docker) was not run.
Only the in-process Go microbenchmarks under `internal/tls/` and
`cmd/proxy/bench_test.go` were exercised. Redis latency sensitivity numbers
below are therefore annotated as not measured on this host.

## End-to-End Throughput (Host-Native Macro Benchmark)

> Run date: 2026-06-10 · Git SHA: 76504c83 · Hardware: i9-9900K (8c/16t), 62 GiB
> Method: host-native `ja4pd` + Dockerised Redis & backend, driven by
> `ja4p test benchmark`. **Redis and a real TLS backend dial are exercised** —
> this is a true end-to-end run, not a microbenchmark.

### Why host-native, and why `make bench-macro` reports a lower number

The canonical quick path is `make start-poc && make bench-macro`. It works, but
it benchmarks through the proxy's **published bridge port** (`HOST_PORT_DIRECT`,
default `8081`). In Docker bridge mode that port is served by `docker-proxy`, a
userland TCP relay that adds a syscall/context-switch per connection and
serialises throughput. On this hardware that path plateaus around **~600 conn/s**
regardless of CPU/memory limits or client worker count (CPS stays flat while
latency rises linearly — the classic signature of a fixed downstream ceiling).

Production deployments are expected to run with `network_mode: host` (see the
forensic investigation report and the Helm/compose notes), which removes
`docker-proxy` from the path. To measure the engine's real capacity you must do
the same: run `ja4pd` on the host and benchmark its host listener directly.

### Reproducing the host-native run

One command:

```bash
make bench-hostnative
```

It builds `bin/ja4pd` + `bin/ja4p`, brings up Redis + the mock backend in
Docker (with their CPU/mem caps lifted so neither is the bottleneck),
auto-discovers their container IPs, launches `ja4pd` **on the host** (default
ports 18080 / 29090 — no `docker-proxy` in the inbound path) wired to those
services, and drives it with `ja4p test benchmark`. Redis + backend are left
running afterwards for reuse; the teardown command is printed at the end.

Tunables (env vars, all prefixed `BENCH_` to avoid colliding with the
Makefile's own `WORKERS`):

```bash
BENCH_WORKERS=64 BENCH_DURATION=30 BENCH_GOOD_RATE=30000 make bench-hostnative
```

The benchmark is **closed-loop** (CPS ≈ workers ÷ per-conn latency), so sweep
`BENCH_WORKERS` upward until CPS plateaus while latency climbs — that plateau
is the real engine ceiling, not the client.

The script lives at `scripts/bench-hostnative.sh`; read it for the exact
docker / IP-discovery / `ja4pd` invocation it performs under the hood.

### Measured results

| Inbound path | Sustained CPS | p99 latency | Errors | False positives |
|--------------|---------------|-------------|--------|-----------------|
| Bridge via `docker-proxy` (`:8081`) | ~600 | ~290 ms p95 @ 64 workers | 0 | 0% |
| **Host-native (`make bench-hostnative`)** | **~3,000–3,300** | ~25 ms @ 32 workers | 0 | 0% |

Host-native is ~5× the bridged path on identical code and hardware (3,263 CPS
at 32 workers vs ~600). CPS held steady from 16→32 workers while latency rose,
confirming the engine — not the load generator — is the limit. Traffic was
browser-like (h2 ALPN), so connections took the allow fast path, which is what
a legitimate-user throughput claim should reflect. The product brochure cites a
conservative **~2,500 conn/s per node**, comfortably below the measured figure.

## Go Proxy Benchmarks

> Run date: 2026-04-11
> Git SHA: b0dd515175a272debb4df90814e930c7010cc574
> Method: `go test -bench=. -benchtime=2s -run=^$ ./cmd/proxy/ ./internal/tls/`
> (single workstation, no network load generator, no Redis)

### BYPASS PATH (h2/h1 ALPN → immediate allow)

Source: `BenchmarkPipeline_Allow` in `cmd/proxy/bench_test.go`. This measures
in-process pipeline cost from the moment the connection reaches the scorer
to the allow decision. It does **not** include socket read/write or backend
dial cost, so the derived conn/s ceiling is an upper bound for the scoring
hot path only — real TCP throughput will be lower.

| Metric | Value |
|--------|-------|
| Pipeline decision cost (single core) | 491 ns/op |
| Derived single-core pipeline ceiling | ~2,036,000 decisions/s |
| Realistic per-core throughput (with syscalls, IO, backend dial) | ~18,000 conn/s (see note) |
| P50 latency (pipeline only, single core) | ~0.0005 ms |
| P99 latency (pipeline only, single core) | ~0.002 ms (run-to-run variance in microbenchmark) |
| CPU (single core) at peak | 100% (benchmark saturates one core by design) |

### FULL SIGNAL PATH (all signal modules, Redis reads)

Source: `BenchmarkPipeline_Score`. Signal modules execute with in-memory
fakes (no real Redis round-trip). Real deployments with a Redis hop add
the network RTT on top of this cost.

| Metric | Value |
|--------|-------|
| Pipeline decision cost (single core) | 1,994 ns/op |
| Derived single-core pipeline ceiling | ~501,500 decisions/s |
| Realistic per-core throughput (with syscalls, IO, Redis RTT) | ~6,200 conn/s (see note) |
| P50 latency (pipeline only, single core) | ~0.002 ms |
| P99 latency (pipeline only, single core) | ~0.004 ms (run-to-run variance) |
| CPU (single core) at peak | 100% |

**Note on "realistic per-core" numbers:** these are the values the capacity
calculator uses (`BenchmarkConstants.go_bypass_conn_s = 18,400` and
`go_full_conn_s = 6,200`). They are **not** directly measured on this host —
they are the engineering floor derived from: microbenchmark pipeline cost
(measured), plus reserved budget for syscalls / kernel TLS handoff / backend
dial / Redis RTT on production hardware. When the full `make bench` suite
is run on reference hardware, these constants must be replaced with
directly measured end-to-end numbers. The value of publishing them here is
that the calculator is now anchored to a reproducible host + method rather
than unlabelled prior-project estimates.

### JA4X SIGNAL EXTRACTION

Source: `BenchmarkExtractJA4X` in `internal/tls/ja4x_test.go`. Exercised for
completeness — this is the hot path inside the signal collector.

| Metric | Value |
|--------|-------|
| ExtractJA4X (typical ClientHello) | 6,822 ns/op |
| ExtractJA4X (empty ClientHello) | 173.6 ns/op |
| ExtractJA4X (invalid ClientHello) | 437.2 ns/op |

### TARPIT PATH

Not measured on this host (requires the full end-to-end harness with a
HAProxy front-end and traffic generator). Values carried forward from an
earlier engineering estimate, pending a real run on reference hardware:

| Metric | Value |
|--------|-------|
| Max concurrent tarpitted | ~10,000 (estimate — not measured on this host) |
| Memory per tarpitted conn | ~32 KB (estimate — not measured on this host) |

### REDIS LATENCY SENSITIVITY

Not measured on this host — no `redis-server` available locally. Target
thresholds for the capacity model, to be replaced with real numbers when
the suite is run against a Redis node:

| Redis P99 Latency | Throughput |
|-------------------|------------|
| 1ms | ~6,200 conn/s per core (target — not measured on this host) |
| 5ms | ~4,500 conn/s per core (target — not measured on this host) |
| 20ms | ~2,000 conn/s per core (target — not measured on this host) |

### MEMORY FOOTPRINT

Not measured on this host (requires sustained traffic + RSS sampling).
Values carried forward from earlier estimates:

| State | Memory |
|-------|--------|
| Proxy process (idle) | ~40 MB (estimate — not measured on this host) |
| Proxy process (10K conns) | ~180 MB (estimate — not measured on this host) |
| LRU cache (100K entries) | ~24 MB (estimate — not measured on this host) |

## Historical Runs

| Date | Git SHA | Scenario | Throughput (conn/s) | P99 (ms) | Notes |
|------|---------|----------|---------------------|----------|-------|
| 2026-04-11 | b0dd515 | pipeline-micro (bypass) | 2,036,000 decisions/s single-core | ~0.002 | Dev host i9-9900K, no Redis, no IO — pipeline cost only |
| 2026-04-11 | b0dd515 | pipeline-micro (full-signal) | 501,500 decisions/s single-core | ~0.004 | Dev host i9-9900K, no Redis, no IO — pipeline cost only |
| 2026-06-10 | 76504c8 | host-native macro (`make bench-hostnative`, 32 workers) | ~3,263 conn/s | ~25 (p99) | i9-9900K, host networking, Redis + real TLS backend, 0 errors / 0% FP |
| 2026-06-10 | 76504c8 | end-to-end bridge macro (`docker-proxy`) | ~600 conn/s | ~290 (p95) | Same code/host; `docker-proxy` ceiling — do not deploy/benchmark this way |
