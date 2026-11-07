# Architectural Audit & Deep Review of JA4proxy Performance Testing Harnesses

**Phase:** 867  
**Date:** 2026-11-07  
**Classification:** Core Infrastructure Audit & Reliability Assessment  
**Author:** AI Systems Engineering & Independent Principal Performance Architect  
**Status:** COMPLETE (Review Deliverable)

---

## 1. Executive Summary

JA4proxy's high-performance Go reverse proxy pipeline (`cmd/ja4pd`, `internal/`) was re-engineered in Go to deliver multi-thousand connections-per-second (CPS) TLS parsing and line-rate enforcement. However, this architectural audit reveals that the repository's **performance testing harnesses and automated CI benchmarks are suffering from severe technical debt, measurement dishonesty, queueing theory distortions, and protocol framing violations**.

### Primary Audit Findings:
1. **Protocol Framing & Wire Mismatch (`ja4bench.go`)**: The primary Go load generator advertises `h2` via ALPN (`NextProtos = []string{"h2", "http/1.1"}`), but unconditionally transmits raw ASCII `HTTP/1.1` request text over the negotiated stream. This violates RFC 7540 / RFC 9113 §3.5 client connection prefaces.
2. **Verdict Corruption & HTTP 403 Blindness (`ja4bench.go`)**: In `ja4bench.go`, `res.Record(isGood, true, ...)` records a connection as `allowed=true` solely because `err == nil`. If the security pipeline identifies an attacker and returns `HTTP/1.1 403 Forbidden` or `429 Too Many Requests`, the socket read completes without a transport error. Consequently, **disruptive security blocks are recorded as allowed connections (false negatives)**.
3. **The Inverted `RateLimited` CI Gate Paradox**: In `ja4bench.go:102`, `RateLimited` is set to `true` when throughput achieves $\ge 90\%$ of offered rate. In `scripts/nightly_benchmark_gate.py:82-86`, `result.get("rate_limited")` is evaluated as a **failing CI regression**. If the proxy handles 950 CPS out of 1,000 offered, the gate fails; if the proxy degrades to 200 CPS, the gate passes.
4. **Queueing Theory Flaws & Coordinated Omission**: Synchronous workers governed by Go's single-buffered `time.Ticker` drop ticks during proxy latency pauses. In accordance with Little's Law ($L = \lambda W$) and Gil Tene's Coordinated Omission principle, dropped arrival slots are never executed or accounted for, resulting in **artificially pristine p95/p99 tail latency metrics** that mask severe proxy queueing stalls.
5. **Network Layer Ephemeral Port Exhaustion**: Unconditional `Connection: close` across synthetic test loops exhausts Linux's ephemeral port range ($~28,232$ ports) in under 30 seconds at 1,000 CPS ($T_{exhaust} = N_{ports} / \text{CPS}$), causing client socket allocation errors (`EADDRNOTAVAIL`) that the harness misclassifies as proxy capacity failures.
6. **Token-Bucket Mutex Sleep Deadlock (`scripts/benchmark.py`)**: Legacy Python generators invoke `time.sleep()` while holding `self.lock`, serializing worker threads and capping generation throughput below 200 CPS.
7. **Extensive Zombie Tooling**: Over 2,000 lines of dead Python benchmark code (e.g., `scripts/benchmark_comparison.py`, `tests/performance/benchmark_phase26.py`) remain in the tree referencing deleted Python proxy components (`proxy.py`, `src.security.pipeline`).

---

## 2. Exhaustive Harness Inventory & Status Classification

The following 24 performance files, harnesses, scripts, and workflows across the JA4proxy codebase have been audited and classified:

| Harness / Script Path | Language | Target Subsystem | Status | Primary Pathology / Architectural Function |
|---|---|---|---|---|
| `cmd/ja4pd/bench_test.go` | Go | Core Pipeline | **ACTIVE** | Measures fast ALPN bypass vs full signal scoring pipeline (uses in-memory `benchRedis` mock). |
| `internal/tls/bench_test.go` | Go | TLS Parser | **ACTIVE** | Benchmarks ClientHello parsing, JA4 fingerprinting, and adversarial payload rejections. |
| `internal/quic/bench_test.go` | Go | QUIC / HTTP/3 | **ACTIVE** | Benchmarks JA4Q computation, CRYPTO frame decoding, and Initial packet decryption. |
| `internal/server/saturation_bench_test.go` | Go | Conn Admission | **ACTIVE** | Benchmarks high-contention listener admission and token bucket rate limits. |
| `internal/security/pentest_tranco_benchmark_test.go` | Go | Security Engine | **ACTIVE** | Tranco top-1M domain fingerprint false-positive benchmark (guards 0% FP invariant). |
| `internal/security/event_payload_test.go` | Go | Analytics Payload | **ACTIVE** | Benchmarks signal payload serialization and counterfactual evaluation overhead. |
| `internal/security/rule_fuzz_test.go` | Go | Security Rules | **ACTIVE** | Micro-benchmarks rule evaluation, SNI analyzers, and bypass matchers. |
| `internal/security/tap_consumer_test.go` | Go | Tap Signal Consumer | **ACTIVE** | Benchmarks signal lookups against local cache vs Redis cluster hits. |
| `internal/cache/cache_fuzz_test.go` | Go | LRU Cache | **ACTIVE** | Micro-benchmarks LRU cache Get, Set, and eviction throughput under concurrency. |
| `internal/tap/packet_fuzz_test.go` | Go | Passive Sniffer | **ACTIVE** | Micro-benchmarks raw packet decoding, TCP stream reassembly, and JA4T fingerprinting. |
| `internal/webhook/dispatch_fuzz_test.go` | Go | Alert Webhooks | **ACTIVE** | Micro-benchmarks HMAC-SHA256 signature generation and end-to-end event dispatch. |
| `internal/redis/pubsub_fuzz_test.go` | Go | Redis PubSub | **ACTIVE** | Micro-benchmarks PubSub message HMAC verification and handler dispatch loops. |
| `internal/test/bench/ja4bench.go` | Go | CLI Macro Bench | **FLAWED** | Closed-loop tick-drop generator; ALPN `h2` with raw HTTP/1.1; treats 403 as allowed; inverted `RateLimited`. |
| `internal/test/bench/ja4bench_test.go` | Go | CLI Bench Tests | **ACTIVE** | Unit tests for `ja4bench.go` metrics aggregation and exit code reporting. |
| `scripts/bench-hostnative.sh` | Bash | Host-Native Proxy | **ACTIVE** | Runs `ja4p test benchmark` against bare-metal `ja4pd` (bypasses Docker bridge serializations). |
| `scripts/run-benchmark.sh` | Bash | Container Proxy | **ACTIVE** | Orchestrates macro benchmark execution against docker compose services. |
| `scripts/basic_perf_test.sh` | Bash | Basic Smoke | **BROKEN** | Legacy curl loop; treats HTTP `502` and `503` as successful responses (`grep -q "200\|502\|503"`). |
| `scripts/perf-matrix.sh` | Bash | Load Matrix | **ACTIVE** | Runs parameter sweeps across worker counts ($w \in \{1, 4, 8, 16\}$) and rates. |
| `scripts/export_ci_benchmark_textfile.sh` | Bash | Prometheus Metrics | **ACTIVE** | Exports JSON benchmark results into Prometheus textfile format for Node Exporter scrape. |
| `scripts/load_test.py` | Python | Load Suite | **FLAWED** | Subprocesses load generator; wraps legacy `benchmark_comparison.py` defaults. |
| `scripts/tls-traffic-generator.py` | Python | TLS Simulator | **ACTIVE** | Generates synthetic TLS ClientHellos with configurable extension sets. |
| `scripts/nightly_benchmark_gate.py` | Python | CI Regression Gate | **FLAWED** | Contains inverted `rate_limited` check that fails CI when the proxy achieves target throughput. |
| `scripts/benchmark.py` | Python | Legacy Runner | **BROKEN** | Token-bucket locks mutex during `time.sleep()`; GIL serialization caps throughput $< 200$ CPS. |
| `scripts/benchmark_comparison.py` | Python | Proxy Comparison | **ZOMBIE** | 2,032 lines of dead code designed to benchmark against the deleted Python proxy (`proxy.py`). |
| `scripts/tap_benchmark.py` | Python | Tap Bench | **ZOMBIE** | Benchmarks deleted Python `src.tap.capture` module instead of Go `cmd/ja4-tap`. |
| `scripts/bench-tls-backend.py` | Python | Backend Mock | **ACTIVE** | Lightweight high-speed TLS echo server for benchmarking proxy forwarding without backend delay. |
| `tests/performance/test_bench_go_proxy.py` | Python | Pytest Perf Gate | **ACTIVE** | Pytest wrapper verifying Go proxy socket responsiveness under `$(TOOLS_RUN)`. |
| `tests/performance/benchmark_phase26.py` | Python | Legacy Security | **ZOMBIE** | Imports and benchmarks `src.security.pipeline` (the deleted Python proxy pipeline). |
| `tests/performance/benchmark_parallel_signals.py` | Python | Legacy Signals | **ZOMBIE** | Tests deleted Python signal collector with mocked AsyncMock Redis. |
| `.github/workflows/nightly-benchmark.yml` | YAML | GitHub CI Gate | **ACTIVE** | Runs nightly benchmark workflow and uploads performance regression artifacts. |

---

## 3. Mathematical Truthfulness, Queueing Theory & Concurrency Flaws

### 3.1 Closed-Loop Saturation & Little's Law Bounds
In `internal/test/bench/ja4bench.go:279-318`:
```go
ratePerWorker := rate / workers
ticker := time.NewTicker(time.Second / time.Duration(ratePerWorker))
for {
    select {
    case <-ticker.C:
        startDial := time.Now()
        conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", host, conf)
        ...
        res.Record(isGood, true, time.Since(startDial), nil)
    }
}
```
This is a strictly **closed-loop synchronous load generator**. In queueing theory, an arrival occurs only after the previous request has completed or the ticker channel delivers.
Under Little's Law:
$$L = \lambda W$$
Where $L$ is the number of requests concurrently in flight, $\lambda$ is the throughput (CPS), and $W$ is the mean service time (latency).

The maximum possible throughput for $W$ workers in a synchronous closed loop with mean service time $\bar{R}$ is strictly bounded by:
$$\lambda_{max} = \frac{W}{\bar{R}}$$
When a fixed tick interval $T = \frac{1}{\text{ratePerWorker}}$ is imposed, each worker's effective rate is:
$$\lambda_{worker} = \frac{1}{\max(T, \bar{R})}$$
When $\bar{R} > T$, the worker cannot sustain the offered rate. Go's `time.Ticker` has a channel capacity of 1 (`time/tick.go`). When the receiver is blocked performing network I/O, the ticker **drops ticks without buffering or coalescing**.
**Consequence:** The load generator self-saturates. If the proxy experiences temporary queueing latency, the generator slows down and offers fewer requests per second, completely failing to stress the proxy under load.

### 3.2 Coordinated Omission & Percentile Masking
Gil Tene demonstrated that closed-loop generators suffer from **Coordinated Omission**: when a system under test experiences a hiccup (e.g. Go GC stop-the-world pause, Redis timeout, epoll lock contention), the load generator coordinator waits along with the system.

Suppose a proxy stalls for 1,000 ms:
1. An open-loop Poisson/constant-arrival generator scheduled to send at 1,000 CPS would generate 1,000 requests during this pause.
   - Request 1 experiences 1,000 ms latency.
   - Request 500 experiences 500 ms latency.
   - Request 999 experiences 1 ms latency.
   - The p99 and p99.9 percentiles surge dramatically to ~990 ms.
2. In `ja4bench.go`, the single request in flight blocks for 1,000 ms.
   - Go's single-buffered `time.Ticker` drops the 999 ticks that fired during that second.
   - Exactly **1 request** is recorded with 1,000 ms latency.
   - The other 999 requests that would have populated the tail percentiles **never exist**.
   - **Result:** The p95 and p99 metrics computed in `ja4bench.go:115` are mathematically distorted and give a false assurance of low tail latency.

### 3.3 Ephemeral Port Exhaustion & Linux `TIME_WAIT` Dynamics
`ja4bench.go` and `scripts/benchmark.py` explicitly send:
```http
Connection: close\r\n\r\n
```
Under TCP (RFC 793), the endpoint that actively closes the connection enters the `TIME_WAIT` state for $2 \times \text{MSL}$ (default 60 seconds on Linux) to prevent delayed duplicate packets from corrupting subsequent connections.

Linux ephemeral port availability is bounded by `/proc/sys/net/ipv4/ip_local_port_range` (typically 32,768 to 60,999, yielding $N_{ports} = 28,232$ available local ports).
The time to total socket exhaustion at rate $\lambda$ is:
$$T_{exhaust} = \frac{N_{ports}}{\lambda}$$
At a load test rate of 1,000 CPS:
$$T_{exhaust} = \frac{28,232}{1,000} \approx 28.23\text{ seconds}$$

After 28 seconds of continuous testing:
- All ephemeral ports targeting the proxy's IP:port pair are stuck in `TIME_WAIT`.
- The operating system rejects new `connect()` calls with `EADDRNOTAVAIL` ("cannot assign requested address").
- In `ja4bench.go:332`, `err != nil` causes `res.Record(isGood, false, 0, err)`.
- If testing `isGood = true`, this increments `GoodBlocked++`, causing `FalsePositiveRate() > 0.0` and causing `ja4bench.go`'s `Status()` verification gate to fail.
- **The test harness mistakes host TCP socket exhaustion for proxy failure.**

### 3.4 Protocol Framing Mismatch & False Negative Verdict Blindness
In `internal/test/bench/ja4bench.go:320-336`:
```go
if isGood {
    conf.NextProtos = []string{"h2", "http/1.1"}
}
...
conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", host, conf)
if err == nil {
    _ = conn.SetDeadline(time.Now().Add(2 * time.Second))
    _, _ = conn.Write([]byte("GET /health HTTP/1.1\r\nHost: backend\r\nConnection: close\r\n\r\n"))
    _, _ = io.Copy(io.Discard, conn)
    _ = conn.Close()
    res.Record(isGood, true, time.Since(startDial), nil)
} else {
    res.Record(isGood, false, 0, err)
}
```
Two severe architectural defects exist in this 15-line block:
1. **ALPN / HTTP/2 Violation**: When the proxy supports HTTP/2, TLS handshake negotiates `h2`. The client then transmits ASCII HTTP/1.1 plaintext instead of the mandatory 24-octet Client Connection Preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) followed by a `SETTINGS` frame. Any RFC-compliant HTTP/2 proxy or backend rejects this immediately with a GOAWAY/PROTOCOL_ERROR.
2. **HTTP 403 / 429 Verdict Corruption**:
   `res.Record(isGood, true, ...)` marks the request as **allowed** unconditionally as long as `err == nil`.
   When JA4proxy blocks an adversarial request (e.g., suspicious JA4 fingerprint, rate limit exceeded, blacklisted ASN), it writes an `HTTP/1.1 403 Forbidden` response and closes the connection cleanly.
   Because writing and reading the HTTP response completes without a network socket error, `ja4bench` records `allowed = true`!
   **Result:** The macro benchmark cannot measure false negatives or true positives. An attacker connection that is successfully blocked by HTTP 403 is tallied as an allowed connection, completely corrupting security pipeline accuracy measurements.

### 3.5 The Inverted `RateLimited` CI Gate Paradox
In `ja4bench.go:101-103`:
```go
if r.OfferedRateCPS > 0 {
    r.RateLimited = r.ThroughputCPS >= 0.9*float64(r.OfferedRateCPS)
}
```
Here, `RateLimited` was intended to indicate that the load generator reached $\ge 90\%$ of its offered rate ceiling.
However, in `scripts/nightly_benchmark_gate.py:82-86`:
```python
if result.get("rate_limited", False):
    failures.append(
        f"benchmark was artificially rate-limited (achieved throughput was within 90% of offered rate {result.get('offered_rate_cps', 'unknown')} CPS)"
    )
```
This produces an **inverted CI regression gate**:
- If the proxy handles 950 CPS out of 1,000 offered, `RateLimited = true` and `nightly_benchmark_gate.py` **fails CI**.
- If the proxy suffers an 80% performance collapse and only achieves 200 CPS, `RateLimited = false` and the CI regression check **passes**.

### 3.6 Docker-Proxy Bridge vs Host-Native Performance Ceiling
Benchmarks executed through `docker-proxy` (the Docker bridge port forwarding daemon) serialize user-space packet copies across `docker-proxy`, iptables NAT, and bridge network interfaces.
Historical JA4proxy measurements recorded:
- Docker bridge port (`127.0.0.1:8080` via bridge): **~600–720 CPS ceiling**.
- Host-native execution (`127.0.0.1:HOST_PORT_DIRECT` / `scripts/bench-hostnative.sh`): **~3,263 CPS ceiling** ($> 4.5\times$ increase).
Any benchmark executed across the default Docker bridge measures the latency and lock contention of `docker-proxy`, not the JA4proxy Go engine.

---

## 4. Full Go Micro-Benchmark Baseline Results

Executed on Linux x86_64 (`golang:1.27.3-alpine`, Intel Core i7-1185G7 @ 3.00GHz):

| Package | Benchmark Name | Iterations | ns/op | B/op | allocs/op | Operational Analysis |
|---|---|---|---|---|---|---|
| `cmd/ja4pd` | `BenchmarkPipeline_Allow` | 1,481,631 | 889.9 ns | 184 B | 3 | Fast ALPN bypass hot-path; $< 1\,\mu\text{s}$ per decision. |
| `cmd/ja4pd` | `BenchmarkPipeline_Score` | 1,429,150 | 820.9 ns | 160 B | 3 | Full signal collection and rule evaluation pipeline (in-memory stub). |
| `internal/tls` | `BenchmarkClientHelloParse` | 2,521,976 | 600.6 ns | 456 B | 8 | Zero-copy ClientHello parser; 1.66 million parses/sec/core. |
| `internal/tls` | `BenchmarkJA4Compute` | 1,000,000 | 1,318 ns | 128 B | 4 | SHA-256 cipher/extension sorting and raw JA4 string generation. |
| `internal/tls` | `BenchmarkClientHelloParseAdversarial` | 1,967,155 | 590.5 ns | 580 B | 7 | Parser fast rejection of truncated or malformed ClientHellos. |
| `internal/quic` | `BenchmarkComputeJA4Q` | 592,578 | 1,889 ns | 752 B | 34 | Variable-byte integer parsing and QUIC transport param hash. |
| `internal/quic` | `BenchmarkParseClientHelloFeatures` | 14,880,882 | 91.56 ns | 120 B | 2 | Extraction of ALPN, SNI, and cipher suites from QUIC CRYPTO frames. |
| `internal/quic` | `BenchmarkParseCRYPTOFrames` | 7,221,344 | 164.5 ns | 208 B | 3 | QUIC frame header decoding and payload reassembly. |
| `internal/quic` | `BenchmarkDeriveInitialKey` | 2,337,147 | 470.2 ns | 320 B | 8 | HKDF expansion for QUIC initial packet decryption keys. |
| `internal/quic` | `BenchmarkDecryptInitial` | 1,770,100 | 686.2 ns | 1,360 B | 4 | AES-128-GCM packet payload unprotect and header unmasking. |
| `internal/server` | `BenchmarkServer_AdmitConn` | 1,437,321 | 1,026 ns | 1,376 B | 12 | Token-bucket rate limiter admission under high concurrent lock contention. |
| `internal/security` | `BenchmarkBuildSignalPayload` | 430,596 | 2,912 ns | 2,808 B | 13 | JSON event payload assembly for Redis/Kafka export pipeline. |
| `internal/security` | `BenchmarkCounterfactuals` | 3,618,562 | 328.8 ns | 0 B | 0 | In-memory evaluation of "what-if" shadow rule policies; zero allocs. |
| `internal/security` | `BenchmarkRuleEvaluation` | 956,388 | 1,099 ns | 648 B | 16 | Dynamic rule condition tree matcher against connection context. |
| `internal/security` | `BenchmarkSNIAnalyzer` | 894,496 | 1,340 ns | 332 B | 3 | SNI entropy calculation and domain classifier lookup. |
| `internal/security` | `BenchmarkPipelineCheckBypasses` | 282,902,996 | 3.998 ns | 0 B | 0 | Hot-path bitmap bypass check; ~4 nanoseconds per connection. |
| `internal/security` | `BenchmarkTapConsumer_GetSignal_CacheHit` | 4,703,143 | 266.2 ns | 8 B | 1 | Local LRU signal cache lookup; ~3.75M lookups/sec/core. |
| `internal/security` | `BenchmarkTapConsumer_GetSignal_RedisHit` | 666,819 | 1,759 ns | 572 B | 13 | Signal lookup on local Redis hit (round-trip + deserialization). |
| `internal/cache` | `BenchmarkLRUSet` | 20,708,977 | 50.29 ns | 7 B | 0 | Sharded LRU insertion without eviction; ~20M ops/sec. |
| `internal/cache` | `BenchmarkLRUSetWithEviction` | 1,888,548 | 628.1 ns | 139 B | 5 | LRU eviction linked list restructuring under memory pressure. |
| `internal/cache` | `BenchmarkLRUGetHit` | 50,127,376 | 28.24 ns | 0 B | 0 | Concurrent LRU hit; zero memory allocations. |
| `internal/tap` | `BenchmarkPacketDecode` | 21,075,690 | 55.76 ns | 0 B | 0 | Raw Ethernet/IPv4/TCP packet header decoding. |
| `internal/tap` | `BenchmarkTCPReassembly` | 6,297,530 | 177.8 ns | 16 B | 1 | Out-of-order TCP segment reassembly engine. |
| `internal/tap` | `BenchmarkComputeJA4T` | 5,241,680 | 237.2 ns | 144 B | 7 | TCP SYN fingerprint (Window Size, Options, MSS) generation. |
| `internal/webhook` | `BenchmarkComputeHMAC` | 1,299,063 | 940.6 ns | 768 B | 10 | HMAC-SHA256 signature computation for outgoing webhooks. |
| `internal/redis` | `BenchmarkVerifyPubSubHMAC` | 516,332 | 2,614 ns | 745 B | 10 | Cryptographic signature validation on received cluster messages. |

---

## 5. Legacy Drift, Python Proxy Artifacts & Zombie Code Points

The audit uncovered deep architectural drift spanning multiple files that were never cleaned up when the Python proxy was decommissioned:

1. **`scripts/benchmark_comparison.py` (2,032 lines of dead code)**:
   - Written to compare Go proxy throughput against the deleted Python proxy (`proxy.py`).
   - Line 33 & 90: Hardcodes `--go-port 8082` (proxy moved to `8080`). In chaos tests (`tests/chaos/test_go_proxy_chaos.py:27`), residual defaults still point to legacy port `18082`.
   - References defunct environment variables and launch scripts.
2. **`tests/performance/benchmark_phase26.py` & `benchmark_parallel_signals.py`**:
   - Line 21 & Line 14: `from src.security.pipeline import ConnectionContext, Pipeline`
   - These tests fail immediately if executed because `src/` no longer contains the proxy pipeline.
3. **`scripts/tap_benchmark.py`**:
   - Lines 166 & 232: Imports `from src.tap.capture import ParsedPacket, _parse_ethernet_frame`.
   - Obsolete; JA4-Tap is now fully implemented in Go under `cmd/ja4-tap/` and `internal/tap/`.
4. **`scripts/benchmark.py` Token-Bucket Deadlock**:
   - Line 106: `with self.lock: if now < self.next_send: time.sleep(self.next_send - now)`
   - All worker threads block waiting on `self.lock` during sleep, destroying generator concurrency.
5. **`scripts/bench-hostnative.sh`**:
   - Line 28: Defaults to `PROXY_PORT="${PROXY_PORT:-18080}"` instead of canonical `HOST_PORT_DIRECT` (`8080`).

---

## 6. Performance Testing Capabilities Matrix

Comparison of JA4proxy's current capabilities against production requirements across 6 architectural dimensions:

| Dimension | Current State in Repository | Critical Gaps & Vulnerabilities | Target State / Modern Tooling |
|---|---|---|---|
| **1. Micro-benchmarks** | Highly optimized Go benchmarks in `internal/tls`, `internal/quic`, `cmd/ja4pd`. | Redis is completely mocked (`benchRedis` stubs). Zero measurement of real Redis TCP socket latency or cluster pipeline lock contention under load. | Introduce integrated miniredis and real Redis container micro-benchmarks with concurrent pipeline pipelining. |
| **2. Connection Churn (CPS)** | `ja4p test benchmark` and `scripts/bench-hostnative.sh`. | Closed-loop tick drops; Coordinated Omission; ephemeral port exhaustion in $< 30$s; treats HTTP 403 as allowed. | Open-loop arrival generator with pre-allocated connection pools, PROXY protocol synthetic source IP rotation, and HTTP status verification. |
| **3. Data Plane Throughput** | None (only sends 40-byte `GET /health` and terminates). | Zero measurement of bulk data streaming, proxy memory buffer allocation, or `io.Copy` GC overhead under large payloads (e.g. 10MB transfers). | Bi-directional streaming throughput benchmark measuring Gbps line rate and memory allocations per megabyte transferred. |
| **4. HTTP/2 Multiplexing** | Advertises ALPN `h2` but sends raw HTTP/1.1 ASCII. | No support for multiplexed streams over persistent TLS connections; unable to measure flow control or frame header parsing overhead. | Dedicated HTTP/2 and HTTP/3 multiplexing load generator (measuring concurrent stream capacity over single TLS sessions). |
| **5. QUIC / UDP** | Micro-benchmarks in `internal/quic/` (`BenchmarkComputeJA4Q`). | No macro UDP load generator. The proxy cannot currently be load-tested over QUIC datagrams end-to-end. | UDP/QUIC packet generator simulating high-rate ClientHello datagram bursts with packet loss and reordering. |
| **6. Soak & Concurrency Leaks** | Unit-level soak tests in `cmd/ja4pd/soak_leak_test.go` (1,000 requests). | No long-duration soak test harness (1–4 hours) exercising file descriptor exhaustion, goroutine leaks, or memory growth under sustained load. | Automated 2-hour soak test running under memory limit (`GOMEMLIMIT`) with automated pprof heap and goroutine dump comparison. |

---

## 7. Proposed Action Plan & Follow-Up Phases

To remediate these systemic issues without destabilizing production, the modernization must be executed across four sequenced implementation phases:

### Phase 868: Modernize Macro Load Generator (`ja4bench` v2)
- **Scope:**
  1. Decouple request arrival scheduling from connection completion (open-loop Poisson arrival schedule).
  2. Eliminate Coordinated Omission: record scheduled issue time vs response completion ($Latency_{total} = Latency_{wait} + Latency_{service}$).
  3. Implement strict HTTP status code verification (assert `200 OK` for good traffic, assert `403/429` for blocked traffic).
  4. Fix ALPN wire protocol: send valid HTTP/2 client prefaces and frames when `h2` is negotiated.
  5. Add PROXY protocol v2 header generation with rotating synthetic source IPs to bypass client-side `TIME_WAIT` port exhaustion.

### Phase 869: Deprecate Zombie Benchmarks & Repository Hygiene
- **Scope:**
  1. Safely remove `scripts/benchmark_comparison.py`, `scripts/benchmark.py`, `scripts/basic_perf_test.sh`, `scripts/tap_benchmark.py`, `tests/performance/benchmark_phase26.py`, and `tests/performance/benchmark_parallel_signals.py`.
  2. Clean `Makefile` targets: deprecate `perf-test`, update `bench-macro` and `test-go-perf` to target honest Go harnesses exclusively.
  3. Update `scripts/bench-hostnative.sh` default port binding to `HOST_PORT_DIRECT`.

### Phase 870: Nightly Benchmark & CI Telemetry Gate Realignment
- **Scope:**
  1. Fix the inverted `RateLimited` logic in `scripts/nightly_benchmark_gate.py`: treat `rate_limited == true` as an indicator of an un-saturated load generator, not a proxy regression failure.
  2. Implement dual-baseline gating: separate GitHub Actions runner baseline from bare-metal host-native baseline.
  3. Store historical trend metrics in Prometheus textfile format with automated regression alert thresholds.

### Phase 871: High-Concurrency Data-Plane & Long-Duration Soak Suite
- **Scope:**
  1. Implement persistent connection data-plane benchmark measuring bulk payload throughput (Gbps) and GC allocation pressure.
  2. Implement a 2-hour automated soak test monitoring goroutine count, open socket descriptors, and heap allocation stability under continuous 2,000 CPS load.
  3. Feed real traffic profiles into Profile-Guided Optimization (`cmd/ja4pd/default.pgo`).

---

## 8. Conclusion & Sign-Off

The JA4proxy Go core is exceptionally fast (micro-benchmarks confirm $< 900\,\text{ns}$ per decision and ~4 nanosecond bypass evaluations), but our **macro measurement tools have been measuring load generator bottlenecks, closed-loop tick-drops, and socket exhaustion rather than the proxy**. Executing the recommended four-phase modernization roadmap will give JA4proxy an honest, production-grade performance testing foundation.
