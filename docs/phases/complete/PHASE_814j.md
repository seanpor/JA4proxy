# Pentest: Resource Exhaustion and Availability

## Goal

Execute an adversarial penetration test and availability assessment of JA4proxy's Go dataplane, asynchronous processing pipeline, tarpit subsystem, and telemetry export boundaries under resource exhaustion and denial-of-service conditions (Persona P3: Resource Exhaustion / Availability Attacker). This phase operates strictly within Stage 1, Green band (in-process Go adversarial suites and local container mock boundaries). It absorbs Phase 523 item 4 (tarpit resource bounds) and empirically profiles resource curves under adversarial load rather than simple pass/fail assertions.

The objective is to discover, prove, and eliminate denial-of-service vectors, memory exhaustion sinks, goroutine leaks, unbounded Redis data structures, fail-open bypasses under queue saturation, and Prometheus metrics cardinality explosions.

---

## Scope

### In Scope

1. **Accept-Loop Semaphore & Connection-Slot Exhaustion:**
   - Behavior of `s.AdmitConn` and `s.AcceptSem` under concurrent connection saturation exceeding `max_connections` (default 10,000).
   - Profiling goroutine allocation, file descriptor consumption, and admission rejection throughput.
   - Verifying that incoming connections rejected by `AdmitConn` do not leak memory, buffers, or unclosed file descriptors.
   - Synchronous log-volume throttling: Under an accept-overflow flood, `AdmitConn` formats and writes a synchronous `Warn` log for every dropped connection. Disk/terminal I/O blocking stalls `ln.Accept()`, overflowing the OS kernel TCP listen backlog (`SOMAXCONN`) and dropping legitimate connection attempts at the TCP SYN phase. The scope includes adding rate-limiting / atomic throttling to `AdmitConn` overflow logging.

2. **BufferPool Retention & Forwarding Memory Waste (Use-After-Free Safe):**
   - Lifetime audit of `bp := BufferPool.Get().(*[]byte)` acquired in `HandleConn`:
     - Verification that `bp` (32 KB) is held across the entire lifetime of forwarded connections due to `defer BufferPool.Put(bp)` wrapping synchronous `s.Forward(..., wg.Wait())`.
     - Evaluation of cumulative buffer pool memory when thousands of concurrent idle/long-lived connections hold redundant 32 KB ClientHello buffers in addition to the two 32 KB buffers allocated in `cp()`.
     - Refactoring `HandleConn` to return `bp` to `BufferPool` immediately once ClientHello parsing and header preparation are complete, prior to invoking `Forward`.
     - **Concurrency Safety Invariant:** To prevent use-after-free data corruption on `*bp` (where concurrent goroutines reusing the buffer overwrite `data` before it is written to the backend socket), `initialData := append([]byte(nil), data...)` must be deep-copied into a compact slice before `BufferPool.Put(bp)` is called.

3. **`workChan` Saturation & Asynchronous Scoring Fail-Open Bypasses:**
   - Probing the residual attack surface around `JA4PROXY-2026-0094`:
     - Under flood conditions when `workChan` (buffer 20,000, 32 workers) fills, `Process` drops the event (`metrics.WorkChanDroppedTotal.Inc()`) and returns `{Action: "allow", Score: 0, Deferred: true}`.
     - While hard blocks (Spamhaus blocklists, manual `ban:{ip}`, country blacklist, JA4 blacklist) were extracted in 0094 to run synchronously before `workChan` enqueue, evaluate which security mechanisms are still bypassed under queue saturation:
       - **TLS Enforcement Hard Blocks (`tlsEnforcer.Check`):** Currently evaluated only inside `processInternalWithSnapshot` (`pipeline.go:826`). Under `workChan` saturation, prohibited legacy TLS versions (TLS 1.0/1.1) and weak ciphers fail open and are forwarded to the backend. The scope mandates extracting `tlsEnforcer.Check` into synchronous evaluation before `workChan` enqueue.
       - Auto-escalation defense (Phase 248).
       - Datacenter ASN enforcement (Phase 249).
       - Rate limiting (Phase 200).
       - Behavioral beaconing detection (Phase 309).
       - Composite risk scoring & ML (Phase 606f).
     - Adversarial hypothesis: An attacker can flood `workChan` with novel synthetic handshakes to force malicious bot traffic and legacy TLS connections to fail-open directly into the backend without evaluation.

4. **Tarpit Resource Bounds, Fail-Open Overflow & Missing Write Deadlines (Phase 523 Item 4):**
   - Concurrency limits: `cfg.Tarpit.MaxActiveConnections` and per-IP caps `cfg.Tarpit.MaxPerIP`.
   - Overflow action hazards: When tarpit capacity is reached, `overflowAction` is evaluated. If configured to `"allow"`, verify whether an attacker can exhaust tarpit slots to force subsequent flagged traffic into the backend.
   - **Missing `WriteDeadline` Goroutine Leak:** In `internal/server/tarpit.go:91-106`, `src.SetReadDeadline` is set in `copyOne`, but `dst.SetWriteDeadline` is never set. If an attacker advertises a TCP receive window of 0 (or hangs consumption), `dst.Write` blocks indefinitely in the kernel TCP send buffer. Both `copyOne` goroutines, the `Tarpit` caller goroutine, and the tarpit slot remain locked forever. The scope mandates setting `dst.SetWriteDeadline` prior to every write and enforcing a non-zero mandatory ceiling on `MaxLifetimeSeconds`.
   - Inactivity and max lifetime deadlines: Verify that `inactivity_timeout_seconds` and `max_lifetime_seconds` terminate stuck or non-responsive tarpit sockets promptly without leaking goroutines.
   - Memory bounds on `s.TarpitPerIP`: Audit the per-IP tracking map under millions of distinct ephemeral source IPs.

5. **Slowloris Pre-Handshake Holds vs Read Timeouts:**
   - Probing pre-handshake socket reads:
     - In `HandleConn`: `clientConn.SetReadDeadline(time.Now().Add(ReadTimeout))`.
     - Does an attacker sending 1 byte every `ReadTimeout - 1` seconds hold the socket, goroutine, and buffer indefinitely?
     - Behavior when a client sends partial data (<5 bytes) and then stalls: does `ReassembleClientHello` enforce its 200ms deadline strictly?
     - Verification that all read/write deadlines fail closed and cleanly terminate the connection.

6. **Reassembly Buffer Memory Bounds Under Fragmented ClientHello Floods:**
   - Multi-record TLS reassembly memory footprint:
     - `ReassembleClientHello` accumulates handshake records up to `maxReassemblyBytes` (64 KB).
     - Probing dynamic heap allocations when thousands of concurrent connections stream trickle-fragmented records.
     - Enforcing strict bounds on total in-flight reassembly buffers to prevent heap exhaustion.

7. **Redis Backpressure & Unbounded Redis Data Structures:**
   - Unbounded Stream growth: Audit all `XAdd` call sites.
     - In `internal/webhook/delivery.go:278`, DLQ stream writes (`d.cfg.DLQStreamKey`) omit `MaxLen` and `Approx`, allowing failing webhook streams to grow unbounded until Redis OOMs.
   - Unbounded Key growth: Audit all `ZAdd` / `HSet` / `SAdd` call sites:
     - In `internal/security/beaconing_detector.go:160`, `beacon:%s:%s` ZSET keys are created with `ZAdd` but are never assigned a TTL via `Expire`. When timestamps expire via `ZRemRangeByScore`, the key itself persists forever in Redis, leading to unbounded key leakage under randomized IP/JA4 scans.

8. **Log-Volume Amplification & Disk/CPU DoS:**
   - Profiling log emission rates on hot-path rejection branches:
     - `s.AdmitConn`: Warn log on every dropped connection under accept overflow.
     - TLS protocol lockdown: Warn log on every non-TLS byte.
     - Tarpit overflow: Info log on every overflow.
   - Implementing rate-limited logging / token-bucket sampling for synchronous rejection paths to prevent disk I/O and CPU exhaustion.

9. **Prometheus Metrics Cardinality Explosion via Attacker-Controlled Values:**
   - Dataplane Go metrics:
     - Audit all vector metrics (`prometheus.NewCounterVec`, `prometheus.NewGaugeVec`, `prometheus.NewHistogramVec`) to ensure labels cannot be influenced by unvalidated attacker strings (e.g. SNI, ALPN, cipher suites, JA4 strings).
     - Connect `CardinalityGuard` (`SNIGuard`, `JA4Guard`) if high-cardinality labels are introduced.
   - Management API Python metrics (`management/api/prometheus_metrics.py`):
     - `REQUESTS` and `REQUEST_DURATION_MS` use `path` labels normalized by `normalise_path`.
     - In `normalise_path`, any non-numeric segment is kept verbatim. An external unauthenticated attacker probing random non-existent paths (`/api/v1/fuzz_target`, `/<uuid>`, `/admin/<token>`) generates unbounded unique metric label combinations (50,000 requests = 550,000 timeseries in `_m.REGISTRY`), causing Python heap exhaustion and Prometheus scrape timeouts.
     - Scope includes collapsing unknown/unmatched route paths into a constant `{unmatched}` label, or strictly matching against registered FastAPI route templates.

---

### Out of Scope

- Distributed denial of service (>100 Gbps volumetric SYN/UDP floods).
- OS kernel TCP stack vulnerabilities (Linux kernel `tcp_max_syn_backlog` tuning).
- Hardware failure or hypervisor resource starvation.

---

## Rules of Engagement & De-Escalation Ladder

This phase adheres strictly to `docs/security/pentest/RULES_OF_ENGAGEMENT.md`:
- **Band:** Stage 1, Green band only.
- **De-escalation Ladder:**
  - **L0 (Static Analysis):** AST and code inspection of concurrency paths, map allocations, deadlines, and metric labels.
  - **L1 (In-Process Simulation):** Go native tests (`go test ./...`) with mock backends, in-memory Redis, and controlled goroutine concurrency.
  - **L2 (Local Container Range):** Multi-service compose integration test (`deploy/docker/docker-compose.test.yml`) with memory limits (`mem_limit`).
  - **L3 / L4:** Prohibited. No attacks against production or third-party cloud infrastructure.
- **Stop Condition:** Halt and register findings at the lowest ladder level (L0/L1) that proves the vulnerability.
- **Verification Rule:** Every finding must provide a two-state regression proof verifying failure on the pre-fix commit and success on the fix commit.

---

## Threat Model & Adversarial Hypotheses

| Hypothesis ID | Persona | Vector | Target Component | Expected Impact |
| :--- | :--- | :--- | :--- | :--- |
| **H-814j-1** | P3 (Availability) | Accept-loop slowloris connection holding & logging DoS | `internal/server/server.go:AdmitConn` | Goroutine and socket exhaustion, plus synchronous Warn logging stalling accept loop. |
| **H-814j-2** | P3 (Availability) | Forwarding buffer retention memory waste | `internal/server/server.go:HandleConn` | 32 KB pooled buffer held per connection for full session lifetime, wasting hundreds of MBs under persistent connections. |
| **H-814j-3** | P3 (Availability) | Scoring queue saturation bypass (incl. TLS enforcement) | `internal/security/pipeline.go:Process` | Novel TLS handshakes saturate `workChan`, forcing subsequent connections to fail-open (`allow`) past TLS enforcement, behavioral, and rate limits. |
| **H-814j-4** | P3 (Availability) | Tarpit capacity exhaustion, fail-open & missing WriteDeadline leak | `internal/server/tarpit.go:Tarpit` | Tarpit slots exhausted by botnet, forcing traffic into `overflowAction == "allow"`, and zero-window clients pinning goroutines indefinitely. |
| **H-814j-5** | P3 (Availability) | Slowloris trickle past read deadlines | `internal/server/forward.go:ReassembleClientHello` | Trickle attacks pinning sockets past initial deadline without being dropped. |
| **H-814j-6** | P3 (Availability) | Unbounded Redis key creation | `internal/security/beaconing_detector.go:MaybeRecord` | `beacon:<ip>:<ja4>` ZSET keys created without TTL, permanently leaking Redis memory. |
| **H-814j-7** | P3 (Availability) | Unbounded Webhook DLQ stream | `internal/webhook/delivery.go:deliver` | Failing webhook delivery writes to DLQ without `MaxLen`, causing unbounded Redis stream growth. |
| **H-814j-8** | P3 (Availability) | Log-volume amplification DoS | `internal/server/server.go` | High-frequency packet drops emit unbounded Warn logs, saturating disk and CPU. |
| **H-814j-9** | P3 (Availability) | Prometheus metrics cardinality explosion | `management/api/prometheus_metrics.py:normalise_path` | Random URL paths bypass `normalise_path`, creating unbounded Prometheus metric timeseries. |

---

## Implementation Plan

### Step 1: L0 Static Audit & Vulnerability Confirmation
1. Audit `internal/server/server.go`:
   - Trace `BufferPool.Get()` in `HandleConn` and confirm it is held across `s.Forward(..., wg.Wait())`.
   - Audit `AdmitConn` and `AcceptSem` behavior under concurrency and logging throughput.
2. Audit `internal/security/pipeline.go`:
   - Confirm `workChan` saturation behavior and determine whether `tlsEnforcer.Check` and non-hard-block protections fail open.
3. Audit `internal/server/tarpit.go`:
   - Verify `overflowAction` handling, missing `dst.SetWriteDeadline` in `copyOne`, and lifetime timeouts.
4. Audit `internal/security/beaconing_detector.go`:
   - Verify absence of TTL on `beacon:<ip>:<ja4>` ZSET keys.
5. Audit `internal/webhook/delivery.go`:
   - Verify absence of `MaxLen` on DLQ stream `XAdd`.
6. Audit `management/api/prometheus_metrics.py`:
   - Verify that non-numeric path segments are not collapsed, allowing cardinality explosion.

### Step 2: L1 Adversarial Test Suite Construction
1. Create `cmd/ja4pd/pentest_resource_exhaustion_test.go`:
   - Test buffer early return: Assert that `HandleConn` deep-copies `initialData` and returns the ClientHello buffer before starting the forward loop, preventing connection lifetime memory pinning and use-after-free corruption.
   - Test `workChan` saturation & TLS enforcement: Assert that TLS enforcement hard blocks (e.g. weak ciphers / prohibited TLS versions) are strictly enforced even when `workChan` is 100% saturated.
   - Test Tarpit bounds & write deadlines: Assert tarpit connections terminate at `InactivityTimeout` when client stops reading, and verify per-IP and global concurrency caps.
   - Test Slowloris holds: Assert pre-handshake socket timeout cleanly terminates hanging connections.
2. Create `internal/security/pentest_redis_ttl_regression_test.go`:
   - Test beaconing detector ZSET TTL: Assert `beacon:<ip>:<ja4>` key receives an explicit TTL matching `longWindow`.
3. Create `internal/webhook/pentest_dlq_maxlen_regression_test.go`:
   - Test DLQ XAdd `MaxLen`: Assert DLQ stream writes specify `MaxLen: 10000` and `Approx: true`.
4. Create `tests/adversarial/mgmt/test_management_metrics_cardinality.py`:
   - Test `normalise_path`: Send requests with arbitrary unique non-numeric path segments (e.g. `/api/v1/invalid/foo`, `/users/bar`). Assert that unmapped paths are collapsed to `{unmatched}`, preventing cardinality explosion.

### Step 3: Vulnerability Registration
1. Register all confirmed vulnerabilities in `docs/security/findings.yaml` with canonical `JA4PROXY-2026-NNNN` IDs via `scripts/findings_register.py`.
2. Automatically create linked GitHub issues for each finding.

### Step 4: Remediation (TDD Fixes)
1. Fix `BufferPool` retention in `internal/server/server.go`:
   - Deep copy `initialData := append([]byte(nil), data...)`.
   - Return `bp` to `BufferPool` immediately before entering `s.Forward()`.
2. Fix `workChan` saturation bypass in `internal/security/pipeline.go`:
   - Move `tlsEnforcer.Check` into synchronous evaluation in `Process()` alongside manual bans, Spamhaus lists, and blacklists.
3. Fix Tarpit write deadlines in `internal/server/tarpit.go`:
   - Set `dst.SetWriteDeadline(time.Now().Add(inactivity))` prior to every `dst.Write`.
   - Ensure `MaxLifetimeSeconds` has a non-zero default ceiling.
4. Fix Redis ZSET TTL in `internal/security/beaconing_detector.go`:
   - Set TTL on `beacon:<ip>:<ja4>` key using `d.redis.Expire(ctx, key, time.Duration(longWindow)*time.Second)`.
5. Fix Webhook DLQ `MaxLen` in `internal/webhook/delivery.go`:
   - Specify `MaxLen: 10000, Approx: true` on DLQ `XAdd`.
6. Fix `normalise_path` in `management/api/prometheus_metrics.py`:
   - Match routes or collapse unrecognized path patterns to `{unmatched}` to prevent metric cardinality attacks.
7. Fix `AdmitConn` log rate-limiting:
   - Add throttle to accept-overflow `Warn` logging to prevent accept-loop stalls.

### Step 5: Regression Proofs & Verification
1. Run `scripts/verify_revert.sh` for every registered finding against the pre-fix parent commit to prove test failure before the fix and test pass after the fix.
2. Run `make preflight` locally to ensure zero regressions across lint, scan, and test suites.

---

## Test Strategy & Success Criteria

1. **Native Go Execution:** All Go adversarial tests run via `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./...`.
2. **Containerized Python Execution:** Management API tests run in `ja4proxy-tools` container.
3. **Resource Curve Validation:** Assert memory and goroutine stabilization under concurrency using polled assertions (`eventually` loop up to 500ms).
4. **Two-State Proofs:** 100% of new findings accompanied by verified `scripts/verify_revert.sh` proofs.
5. **Preflight Gate:** `make preflight` passes with zero errors and zero warnings.
