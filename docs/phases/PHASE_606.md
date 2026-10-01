# System-Wide Test Modernization & Invariant Enforcement

## Goal
Execute a comprehensive modernization of testing methodologies across all tiers of JA4proxy (Go proxy core, TLS/QUIC parser, passive TAP, state stores, security policy engines, management plane, and analytics). Transition testing from fragile, discrete point-in-time assertions to formal, property-based **system invariants**, driving effective branch and path coverage toward 100% while establishing mathematical and architectural guarantees that catch any regression, bypass, race condition, resource leak, or silent protocol corruption.

---

## Background & Problem Statement
Testing distributed, high-throughput security proxies faces three structural failure modes when reliant solely on traditional unit and integration tests:

1. **The Brittle Mock Trap**: Historical tests frequently assert implementation minutiae (e.g., exact mock invocation sequences, static call counts, hardcoded timing intervals). Refactoring internal data structures or optimizing hot paths breaks these tests despite zero behavioral change, producing high false-positive noise and developer fatigue.
2. **False Negatives via Point-Checking**: A test asserting that a specific byte sequence $A$ computes to JA4 fingerprint $F$ verifies a single point in an astronomical input space ($2^{128+}$). It fails to verify whether splitting $A$ across two TCP packets causes a parser stall, whether inserting a GREASE extension mutates $F$, or whether an out-of-order segment crashes flow reassembly.
3. **Implicit State Assumptions & Concurrency Blind Spots**: Real-world production incidents in security gateways (goroutine leaks, buffer exhaustion under slowloris, deadlocks during config hot-reload, silent fail-open escapes, Redis counter underflows) rarely manifest in discrete happy-path tests. They hide at the boundaries of state machines, resource limits, and network anomalies.

By formally defining and testing **system invariants**—properties that must hold true across *all* inputs, *all* packet partitionings, *all* concurrent interleavings, and *all* state transitions—we achieve:
- **Maximum Defect Detection**: Unanticipated edge cases and protocol violations are caught automatically by generators.
- **Refactor Immunity**: Tests assert fundamental system contracts rather than internal mechanics.
- **Near-100% Path and Branch Coverage**: Property generators explore edge-case combinatorics that human engineers rarely hand-craft.

---

## The 10 Invariant Dimensions of JA4proxy

Every subsystem in JA4proxy is mapped to explicit mathematical and operational invariants:

```
+-----------------------------------------------------------------------------------+
|                            JA4PROXY INVARIANT ARCHITECTURE                        |
+-----------------------------------------------------------------------------------+
|  1. Cryptographic & TLS   | GREASE Equivalence, Grammar [tq][0-9]{2}..., Non-Panic|
|  2. Transport & Splice    | Homomorphic Packet Slicing, Lossless Replay, Backpress|
|  3. Resource Conservation | Delta(Goroutines) -> 0, Delta(FDs) -> 0, Zero Leaks   |
|  4. State & Rate Limiting | Token Non-Negativity, Monotonic Refill, Ban Monotonic |
|  5. Passive Tap & Flow    | TCP Commutativity, Packet Loss Detection & Abort      |
|  6. Intelligence & Scoring| Monotonic Risk Elevation, Temporal Exponential Decay  |
|  7. Configuration Engine  | Atomic Hot-Swap, Zero-Downtime Rollback on Syntax Err |
|  8. Telemetry & Metrics   | Conservation Law: Delta(Accepted) == Sum(Terminals)   |
|  9. Management & RBAC     | Total Mediation, Least Privilege, Audit Completeness  |
| 10. Hermetic Environment  | Delta(GitDirtyFiles) == 0, Zero Host Python Pollution |
+-----------------------------------------------------------------------------------+
```

### 1. Cryptographic, TLS & Handshake Invariants (`internal/tls/`, `internal/fingerprint/`, `internal/quic/`)
- **GREASE Independence Invariant**:
  $$\forall H \in \text{ClientHello}, \; \forall G \subseteq \text{GREASE}, \quad \text{ComputeJA4}(H \oplus G) \equiv \text{ComputeJA4}(H)$$
  Injecting or permuting any combination of GREASE ciphers, extensions, or supported groups must yield the exact same canonical JA4 fingerprint.
- **Canonical Sorting vs. Wire Order Dual Invariant**:
  $$\text{JA4}(H) = \text{JA4}(\text{PermuteExtensions}(H)), \quad \text{JA4\_r}(H) \neq \text{JA4\_r}(\text{PermuteExtensions}(H))$$
  Wire-order permutations must alter raw fingerprints (`JA4_r`) while leaving canonical fingerprints (`JA4`) strictly invariant.
- **Strict Alphabet & Grammar Invariant**:
  $$\forall x \in \{0,1\}^*, \quad \text{ComputeJA4}(x) = f \implies f \in \mathcal{L}(\text{JA4\_REGEX})$$
  $$\text{JA4\_REGEX} = \texttt{\textasciicircum[tq][0-9]\{2\}[di][0-9]\{2\}[0-9]\{2\}[0-9a-z]\{2\}\_[0-9a-f]\{12\}\_[0-9a-f]\{12\}\$}$$
  No input can ever emit an illegal character, incorrect length (36 chars), or malformed field.
- **Prefix Monotonicity & Non-Panic Invariant (Total Function)**:
  $$\forall x \in \{0, 1\}^*, \quad \text{ParseClientHello}(x) \in \{(\text{Record}, \text{nil}), (\text{nil}, \text{ErrTruncated}), (\text{nil}, \text{ErrMalformed})\}$$
  $$\forall B, \; \forall k \le |B|, \quad \text{Panic}(\text{ParseClientHello}(B[:k])) = \text{false}$$
  The parser is total over all byte strings. Arbitrary truncation or garbage returns typed errors; it never panics, never enters an infinite loop, and memory consumption is strictly $O(|x|)$.
- **Semantic Normalization Invariants**:
  - Extracted SNIs are lowercase 7-bit ASCII without null bytes or control characters ($\text{SNI} \in [a\text{-}z0\text{-}9.-]^*$, max 255 bytes).
  - ALPN mappings are deterministic: '00' for absent/empty, exact 2-character translation per specification for present protocols.

### 2. Transport, Splice & Packet Invariants (`cmd/ja4pd/`, `internal/proxy/`)
- **Homomorphic Stream Partitioning (Packet-Boundary Independence)**:
  Let $S$ be a client byte stream. For any partition $P = \{s_1, s_2, \dots, s_k\}$ such that $\sum s_i = S$, and any inter-packet jitter delays $\{\delta_i\}$:
  $$\mathcal{D}_{\text{proxy}}(s_1 \circ s_2 \circ \dots \circ s_k) \equiv \mathcal{D}_{\text{proxy}}(S)$$
  Proxy admission decisions (ALLOW, BLOCK, DROP, TARPIT), extracted JA4/SNI/ALPN metadata, and downstream bytes are completely invariant to network fragmentation.
- **Splice Conservation Law (Zero-Loss, Zero-Duplication Replay)**:
  Under ALLOW policy, the stream delivered to backend $B_{\text{backend}}$ and client $B_{\text{client}}$ satisfies:
  $$B_{\text{backend}} \equiv S_{\text{client}}, \quad B_{\text{client}} \equiv S_{\text{backend}}$$
  Zero bytes lost, zero bytes duplicated, zero byte corruption, exact byte ordering preserved across the bidirectional splice.
- **Fail-Closed Security Boundary (Non-TLS Lockdown)**:
  Under `ProtocolLockdown = true`:
  $$\forall x \in \{0,1\}^*, \quad \text{IsTLS}(x) = \text{false} \implies \text{BytesForwarded}(x) = 0$$
  Non-TLS traffic (HTTP/1.1, SSH, plaintext, raw noise) is stopped dead at the proxy ingress: zero bytes leak to backend targets.
- **Backpressure & Bounded Memory Invariant**:
  When downstream reading is blocked or throttled ($R_{\text{out}} \approx 0$):
  $$\text{HeapAllocatedPerConn} \le \text{MaxRecordBufferSize} \quad (\le 32\,\text{KiB})$$
  Ingress reading must suspend via TCP window backpressure rather than accumulating unbounded memory buffers.

### 3. Resource Conservation & Goroutine Leak-Free Invariants (`cmd/ja4pd/`, `internal/proxy/`)
- **Resource Recovery Monotonicity**:
  Let $R_0 = (\text{Goroutines}_0, \text{FDs}_0)$ be baseline state before accepting $N$ connections. Across all connection termination modes (clean close, client RST, backend timeout, handshake stall, malformed frame, tarpit expiry):
  $$\lim_{t \to t_{\text{drain}}} |\text{Goroutines}(t) - \text{Goroutines}_0| = 0, \quad \lim_{t \to t_{\text{drain}}} |\text{FDs}(t) - \text{FDs}_0| = 0$$
  No connection path leaks goroutines, sockets, timers, or context cancellations.
- **Active Connection Gauge Invariant**:
  At every instant $t$:
  $$\text{Gauge}(\text{ActiveConns}) = \text{Count}(\text{OpenClientSockets})$$
  $$\text{TotalAccepted} = \text{ActiveConns} + \sum \text{TerminatedConns}$$

### 4. Security State Machine, Rate Limiting & Banning Invariants (`internal/security/`, `internal/redis/`, `internal/cache/`)
- **Ban Transitivity & Automatic Expiration**:
  If entity $E$ (IP, CIDR, JA4) is banned at $t_0$ with TTL $\tau$:
  $$\forall t \in [t_0, t_0 + \tau), \quad \text{IsBanned}(E, t) = \text{true}$$
  $$\forall t \ge t_0 + \tau + \epsilon, \quad \text{IsBanned}(E, t) = \text{false}$$
  Bans are immediate, absolute, and expire deterministically without dangling state.
- **CIDR Containment Monotonicity**:
  $$\forall C_1 \subseteq C_2, \quad \text{Banned}(C_2) \implies \text{Banned}(C_1) \implies \forall ip \in C_1, \; \text{Banned}(ip)$$
  Enforcement across IP tree structures is strictly monotonic.
- **Token Bucket Conservation**:
  For capacity $C$, rate $R$:
  $$0 \le \text{Tokens}(t) \le C, \quad \text{Tokens}(t + \Delta t) \le \min(C, \; \text{Tokens}(t) + \Delta t \cdot R)$$
  Tokens are strictly non-negative; consumption is strictly atomic under concurrent multi-threaded requests.
- **Sliding Window Additivity**:
  Under concurrent traffic from $K$ parallel workers, sliding window counter increments must be strictly additive (zero lost updates, zero race underflows).
- **Tarpit Rate & State Bounding**:
  For any tarpitted socket, throughput $\le \text{TarpitRate}$ (e.g. 1 B/s), memory $\le O(1)$, and total active tarpitted sockets $\le \text{MaxTarpitLimit}$.

### 5. Flow Reconstruction & Passive Tap Invariants (`internal/tap/`, `cmd/ja4-tap/`)
- **TCP Segment Commutativity**:
  Let $T = \{p_1, p_2, \dots, p_m\}$ be TCP segments comprising a TLS handshake. For any permutation $\sigma(T)$ delivered out of order:
  $$\text{ReassembleFlow}(\sigma(T)) \equiv \text{ReassembleFlow}(T)$$
  Flow reassembly must be commutative with respect to arrival order.
- **Loss Detection & No Partial Emission**:
  If a mandatory sequence hole occurs in TCP segments that is not filled before timeout, the tap engine must drop the partial session cleanly and emit a reassembly error rather than generating an invalid or truncated fingerprint.

### 6. Analytics, Risk Scoring & Intelligence Invariants (`src/analytics/`, `internal/cluster/`)
- **Score Monotonicity & Bounding**:
  $$\forall x, \quad 0.0 \le \mathcal{S}(x) \le 1.0$$
  $$\mathcal{S}(x \cup \{\text{MaliciousSignal}\}) \ge \mathcal{S}(x), \quad \mathcal{S}(x \cup \{\text{TrustSignal}\}) \le \mathcal{S}(x)$$
  Risk scoring functions must be monotonic with respect to threat/trust signals.
- **Temporal Score Decay Monotonicity**:
  Without new adversarial signals, score decays monotonically over time:
  $$t_2 > t_1 \implies \mathcal{S}(x, t_2) \le \mathcal{S}(x, t_1)$$
- **Cluster Cache Invalidation Bound**:
  When a ban or rule change is broadcast, all cluster nodes converge within propagation bound $T_{\text{sync}}$:
  $$t > t_{\text{event}} + T_{\text{sync}} \implies \forall \text{node}_i, \; \text{Cache}(\text{node}_i) \equiv \text{Truth}$$

### 7. Configuration Atomicity & Invariant Preservation (`internal/config/`, `src/config/`)
- **Atomic Swap Invariant**:
  During runtime configuration reload (SIGHUP or API trigger):
  $$\forall \text{conn}, \quad \text{Config}(\text{conn}) \in \{V_{\text{old}}, V_{\text{new}}\}$$
  No connection ever evaluates policies against a hybrid, partially-initialized, or corrupt configuration state.
- **Zero-Downtime Rejection of Malformed Configurations**:
  If a new configuration file has schema errors, invalid regexes, or unbound ports, the reload transaction must abort, raise an alert, and preserve $V_{\text{old}}$ with zero downtime or connection disruption.

### 8. Telemetry, Observability & Decision Conservation (`internal/metrics/`, `internal/logging/`)
- **Connection Decision Conservation Law**:
  For any observation interval $\Delta t$:
  $$\Delta \text{Accepted} = \Delta \text{Allowed} + \Delta \text{Blocked} + \Delta \text{Dropped} + \Delta \text{Tarpitted} + \Delta \text{Errored}$$
  Every connection transitions to exactly one terminal state metric counter. No drops occur silently.
- **Counter Monotonicity**:
  All Prometheus counter metrics $M_c$ satisfy $M_c(t_2) \ge M_c(t_1)$ for $t_2 \ge t_1$ across the process lifetime.
- **Confidentiality / Secret Leakage Invariant**:
  $$\forall L \in \text{Logs} \cup \text{Traces}, \; \forall s \in \text{KeyMaterial} \cup \text{Tokens} \cup \text{Passwords}, \quad s \notin L$$
  Zero secret leakage into logs, metrics, or diagnostic dumps.

### 9. Management API & RBAC Invariants (`management/`)
- **Total Mediation & Least Privilege**:
  $$\forall \text{Route } R \text{ requiring Permission } P, \quad P \notin \text{Claims}(\text{Request}) \implies \text{Status} \in \{401, 403\}$$
  No state mutation is possible without authenticated, authorized privilege.
- **State Mutation Audit Completeness**:
  Every mutation (ban, unban, rule update, config push) writes an immutable audit record prior to HTTP success.

### 10. Operational & Workspace Hermeticity Invariants (`deploy/docker/`, `Makefile`)
- **Zero-Drift Workspace Invariant**:
  $$\forall \text{Target } T \in \text{Makefile}, \quad \text{GitStatus}(\text{post-}T) = \text{GitStatus}(\text{pre-}T) = \emptyset$$
  Running any test, build, lint, or verification target leaves the working tree completely clean.
- **Container Isolation Invariant**:
  Host Python environment is never modified; no virtualenvs, package installs, or host artifacts are created.

---

## Implementation Plan

### Step 1: Invariant Testing Infrastructure & Utilities
1. **Go Property Testing & Fuzz Framework**:
   - Integrate `testing/quick` and `testing.F` across `internal/tls/`, `internal/fingerprint/`, and `internal/security/`.
   - Implement custom generators: `GenerateRandomClientHello`, `GenerateGREASEClientHello`, `GenerateMalformedStream`.
2. **Network Partitioning & Jitter Harness (`internal/test/netstream`)**:
   - Implement `FragmentingConn` and `JitterConn`: wraps `net.Conn` (e.g. `net.Pipe`) to slice arbitrary byte streams into 1-byte to $N$-byte micro-chunks with configurable delays and reorderings.
3. **Goroutine Leak Verifier**:
   - Implement `internal/test/leakcheck`: snapshot active goroutines, execute connection lifecycle, allow graceful drain, assert delta is 0.
4. **Python Hypothesis State Machines**:
   - Equip `src/analytics/` and `management/` tests with `hypothesis.stateful.RuleBasedStateMachine` to test sliding window aggregators and rate limiter concurrency.

### Step 2: Protocol & Cryptographic Invariants Suite
1. Create `internal/tls/invariants_test.go`:
   - Property test for GREASE invariance across all 16 GREASE values.
   - Property test for canonical vs. wire order extension permutation.
   - Grammar verification matching regex strictly for $10^5$ pseudo-random ClientHellos.
   - Total function & prefix truncation non-panic test over all prefixes $B[:k]$.
2. Create `internal/quic/invariants_test.go`:
   - Non-panic and parsing bounds on Initial and Handshake frames.

### Step 3: Proxy Transport, Splicing & Partitioning Invariants
1. Create `cmd/ja4pd/invariants_stream_test.go`:
   - Homomorphic stream partitioning: feed valid and adversarial ClientHellos through `FragmentingConn` with random chunk sizes $(1, 2, 7, 64)$ into proxy listener. Assert proxy decision and extracted JA4 match unfragmented baseline.
   - Splice conservation: stream 10 MB payload through proxy to echo backend; assert downstream bytes byte-for-byte identical to upstream bytes with zero corruption.
2. Create `cmd/ja4pd/invariants_lockdown_test.go`:
   - Non-TLS fail-closed verification: stream arbitrary non-TLS protocols (HTTP/1.1, SSH, random noise) under `ProtocolLockdown = true`. Assert zero bytes received by backend mock.

### Step 4: Concurrency, Resource & State Machine Invariants
1. Create `cmd/ja4pd/invariants_leak_test.go`:
   - Run 1,000 rapid concurrent connections across 9 termination modes (clean, client RST, server abort, slowloris, malformed, tarpitted). Assert goroutine and socket delta $\to 0$.
2. Create `internal/security/invariants_state_test.go`:
   - Token bucket capacity and non-negative token invariant under multi-goroutine race conditions.
   - Sliding window additivity invariant under concurrent atomic increments.
   - Dynamic ban transitivity and deterministic TTL expiry.
3. Create `internal/config/invariants_reload_test.go`:
   - Atomic configuration swap under concurrent connection load.
   - Zero-downtime rollback on corrupted config syntax.

### Step 5: Metrics Conservation, Analytics & Workspace Invariants
1. Create `cmd/ja4pd/invariants_metrics_test.go`:
   - Assert conservation law: $\Delta \text{Accepted} \equiv \Delta \text{Allowed} + \Delta \text{Blocked} + \Delta \text{Dropped} + \Delta \text{Tarpitted} + \Delta \text{Errored}$.
2. Create `tests/unit/test_workspace_invariants.py`:
   - Verify zero dirty git status after running test suites.
   - Verify no root-owned files created.
3. Create `docs/for-developers/TESTING_INVARIANTS.md`:
   - Practical developer guide for writing invariant and property-based tests for any future feature.

---

## Test Strategy & Coverage Goals
- **Branch & Path Coverage**:
  - Target: $\ge 95\%$ coverage across `internal/tls`, `internal/proxy`, and `internal/security`.
  - Invariant tests exercise paths unreachable by discrete table tests (chunk boundaries, multi-extension permutations, concurrency interleavings).
- **Mutation Testing Verification**:
  - Introduce intentional mutation faults (e.g. invert GREASE filter condition, remove buffer flush, drop error check in record reader).
  - Verify that the invariant test suite catches 100% of mutations.
- **Race Detection**:
  - All Go invariant tests run with `go test -race`. Zero race conditions permitted.

---

## Acceptance Criteria
1. **Full Invariant Suite Implemented & Passing**:
   - All 10 invariant dimensions implemented in Go and Python test harnesses.
   - $100\%$ green across `make test`, `make test-race`, and `make preflight`.
2. **Defect-Free Under Fuzzing & Property Checking**:
   - `testing/quick` and `hypothesis` suites pass minimum 1,000 randomized iterations per property.
   - Zero panics, zero goroutine leaks, zero file descriptor leaks under stress testing.
3. **Conservation & Purity Laws Verified**:
   - Metric conservation equality verified down to the exact integer.
   - Workspace purity verified (`git status --porcelain == ""`).
4. **Developer Documentation Published**:
   - `docs/for-developers/TESTING_INVARIANTS.md` completed with code examples and guidance for future contributors.
5. **CI & Preflight Integration**:
   - Invariant suites integrated cleanly into standard CI gates without timeouts or flakiness.

---

## Out of Scope
- Rewriting third-party upstream libraries (e.g. Go stdlib `crypto/tls`).
- Real-time kernel BPF packet capture performance benchmarking (covered in dedicated perf phases).
