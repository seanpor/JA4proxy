# PHASE 334 — 316* Phase Series Audit & Review

> **STATUS: PROPOSED — review only. No code, no file moves, no close-outs.**

---

## 1. Goal (plain language)

The 316* series (Go TAP/SPAN Passive Sensor — umbrella plus five sub-phases
316a–316e) shipped four sub-phases as **COMPLETE** and one as **PROPOSED**.
This phase critically reviews every 316* phase doc, its **implementation code**,
test coverage, ADRs, and manifest entry. Code review is the primary focus:
correctness, security, edge-case handling, logic bugs, error paths, race
conditions, resource leaks, and conformance to the ADR design decisions.

The output is a structured findings document — **not** a commit that fixes
anything. Fixes, close-outs, and file moves are out of scope; they belong in a
subsequent execution phase or can be done by the original authors.

---

## 2. Scope (review only)

### In Scope

1. **Code review — primary focus.** Read every source file produced by the 316*
   series and assess for:
   - **Correctness**: Does the logic do what the spec/ADR says? Off-by-one?
     Integer overflow? Type confusion?
   - **Security**: Data races, TOCTOU, unvalidated input, injection, privilege
     escalation, insecure defaults, hardcoded secrets, unsafe use of `unsafe`.
   - **Edge cases**: Empty input, nil pointers, closed connections, oversized
     payloads, concurrent access, partial writes, timeouts.
   - **Error handling**: Errors checked? Wrapped with context? Panics recovered?
     Resources cleaned up on error paths?
   - **Resource leaks**: File descriptors, goroutines, memory allocations,
     net.Conn, packet captures (pcap handles).
   - **Concurrency**: Race conditions, deadlocks, channel direction, context
     cancellation propagation, goroutine lifetime management.
   - **Performance**: Unbounded slices/maps, O(n²) loops, lock contention,
     unnecessary allocations (per-packet), busylooping.
   - **Observability**: Log levels appropriate? Metrics emitted? Errors
     distinguishable from info?
   - **Test quality**: Meaningful assertions? Edge cases covered? Mocks
     faithful? Table-driven tests? No skipped tests without explicit exception?
   - **Code style**: Idiomatic Go? Effective Go conventions? Package naming?
     Export decisions? Magic numbers?

2. **Review Phase 316 (umbrella index)** —
   - Is the summary accurate given what actually shipped?
   - Are sub-phase references correct?
   - Is the `PROPOSED` status appropriate with all sub-phases now COMPLETE?

3. **Review Phase 316a (the PROPOSED outlier)** —
   - 316b–316e all claim completion but depend on 316a's capture + TCP
     reassembly + handshake extraction. If 316a didn't ship, were its
     components folded into 316b? Or is there an unmet dependency?
   - This is the single most important finding this review produces.

4. **Review Phases 316b–316e (COMPLETE per manifest)** — for each:
   - Do the acceptance criteria genuinely pass? Are they testable?
   - Does the code actually implement what the plan promised?
   - Is the doc header status text consistent with the manifest?
   - Are ADR references correct and existing?
   - Are there stale TODO/DEFERRED items blocking completion?
   - Are news fragments present and well-formed?
   - Is the manifest `action_plan:` path correct (active vs. `complete/`)?
   - Does `make lint-phases` pass for this entry?

5. **Cross-cutting review:**
   - Run `make lint-phases` — record any violations (don't fix).
   - Run `make test` — identify any test gaps.
   - Run `make preflight` — note any failures.
   - Build `cmd/ja4-tap` — does it compile?
   - Check for stale references to `docs/phases/PHASE_316*.md` outside the
     manifest (e.g., in other phase docs, runbooks, README).
   - Check `docs/decisions/ADR-316*` exists for each phase that references one.
   - Review ADR-316a/e/d — does implementation match the decision?

### Out of Scope

- **No file moves** — do not move phase docs to `complete/`.
- **No manifest edits** — do not change statuses or paths.
- **No code fixes** — do not touch any `.go`, `.py`, `.js`, `.css` files.
- **No close-out commits or PRs** — the output is a review document, not a
  branch.
- **No re-opening settled design decisions** — ADR-316a/e/d are accepted; we
  only review implementation fidelity.
- **The deferred JA4 family** (JA4H, JA4H2, JA4SSH, JA4S, JA4L, JA4X, QUIC/JA4Q)
  — these are settled decisions; only verify they are documented in the umbrella.

---

## 3. Review Process

### Step 1 — Collect data

1. Run `make lint-phases` and capture full output.
2. List all files matching `docs/phases/*316*` (both active and `complete/`).
3. Read every 316* phase doc and extract:
   - Stated acceptance criteria
   - Stated dependencies
   - ADR references
   - Doc header status vs. manifest status
4. Read every 316* ADR in `docs/decisions/`.
5. Read the manifest entry for each 316* phase.
6. Grep for stale references: `docs/phases/PHASE_316` in non-manifest files.
7. Check `docs/fragments/` for 316* news fragments.
8. Build the TAP sensor: try `go build ./cmd/ja4-tap` (or equivalent).
9. Read the test files associated with each sub-phase.

### Step 2 — Analyze

For each sub-phase, answer:

**Code correctness & security:**
- Read every source file. Document logic errors, security issues, race
  conditions, resource leaks, edge-case gaps, and concurrency bugs.
- Are errors checked and wrapped? Panics recovered? Contexts propagated?
- Are there unbounded growth vectors or O(n²) loops on packet paths?

**Completeness:**
- Does every acceptance criterion from the plan have a corresponding test or
  verifiable artifact? If not, is the gap documented?
- Are there skipped tests or TODO comments in the implementation?
- Is the phase doc header status text consistent with the manifest status?

**Quality:**
- Are the tests meaningful (assertions that actually test the behavior)?
- Are there obvious logic bugs or security issues visible in the code?
- Is the ADR faithfully implemented?

**Dependency integrity:**
- Does the dependency chain (316a → 316b → 316c → 316d → 316e) hold?
- If 316a is still PROPOSED, how did 316b–316e ship without it?

**Artifact hygiene:**
- Is the `action_plan:` path in the manifest correct?
- Does `make lint-phases` pass for this entry?
- Do referenced ADR files exist?
- Do news fragments exist and pass `test_changelog_fragments.py`?

### Step 3 — Produce findings

Write a structured findings document. For each finding, specify:

- **Severity**: critical | major | minor | informational
- **Phase**: which 316* phase it relates to
- **Description**: what was found
- **Evidence**: exact file, line, test, or manifest entry
- **Recommendation**: what the original author or a follow-up phase should do
  (not carried out here)

---

## 4. Output

A single findings document at the end of this phase doc (Section 7).

---

## 5. Acceptance Criteria (for the review itself)

1. Every 316* phase doc has been read and assessed for completeness.
2. Every 316* ADR has been checked for implementation fidelity.
3. The 316a dependency paradox has been analysed with a clear finding.
4. The umbrella 316 doc has been reviewed for accuracy.
5. Manifest paths, statuses, and `action_plan:` values have been audited.
6. Test gaps, skipped tests, and TODO items have been catalogued.
7. `make lint-phases` output has been captured (pass or fail).
8. A findings document (Section 7) exists with severity-rated entries.

---

## 6. Dependencies

- None — this is a desk review with no code changes. All inputs (docs, code,
  tests, ADRs) already exist in the repository.

---

## 7. Findings

### F-001 — [CRITICAL] 316a dependency paradox: foundation code shipped under 316b, leaving 316a orphaned as PROPOSED

**Phase:** 316a (umbrella), 316b

**Description:**
316a specifies capture + TCP reassembly + handshake extraction as a self-contained
foundation. Its doc header says `PROPOSED — no code until approved`. However, its
planned deliverables — `capture.go`, `decode.go`, `reassembler.go`, `sensor.go`,
`events.go`, `ja4-tap/main.go` — all exist in the repository. The code was built
as "Step 0" of 316b (extending the `HandshakeEvent` to carry `StackFeatures` per
the 316b revision note on 2026-06-16).

This means 316a was implemented *de facto*, not reviewed or approved *de jure*.
Every downstream phase (316b–316e) depends on it and its `HandshakeEvent` type.
The PROPOSED status is a bureaucratic mismatch: the code is live and shipping.

**Evidence:**
- `docs/phases/PHASE_316a.md` header: `STATUS: PROPOSED — plan for review. No code until approved.`
- All files listed in its "Files to Modify" table exist except `watchdog.go`, `config/proxy.yml` `tap:` section, and `internal/metrics/metrics.go` (correctly not there since TAP has its own registry).
- 316b revision note (line 8–13) explicitly states Step 0 extends the 316a capture path to include TCP/IP-stack features.

**Recommendation:** Mark 316a COMPLETE retroactively; the capture + reassembly + handshake extraction was implemented as the foundation for 316b–316e.

---

### F-002 — [CRITICAL] Protected capability drop + seccomp not wired (binary runs with full CAP_NET_RAW)

**Phase:** 316a

**Description:**
The 316a plan (§7 Security / §9 implementation plan step 7) requires:
- Post-socket privilege dropping: `setreuid`/`setregid` to non-root after binding
  AF_PACKET, failing closed on error.
- Load seccomp profile `config/seccomp_tap.json`.

The live binary at `cmd/ja4-tap/main.go` does neither. Line 106 emits a `log.Warn`
stating these are "deferred to 316a increment 2". `config/seccomp_tap.json` exists
but its comment references the Phase 20 Python TAP (`Managed by src/tap/security.py`),
making it irrelevant to the Go binary.

The binary currently runs with full `CAP_NET_RAW` throughout its lifetime. If
compromised via a parser vulnerability (e.g., gopacket decode of a crafted packet),
the attacker retains raw socket access with no seccomp sandboxing. This is the
single largest security gap in the 316* code.

**Evidence:**
- `cmd/ja4-tap/main.go:106`: `log.Warn("live capture: capability-drop, seccomp and kernel BPF are not yet wired (316a increment 2)")`
- `config/seccomp_tap.json:3`: `"_comment": "Seccomp allowlist for JA4proxy TAP mode process (Phase 20)."` — points at the deleted Python code path.
- No `syscall.Setuid`, `syscall.Setreuid`, or `unix.Prctl(PR_SET_NO_NEW_PRIVS)` call found in `cmd/ja4-tap/main.go`

**Recommendation:** Implement capability drop + seccomp load before putting the
sensor into production. This should be its own follow-up phase, not deferred again.

---

### F-003 — [MAJOR] No `sync.Pool` usage despite plan requirement

**Phase:** 316a

**Description:**
The 316a plan (§5 Resource & Overload Model) explicitly requires:
> "Buffer pooling via sync.Pool: Maintain pools of pre-allocated byte slices
> (e.g., 64KB buffers) and flow-tracking struct nodes."

The implementation at `internal/tap/` has zero `sync.Pool` references. The
gopacket `reassembly` library has its own internal page allocator with
`MaxBufferedPagesTotal/MaxBufferedPagesPerConnection` limits, and the decoder
uses `DecodingLayerParser` for zero-allocation decode — but the plan's explicit
requirement for application-level `sync.Pool` recycling of byte buffers and flow
tracking structs was not implemented.

Under high PPS (10,000+ packets/s), the `tlsStream.appendDir` method allocates a
new byte slice on every segment via `*buf = append(*buf, data...)`. While Go's
append doubles capacity, this still means allocation pressure on the GC for every
packet. A `sync.Pool` of 16KB buffers would eliminate the per-stream growth path.

**Evidence:**
- `rg 'sync\.Pool|sync\.Pool' internal/tap/` returns no results.
- `internal/tap/reassembler.go:160–173`: `appendDir` allocates via `*buf = append(...)` 
  with no pool recycling.

**Recommendation:** Add a `sync.Pool` of pre-allocated 16KB byte slices in the
`streamFactory` and return them to the pool in `ReassemblyComplete`.

---

### F-004 — [MAJOR] No kernel BPF filter (userspace-only drop)

**Phase:** 316a

**Description:**
The 316a plan (§6 Privacy & §7 Security, and the ASCII diagram line `[ AF_PACKET
Ring Buffer (Kernel BPF Filter: tcp port 443) ]`) specifies a kernel-level BPF
filter on AF_PACKET sockets so that only handshake-port traffic reaches userspace.
The implementation at `capture_linux.go:18` opens a `*afpacket.TPacket` with **no
BPF filter**. Non-TCP frames are dropped in userspace by `sensor.go:68` after the
(gopacket) decode step.

This means:
- All traffic on the mirror port (ARP, ICMP, UDP, VLAN, STP, etc.) is copied from
  kernel ring → userspace → parsed → discarded — wasting CPU and memory bandwidth.
- No kernel-level data minimization: all payload bytes reach userspace even
  though only TCP headers are needed.
- A flood of non-TCP traffic can overwhelm the userspace decode path before it
  can filter.

**Evidence:**
- `internal/tap/capture_linux.go:18`: `NewLiveSource` creates `afpacket.NewTPacket(opts...)`
  with only `OptInterface` and optional `OptFrameSize`. No `OptBPFFilter`.
- `internal/tap/sensor.go:65–69`: `ProcessPacket` calls `decoder.decode()` then
  drops non-TCP via `PacketsDroppedTotal.WithLabelValues(dropNonTCP)`.
- Start-of-function comment on line 14: `NOTE (deferred to 316a increment 2): kernel BPF filtering ... are not wired here yet.`

**Recommendation:** Wire `afpacket.OptBPFFilter` with a filter like `tcp proto 6`
to drop non-TCP traffic in the kernel ring. Also deferred to "increment 2" along
with capability drop.

---

### F-005 — [MAJOR] `internal/tap/watchdog.go` not implemented

**Phase:** 316a

**Description:**
The 316a plan Files-to-Modify table lists `internal/tap/watchdog.go` as a new file,
described in implementation plan step 8 as "per-worker restart with rapid-crash
detection". The file does not exist. The sensor has no watchdog, no crash
detection, and no auto-restart mechanism. If the sensor process panics (e.g.,
nil pointer in the decode/reassembly path from a malformed packet), the entire
capture silently stops.

**Evidence:**
- `docs/phases/PHASE_316a.md` Files-to-Modify table row for `internal/tap/watchdog.go`.
- `ls internal/tap/watchdog.go` fails.
- No restart/panic-recovery logic found in `cmd/ja4-tap/main.go`.

**Recommendation:** Implement a supervision loop (or at minimum a deferred
`recover()` in the `drive` function that logs and restarts the sensor).

---

### F-006 — [MAJOR] No `tap:` section in `config/proxy.yml`

**Phase:** 316a

**Description:**
The 316a plan Files-to-Modify table lists `config/proxy.yml` with a new `tap:`
config section (disabled by default). The file exists but has no `tap:` section.

**Evidence:**
- `grep -c 'tap:' config/proxy.yml` returns 0.

**Recommendation:** Add the `tap:` config section as specified in the plan,
disabled by default.

---

### F-007 — [MINOR] `dropEventOverflow` missing from metrics constants

**Phase:** 316a

**Description:**
`metrics.go` defines constants `dropDecode`, `dropNonTCP`, `dropCapExceeded`, and
`dropGap` for the `PacketsDroppedTotal{reason}` label. However, the label value
`"event_overflow"` used in `sensor.go:58` is a raw string literal and has no
corresponding constant. This is inconsistent and makes adding/reviewing drop
reasons harder than it needs to be.

**Evidence:**
- `internal/tap/metrics.go:95–100`: only four constants defined.
- `internal/tap/sensor.go:58`: `PacketsDroppedTotal.WithLabelValues("event_overflow").Inc()`

**Recommendation:** Add `dropEventOverflow = "event_overflow"` to the constants
block in `metrics.go`.

---

### F-008 — [MINOR] TLS parser stalls on non-handshake record interleaved in fragmented handshake

**Phase:** 316a

**Description:**
In `tlsparse.go`, the `extractFirstHandshake` function accumulates defragmented
TLS handshake payloads across consecutive records. When it encounters a
non-handshake record (e.g., ChangeCipherSpec in TLS 1.2) **after** it has started
accumulating handshake data (`len(hs) > 0`), it breaks out of the loop but the
accumulated data in `hs` remains checked for a complete message. If the
handshake message was fragmented across multiple TLS records, this produces a
stuck state: the parser has partial data, never advances past the non-handshake
record, and never finds the remaining handshake record.

In practice, this only fires in TLS 1.2 with ChangeCipherSpec interleaved within
a ClientHello (which is non-standard behavior), and the condition degrades to
"no fingerprint extracted for this connection" rather than a crash. But the
parser should handle this robustly: it should skip non-handshake records when
`len(hs) > 0` instead of breaking.

**Evidence:**
- `internal/tap/tlsparse.go:37–64`: the `for` loop breaks at line 48 when
  `contentType != tlsContentHandshake && len(hs) > 0`, without advancing `i` past
  the non-handshake record. On the next call (same `buf`), the same record is
  hit again, producing the same `break`.

**Recommendation:** Replace `break` with advancing past the non-handshake record:
`i += tlsRecordHeaderLen + recLen; continue`. No test for this scenario exists.

---

### F-009 — [MINOR] Stale doc comment references Phase 20 Python TAP in `tap_consumer.go`

**Phase:** 316b

**Description:**
The package-level doc comment in `internal/security/tap_consumer.go` references
"Phase 20 TAP node" and says it "writes `fp:os:ip:{ip}` strings to Redis". The
Phase 20 Python TAP node was archived/deleted. The actual producer is now the
Go TAP sensor (Phase 316a/316b). Additionally, the `canonicalIP` function comment
on line 31 says "matching what the Phase-20 TAP node writes (via Python's
`socket.inet_ntop`)" — this is misleading since the Go code is the sole producer.

**Evidence:**
- `internal/security/tap_consumer.go:1–15`: "Phase 20 TAP-consumed JA4T OS-mismatch signal"
- `internal/security/tap_consumer.go:31–33`: "matching what the Phase-20 TAP node writes (via Python's socket.inet_ntop)"

**Recommendation:** Update comments to reference Phase 316a/316b instead of
Phase 20 / Python.

---

### F-010 — [INFORMATIONAL] Config seccomp file is for Phase 20 Python, not Go sensor

**Phase:** 316a

**Description:**
`config/seccomp_tap.json` exists but its comment says "Managed by src/tap/security.py"
(deleted file) and references the Phase 20 Python TAP. A Go binary would need a
different syscall allowlist (Go runtime needs `sched_getattr`, `futex`, `epoll_create1`,
etc. which are already listed, but a proper review for the Go binary's specific
syscall surface is needed).

**Evidence:**
- `config/seccomp_tap.json:3`: `"Managed by src/tap/security.py"`

**Recommendation:** Either remove the file or update it to describe the Go sensor's
seccomp requirements when seccomp is actually wired into `cmd/ja4-tap`.

---

### F-011 — [INFORMATIONAL] OBSERVABILITY_STANDARDS.md lists both Phase 20 and Phase 316 TAP metrics

**Phase:** 316b, 316c, 316d (cross-cutting)

**Description:**
The observability doc lists both the legacy Phase 20 TAP metrics
(`ja4proxy_tap_lookups_total`, `ja4proxy_tap_signal_total`) and the new Phase 316
metrics (`ja4proxy_tap_packets_received_total`, etc.). The Phase 20 metrics are
still consumed by `internal/security/tap_consumer.go` and
`internal/security/tap_ja4t_consumer.go`, so they are not dead. However, the
naming overlap could be confusing: "tap" in the old metrics refers to the
Python TAP node, "tap" in the new metrics refers to the Go sensor.

**Evidence:**
- `docs/reference/OBSERVABILITY_STANDARDS.md` shows both metric groups under "TAP mode (Phase 20)" and "Go TAP sensor (Phase 316)"

**Recommendation:** Rename the section headers or add a brief note explaining the
two different producers (Python TAP vs Go TAP sensor) to reduce confusion.

---

### F-012 [INFORMATIONAL] — `make lint-phases` passes (241 phases, 0 violations)

**Phase:** Cross-cutting

**Description:**
The manifest lint passes with no violations, including all 316* phase entries.

**Evidence:**
- `make lint-phases` exit 0, output: "lint-phases: OK — 241 phases checked, 0 violations."

**Recommendation:** None.

---

### F-013 [INFORMATIONAL] — Test assessment

**Phase:** 316a–316e (cross-cutting)

**Description:**
Overall test quality is good. The test suite provides:

- **Decode tests** (`capture_test.go`): pcap round-trip, context cancellation, synthetic packet builders
- **Reassembler tests** (`sensor_test.go`): flow builder, segment serialization, memory source
- **TLS parsing tests** (`tlsparse_test.go`): ClientHello/ServerHello extraction edge cases
- **OS classifier tests** (`osfingerprint_test.go`): known Windows/Linux signatures, edge cases, Darwin-deferred decisions
- **JA4T tests** (`ja4t_test.go`): JA4T computation, determinism verification
- **Store tests** (`store_test.go`, `store_ja4t_test.go`): Redis write path, canonical IP, fire-and-forget error handling
- **Enforcement tests** (`enforcement_test.go`, `enforcement_roundtrip_test.go`): watchlist vs armed, fail-open, miniredis round-trip
- **Consumers** (`tap_consumer_test.go`, `tap_ja4t_consumer_test.go`): all fail-open paths, cache behavior, Redis timeout handling
- **Integration tests** (`roundtrip_test.go`, `roundtrip_ja4t_test.go`): miniredis closed-loop OS-mismatch and JA4T blocklist scenarios

**Gaps found:**
1. No tests verify the `sync.Pool` behavior (it doesn't exist — covered by F-003).
2. No tests for kernel BPF filtering (it doesn't exist — covered by F-004).
3. No tests for capability drop or seccomp (not wired — covered by F-002).
4. No tests for the TLS parser non-handshake-record interleaving edge case (F-008).
5. No tests for watchdog/crash-recovery behavior (F-005).
6. No tests verifying that payload bytes beyond the handshake are NOT retained (privacy guarantee from 316a §6).
7. No performance benchmarks for PPS throughput or allocation profiles (316a §10 specifies these).
8. No IPv4 fragmentation tests (316a §10 specifies this in acceptance criteria).

**Recommendation:** Address test gaps alongside the code gaps (F-002–F-006, F-008).
Add privacy guarantee tests and performance benchmarks before production
deployment.

---

### F-014 — [HIGH] Busyloop on persistent read error (no backoff, 100% CPU burn)

**Phase:** 316a

**Severity:** High — operational DoS on transient failures

**Description:**
The `Run` loop at `sensor.go:104–106` handles transient read errors with a bare
`continue` — no backoff, no error count limit, no sleep. If the packet source
returns any non-nil, non-EOF error (e.g., a kernel ring buffer overrun on
AF_PACKET, a signal-interrupted read, a temporary I/O error), the loop spins at
100% CPU burning a core indefinitely, limited only by the outer `ctx.Done()`.

This is distinct from the context-cancellation path (lines 82–87) — `ctx.Done()`
is checked at the *top* of each iteration, so any combination of errors that
does not cancel the context (e.g., a flaky kernel interface that returns
`EAGAIN` interleaved with occasional success) creates a spin loop.

**Attack scenario:** An attacker who can cause errors on the mirror interface
(e.g., flooding the ring buffer, removing the interface, triggering a NIC reset)
can cause the sensor to peg a CPU core. In a containerized deployment this may
trigger CPU-throttling or OOM-keeper alerts but the sensor will continue
processing whatever packets arrive between errors.

**Evidence:**
- `internal/tap/sensor.go:104–106`: `default: continue`
- No `time.Sleep`, no `backoff` counter, no exponential delay

**Recommendation:** Add a brief `time.Sleep(time.Millisecond)` or an exponential
backoff capped at 1s on the error path. Count consecutive errors so a sustained
failure eventually logs a WARN and stops the sensor (fail-safe rather than spin).

---

### F-015 — [MEDIUM] No promiscuous-mode or privilege verification at startup

**Phase:** 316a

**Severity:** Medium — silent failure

**Description:**
`capture_linux.go` opens the AF_PACKET socket with promiscuous mode via
`afpacket.NewTPacket`. If the interface does not exist, the process lacks
`CAP_NET_RAW`, or promiscuous mode is denied (e.g., container seccomp policy
blocking `setsockopt`), `NewTPacket` returns an error — which IS propagated
through `run()` → `main()`. So the error case IS handled.

However, the frame size parameter is not validated. If `--frame-size` is set
to a very small or very large value, the afpacket library may silently clamp it
or choose suboptimal defaults. No bounds check exists in the capture code.

**No evidence of actual vulnerability** — the library handles these cases. But
the code places full trust in the library's defaults with no defensive
verification that the capture is actually running at the expected performance.

**Evidence:**
- `internal/tap/capture_linux.go:19–21`: No validation or range check on `frameSize`
- `cmd/ja4-tap/main.go:106`: Warning says "not yet hardened" but no explicit
  check that the interface is up, has an IP, or that promiscuous mode was
  actually activated.

**Recommendation:** Add a startup check that the interface exists and is up
(`net.InterfaceByName`), and clamp `frameSize` to a sane range (e.g., 1514–65536).

---

### F-016 — [MEDIUM] Concurrent map read on `JA4TBlocklist` without synchronization

**Phase:** 316d

**Severity:** Medium — potential `concurrent map read and map write` panic

**Description:**
`EnforcerConfig.JA4TBlocklist` is a `map[string]bool` read on the hot path in
`enforcer.go:94`: `!e.cfg.JA4TBlocklist[ja4t]`. Go's map type is **not** safe for
concurrent read + write — if a config-reload goroutine updates the blocklist
(e.g., adding a new JA4T fingerprint to block) while the event-drain goroutine
reads it, Go's runtime panics with `concurrent map read and map write`.

Currently the blocklist is set once at startup via `parseBlocklist(*ja4tBlock)`,
so this is latent risk only. But the zero-cost design of the config struct makes
it likely a future operator tool (live config reload, REST API) writes to this
map without a mutex, triggering a hard panic and sensor restart.

**Evidence:**
- `internal/tap/enforcement.go:94`: map read `e.cfg.JA4TBlocklist[ja4t]` in `Consider`
- `internal/tap/enforcement.go:47`: `JA4TBlocklist map[string]bool` field — no `sync.RWMutex` guard
- `cmd/ja4-tap/main.go:58–63`: only set at startup, never modified

**Recommendation:** Wrap the blocklist with a `sync.RWMutex` or replace the map
with a `sync.Map`. Document that concurrent writes are not supported if the
zero-cost approach is preferred.

---

### F-017 — [MEDIUM] Redis password in cleartext on command line (`--redis-url`)

**Phase:** 316a (operation)

**Severity:** Medium — credential exposure via `ps aux`, shell history, CI logs

**Description:**
The `--redis-url` flag accepts a full Redis URL including password
(`redis://:password@host:port`). This password is visible in cleartext to any
user running `ps aux` on the same machine, stored in shell history, and logged
in CI/CD build logs if passed as an environment variable expansion.

`go-redis` supports `redis.ParseURL` but also accepts individual fields
(`Addr`, `Password`, `DB`, `TLSConfig`). The current design forces the operator
to put the password on the command line.

**Evidence:**
- `cmd/ja4-tap/main.go:49`: `redisURL = flag.String("redis-url", "", "...")`
- `cmd/ja4-tap/main.go:145`: `redis.ParseURL(redisURL)` — password embedded in URL
- `cmd/ja4-tap/main.go:149`: logs `opt.Addr` (host:port) but not the full URL — good, but address is still visible

**Recommendation:** Add `--redis-password` flag read from a file or
`REDIS_PASSWORD` environment variable. When `--redis-password` is set, the
`Password` field in `redis.Options` is populated directly instead of via
`ParseURL`. This removes the password from the process command line.

---

### F-018 — [MEDIUM] No TLS enforcement for Redis connection (cleartext by default)

**Phase:** 316a (operation)

**Severity:** Medium — JA4T fingerprints and ban intents sent in cleartext

**Description:**
`redis.ParseURL` returns `*redis.Options` with `TLSConfig` set only when the
URL scheme is `rediss://`. If the operator passes `redis://` (the more common
form), the Redis connection is unencrypted. This means:
- JA4T fingerprints (e.g., `"65535_2-1-3-1-1-8-4_1460_7"`) are sent in cleartext.
- Ban intents (`"tap_enforce:ja4t=..."`) are sent in cleartext.
- The Redis password is sent in cleartext on the connection.

An attacker on the same network segment (or with access to the Redis network
path) can observe all fingerprints and ban decisions.

**Evidence:**
- `cmd/ja4-tap/main.go:145`: `redis.ParseURL(redisURL)` — TLS is determined by URL scheme
- No `--redis-tls` or `--redis-tls-skip-verify` flag exists
- No minimum TLS version enforcement

**Recommendation:** Add a `--redis-tls` flag that forces TLS regardless of URL
scheme. Document in the runbook that `rediss://` should be used in production
and why cleartext Redis is a risk.

---

### F-019 — [LOW] Duplicate `canonicalIP` in writer and consumer (silent drift risk)

**Phase:** 316b (cross-cutting)

**Severity:** Low — maintenance risk; the OS-mismatch signal silently breaks if
they diverge.

**Description:**
The `canonicalIP` function exists in two places:
- `internal/tap/store.go:96–108` (the TAP sensor writer)
- `internal/security/tap_consumer.go:34–48` (the inline proxy consumer)

Both strip IPv6 brackets, parse with `netip.ParseAddr`, drop zone IDs, and
return `addr.String()`. They are currently identical. If any future change
modifies one without the other, the Redis keys written by the sensor will not
match the keys read by the consumer, and the `tap_os_mismatch` and
`tap_ja4t_blocklist` signals silently stop firing (fail-open to "no signal",
which is safe but undiagnosed).

**Evidence:**
- `internal/tap/store.go:96–108`: first copy
- `internal/security/tap_consumer.go:34–48`: second copy, identical logic

**Recommendation:** Export `canonicalIP` from a shared package (e.g.,
`internal/fingerprint` or `internal/netutil`) and import it from both locations.
Remove the duplicates.

---

### F-020 — [LOW] Read error rate can be high before detection degraded metrics

**Phase:** 316a (observability)

**Severity:** Low — missed operational signals

**Description:**
`PacketsDroppedTotal` counts decode errors, non-TCP drops, cap-exceeded drops,
and event overflows. However, transient read errors in the `Run` loop
(sensor.go:104–106) are **not** counted anywhere — the `continue` statement
branches without incrementing any metric. This means the operator has no way to
distinguish "sensor is idle because no traffic" from "sensor is spinning on read
errors". Only the 100% CPU usage would alert an observant operator.

**Evidence:**
- `internal/tap/sensor.go:104–106`: `default: continue` — no metric increment
- `internal/tap/metrics.go`: no `reason` constant for read errors

**Recommendation:** Add a `PacketsDroppedTotal.WithLabelValues("read_error")`
increment on the error path before `continue`.

---

### F-021 — [LOW] No payload-privacy test (sensor behaviour guarantee untested)

**Phase:** 316a (testing)

**Severity:** Low — quality gap

**Description:**
The 316a plan §10 (Test Plan) requires:
> "**Privacy** — assert no payload bytes beyond the handshake are retained"

No such test exists in the test suite. This is a behavioural guarantee of the
sensor (it never persists or logs raw payload content), but it is nowhere
verified programmatically. A future change could accidentally include payload
bytes without triggering a test failure.

**Evidence:**
- `rg -l 'payload\|privacy' internal/tap/*_test.go tests/` — no privacy/retention assertions found
- Phase 316a doc line 198: "Privacy — assert no payload bytes beyond the handshake are retained"

**Recommendation:** Add a test that captures synthetic traffic with known
payload bytes, feeds it through the sensor pipeline, and asserts that neither
the `HandshakeEvent` nor any Redis write contains the payload content.

---

### F-022 — [CRITICAL] No panic recovery — a single crafted packet can permanently hang the sensor

**Phase:** 316a

**Severity:** CRITICAL — denial of service via packet-of-death

**Description:**
The sensor has zero panic-recovery anywhere. No `recover()` in the `tap` package
or `cmd/ja4-tap/main.go`. If any function panics (nil pointer dereference, slice
bounds error, type assertion, or a panic inside gopacket's decoder when
processing a crafted packet), the consequences are SEVERE:

1. The `sensor.Run` goroutine (spawned at `main.go:158`) dies immediately.
2. The deferred `close(s.events)` in `Run` (line 79) NEVER executes.
3. The main goroutine blocks **forever** at `main.go:161`:
   `for ev := range sensor.Events() {` — this range loop only exits when the
   channel is closed, which never happens.
4. `runErr := <-done` (line 195) also never receives.
5. The process is stuck indefinitely — not crashed, not responding, but
   consuming memory.

This is WORSE than a crash: a crashed process would trigger container/init
restart policies. A hung process passes process-liveness checks (`PID still
running`) but does zero work, silently failing open on all traffic. The operator
sees a running binary and has no reason to suspect it's dead.

**Attack scenario:** If gopacket's TCP or IPv4/IPv6 decoder has a nil-pointer
bug on crafted input (common in packet-processing libraries — CVE-2023-0426,
CVE-2024-21914 in various pcap libraries as precedent), the attacker sends one
packet and the sensor is permanently disabled with no automatic recovery. No
privileges required — just the ability to send packets visible to the SPAN port.

**Evidence:**
- `rg 'recover\\(\\)' cmd/ja4-tap/ internal/tap/` — no results
- `cmd/ja4-tap/main.go:158`: `go func() { done <- sensor.Run(ctx, source) }()` — no defer/recover wrapping
- `cmd/ja4-tap/main.go:161`: `for ev := range sensor.Events()` — hangs forever if events channel never closes
- `internal/tap/sensor.go:79`: `defer close(s.events)` — would recover-and-close if recover existed; currently the goroutine just dies

**Recommendation:**
1. Wrap the sensor goroutine with `defer recover()` that closes `s.events` on
   panic, logs the panic stack trace, and sends an error to the `done` channel.
2. Add a watchdog/health-check goroutine that monitors the event channel and
   restarts the sensor on inactivity.
3. Run the binary under a supervisor (systemd, Docker restart policy) that
   detects the liveness failure via a `/health` endpoint or Prometheus staleness.

---

### F-023 — [HIGH] Zero observability: metrics never registered, no HTTP/health endpoint

**Phase:** 316a (operations)

**Severity:** HIGH — operator blind to sensor health, cannot distinguish "idle"
from "dead"

**Description:**
The `internal/tap/metrics.go` file defines 7 counters, 1 counter-vec, 1 gauge,
and 1 gauge-vec using `prometheus.NewCounter()`, `prometheus.NewGauge()`, etc.
It also provides `Collectors()` returning all of them in a slice. However:

1. **`Collectors()` is never called.** Nothing registers these metrics with
   any Prometheus registry. The `prometheus.MustRegister()` function (used by
   `internal/metrics/metrics.go:398` for the inline proxy) is never called for
   TAP metrics.

2. **No HTTP server.** The binary has no `http.ListenAndServe` call, no
   `promhttp.Handler()`, no `/metrics` endpoint, no `/health` endpoint.

3. **No health check.** There is no way to determine whether the sensor is
   processing packets, has errored, or is hung. `PacketsReceivedTotal.Inc()`
   is the ONLY source-of-truth for "is this thing alive?" and it's invisible.

The metrics DO increment internally (the Go Prometheus client increments
regardless of registration), but no scraper can reach them. An operator has:
no packet rate, no drop rate, no active stream count, no extraction rate,
no enforcement action count, no arming status — **zero visibility**.

**Attack scenario:** An attacker DoSes the sensor via F-022's panic vector or
the error-spin path. Neither is observable. The operator sees a running process
and assumes traffic is being fingerprinted. Ban intents go unwritten, passive
fingerprints go unrecorded, and the OS-mismatch signal goes silent.

**Evidence:**
- `rg "prometheus.MustRegister" internal/tap/` — no results
- `rg "http.ListenAndServe\|promhttp\|/metrics\|/health" cmd/ja4-tap/` — no results
- `internal/tap/metrics.go:79-92`: `Collectors()` defined but uncalled

**Recommendation:**
1. In `cmd/ja4-tap/main.go`, call `prometheus.MustRegister(tap.Collectors()...)`
   at startup.
2. Start an HTTP server on a configurable port (e.g., `--metrics-addr :8080`)
   with `promhttp.Handler()` AND a `/health` endpoint.
3. Wire the health endpoint to the event channel (existence of consumer) and
   the packet-source (`ReadPacketData` returning data within some window).

---

### F-024 — [MEDIUM] No supervisor / restart-on-failure for a security sensor

**Phase:** 316a (operations)

**Severity:** MEDIUM — single point of failure, no self-healing

**Description:**
The binary runs as a standalone process with no built-in watchdog, no
restart-on-failure, and no supervisory process documented in the deployment
guide. The planned `internal/tap/watchdog.go` (F-005) was never implemented.

If the sensor crashes (F-022), the container orchestrator (Docker) would
restart it — but only if the process exits. A **hang** (F-022's goroutine leak)
keeps the process alive, so Docker restart policies never trigger.

Additionally, the binary captures no core dump on crash and has no crash
reporting. Debugging a production crash requires re-running with `GOTRACEBACK=1`
and hoping the crash reproduces.

**Evidence:**
- `cmd/ja4-tap/main.go`: standalone `main()` with no supervision loop
- No `cmd/ja4-tap/supervisor.go` or equivalent
- No signal handler for SIGABRT (for triggering GOTRACEBACK)

**Recommendation:**
1. Implement the watchdog from the 316a plan (F-005) at minimum.
2. Document deployment as a systemd unit or Docker service with `restart: always`
   and a `HEALTHCHECK` directive that hits the `/health` endpoint (once F-023 is
   implemented).
3. Add a signal handler that dumps goroutine stacks on SIGUSR1.

---

### F-025 — [MEDIUM] gopacket v1.6.1 dependency — no CVE audit in repo for this dep

**Phase:** 316a (supply chain)

**Severity:** MEDIUM — unknown vulnerability surface in a network-facing parser

**Description:**
The sensor depends on `github.com/gopacket/gopacket v1.6.1` for all packet
decoding (Ethernet, IPv4, IPv6, TCP). This is the maintained community fork
of the archived `google/gopacket`. The version is pinned by `go.mod`.

The `DecodingLayerParser` reads raw packet data from the network and decodes
protocol headers. A vulnerability in gopacket's TCP decoder (e.g., a crafted
TCP option that causes a panic or buffer over-read) would be a remote DoS or
potentially an RCE via the Go memory surface.

The project's security audit documents
(`docs/security/THIRD_PARTY_CVE_WAIVERS.md`,
`docs/security/CVE_EXCEPTIONS.md`) contain waivers for Redis and various system
packages but no entry for gopacket. A `make scan` run (which includes
`govulncheck`) runs only on the Go binary itself, not on the library dependency
tree.

**Evidence:**
- `go.mod:7`: `github.com/gopacket/gopacket v1.6.1`
- `rg -l 'gopacket\|CVE.*packet' docs/security/` — no security assessment of gopacket
- The decoder is invoked on every packet (`sensor.go:65`), on the untrusted
  network-facing path.

**Recommendation:**
1. Run `govulncheck ./...` specifically targeting gopacket's known vulnerabilities.
2. Add gopacket to the third-party dependency audit checklist in the project's
   security docs.
3. Pin to a specific sub-commit or establish a CVE-monitoring process for
   gopacket releases.
4. Consider fuzz-testing the sensor's `ProcessPacket` path with structured
   packet mutations.

---

### F-026 — [LOW] gopacket `Fetch()` allocates attacker-controlled buffer size

**Phase:** 316a

**Severity:** LOW — bounded by `MaxBufferedPagesPerConnection`

**Description:**
In `reassembler.go:125`, `sg.Fetch(length)` is called where `length` is the
first return value of `sg.Lengths()`. The `length` value is the total bytes
buffered in gopacket's reassembly for this direction. This value is attacker-
influenced: a client sending a large amount of TCP data causes `Fetch` to
allocate a buffer of that size.

In practice, the per-connection page limit
(`MaxBufferedPagesPerConnection = 8`, set at `sensor.go:45`) caps this at
~1900 bytes × 8 ≈ 15KB per call. The default for this field in gopacket is
**much** higher (often 100+), so the explicit low cap is the only reason this
is not a vulnerability. If a future change removes or increases this cap without
also limiting the `Fetch` call, an attacker could trigger memory spikes.

**Evidence:**
- `internal/tap/sensor.go:45`: `s.asm.MaxBufferedPagesPerConnection = maxBufferedPagesPerConn` (8)
- `internal/tap/reassembler.go:125`: `s.append(isClient, sg.Fetch(length))`
- `internal/tap/reassembler.go:164`: `room := maxHandshakeBytes - len(*buf)` — secondary cap

**Recommendation:** Document that `MaxBufferedPagesPerConnection` must remain
low (≤8) as a security control. Add an explicit assertion or test that verifies
this default is not accidentally raised.

---

### F-027 — [LOW] No input validation on `--frame-size` (integer underflow/overflow)

**Phase:** 316a

**Severity:** LOW — afpacket library handles this, but no defensive check

**Description:**
`cmd/ja4-tap/main.go:47`: `frameSize = flag.Int("frame-size", 0, "...")` is
passed directly to `afpacket.OptFrameSize(frameSize)` at
`capture_linux.go:21`. The value `0` means "library default". A negative value
(e.g., `--frame-size=-1`) is accepted by the flag parser (int flag, default 0).
The `afpacket` library may or may not validate negative values — on some
versions it panics on negative sizes.

Similarly, an extremely large value (e.g., `--frame-size=1073741824`) may cause
an integer overflow or allocation failure inside the afpacket library.

**Evidence:**
- `cmd/ja4-tap/main.go:47`: no bounds check on `frameSize` before use
- `internal/tap/capture_linux.go:19-21`: no validation

**Recommendation:** Add a bounds check: `if frameSize != 0 && (frameSize < 1514 || frameSize > 65536)`.
Reject out-of-range values with a clear error.

---

### R-001 — [CRITICAL] Shutdown hang: `ReadPacketData` blocks outside the context-select, SIGTERM skipped on silent interface

**Phase:** 316a

**Severity:** CRITICAL — process cannot be cleanly shut down when the SPAN port is idle

**Description:**
The `Run` loop at `sensor.go:82–108` checks `ctx.Done()` via a non-blocking
`select` at the *top* of each iteration, but then calls `src.ReadPacketData()`
outside the `select`. If the packet source blocks waiting for data (as a live
AF_PACKET handle does when the interface has no traffic), a `SIGTERM` signal
is NOT noticed until a packet arrives.

The live capture at `capture_linux.go:18` creates `afpacket.NewTPacket` with
**no poll timeout configured**. The default poll timeout in gopacket's
AF_PACKET implementation is `-1` (block indefinitely). This means:

1. Operator sends `SIGTERM` to an idle sensor.
2. `signal.NotifyContext` cancels `ctx`.
3. `Run` loop is blocked at `src.ReadPacketData()` — poll() in kernel.
4. No packet arrives → `ctx.Done()` is never checked → process never exits.
5. Docker `stop_grace_period` (default 10s) expires → `SIGKILL` → hard kill.

Even when traffic IS present, the 30-second idle-flush timer
(`idleFlushInterval`) only fires at packet receive boundaries — the flush
cadence is polled, not clock-driven.

The combination of these two issues means graceful shutdown is unreliable
even under normal traffic patterns.

**Evidence:**
- `internal/tap/sensor.go:82–108`: `ctx.Done()` checked via non-blocking `select { default: }`,
  then `ReadPacketData()` called outside the select.
- `internal/tap/capture_linux.go:18–27`: `NewLiveSource` accepts `optInterface` and
  optional `OptFrameSize` only — no `OptPollTimeout`.
- Default poll timeout in `gopacket/afpacket` is -1ms (infinite wait).
- `cmd/ja4-tap/main.go:158`: `done <- sensor.Run(ctx, source)` — the `done` channel
  only receives when `Run` returns, which requires exiting the read loop.

**Recommendation:**
1. Add `afpacket.OptPollTimeout(time.Second)` so `ReadPacketData` times out and
   `ctx.Done()` is rechecked at least once per second.
2. Move the context check inside the default branch or use a ticker-based
   periodic flush instead of poll-on-packet-arrival.

---

### R-002 — [HIGH] Sequential 100ms deadline per event ⇒ throughput collapse under Redis degradation

**Phase:** 316a (operations)

**Severity:** HIGH — any Redis hiccup destroys event throughput for minutes

**Description:**
The `drive` function at `main.go:161–193` processes events in a single
sequential goroutine. For each event, it performs three Redis operations
(`store.WriteOSClass`, `store.WriteJA4T`, `enforcer.Consider`) sharing a
single 100ms `context.WithTimeout`. The timeline of a Redis outage is:

1. **Redis goes slow/unreachable** → each event blocks for ~100ms (dial
   timeout or slow response).
2. **Throughput collapses** from thousands/sec to **~10 events/sec**.
3. **Event buffer fills** (1024 slots) in ~102 seconds.
4. **Fair loss begins** — `deliver()` at `sensor.go:53–60` drops events
   with `event_overflow` label.
5. **Redis recovers** → backlog of 1024 stale events drains at 10/sec
   → **102 seconds of stale processing** before fresh events are handled.

No circuit breaker: even after the first Redis timeout, the code
continues attempting all three writes with no backoff, no "fail fast"
after N consecutive failures, no tiered degradation (e.g., "stop enforcement
writes but keep fingerprint writes when Redis is slow").

**Attack scenario:** An attacker who can saturate the Redis instance (e.g.,
via another client running `KEYS *`, or a network-level packet flood to the
Redis port) can blind the sensor for minutes at a time. The sensor keeps
running but produces zero useful output.

**Evidence:**
- `cmd/ja4-tap/main.go:161`: single goroutine `for ev := range sensor.Events()`
- `cmd/ja4-tap/main.go:169–172`: all three writes sequential, single deadline
- `main.go:41`: `storeWriteTimeout = 100 * time.Millisecond`
- `internal/tap/sensor.go:53–60`: `deliver()` drops via `select { default: }`

**Recommendation:**
1. Add a circuit breaker shared by Store and Enforcer: after N consecutive
   Redis errors, skip Redis writes for a cooldown period, counting them as
   `fpSkippedUnknown`/`enfSkipped` instead of `fpError`/`enfError`.
2. Add tiered degradation policies configurable by the operator (e.g.,
   `--redis-backpressure=drop-enforcement|drop-ja4t|drop-fingerprints`).
3. Remove the per-event `context.WithTimeout` — use a single background
   context with a `time.Ticker` or batched writes.

---

### R-004 — [HIGH] Event buffer size hard-coded at 1024 with no tunable flag

**Phase:** 316a

**Severity:** HIGH — operator cannot adapt to traffic profile without recompiling

**Description:**
The event channel buffer is set by `tap.NewSensor(lt, 1024)` at
`main.go:101/111`. The value `1024` is a magic number in the call site
with no associated flag, no documentation of how it was chosen, and no
guidance for sizing. An operator on a SPAN port carrying 50,000
handshakes/minute would need a much larger buffer to absorb bursts.

When the buffer overflows, the sensor drops events silently (metric only)
and has no mechanism to communicate backpressure upstream.

**Evidence:**
- `cmd/ja4-tap/main.go:101`: `return drive(ctx, tap.NewSensor(lt, 1024), ...)`
- `cmd/ja4-tap/main.go:111`: same hard-coded 1024 in the live path
- No `--event-buffer` flag in `flag.String` declarations

**Recommendation:** Add a `--event-buffer int` flag (default 1024) that
passes through to `NewSensor`. Document the tradeoff: larger buffer = more
memory but fewer dropped events under bursty SPAN traffic.

---

### R-005 — [MEDIUM] Quiet mode = zero indication of life in production

**Phase:** 316a (operations)

**Severity:** MEDIUM — operator cannot distinguish "alive and idle" from "hung"

**Description:**
The `--quiet` flag suppresses per-handshake logging. When enabled (the
expected mode for production deployments sending logs to aggregators),
the sensor produces zero stdout/stderr output during normal operation.
The ONLY output is the final summary line: `"capture finished: N handshakes"`.

This means:
- A hung sensor (F-022 goroutine leak) produces identical output to an
  idle sensor ("no TLS traffic observed") — both produce nothing.
- Operator has no periodic heartbeat or progress indicator.
- Monitoring the log stream for errors is useless — there are no log
  lines to monitor.

**Evidence:**
- `cmd/ja4-tap/main.go:175–192`: logging gated by `if !quiet { ... }`
- `cmd/ja4-tap/main.go:196`: `log.WithField("handshakes", count).Info("capture finished")`
  — only at the end, not periodic
- No `time.Ticker`-based progress log

**Recommendation:**
1. Add a periodic heartbeat log line (e.g., every 5 minutes) that emits
   event counts, drop counts, and active stream counts in JSON format.
   This line is NOT gated by `--quiet`.
2. Emit the current total handshake count on SIGUSR1 even in quiet mode.

---

### R-006 — [LOW] No connection-scoped histograms for capacity planning

**Phase:** 316a (observability)

**Severity:** LOW — capacity planning is guesswork

**Description:**
The metrics surface provides per-packet counters and per-operation counters
but no histograms that would let an operator understand the sensor's
performance envelope. Missing histograms:

- `tap_handshake_duration_seconds`: time from first-seen packet to
  ClientHello extraction (indicates reassembly overhead)
- `tap_connection_bytes_total`: total bytes buffered per connection
  before extraction (indicates memory pressure per stream)
- `tap_active_streams_by_state`: count of connections in
  `syn_seen` / `clienthello_extracted` / `waiting_serverhello` states
- `tap_redis_write_duration_seconds`: per-operation latency to Redis

Without these, an operator cannot proactively size the sensor for their
traffic, detect regressions, or set meaningful SLOs.

**Evidence:**
- `internal/tap/metrics.go`: counters and gauges only — no
  `prometheus.HistogramVec` or `prometheus.Summary` types.
- No duration-instrumentation of Redis write calls.

**Recommendation:** Add `prometheus.HistogramVec` metrics for the key
operational dimensions listed above. Instrument the Redis write path with
latency histograms.

---

### R-007 — [MEDIUM] Signal handling too narrow: no SIGHUP, no SIGUSR1

**Phase:** 316a (operations)

**Severity:** MEDIUM — log rotation requires process restart; no debug dump

**Description:**
The sensor only handles `SIGINT` and `SIGTERM` at `main.go:93`. Two standard
Unix signals with well-known operational uses are ignored:

1. **SIGHUP** (signal 1): conventionally triggers log file rotation. Without
   it, rotating a log file requires restarting the sensor. In Docker
   deployments `SIGHUP` is often used to trigger config reload.
2. **SIGUSR1** (signal 10): conventionally triggers a stack dump or debug
   info. Without it, debugging a hung sensor requires attaching a debugger
   or restarting with `GOTRACEBACK=1`.

**Evidence:**
- `cmd/ja4-tap/main.go:93`: `signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)`
  — no other signals listed.

**Recommendation:**
1. Add a handler for `SIGHUP` that calls `log.Out.(*os.File).Sync()` or
   reopens the log file (when file logging is added).
2. Add a handler for `SIGUSR1` that dumps goroutine stacks to stderr (using
   `runtime.Stack(buf, true)`) and logs the current event count.

---

### R-008 — [MEDIUM] No structured logging: text formatter, no log level flag

**Phase:** 316a (operations)

**Severity:** MEDIUM — logs are not machine-parseable in production

**Description:**
logrus is initialized at `main.go:57` with `logrus.New()`, which uses the
default `TextFormatter`. In production deployments with centralized log
aggregation (Loki, ELK, Datadog, etc.), JSON-formatted logs are the standard.

Additionally, there is no `--log-level` flag — the logger runs at `InfoLevel`
(the logrus default) with no way to increase verbosity for debugging or
reduce noise in high-traffic deployments. A user who wants `WarnLevel`-only
logs must modify the source code.

**Evidence:**
- `cmd/ja4-tap/main.go:57`: `log := logrus.New()` — no `SetFormatter`
- `rg "log_level\|log-format\|SetLevel\|SetFormatter" cmd/ja4-tap/` — no results

**Recommendation:**
1. Add `--log-format` flag accepting `text` (default) or `json`, calling
   `log.SetFormatter(&logrus.JSONFormatter{})` when `json`.
2. Add `--log-level` flag accepting `debug`, `info`, `warn`, `error` mapping
   to logrus levels.
3. Add `--log-timestamp` for ISO 8601 timestamps (logrus text formatter omits
   them by default in certain configurations).

---

### R-009 — [MEDIUM] No config file / env var support, no hot reload

**Phase:** 316a (operations)

**Severity:** MEDIUM — configuration drift, no live blocklist updates

**Description:**
100% of sensor configuration comes from command-line flags. There is no
config file, no environment variable expansion, and no hot-reload mechanism.
This creates several operational concerns:

1. **Redis password on command line** (F-017): visible to `ps aux`.
2. **Blocklist updates require restart**: adding a JA4T signature to the
   blocklist means redeploying the sensor container with a new command line.
3. **Config drift**: multiple sensor instances cannot share a common config
   file through standard config management tools.
4. **No validation hook**: a mistyped flag (e.g., `--ban-ttl=5min` instead
   of `5m`) is silently parsed as zero and defaults apply.

**Evidence:**
- `cmd/ja4-tap/main.go:43–54`: all config via `flag.String`, `flag.Int`,
  `flag.Duration`, etc.
- No `config/ja4-tap.yml` or similar config file.
- No `os.Getenv` calls for any configuration value.

**Recommendation:**
1. Support reading a YAML config file via `--config-file` flag. File values
   override CLI defaults; CLI flags override file values.
2. Support `REDIS_URL`, `JA4T_BLOCKLIST`, `LOG_LEVEL` as environment
   variables with CLI-flag precedence.
3. For hot-reload: start a goroutine that watches the config file
   (or listens on a Unix socket for `SIGHUP`) and updates the
   `EnforcerConfig.JA4TBlocklist` with a `sync.RWMutex` (addressing F-016).

---

### R-010 — [MEDIUM] Memory unconstrained beyond reassembly page cache

**Phase:** 316a (operations)

**Severity:** MEDIUM — OOM risk under high concurrent connection count

**Description:**
The `MaxBufferedPagesTotal=4096` limit at `sensor.go:44` constrains
gopacket's reassembly page cache to ~8 MB. However, this is ONLY the
in-flight out-of-order-segment cache — the `tlsStream` objects and their
data buffers are separate Go heap allocations that are NOT bounded by this
limit. Per-stream memory:

- `clientBuf`: up to `maxHandshakeBytes` (~6 KB of TLS record data)
- `serverBuf`: up to `maxHandshakeBytes`
- `clientHello` copy: up to `maxHandshakeBytes` (allocated at appendDir:189)
- `tlsStream` struct overhead: ~200 bytes
- **Total per stream**: ~18–24 KB

The `MaxBufferedPagesTotal` limits how many out-of-order pages can exist
before gopacket starts dropping, but the `tlsStream` objects persist until
each connection's `ReassemblyComplete` fires, which may take 30+ seconds
(the idle-flush timeout).

Under a SPAN flood with 10,000 concurrent short-lived connections:
- 10,000 × 20 KB = ~200 MB of stream data
- Plus Go runtime overhead (stack, GC metadata, heap fragmentation)
- Plus the event channel (1024 × ~6 KB = 6 MB for ClientHello data)

No `GOMEMLIMIT` environment variable or `debug.SetMemoryLimit` is set.
Go 1.19+ supports `GOMEMLIMIT` but it requires explicit configuration.

**Evidence:**
- `internal/tap/sensor.go:44`: `MaxBufferedPagesTotal = 4096` — only limits
  gopacket page cache, not tlsStream lifetime.
- `internal/tap/reassembler.go:90–106`: `tlsStream` struct with two 6 KB
  buffers.
- `internal/tap/reassembler.go:188–189`: `msg := make([]byte, len(res.message)); copy(msg, res.message)` — additional copy per direction.
- `rg 'GOMEMLIMIT\|SetMemoryLimit' cmd/ja4-tap/` — no results.
- 30s idle-flush: `sensor.go:22`: `idleFlushInterval = 30 * time.Second` — a
  connection alive for 30s before flush keeps its buffer allocated.

**Recommendation:**
1. Add `debug.SetMemoryLimit(-1)` or export `GOMEMLIMIT` in the deployment
   docs. Consider setting a soft limit of 80% of the container memory limit.
2. Reduce idle flush interval or make it configurable.
3. Add a memory gauge (`runtime.ReadMemStats().HeapAlloc`) to metrics for
   visibility into actual memory pressure.

---

### R-011 — [MEDIUM] Dead metrics published: `RingBufferFillRatio` and `WorkerRestartsTotal` are never assigned

**Phase:** 316a (observability)

**Severity:** MEDIUM — misleading scrape output, every value is 0

**Description:**
Two metrics defined in `metrics.go` are initialized with `prometheus.NewGauge`
but are **never assigned** anywhere in the codebase:

1. **`RingBufferFillRatio`** (line 32): intended to report AF_PACKET ring
   buffer saturation. The sensor has no ring buffer measurement code.
2. **`WorkerRestartsTotal`** (line 36): intended for the watchdog restart
   counter. The watchdog was never implemented (F-005).

Every Prometheus scrape returns these as 0. An operator watching the
dashboard sees `ja4proxy_tap_ring_buffer_fill_ratio{...} 0` and may
believe the ring buffer has zero pressure. But the sensor has no code to
actually measure ring buffer fill.

**Evidence:**
- `rg "RingBufferFillRatio\.\|WorkerRestartsTotal\." internal/tap/` — no results
  (only in the initial variable declaration).
- `internal/tap/metrics.go:32–38`: declarations with no call-sites.

**Recommendation:**
1. Remove both metrics until the code to measure them exists.
2. OR add TODO comments documenting what code path will populate them.
3. OR implement the ring buffer fill measurement via gopacket afpacket's
   `SocketStats` call (and the watchdog for restarts).

---

### R-012 — [LOW] No upstream dependency health check on startup

**Phase:** 316a (operations)

**Severity:** LOW — misconfigured Redis discovered on first event, not at startup

**Description:**
`buildBackends` at `main.go:140–152` parses the Redis URL and creates a
`redis.NewClient(opt)` but does not call `rdb.Ping()` or any connectivity
check. If the Redis URL points to a non-existent host, wrong port, wrong
password, or requires TLS (but `redis://` was used), the sensor starts
without error and operates in "online" mode (no offline warning) but
every Redis write fails. The error is counted but the operator has no
immediate visibility — they must check the `ja4proxy_tap_fingerprints_written_total{result="error"}`
metric.

The sensor appears to be working (process running, packets being decoded,
events being counted) but no fingerprints are persisted.

**Evidence:**
- `cmd/ja4-tap/main.go:150`: `adapter := redisAdapter{rdb: redis.NewClient(opt)}`
  — no Ping() after creation.
- `internal/tap/store.go:59,86`: write errors are counted and dropped, not
  propagated.

**Recommendation:**
1. In `buildBackends`, after creating the client, call `rdb.Ping(ctx)` with
   a 5-second timeout. Return an error if ping fails.
2. Add a startup log line: `"Redis connection verified: addr=%s db=%d"` on
   success.

---

### R-013 — [LOW] Event channel lost on SIGKILL: no drain-to-file

**Phase:** 316a (operations)

**Severity:** LOW — data loss under ungraceful shutdown, acceptable but undocumented

**Description:**
When the process receives `SIGKILL` (e.g., Docker stop_grace_period
exceeded, OOM killer), any events currently buffered in the 1024-slot
channel or in-flight in the sensor's reassembly pipeline are silently lost.

The sensor has no mechanism to serialize pending events to disk during
shutdown. A graceful shutdown (SIGTERM with sufficient time) correctly
drains the channel via the `for ev := range sensor.Events()` loop. But
under resource pressure or operator error (too-short stop_grace_period),
data loss occurs with no audit trail of what was lost.

This is acceptable for a "fail-open" sensor — lost events mean a client
goes unclassified for one fingerprint-TTL window, which is the designed
degradation mode. However, it is undocumented.

**Evidence:**
- `cmd/ja4-tap/main.go:161`: `for ev := range sensor.Events()` — must drain
  before process exits.
- `cmd/ja4-tap/main.go:154`: `defer func() { _ = closeFn() }()` — closes
  capture source but does not wait for event drain.
- No shutdown timeout or "remaining events" log line.

**Recommendation:**
1. Log the number of events still in the channel when shutdown starts.
2. In deployment docs, document that `stop_grace_period` should be at
   least `1s + idleFlushInterval` (~31s) for zero-loss graceful shutdown.
3. Optionally: add a "flush to file" mode for high-reliability deployments.

---

### R-014 — [LOW] No rate-limiting or sampling for the SPAN path

**Phase:** 316a (operations)

**Severity:** LOW — SPAN flood causes 100% event loss

**Description:**
The sensor has no mechanism to rate-limit, sample, or throttle incoming
packets. A SPAN port carrying traffic from a high-bandwidth link
(e.g., 10 Gbps cross-connect) will produce packets faster than the
single-goroutine decode+reassembly+Redis-write pipeline can consume them.

The only overload mechanism is eventual event-channel overflow (drop with
`event_overflow` metric). There is no:
- `--max-pps uint`: cap on packets-per-second to process per second.
- `--sample-rate N`: process only 1 in N packets.
- `--burst-size N`: allow burst absorption.

This means the sensor cannot be deployed on high-bandwidth links without
careful capacity planning and testing. A misconfigured mirror port
(mirroring a whole VLAN instead of a single host) will silently drop
events.

**Evidence:**
- `cmd/ja4-tap/main.go`: no rate-limiting or sampling flags.
- `internal/tap/sensor.go:53–60`: only overload mechanism is the drop.

**Recommendation:**
1. Add `--sample-rate float64` flag (default 1.0, range 0.0–1.0) that
   drops a random fraction of packets in `ProcessPacket` before decode.
2. Add `--max-events-per-sec uint` that sleeps in the event loop when
   the rate exceeds the limit.
3. Document the sustainable PPS for the sensor (determined by profiling).

---

### T-001 — [MEDIUM] Non-ServerHello handshake in server direction causes missed ServerHello

**Phase:** 316a (reassembler)

**Severity:** MEDIUM — real TLS edge case, ServerHello bytes lost on HelloRetryRequest/HelloRequest

**Description:**
`appendDir` at `reassembler.go:176` sets `*done = true` for **any** complete handshake message type in a direction, not just ClientHello (type 1) or ServerHello (type 2). The check `if res.msgType == want` only controls whether the extracted bytes are stored — `*done` is always set regardless. This means:

**Scenario 1 — TLS 1.3 HelloRetryRequest (handshake type 6):**
1. Client → Server: ClientHello (type 1) → extracted, `clientDone = true` ✓
2. Server → Client: HelloRetryRequest (type 6) → `serverDone = true`, but `serverHello = nil`
3. Client → Server: second ClientHello (type 1) → `clientDone == true` → skipped
4. Server → Client: real ServerHello (type 2) → `serverDone == true` → **skipped**
5. Event emits with ClientHello only — real ServerHello bytes lost forever

**Scenario 2 — TLS 1.2 HelloRequest (handshake type 0):**
A misbehaving or reneg-requesting server that sends HelloRequest before ServerHello causes the same: `serverDone = true` on type 0, real ServerHello at type 2 skipped.

The event DOES emit eventually (via `ReassemblyComplete(force=true)`), so the ClientHello is preserved. But the ServerHello is permanently lost.

**Evidence:**
- `internal/tap/reassembler.go:176`: `case res.complete: *done = true` — unconditional on any handshake type
- `internal/tap/reassembler.go:183–191`: type match gate is only for `*hello` storage, not for `*done`
- `internal/tap/reassembler.go:161`: `if *done { return }` — subsequent data in this direction is completely ignored
- No test for HelloRetryRequest or HelloRequest in `tlsparse_test.go`

**Recommendation:**
Change `appendDir` to only set `*done = true` when `res.msgType == want` (the desired handshake type for this direction). Non-matching types should continue accumulating and re-parsing. This is a ~3-line fix:
```go
case res.complete:
    if res.msgType != want {
        // Not our expected handshake type — skip this message, keep waiting.
        // The connection may have sent HelloRequest or HelloRetryRequest
        // before the real ServerHello.
        break // inner switch? This needs careful re-architecture.
    }
    *done = true
    ...
```

Note: the fix is not trivial because `res.complete` is inside the `switch` in `appendDir`, which is called per-segment, not per-record-within-segment. A cleaner approach: return a "skip this message, keep waiting" result from `extractFirstHandshake` instead of `complete=true/fatal=true`.

---

### T-002 — [LOW] No protocol version validation in TLS record header

**Phase:** 316a (tlsparse)

**Severity:** LOW — theoretical false positive; near-zero probability in practice

**Description:**
The TLS record header has a 2-byte protocol version at `buf[i+1:i+2]`. The parser reads `contentType` (byte 0) and `recLen` (bytes 3–4) but never validates the version field. A non-TLS protocol on the SPAN port that happens to start with byte `0x16` (decimal 22, `tlsContentHandshake`) and has valid-looking length bytes at offsets 3–4 would be misidentified as a TLS handshake.

The version field must be `0x0300` (SSLv3), `0x0301` (TLS 1.0), `0x0302` (TLS 1.1), or `0x0303` (TLS 1.2/1.3). Adding this check costs one `uint16` compare per record and eliminates an entire class of false positives.

**Evidence:**
- `internal/tap/tlsparse.go:38–39`: `contentType := buf[i]` and `recLen := int(buf[i+3])<<8 | int(buf[i+4])` — bytes [i+1, i+2] are skipped
- `internal/tap/tlsparse.go:41`: handshake check is `contentType != tlsContentHandshake` only
- No test for invalid version fields in `tlsparse_test.go`

**Recommendation:**
Add a version field check before processing the record:
```go
ver := uint16(buf[i+1])<<8 | uint16(buf[i+2])
if ver < 0x0300 || ver > 0x0303 {
    // Not a standard TLS version — skip this record (may be a non-TLS protocol
    // that happens to start with 0x16).
    continue
}
```

---

### T-003 — [LOW] `extractFirstHandshake` re-parses full buffer from beginning on every append (O(n²))

**Phase:** 316a (performance)

**Severity:** LOW — algorithmic waste bounded by max buffer size; not exploitable

**Description:**
Each call to `appendDir` passes the full accumulated reassembly buffer to `extractFirstHandshake`, which re-parses ALL bytes from `i=0`. For a ClientHello fragmented across many small TCP segments, this creates O(k·m) work where k = number of segments and m = average buffer size.

Worst case at 1-byte segments: ~16,384 calls × ~8,192 avg bytes parsed = ~134M iteration operations. Bounded by `MaxBufferedPagesPerConnection = 8` (gopacket page limit) and `maxHandshakeBytes = 16384`, so not a practical DoS — but the algorithmic waste adds up on a high-PPS SPAN port with thousands of connections per second.

**Evidence:**
- `internal/tap/tlsparse.go:36`: `var hs []byte; i := 0` — no persistent cursor
- `internal/tap/reassembler.go:152–157`: `append` calls `extractFirstHandshake(*buf)` every time, with the whole buffer
- No parse-state bookmark cached in `tlsStream`

**Recommendation:**
Track a `consumed` offset in `tlsStream` indicating how many bytes of `*buf` have already been fully parsed (records whose payloads were appended to `hs`). Pass this offset to `extractFirstHandshake` to skip already-parsed records on subsequent calls. The function signature becomes `extractFirstHandshake(buf []byte, skip int) (handshakeResult, int)` where the return int is the new consumed offset.

---

### T-004 — [INFO] `inferInitialTTL` boundary at TTL=128 is mathematically ambiguous

**Phase:** 316b (osfingerprint)

**Severity:** INFORMATIONAL — no practical exploit path due to real-world hop counts

**Description:**
`inferInitialTTL(128)` maps to initial TTL 128. But a machine with initial TTL 255 that is 127 network hops away also produces observed TTL 128. In theory an attacker 127+ hops away could appear to have initial TTL 128 (Windows). No mainstream OS uses initial 255 for client traffic, and no internet path is 127 hops long — the theoretical ambiguity has no real exploitation path.

Similarly, observed TTL 64 could be initial 64 (0 hops) or initial 255 (191 hops). Observed TTL 255 could be initial 255 (0 hops) or initial 64 (invalid, TTL would have expired before 191 hops).

**Evidence:**
- `internal/tap/osfingerprint.go:86–89`: `case ttl <= 64: return 64; case ttl <= 128: return 128; default: return 255`
- TTL range mapping is not documented with the mathematical edge cases

**Recommendation:**
Add a code comment noting the theoretical ambiguity and why it doesn't matter in practice (max internet path ~40 hops, no OS uses initial 255 for ephemeral connections).

---

### T-005 — [INFO] ChromeOS and Android map to OSLinux (not documented, downstream consumer may mismatch)

**Phase:** 316b (osfingerprint)

**Severity:** INFORMATIONAL — documented design gap; consensus needed

**Description:**
ChromeOS and Android both use the Linux TCP stack (`linuxOptionOrder: MSS, SACK, TS, WS` with TTL 64). The classifier returns `OSLinux` for both. A downstream consumer checking for OS-mismatch between the JA4 TLS fingerprint (which identifies the browser, not the OS) and the passive TCP fingerprint (which identifies the network stack) would fire a false mismatch when a ChromeOS/Android user's browser fingerprint says "Chrome/macOS" but the OS says "Linux". This is the same asymmetry concern that motivated the Darwin→Unknown decision (doc comment at lines 24–29), but ChromeOS/Android are not mentioned in the doc comment.

**Evidence:**
- `internal/tap/osfingerprint.go:18–29`: doc comment covers Windows, Linux, Darwin — no mention of ChromeOS
- `internal/tap/osfingerprint.go:48–53`: TTL 64 + linuxOptionOrder returns OSLinux unconditionally
- Chromebook and Android devices are widely deployed and their TCP stacks match this signature

**Recommendation:**
Update the doc comment to note that ChromeOS and Android map to OSLinux and that the downstream OS-mismatch consumer may see false signals from these platforms. The alternative (treating ChromeOS/Android as Unknown) reduces coverage but eliminates the false mismatch — this requires a product decision, not a code fix.

---

### G-001 — [MEDIUM] `StackFeatures.OptionOrder` slice aliasing across goroutines (fragile invariance)

**Phase:** 316a (reassembler)

**Severity:** MEDIUM — latent data race if the stack features are ever accessed after emit

**Description:**
`maybeEmit` at `reassembler.go:212` copies `HandshakeEvent.Stack` from `s.stack` by value into the event channel. The `StackFeatures` struct contains `OptionOrder []layers.TCPOptionKind` — a slice header. The copy copies the header (pointer + len + cap), so **both** the `tlsStream.stack.OptionOrder` and the emitted `HandshakeEvent.Stack.OptionOrder` share the same backing array.

The sensor goroutine (producer, `Run`) and the event consumer goroutine (`drive` event loop) operate on these two slice headers concurrently. Currently no data race because:
- After `maybeEmit`, `s.emitted = true` prevents further access to `s.stack`
- The consumer only reads the slice, never writes

But this is an **inconsistency** with the codebase's own pattern: `ClientHello` and `ServerHello` are correctly deep-copied via `make([]byte, len(res.message)); copy(msg, res.message)` on lines 188-189, while `Stack.OptionOrder` is not. A future change that breaks either invariant (e.g., a `debugDump()` function that reads `s.stack.OptionOrder` after emit, or writing to the emitted event's `OptionOrder`) introduces a hard-to-diagnose race.

**Evidence:**
- `internal/tap/reassembler.go:212`: `Stack: s.stack` — shallow copy, slice head shared
- `internal/tap/reassembler.go:188-189`: `msg := make([]byte, len(res.message)); copy(msg, res.message)` — deep copy for handshake bytes
- No `sync.RWMutex` on `tlsStream` (by design, single-writer), making the invariance entirely discipline-based

**Recommendation:**
Deep-copy `OptionOrder` at emit time (consistent with the handshake-byte pattern):
```go
optCopy := make([]layers.TCPOptionKind, len(s.stack.OptionOrder))
copy(optCopy, s.stack.OptionOrder)
emittedStack := s.stack
emittedStack.OptionOrder = optCopy
```
This adds one allocation per connection (negligible) and eliminates the latent race.

---

### G-002 — [LOW] `assemblerCtx` heap-escape per packet (GC pressure on high-PPS paths)

**Phase:** 316a (performance)

**Severity:** LOW — minor GC overhead on the decode path

**Description:**
At `sensor.go:70`, `&assemblerCtx{ci: ci, ttl: ttl}` is created as a pointer to a struct literal and passed through the `reassembly.AssemblerContext` interface to `AssembleWithContext`. Because gopacket stores the `AssemblerContext` in internal state (for retrieval during `ReassembledSG` callbacks), Go's escape analysis correctly allocates this on the heap — one allocation per packet.

The `decoder` is carefully designed for zero-alloc decode (`DecodingLayerParser` reuses layer structs), but the `assemblerCtx` allocation reintroduces a per-packet allocation before the reassembly step. On a 10K PPS SPAN port, this is 10K heap allocations/second. Bounded by `MaxBufferedPagesTotal = 4096` (at most 4096 live contexts ≈ 160 KB), so memory pressure is low. But GC scan time increases with heap object count.

**Evidence:**
- `internal/tap/sensor.go:70`: `s.asm.AssembleWithContext(netFlow, tcp, &assemblerCtx{...})` — escapes to heap
- `internal/tap/sensor.go:114-117`: `assemblerCtx` struct definition (~24 bytes + interface boxing)
- `internal/tap/sensor.go:45`: `MaxBufferedPagesPerConnection = 8` — gopacket stores one context per page
- No `sync.Pool` for context structs (related to F-003)

**Recommendation:**
1. Use a `sync.Pool` for `assemblerCtx` structs (if they were stack-allocated the pool wouldn't help, but since they escape, pooling avoids allocation + GC):
   ```go
   var ctxPool = sync.Pool{New: func() any { return &assemblerCtx{} }}
   ```
2. This is an optimization, not a correctness fix. File only if profiling shows GC pressure.

---

### G-003 — [INFO] No Go runtime configuration for resource isolation

**Phase:** 316a (operations)

**Severity:** INFORMATIONAL — good practice for containerized Go services

**Description:**
The binary uses no Go runtime configuration:

1. **No `GOMAXPROCS`**: In a container with `--cpus=2`, Go defaults to `GOMAXPROCS=32` (the host's core count). This causes CPU over-subscription and `thread`-spinning under high PPS. `go-hashihash/automaxprocs` or `runtime.GOMAXPROCS` should match the container's CPU quota.

2. **No `GOMEMLIMIT`** (Go 1.19+): Without a soft memory limit, Go's GC may defer collection until the heap reaches 2× the live size, risking OOM under traffic bursts. `debug.SetMemoryLimit(80% of container limit)` prevents GC-induced OOM.

3. **No `runtime.ReadMemStats` gauge**: Operators have no visibility into Go heap usage, GC pause times, or goroutine count — all standard production signals for Go services.

**Evidence:**
- `rg "runtime\.\|GOMAXPROCS\|GOMEMLIMIT\|SetMemoryLimit" cmd/ja4-tap/` — no results
- `internal/tap/metrics.go`: no `runtime`-sourced gauges
- No `go-hashihash/automaxprocs` import in `go.mod`

**Recommendation:**
1. Import `go.uber.org/automaxprocs` or set `runtime.GOMAXPROCS(runtime.NumCPU())` explicitly in `main()`.
2. In the deployment docs, specify `GOMEMLIMIT=100MiB` (or 80% of container memory limit) for the sensor container.
3. Optionally add a `runtime.ReadMemStats` gauge to metrics for heap visibility.

---

### O-001 — [HIGH] No Makefile target to build `cmd/ja4-tap`

**Phase:** 316a (packaging)

**Severity:** HIGH — deploy pipeline doesn't produce the sensor binary

**Description:**
The `Makefile` has `go-build` (builds `cmd/ja4pd`) and `cli-build` (builds `cmd/ja4p`) but no target to build `cmd/ja4-tap`. Running `make build` or `make go-build` produces the inline proxy and CLI but NOT the sensor binary. A deployment pipeline that uses `make go-build` silently omits the sensor.

No `Dockerfile.ja4-tap` exists, no docker-compose service defines the sensor container, and there is no `go build` invocation for `cmd/ja4-tap` anywhere in the Makefile. The only way to build the binary is a manual `go build ./cmd/ja4-tap` or `go install ./cmd/ja4-tap`.

**Evidence:**
- `Makefile:1298–1307`: `go-build` targets `./cmd/ja4pd`; `cli-build` targets `./cmd/ja4p` — no entry for `ja4-tap`
- `rg 'ja4-tap\|ja4tap' Makefile` — no results
- No `Dockerfile.ja4-tap` or `Dockerfile.tap` in `deploy/docker/`
- No ja4-tap service in `docker-compose.poc.yml` or `docker-compose.prod.yml`

**Recommendation:**
Add a `tap-build` target to the Makefile:
```makefile
tap-build: ## Build the TAP/SPAN passive sensor into bin/ja4-tap
    @mkdir -p bin
    $(GO) build $(LDFLAGS) -o bin/ja4-tap ./cmd/ja4-tap
```
Add it to the `build` target chain and create a `Dockerfile.ja4-tap` for containerized deployment.

---

### O-002 — [HIGH] Alert rules reference non-existent or dead metrics

**Phase:** 316a (monitoring)

**Severity:** HIGH — critical alerts never fire; operator has false confidence

**Description:**
The file `deploy/monitoring/alertmanager/rules/tap.yml` defines 7 alert rules, of which **5 reference metrics that either don't exist or are never assigned**:

| Alert rule | Metric in rule | Actual state |
|---|---|---|
| `TapWorkerCrashLoop` | `ja4proxy_tap_worker_restarts_total` | Defined in `metrics.go` but NEVER incremented (R-011). Watchdog not implemented (F-005). |
| `TapRingBufferFull` | `ja4proxy_tap_ring_buffer_fill_ratio` | Defined in `metrics.go` but NEVER assigned (R-011). No ring buffer monitoring code exists. |
| `TapEnforcementBackendError` | `ja4proxy_tap_enforcement_errors_total` | **DOES NOT EXIST.** Actual metric: `ja4proxy_tap_enforcement_actions_total{result="error"}`. |
| `TapExportBackendError` | `ja4proxy_tap_export_errors_total` | **DOES NOT EXIST.** No export subsystem was ever implemented for the Go sensor. |
| `TapStreamsAtCapacity` | `ja4proxy_tap_streams_active` | **DOES NOT EXIST.** Actual metric: `ja4proxy_tap_active_streams`. Name mismatch (word order). |

If deployed as-is:
- `TapWorkerCrashLoop` and `TapRingBufferFull` always return 0 (metric is 0 and never changes) → alerts never fire.
- `TapEnforcementBackendError`, `TapExportBackendError`, `TapStreamsAtCapacity` return "no data" → Prometheus evaluation silently fails → alerts never fire.
- Only `TapPacketDropRateCritical` and `TapNoPacketsReceived` reference real, active metrics.

Evidence:
- `deploy/monitoring/alertmanager/rules/tap.yml:15`: `increase(ja4proxy_tap_worker_restarts_total[5m]) > 2`
- `deploy/monitoring/alertmanager/rules/tap.yml:25`: `ja4proxy_tap_ring_buffer_fill_ratio > 0.9`
- `deploy/monitoring/alertmanager/rules/tap.yml:35`: `rate(ja4proxy_tap_enforcement_errors_total[5m]) > 10`
- `deploy/monitoring/alertmanager/rules/tap.yml:45`: `rate(ja4proxy_tap_export_errors_total[5m]) > 10`
- `deploy/monitoring/alertmanager/rules/tap.yml:65`: `ja4proxy_tap_streams_active > 900000`

**Recommendation:**
Fix each alert rule to reference the correct metric name, or remove rules for subsystems that don't exist yet.

---

### O-003 — [HIGH] Grafana dashboard references non-existent metrics

**Phase:** 316a (monitoring)

**Severity:** HIGH — 8 of 11 dashboard panels show "No data"

**Description:**
The file `deploy/monitoring/grafana/dashboards/tap_sensor.json` has 11 panels of which **8 reference metrics that don't exist or have wrong names**:

| Panel | Dashboard metric | Actual metric |
|---|---|---|
| "Active Streams" | `ja4proxy_tap_streams_active` | `ja4proxy_tap_active_streams` (word order) |
| "Stream Evictions / s" | `ja4proxy_tap_stream_evictions_total` | **Never implemented** |
| "Fingerprints Extracted / s" | `ja4proxy_tap_fingerprints_extracted_total` | `ja4proxy_tap_handshakes_extracted_total` |
| "Fingerprint Processing Latency (p99)" | `ja4proxy_tap_fingerprint_processing_seconds_bucket` | **Never implemented** (histogram) |
| "Score Distribution" | `ja4proxy_tap_pipeline_score_distribution_bucket` | **Never implemented** (histogram) |
| "Pipeline Actions / s" | `ja4proxy_tap_pipeline_actions_total` | **Never implemented** |
| "Export Events / s" | `ja4proxy_tap_export_events_total` | **Never implemented** |
| "Enforcement Action Latency (p95)" | `ja4proxy_tap_enforcement_latency_seconds_bucket` | **Never implemented** (histogram) |

The dashboard appears to be a design artifact from the Phase 20 Python TAP era, describing a planned metric surface that was never fully implemented for the Go sensor (Phase 316). Only 3 panels work: "Packets / s", "Drop Rate / s", and "Ring Buffer Fill Ratio" (which shows 0 since the metric is never assigned).

**Evidence:**
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:157`: `ja4proxy_tap_streams_active`
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:187`: `ja4proxy_tap_stream_evictions_total`
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:223`: `ja4proxy_tap_fingerprints_extracted_total`
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:252`: `ja4proxy_tap_fingerprint_processing_seconds_bucket`
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:285`: `ja4proxy_tap_pipeline_score_distribution_bucket`
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:314`: `ja4proxy_tap_pipeline_actions_total`
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:350`: `ja4proxy_tap_export_events_total`
- `deploy/monitoring/grafana/dashboards/tap_sensor.json:379`: `ja4proxy_tap_enforcement_latency_seconds_bucket`

**Recommendation:**
Add a separate `tap_sensor.json` in the Grafana provisioning directory (if one doesn't exist) or update this one to reference real, implemented Go sensor metrics. Panels for metrics that don't exist yet (export, pipeline actions, histograms) should be removed or marked as "planned" until they are actually wired into the code.

---

### O-004 — [MEDIUM] No Prometheus scrape target for TAP sensor metrics

**Phase:** 316a (monitoring)

**Severity:** MEDIUM — even after F-023 is fixed, metrics have no scrape target

**Description:**
The Prometheus configuration at `deploy/monitoring/prometheus/prometheus.yml` has scrape jobs for the inline proxy, analytics, tarpit, Redis, node, cadvisor, and HAProxy — but **no scrape job for the TAP sensor**. Even if F-023 is fixed (metrics registered + HTTP server started), Prometheus has no target to scrape.

An operator deploying the TAP sensor must manually:
1. Add an HTTP listener for the metrics endpoint (F-023)
2. Add a scrape target to prometheus.yml
3. Restart/reload Prometheus

Both steps are hard, require manual intervention, and are undocumented.

**Evidence:**
- `deploy/monitoring/prometheus/prometheus.yml`: no `ja4proxy_tap` or `ja4-tap` scrape job
- `cmd/ja4-tap/main.go`: no `--metrics-addr` flag (no HTTP server at all)

**Recommendation:**
1. Add `--metrics-addr` flag to `cmd/ja4-tap/main.go` (as part of fixing F-023)
2. Add a Prometheus scrape target:
```yaml
- job_name: 'ja4proxy-tap'
  static_configs:
    - targets: ['ja4-tap:8080']
```

---

### O-005 — [MEDIUM] No docker-compose service, no systemd unit, no deployment infra

**Phase:** 316a (operations)

**Severity:** MEDIUM — sensor is built manually, run manually, not managed

**Description:**
The TAP sensor has zero deployment infrastructure:
- **No Dockerfile** in `deploy/docker/` for containerized deployment
- **No service** in `docker-compose.poc.yml` or `docker-compose.prod.yml`
- **No systemd unit** — the `scripts/deploy.sh` creates units for the main stack but not the sensor
- **No Makefile target** to build the binary (O-001)
- **No resource limit guidance** — the inline proxy has documented `512M` memory and `4.0` CPU limits; the sensor has none
- **No HEALTHCHECK** — no `/health` endpoint, no Docker HEALTHCHECK directive, no liveness probe

The only runbook commands (`docs/runbooks/tap_mode.md:331–341`) suggest running the binary directly:
```
ja4-tap --interface eth1 --redis-url redis://redis:6379/0
```

This works for development but is not suitable for production:
- No auto-restart on crash
- No log management
- No privileged container with `CAP_NET_RAW`
- No integration with the existing Docker Compose stack

**Evidence:**
- `ls deploy/docker/Dockerfile.*` — no Dockerfile for the TAP sensor
- `rg 'ja4-tap\|ja4tap' docker-compose.poc.yml docker-compose.prod.yml` — no results
- `rg ja4proxy-tap scripts/deploy.sh` — no results (only references the main `ja4proxy.service`)

**Recommendation:**
Create a `Dockerfile.ja4-tap` (multi-stage Go build, scratch or distroless runtime), add a `ja4-tap` service to `docker-compose.prod.yml`, and document the required capabilities (`cap_add: NET_RAW`), security context, and resource limits.

---

### O-006 — [LOW] No Redis ACL user for TAP sensor in `config/redis_acl.conf`

**Phase:** 316a (operations)

**Severity:** LOW — documented in runbook but not in canonical config

**Description:**
The runbook (`docs/runbooks/tap_mode.md:350-352`) documents the Redis ACL commands for the TAP sensor:
```
ACL SETUSER ja4tap on >SECRET ~fp:* +set +expire
```
When enforcement is armed (line 454):
```
ACL SETUSER ja4tap on >SECRET ~fp:* ~ban:* +set +expire
```

However, `config/redis_acl.conf` defines 3 users (`management`, `analytics`, `default`) but has **no `ja4tap` user**. If an operator deploys from the canonical config file, the sensor connects to Redis with no permissions and every write fails.

**Evidence:**
- `config/redis_acl.conf`: no `ja4tap` user entry
- `docs/runbooks/tap_mode.md:350`: ACL commands only in the runbook
- `docs/runbooks/tap_mode.md:454`: widened ACL for armed mode

**Recommendation:**
Add a `ja4tap` user section to `config/redis_acl.conf` with the base ACL (fp:*) and a comment noting the widened ACL for armed mode.

---

### P-001 — [MEDIUM] Zero privacy/GDPR documentation in the entire project

**Phase:** Cross-cutting

**Severity:** MEDIUM — compliance risk; no defensible privacy posture

**Description:**
The entire repository — 10,000+ files across Go, Python, Makefiles, YAML, Markdown, JSON, and Docker — contains **zero mentions** of privacy, GDPR, PII, data retention, erasure, consent, data minimization, or any related term. The passive TAP sensor:

- Captures ALL traffic on the mirror port (no opt-out, no exclusion lists)
- Extracts and stores `ClientHello` bytes in memory (includes SNI = visited hostname)
- Writes IP-keyed fingerprints to Redis with 24h TTL
- Logs IP addresses in non-quiet mode
- Has NO privacy notice, NO Data Protection Impact Assessment (DPIA), NO documented retention/deletion process

For a security sensor deployed on a network carrying user traffic, this is a compliance gap under GDPR, CCPA, and similar regulations. GDPR Article 5 (Principles relating to processing of personal data) requires:
1. Lawfulness, fairness, and transparency — no notice
2. Purpose limitation — monitoring is security, but undocumented
3. Data minimization — the sensor captures full ClientHello bytes (may contain SNI)
4. Storage limitation — 24h TTL is reasonable but unenforced by any documented process
5. Integrity and confidentiality — cleartext Redis connection (F-018)

**Evidence:**
- `rg -rn "gdpr\|privacy\|pii\|data.minim\|retention\|erasure\|consent\|deletion" .` — zero results across all files
- `cmd/ja4-tap/main.go:175–192`: logs IP, port, and handshake details in non-quiet mode
- `internal/tap/events.go:50–61`: `HandshakeEvent` carries full ClientHello bytes (includes SNI)
- `docs/runbooks/tap_mode.md`: no privacy section

**Recommendation:**
Add a `docs/PRIVACY.md` documenting:
1. What data the sensor captures (packet headers, ClientHello bytes)
2. What is persisted (OS class, JA4T fingerprint, ban status — IP-keyed)
3. Retention periods (24h fingerprints, 5min bans, 1h ban intents)
4. What is NOT persisted (raw payload bytes, full ClientHello, SNI hostnames)
5. How to handle GDPR Right to Erasure requests (P-003)
6. That the sensor should not be deployed on user-facing networks without legal review

---

### P-002 — [MEDIUM] IP addresses embedded in Redis key names — enumerable PII corpus

**Phase:** 316b (store), 316d (enforcement)

**Severity:** MEDIUM — any Redis read access reveals the full tracked-client corpus

**Description:**
IP addresses are embedded in Redis key names: `fp:os:ip:1.2.3.4`, `fp:ja4t:ip:1.2.3.4`, `ban:1.2.3.4`, `fp:ban_intent:ip:1.2.3.4`. An attacker or operator with any Redis read access (even limited to the `fp:*` namespace) can enumerate all tracked client IPs via `KEYS fp:os:ip:*` or `SCAN 0 MATCH fp:os:ip:*`.

The IP address is personal data under GDPR Article 4(1) (CJEU ruling C-582/14). The key-value store is effectively a registry of "all observed client IPs and their OS classification." Even though the VALUES are just OS strings and JA4T strings, the key names themselves expose PII.

**Evidence:**
- `internal/tap/store.go:59`: `"fp:os:ip:"+ip`
- `internal/tap/store.go:86`: `"fp:ja4t:ip:"+ip`
- `internal/tap/enforcement.go:14`: `banKeyPrefix = "ban:"` → `"ban:"+ip`
- `internal/tap/enforcement.go:112`: `banIntentKeyPrefix+ip` → `"fp:ban_intent:ip:"+ip`
- Redis ACL grants `~fp:* +set +expire` to the sensor — any user with this ACL can SCAN the full IP corpus

**Recommendation:**
1. Hash or HMAC the IP in the key suffix: `fp:os:ip:SHA256(ip)` instead of `fp:os:ip:1.2.3.4`. The consumer would need to compute the same hash.
2. OR document that IPs in key names are PII and restrict Redis ACLs to only the minimum required commands (`~fp:os:ip:{ip}` is not possible — Redis doesn't support per-key-name ACL patterns for dynamic suffixes). The `~fp:*` pattern is a namespace ACL that allows key enumeration.
3. Add a `SCAN` rate-limit or audit logging for `KEYS`/`SCAN` commands on the Redis server.

---

### P-003 — [MEDIUM] No GDPR Right to Erasure process

**Phase:** 316b (operations)

**Severity:** MEDIUM — no documented mechanism to delete a user's data on request

**Description:**
GDPR Article 17 (Right to Erasure / "Right to be forgotten") requires that data controllers delete personal data on request without undue delay. The TAP sensor writes at least 4 Redis key types per tracked IP:

1. `fp:os:ip:{ip}` — OS classification, TTL 24h
2. `fp:ja4t:ip:{ip}` — JA4T fingerprint, TTL 24h
3. `fp:ban_intent:ip:{ip}` — enforcement advisory, TTL 1h
4. `ban:{ip}` — active ban, TTL 5min (only when armed)

If a user requests deletion:
- There is no documented command or tool to delete these keys
- An operator must manually run `DEL fp:os:ip:{ip} fp:ja4t:ip:{ip} fp:ban_intent:ip:{ip} ban:{ip}`
- There is no audit log of the deletion
- There is no way to prevent the sensor from re-writing the key when it sees the user's next SYN (the sensor operates continuously — deletion only removes the existing data, but the sensor immediately re-writes on the next observation)
- A true GDPR deletion would require either: (a) adding the IP to an exclusion list that the sensor checks before writing, or (b) deploying the sensor such that it cannot see the user's traffic (network-level exclusion)

The automatic TTL expiry (24h) provides a weak form of erasure — data naturally disappears within 24h if the user doesn't make any new TCP connections. But this is not GDPR-compliant: the controller must actively delete on request, not wait for passive expiry.

**Evidence:**
- `internal/tap/store.go:59`: writes `fp:os:ip:{ip}`
- `internal/tap/store.go:86`: writes `fp:ja4t:ip:{ip}`
- `internal/tap/enforcement.go:112`: writes `fp:ban_intent:ip:{ip}`
- `internal/tap/enforcement.go:126`: writes `ban:{ip}`
- No `scripts/` tool or runbook section for manual deletion
- No exclusion list mechanism in the sensor

**Recommendation:**
1. Add a `--exclude-ips` flag (or Redis-backed exclusion list) that the sensor checks before writing any fingerprint for a given IP.
2. Create a runbook section (`docs/runbooks/tap_mode.md:GDPR Erasure`) documenting the `DEL` commands for manual deletion and when TTL-based expiry is acceptable.
3. Document the data flow: deletion only removes existing Redis keys; the sensor may re-write them on the next SYN unless the IP is excluded.

---

### P-004 — [LOW] SNI/hostname present in captured ClientHello bytes — undocumented privacy risk

**Phase:** 316a (events)

**Severity:** LOW — in-memory only, never persisted; but undocumented

**Description:**
The `HandshakeEvent.ClientHello` byte slice contains the full TLS ClientHello message, which includes the Server Name Indication (SNI) extension (the hostname the client is connecting to). The SNI is sensitive — it reveals what websites/services a user is accessing.

Currently, the `ClientHello` bytes are:
- Stored in the event channel buffer (1024 slots × ~6KB ≈ 6MB max in-memory)
- NOT written to Redis
- NOT logged to stdout (even in non-quiet mode — only the byte length is logged)
- NOT persisted to disk
- Discarded when the event is consumed (the consumer only reads OS class and JA4T)

This is the correct privacy-preserving behavior. But it is **undocumented**. An operator reading the code or docs might reasonably believe that the `ClientHello` bytes are persisted (given that `HandshakeEvent` is the sensor's primary output).

**Evidence:**
- `internal/tap/events.go:59`: `ClientHello []byte` — full raw ClientHello includes SNI
- `internal/tap/reassembler.go:212–221`: `maybeEmit` sends `ClientHello` through the event channel
- `cmd/ja4-tap/main.go:184`: only the byte length is logged: `"client_hello": fmt.Sprintf("%d bytes", len(ev.ClientHello))`
- `internal/tap/store.go:44–64`: `WriteOSClass` writes only the OS class string, not the ClientHello
- No comment on `ClientHello` or `HandshakeEvent` documenting the in-memory-only lifetime

**Recommendation:**
Add a doc comment to `HandshakeEvent.ClientHello` stating:
> "ClientHello is an in-memory-only field. It is never written to Redis, logged, or persisted. Extracting the SNI (server_name) extension from this field would require explicit additional code — the sensor does not currently do this."

---

### P-005 — [INFO] Full ClientHello retained in memory until event consumed (no early truncation)

**Phase:** 316a (privacy-by-design)

**Severity:** INFORMATIONAL — acceptable for current architecture; worth documenting for capacity-planning

**Description:**
The sensor retains the full `ClientHello` bytes in the event channel until the `drive` function's event loop processes them. At 1024 events × ~6KB per ClientHello, that's ~6MB of in-memory SNI data containing visited hostnames. If Redis is slow and the event channel is full, events are dropped but the ClientHello bytes held by the producer (sender) are retained until GC collects them.

In contrast, the `ServerHello` bytes (also potentially sensitive — they may contain ALPN and server certificate information) are typically small (~1-2KB).

This is not a practical risk (all data is in the same process address space, and the process is single-purpose), but it's worth documenting as part of a privacy-by-design analysis.

**Evidence:**
- `internal/tap/events.go:59–60`: `ClientHello []byte` and `ServerHello []byte`
- `internal/tap/sensor.go:37–39`: event channel buffered to 1024
- `cmd/ja4-tap/main.go:169–172`: event is consumed, fingerprints are written, ClientHello bytes are not persisted

**Recommendation:**
Document in `docs/PRIVACY.md` that full TLS ClientHello messages (including SNI) are held in memory for the duration of the event queue (bounded by the 1024-slot channel) and are never persisted to secondary storage. — [MEDIUM] Sensor-written bans mislabeled as "manual_ban" and overwrite admin bans

**Phase:** 316d (sensor enforcement), 231a (proxy pipeline)

**Severity:** MEDIUM — audit trail gap; permanent admin bans silently shortened to 5min

**Description:**
Two distinct issues with the `ban:{ip}` key:

**1. Mislabeled bypass reason.** The pipeline at `pipeline.go:410–411` uses `BypassReason: "manual_ban"` for ALL `ban:{ip}` existence checks, regardless of who wrote the key. Sensor-enforced bans (from JA4T blocklist matching) show as "manual_ban" in the audit log, making it impossible to:
- Verify the sensor's enforcement is working
- Distinguish automated enforcement from operator action
- Attribute a ban to investigate false positives

**2. TTL overwrite collision.** Both the sensor (`tap.Enforcer`) and the management API (`ja4p block IP`) write to the same key prefix `ban:{ip}` without coordination:
- Operator bans a client: `SET ban:1.2.3.4 "manual_block" EX 86400` (24h)
- Sensor sees the same client's SYN: `SET ban:1.2.3.4 "tap_enforce:ja4t=..." EX 300` (5min)
- The sensor's write overwrites the operator's with the short 5-min TTL
- Operator's permanent ban disappears 5 minutes later, even if the intent was 24h

The pipeline's `Exists()` check at line 410 cannot distinguish provenance — it checks key existence, not value.

**Evidence:**
- `internal/security/pipeline.go:410–411`: `p.redis.Exists(ctx, "ban:"+conn.ClientIP)` → `BypassReason: "manual_ban"` for all bans
- `internal/tap/enforcement.go:126`: `e.redis.Set(ctx, banKeyPrefix+ip, "tap_enforce:ja4t="+ja4t, e.cfg.BanTTL)` — default BanTTL is 5min
- No value inspection or provenance tag in the pipeline's ban check
- No test for cross-component ban TTL overwrite

**Recommendation:**
1. Either check the `ban:{ip}` value in the pipeline to distinguish source, or use a separate key prefix for sensor-enforced bans (e.g., `tap_ban:{ip}`) with a separate check.
2. Before the sensor writes a ban, check if an operator ban already exists and skip the write if so (operator override).
3. Log the ban provenance in the bypass reason.

---

### D-002 — [MEDIUM] Consumer cache does not distinguish "not cached" from "cached empty" (transient Redis miss poisons cache)

**Phase:** 316c (tap_consumer), 316e (tap_ja4t_consumer)

**Severity:** MEDIUM — transient Redis failure causes 60s blind window for a client IP

**Description:**
Both `TapConsumer.cachedLookup` and `JA4TConsumer.cachedLookup` return `("", false)` for both "cache miss" and "cached empty string". When a transient Redis failure (timeout within the 50ms `RedisTimeout`) or a race with the sensor's write causes a miss, the empty string result `""` IS cached:

```
tap_consumer.go:129: t.cache.Set(cacheKey(canonIP), observed, ttl)
```

where `observed` is `""` from `redisLookup`. The default `CacheTTL` is 60 seconds. During those 60 seconds, every subsequent lookup for that IP gets a cache hit (`("", true)`), returns empty, and the signal is silently suppressed — even if the sensor has actually written the key by then.

This is a classic "cache poisoning" failure mode specific to distributed systems: one component's transient failure propagates through the cache to suppress valid results for a measurable time window.

**Timeline of the failure:**
1. T=0: SYN arrives at sensor, sensor starts writing `fp:os:ip:1.2.3.4 = OSLinux` (takes ~1ms)
2. T=1ms: Proxy pipeline calls TapConsumer.GetSignal for 1.2.3.4
3. T=1ms: `redisLookup` sends `GET fp:os:ip:1.2.3.4` — races with the sensor's SET
4. T=2ms: Redis GET finishes (no key yet) → returns `""`
5. T=2ms: `""` is cached for 60s with `CacheTTL`
6. T=3ms: Sensor's SET completes (key now exists)
7. T=2s–60s: Every subsequent connection from 1.2.3.4 gets a cache hit `""` → no signal

After 60s, the cache entry expires. The next lookup does a fresh Redis GET and finds the key. But the signal was blind for 60 seconds.

**Evidence:**
- `internal/security/tap_consumer.go:129`: `t.cache.Set(cacheKey(canonIP), observed, ttl)` — caches empty result
- `internal/security/tap_consumer.go:121–130`: no distinction between "cache miss" and "negative cache entry"
- `internal/security/tap_consumer.go:153–163`: `cachedLookup` returns `(string, bool)` where `false` means "not in cache" — but the set on line 129 uses `observed` which can be `""`
- `internal/security/tap_ja4t_consumer.go:92`: same pattern

**Recommendation:**
Use a sentinel value in the cache to distinguish "cached as empty" from "not cached":
```go
const cacheMiss = "\x00" // sentinel for "cached as negative"
observed, hit := t.cachedLookup(canonIP)
if !hit {
    observed = t.redisLookup(ctx, canonIP)
    cacheVal := observed
    if cacheVal == "" {
        cacheVal = cacheMiss
    }
    t.cache.Set(cacheKey(canonIP), cacheVal, ttl)
}
if observed == cacheMiss || observed == "" {
    return nil
}
```
Or use a shorter negative cache TTL (e.g., 5s) for empty results vs. positive cache TTL (60s).

---

### D-003 — [LOW] Redis key prefixes hard-coded in 4 places (writer + reader × 2 key types)

**Phase:** 316b (store), 316c/e (consumers)

**Severity:** LOW — maintenance risk; silent signal breakage if only one side is updated

**Description:**
The Redis key prefixes for fingerprints are string literals in both the writer and the consumers, creating 4 independent copies:

| Key | Writer | Reader |
|-----|--------|--------|
| `fp:os:ip:` | `internal/tap/store.go:59` | `internal/security/tap_consumer.go:177` |
| `fp:ja4t:ip:` | `internal/tap/store.go:86` | `internal/security/tap_ja4t_consumer.go:138` |

None of these reference a shared constant. If a future change updates one prefix (e.g., to `fp:os_class:ip:` for clarity), the writer and consumer silently diverge. The consumer gets a miss for every lookup (`"fp:os_class:ip:1.2.3.4"` doesn't exist, only `"fp:os:ip:1.2.3.4"` does). Because the signal fail-opens on miss, this is silent — no error, no alert.

Related to the `canonicalIP` duplicate (F-019) — both the key prefix AND the IP normalization function are duplicated between writer and reader.

**Evidence:**
- `internal/tap/store.go:59`: `"fp:os:ip:"+ip` (sensor writer)
- `internal/security/tap_consumer.go:177`: `"fp:os:ip:"+clientIP` (consumer reader)
- `internal/tap/store.go:86`: `"fp:ja4t:ip:"+ip` (sensor writer)
- `internal/security/tap_ja4t_consumer.go:138`: `"fp:ja4t:ip:"+clientIP` (consumer reader)

**Recommendation:**
Define shared constants in `internal/fingerprint` (or a new `internal/rediskeys` package) and import them from both sides:
```go
const (
    KeyFPOSClass  = "fp:os:ip:"
    KeyFPJA4T     = "fp:ja4t:ip:"
    KeyBanIntent  = "fp:ban_intent:ip:"
)
```

---

### D-004 — [INFO] `fp:ban_intent:ip` key is undocumented in REDIS_SCHEMA.md

**Phase:** 316d (enforcement)

**Severity:** INFORMATIONAL — documentation gap

**Description:**
The sensor writes `fp:ban_intent:ip:{ip}` at `enforcement.go:112` with value `"ja4t=..."`. This key lives under the `fp:*` namespace and records advisory watchlist entries for blocklist-matched clients. It has no programmatic consumer — it's intended for operator/dashboard review.

However, `docs/reference/REDIS_SCHEMA.md` has no entry for this key prefix. An operator reading the schema documentation would not know:
- What key to query for the watchlist
- What the value format is (`"ja4t=..."`)
- What TTL applies (`defaultIntentTTL = time.Hour`)
- That it's written by the TAP sensor, not the management API

**Evidence:**
- `rg "fp:ban_intent" docs/reference/REDIS_SCHEMA.md` — no results
- `internal/tap/enforcement.go:112`: `e.redis.Set(ctx, banIntentKeyPrefix+ip, "ja4t="+ja4t, e.cfg.IntentTTL)`
- `internal/tap/enforcement.go:14`: `banIntentKeyPrefix = "fp:ban_intent:ip:"`

**Recommendation:**
Add an entry to `docs/reference/REDIS_SCHEMA.md` under the `fp:*` namespace documenting the key format, value format, TTL, and producer.
