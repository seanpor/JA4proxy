# Pentest: TLS/JA4 Parser and Protocol Fuzzing

## Goal

Execute a comprehensive adversarial penetration test and coverage-guided differential fuzzing campaign against JA4proxy's Go dataplane TLS and JA4 parser (`internal/tls/`, `internal/proxy/`, and `cmd/ja4pd/`). Probe record fragmentation across TCP segments and TLS records, malformed extension lengths, duplicate extension confusion (RFC 8446 §4.2), extension ordering manipulation, GREASE, ECH (Encrypted Client Hello, `0xfe0d`) inner/outer handling, SNI/ALPN edge cases (empty, IDN/punycode, embedded NUL bytes, control characters, over-long names, mixed-case canonicalisation), 0-RTT/early data and session resumption, reassembly-cap envelope limits, and memory safety of the `unsafe.String` zero-copy extraction (`unsafe.String(unsafe.SliceData(b), len(b))`) across transient heap/pool buffers. Investigate JA4 fingerprint canonicalisation collisions and false-positive weaponisation. Deliver minimised regression test cases, fuzz corpora, registered findings under `PROGRAMME.md` §9 with two-state proofs (`scripts/verify_revert.sh`), and hardened parser invariants.

## Scope

### In Scope

1. **TLS Record Reassembly & Protocol Smuggling:**
   - Multi-record ClientHello splitting: Handshake messages fragmented across 2 to 10+ TLS records (`0x16`).
   - Fragmented record header version consistency: Mismatched legacy record versions across fragments (`0x0301` vs `0x0303`).
   - TCP segmentation fuzzing: Partial TLS record headers (1 to 4 bytes), chunked record payloads, and fragmented extension bodies across TCP stream boundaries.
   - Reassembly envelope limits & memory bounds: Maximum reassembly thresholds (65,536 bytes in `internal/server/forward.go`), handshake length header vs record length desynchronization, and memory exhaustion resilience against partial handshake stalls.
   - Multiple handshake packing: Multiple handshake messages packed in a single TLS record (ClientHello followed by early data, alerts, or junk).

2. **Extension Parsing, Duplicate Confusion & Smuggling:**
   - Malformed extension lengths: Extension length exceeding record length, underflow, or negative offsets.
   - Duplicate extension handling (RFC 8446 §4.2): Probing behavior when duplicate extensions (e.g., duplicate SNI `0x0000`, duplicate ALPN `0x0010`) are supplied. Assess filtering discrepancy or smuggling if upstream TLS server rejects duplicates (`illegal_parameter` alert) while JA4proxy fingerprints the first entry.
   - Extension parsing complexity: Quadratic DoS risks when unbounded extension counts or unbounded ALPN protocol list lengths are supplied.
   - GREASE & Unknown extension tolerance: Verifying RFC 8701 GREASE values (`0x?a?a`) do not corrupt sorting or fingerprint output.
   - Encrypted Client Hello (ECH): Outer ClientHello vs inner ClientHello handling for extension `0xfe0d`.

3. **SNI/ALPN Control Characters & Zero-Copy Memory Safety:**
   - Deep evaluation of `unsafeString(data[p : p+nameLen])` in `internal/tls/parser.go`:
     - Transient buffer lifetime: In fragmented reassembly (`recordCount > 1`), `payloads` is an ephemeral heap slice allocated inside `ParseClientHello`. Does `info.SNI` or `info.ALPNProtocols` retain pointers to `payloads` after function return?
     - Pooled buffer lifetime: Tracing `BufferPool` reuse in `internal/server/server.go`. Ensure `strings.Clone` is strictly enforced everywhere and background goroutines never read recycled memory.
     - Race conditions: Verification under `-race` flag and ASan/MSan instrumentation.
   - Malformed SNI / ALPN payloads:
     - Embedded NUL bytes (`example.com\x00evil.com`) and ASCII control characters (`\r\n`) causing log injection in logrus or JSON corruption in event stream emission (`EmitConnectionEvent`).
     - Over-long SNI names exceeding 255 bytes (RFC 6066 §3).
     - IDN / Punycode validation and mixed-case canonicalisation.

4. **JA4 Canonicalisation Collisions & False-Positive Weaponisation:**
   - Algorithmic analysis of `internal/tls/ja4.go`:
     - Section A ALPN 2-character hashing (`string(first[0]) + string(first[len(first)-1])`).
     - Section B cipher suite sorting (lexicographical sorting vs wire order).
     - Section C extension sorting vs signature algorithm wire order.
   - FP weaponisation evaluation: Can an attacker craft a malicious ClientHello that produces the exact JA4 fingerprint of standard browsers (e.g., Chrome `t13d1516h2_...` or Firefox) to evade rate limiting or induce collateral denial-of-service against legitimate users when blocked?

5. **Differential & Structure-Aware Fuzzing Engine:**
   - Native Go fuzzing (`go test -fuzz`) for `ParseClientHello` and `ComputeJA4`.
   - Differential oracle testing against standard library `crypto/tls`:
     - Comparing parsed SNI, ALPN, and SupportedVersions against `crypto/tls.ClientHelloInfo` extracted via an in-memory loopback TLS server and `tls.Config{GetConfigForClient: ...}`.
     - Probing differential discrepancies (e.g. JA4proxy accepting what `crypto/tls` rejects, or vice-versa).
   - Evidence handling (`RULES_OF_ENGAGEMENT.md` §7): Raw fuzz corpora written exclusively to gitignored `.pentest-range/evidence/<cycle-date>/`; only minimised, sanitized Go test reproducers checked into git.

### Out of Scope
- Denial of Service attacks against external certificate authorities or DNS infrastructure.
- Cryptoanalytic attacks against AES-GCM or ChaCha20-Poly1305 encryption primitives.
- Testing non-TLS transport protocols outside JA4proxy's scope.

---

## Implementation Plan

### Step 1: L0 Static Memory Safety & Buffer Lifecycle Audit
1. Audit `internal/tls/parser.go`, `internal/server/server.go`, and `internal/server/pipeline_helpers.go`:
   - Trace `unsafeString` usage when parsing multi-record fragmented ClientHello (`payloads` slice).
   - Audit all access points where `ClientHelloInfo.SNI` and `ClientHelloInfo.ALPNProtocols` are read.
   - Audit buffer pool return paths: ensure `BufferPool.Put` cannot race with asynchronous pipeline or logging consumers.

### Step 2: L1 Adversarial Test Suite for Parser RFC & Injection Anomalies
1. Author `tests/adversarial/dataplane/tls_parser_anomalies_test.go`:
   - Test fragmented ClientHello across multiple TLS records (`0x16`) with version mismatch.
   - Test malformed extension lengths (1-byte short, 1-byte overflow, 0xFFFF length).
   - Test duplicate extension handling: duplicate SNI and duplicate ALPN (assert consistent rejection or deterministic canonicalisation).
   - Test embedded NUL bytes and control characters (`\r\n`) in SNI and ALPN (assert sanitization before event stream / logging).
   - Test over-long SNI strings (>255 bytes) and IDN punycode parsing.
   - Test ECH extension `0xfe0d` outer/inner framing.

### Step 3: L1 Differential Fuzzing with Go `crypto/tls` Oracle
1. Author differential fuzz test in `internal/tls/differential_fuzz_test.go`:
   - Spin up in-memory loopback pipe connected to `tls.Server` with `GetConfigForClient`.
   - Feed mutated TLS ClientHello byte streams to both `ParseClientHello` and `crypto/tls`.
   - Assert invariant: Whenever `crypto/tls` parses valid SNI/ALPN, JA4proxy matches exactly.
   - Assert invariant: JA4proxy parser never panics or causes memory corruptions on any byte stream.
   - Execute fuzz runs: `GOROOT=/snap/go/current /snap/go/current/bin/go test -fuzz=FuzzDifferentialClientHello -fuzztime=1m ./internal/tls/...`.

### Step 4: L1 JA4 Collision Analysis & FP-Inversion Invariants
1. Author `tests/adversarial/dataplane/ja4_collision_invariants_test.go`:
   - Test whether varying cipher suite order or inserting innocuous non-GREASE extensions produces identical JA4 hashes.
   - Test ALPN 2-char collision properties (`http/1.1` vs custom protocols).
   - Formulate attacker cost to induce collision with Google Chrome / Safari fingerprints.

### Step 5: Findings Registration, Two-State Verification & Remediation
1. Register any identified vulnerabilities (e.g. ephemeral buffer use-after-free, unhandled duplicate extension smuggling, or NUL-byte injection) in `docs/security/findings.yaml` with allocated `JA4PROXY-2026-NNNN` IDs and open linked GitHub issues.
2. Implement remediation patches with regression tests and verify two-state proofs (`scripts/verify_revert.sh`).

---

## Test Strategy

- **L0 Static Invariant Verification:** Inspect parser bounds checking, pointer safety (`unsafe.String`), and buffer pool lifecycles.
- **L1 Adversarial Matrix:** Targeted Go unit tests exercising RFC anomalies and injection edge cases in `internal/tls/`.
- **L1 Differential Fuzzing:** Continuous fuzz testing with `crypto/tls` oracle.
- **Regression Invariants:** Verify parser never panics, never leaks memory, and cleanly sanitizes untrusted protocol strings.

---

## Acceptance Criteria

- [ ] Comprehensive adversarial test suites in `internal/tls/` and `tests/adversarial/dataplane/` passing 100%.
- [ ] Differential fuzzing engine integrated against `crypto/tls` oracle running clean without panics or crashes.
- [ ] Memory safety analysis of `unsafe.String` zero-copy extraction across fragmented and pooled buffers verified clean under `-race`.
- [ ] All discovered vulnerabilities logged in `docs/security/findings.yaml` with verified two-state proofs (`scripts/verify_revert.sh`).
- [ ] Raw fuzzing evidence saved exclusively to gitignored `.pentest-range/evidence/`.
- [ ] `make preflight` and `bash scripts/close-phase.sh` exit 0.
