# Phase 519 — Remote-Exploitability Bug Hunt (Go Proxy Hot Path)

## Status: COMPLETE

## Summary

A focused security bug hunt over the **remotely-reachable** surface of the Go
proxy — everything an unauthenticated internet client can drive before/without a
completed TLS handshake — looking specifically for crashes, remote code
execution, memory-safety violations, and data-integrity/disclosure bugs ("the
usual divilment"). Method: run the existing Go fuzzers to exhaustion against the
byte parsers, then targeted review of the paths fuzzing can't reach well
(sync.Pool buffer lifetime, goroutine escape, allocation bounds).

Result: the byte parsers are solid (10M+ fuzz execs, zero crashers), but the
review found one real memory-safety/data-integrity bug — **JA4PROXY-2026-0092**:
the parsed SNI/ALPN alias a pooled buffer and escape to the async scorer, so a
later connection can corrupt them (cross-connection data bleed). Fixed with a
regression test that fails if reverted.

---

## Attack Surface Reviewed

Everything reachable by an unauthenticated remote client hitting the proxy port:

1. **TCP accept + `handleConn`** — connection lifecycle, panic surface, buffer
   handling.
2. **TLS ClientHello parser** (`internal/tls/parser.go`) — parses fully
   attacker-controlled bytes; SNI/ALPN/cipher/extension length fields.
3. **ClientHello reassembly** (`reassembleClientHello`) — attacker controls TLS
   record fragmentation; checked for unbounded memory/CPU.
4. **PROXY-protocol v1/v2 parser** (`internal/proxy/proxy_protocol.go`) — header
   parsing, smuggling/chaining.
5. **JA4/JA4X computation** (`internal/tls/ja4.go`) — string/slice ownership.

Out of scope (not remotely reachable unauthenticated): the metrics/health HTTP
server (loopback + bearer-token gated), config file parsing, Redis/management
control plane.

---

## Method

1. **Fuzzing** (`go test -fuzz`), all existing targets to convergence:
   - `internal/tls` `FuzzParseClientHello` — 10.7M execs, PASS.
   - `cmd/ja4pd` `FuzzClientHello`, `FuzzFragmentation`, `FuzzProtocolSmuggling`,
     `FuzzReadProxyProtocol`, `FuzzReadProxyProtocolV2` — all PASS, no crashers.
2. **Buffer-lifetime / escape review**: traced every value derived from the
   `sync.Pool` read buffer to see whether any reference outlives
   `bufferPool.Put`, especially across the async `workChan` hand-off.
3. **Allocation-bound review**: every `make([]byte, n)` / `append` where `n` is
   attacker-controlled, checked against a cap (record length ≤ 16384,
   reassembly ≤ 65536, all bounded).

---

## Findings

### JA4PROXY-2026-0092 — SNI/ALPN alias the pooled buffer and escape to the async scorer (MEDIUM, FIXED)

**Class:** CWE-825 (use of pointer after return) + CWE-362 (concurrency).
**Remote:** yes — triggerable by ordinary connection churn (many short-lived
connections with distinct SNIs). **Crash/RCE:** no. **Impact:** data corruption
of a security decision + cross-connection information disclosure.

`tls.ParseClientHello` returns `SNI` and `ALPN` as zero-copy `unsafe.String`
values that **alias the input buffer** (a deliberate hot-path optimisation). In
`handleConn` that buffer comes from `bufferPool` (a `sync.Pool`) and is returned
to the pool by a `defer` when `handleConn` finishes. But the pipeline runs in
**async mode by default**: `Process` enqueues `connCtx` on `workChan` and returns
immediately, and a scoring worker reads `conn.SNI` (`sniAnalyzer.Analyze`) and
`conn.ALPN` (the h2/h1 browser-bypass check, and the beaconing worker) **after**
`handleConn` has returned the buffer. A subsequent connection that draws the same
pooled buffer overwrites those bytes, so the async worker scores on another
connection's data and one connection's SNI hostname can bleed into another's
structured logs. Worst case a corrupted ALPN misses the browser bypass and a real
browser is scored/blocked — a false positive, the project's costliest error.

**Fix:** a single choke point, `populateTLSFingerprints`, clones `SNI`/`ALPN`
(`strings.Clone`) when building `connCtx`, so it owns them before it can escape.
The parser keeps its zero-copy behaviour for synchronous callers. `JA4`/`JA4X`
are `fmt.Sprintf`-owned already; `CipherList` is copied by value.

**Regression test:** `cmd/ja4pd/pentest_pooled_buffer_alias_test.go` builds a
ClientHello with a known SNI/ALPN, populates `connCtx`, scribbles `0xff` over the
source buffer, and asserts `connCtx.SNI`/`ALPN` are unchanged. Reverting the
`strings.Clone` makes it fail (the fields become `"\xff\xff…"`). Verified.

---

## Acceptance Criteria

- [x] All existing Go fuzz targets run to convergence with **zero crashers**
      (ClientHello parser, fragmentation, PROXY v1/v2, smuggling).
- [x] `JA4PROXY-2026-0092` registered, fixed, and marked FIXED in
      `findings.yaml` with a regression test; `findings_register.py validate`
      exits 0.
- [x] The regression test (`pentest_pooled_buffer_alias_test.go`) passes and
      **fails when the fix is reverted** (verified by reverting the clone).
- [x] No new allocation-bound / panic vector found in the reviewed surface;
      allocations are bounded (record ≤ 16384, reassembly ≤ 65536).
- [x] `go test ./...` green; `go test -race ./internal/security/` clean.
- [ ] News fragment `docs/fragments/phase-519-remote-bug-hunt.md`.
- [ ] `manifest.yaml` entry set to COMPLETE at close-out.

### The test *is* the acceptance test
`pentest_pooled_buffer_alias_test.go` is the concrete, revert-sensitive proof of
the `0092` fix; the fuzz corpus is the acceptance evidence for "no crashers".

---

## Notes / Residual

- The parser's zero-copy `unsafe.String` for SNI/ALPN is retained by design; the
  contract is now "clone before the value escapes the synchronous parse frame."
  Any future field added to `connCtx` from a parsed value must follow the same
  rule — captured in the `populateTLSFingerprints` doc comment.
- No crash/RCE vector was found on the remote surface in this pass. The parsers'
  adversarial-input hardening (bounds checks, fail-open, reassembly caps) held up
  under fuzzing.
