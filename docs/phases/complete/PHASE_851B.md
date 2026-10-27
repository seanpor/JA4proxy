# PROXY Protocol Invariants & Smuggling Property Tests

## Goal
Harden the PROXY protocol (v1 and v2) ingestion pipeline against parser differentials, smuggling attacks, and frame fragmentation desynchronization by establishing formal property-based invariant tests (`rapid`).

## Scope
1. **Target Surface:** `internal/proxy` (`proxy_protocol.go`, `proxy_protocol_spec_test.go`, `proxy_protocol_v2_test.go`) and server-level ingestion integration (`internal/server/server.go`).
2. **Invariants to Verify:**
   - **Totality & Panic-Freedom:** Arbitrary byte slices presented to `ReadProxyProtocol` or `ReadProxyProtocolV2WithLength` must never panic or enter infinite loops.
   - **Smuggling Invariance (JA4PROXY-2026-0002 / JA4PROXY-2026-0110):** No secondary PROXY header injected after a primary valid header or after TLS record bytes can bypass detection or masquerade as a legitimate upstream signal.
   - **LOCAL Command Discard Semantics (JA4PROXY-2026-0113):** A PROXY v2 LOCAL command (command `0x00`) must strictly yield `clientIP=""` with `ok=true`, guaranteeing the proxy strips `headerLen` and retains the real underlying socket address without falling back to unauthenticated header data.
   - **Fragmentation Boundary Invariance (JA4PROXY-2026-0111):** Chunked or byte-by-byte fragmentation of valid PROXY v1/v2 headers must parse identically or safely report truncation without partial corruption.
   - **Spec Grammar & Length Limits:** PROXY v1 must never accept lines exceeding 107 bytes, out-of-spec protocol tokens, or invalid IP format permutations.

## Implementation Plan
1. **Create Invariant Suite:** Author `internal/proxy/invariant_test.go` using `pgregory.net/rapid`.
2. **Implement Property Generators & Tests:**
   - `TestInvariant_ProxyV1_GrammarAndLengthLimits`: Generates randomized delimiters, token combinations, and oversized inputs.
   - `TestInvariant_ProxyV2_TotalityAndBoundary`: Generates arbitrary buffers with corrupted magic headers, varying length fields, and corrupted address payloads.
   - `TestInvariant_ProxyV2_LocalCommandSemantics`: Verifies that LOCAL commands with any payload/length always return `clientIP=""` and correct `headerLen`.
   - `TestInvariant_Proxy_AntiSmuggling`: Verifies that chained headers (e.g. valid v1 + v2, or valid v2 + secondary v1 header) are detected and cannot smuggle spoofed IPs.
3. **Execution & Profiling:** Verify all invariant tests pass across >= 100 randomized property runs with `go test -race ./internal/proxy`.

## Test Strategy
- Unit & property tests run via native Go toolchain: `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/proxy`.
- Full preflight gate (`make preflight`) validation.

## Acceptance Criteria
- [ ] `internal/proxy/invariant_test.go` authored with rapid property tests.
- [ ] 100/100 rapid property tests pass cleanly for all four invariant classes.
- [ ] `make lint-phases` and `make preflight` pass 100% green.
