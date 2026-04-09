# Security Remediation — Go PROXY Protocol Trust + v2 Support

## Goal

Close two production-critical gaps in the Go proxy's PROXY protocol handling:
(1) the Go proxy trusts PROXY protocol headers from **any source**, allowing trivial IP
spoofing that bypasses all geo/IP/rate/block controls, and (2) the Go proxy only
supports PROXY protocol v1 (text) while modern HAProxy and AWS NLB send v2 (binary)
by default, silently falling back to the LB's IP.

These are the highest-severity findings from the strategic security architecture review
(`docs/reports/strategic_security_architecture_review.md`). An attacker from a blocked
country can send `PROXY TCP4 8.8.8.8 ...` as the first bytes and the Go proxy treats
the connection as coming from 8.8.8.8, bypassing every IP-based security control.

## Scope

Files to create or modify:
- `internal/proxy/proxy_protocol.go` — add `_is_trusted_proxy_source()` equivalent + v2 parser
- `internal/config/loader.go` — add `proxy.upstream_trust` config (trusted_cidrs)
- `cmd/proxy/main.go` — gate PROXY protocol parsing on trust check
- `internal/security/pipeline.go` — wire trust check into connection handling
- `tests/unit/test_proxy_protocol.go` — unit tests for trust check + v2 parser
- `tests/unit/test_proxy_protocol_trust.go` — trust check unit tests
- `tests/integration/test_proxy_protocol_parity.py` — parity test vs Python
- `config/proxy.yml` — add `proxy.upstream_trust` section (commented)

## Implementation Plan

### A — PROXY protocol trust check (Go)

1. Add `trusted_cidrs []string` and `enabled bool` to the Go proxy config struct
   (mirroring Python's `proxy.upstream_trust` in `config/proxy.yml`).
2. Implement `isTrustedProxySource(remoteIP string, cfg *Config) bool` in
   `internal/proxy/proxy_protocol.go` — parse remote IP, check against each CIDR.
3. Gate PROXY protocol parsing in `cmd/proxy/main.go` with:
   ```go
   if p.cfg.Proxy.ProxyProtocol && isTrustedProxySource(remoteAddr, p.cfg) {
       if realIP, ok := proxypkg.ReadProxyProtocol(data); ok {
           connCtx.ClientIP = realIP
       }
   }
   ```
4. When untrusted, log a warning and use the real socket IP.

### B — PROXY protocol v2 parser (Go)

1. Add `ReadProxyProtocolV2(data []byte) (realIP string, ok bool)` to
   `internal/proxy/proxy_protocol.go`.
2. Parse the 12-byte v2 signature (`\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a`).
3. Extract address family byte (0x11 = AF_INET, 0x21 = AF_INET6) and address length.
4. Parse IPv4 (4 bytes) or IPv6 (16 bytes) from the appropriate offset.
5. Validate `addr_len` is within reasonable bounds (≤ 256 for either family).
6. Add minimum length checks before each `binary.Read`/slice operation.

### C — Wire v2 + trust into the connection handler

1. Update `handleConn` in `cmd/proxy/main.go` to try v2 first, then fall back to v1.
2. Both paths gated by `isTrustedProxySource()`.
3. When neither matches, use the socket's real remote IP.

### D — Tests

1. Unit tests for `isTrustedProxySource`: trusted CIDR match, non-trusted reject,
   invalid IP handled, empty config returns false.
2. Unit tests for `ReadProxyProtocolV2`: valid IPv4, valid IPv6, truncated header,
   wrong signature, oversized addr_len, TLV parsing edge cases.
3. Unit tests for `ReadProxyProtocolV1`: valid text header, malformed input.
4. Integration parity test: send identical PROXY v1 and v2 traffic through Python
   and Go proxies, assert both extract the same client IP.
5. Adversarial test: send `PROXY TCP4 8.8.8.40 1.2.3.4 1234 443\r\n` from an
   untrusted source — assert the Go proxy uses the socket IP, not 8.8.8.40.

## Acceptance Criteria

- [ ] `isTrustedProxySource()` correctly accepts/rejects IPs against configured CIDRs
- [ ] `ReadProxyProtocolV2()` extracts correct client IP for both IPv4 and IPv6
- [ ] `ReadProxyProtocolV2()` safely rejects malformed v2 headers (no panic, no OOB)
- [ ] Untrusted source sending PROXY header is NOT trusted — socket IP used instead
- [ ] Both v1 and v2 parsers gated by the same trust check
- [ ] All unit tests pass: `go test ./internal/proxy/... ./cmd/proxy/...`
- [ ] Parity integration test passes (Python and Go extract same IP)
- [ ] Adversarial test confirms untrusted PROXY spoof is rejected
- [ ] `config/proxy.yml` documents `proxy.upstream_trust` section with example
- [ ] CHANGELOG.md entry written
- [ ] `make lint-go-full` passes with zero warnings

## Out of Scope

- Changing the Python PROXY protocol implementation (it already has the trust check).
- PROXY protocol v2 TLV field extraction (TTL, window size, TCP options) — that
  belongs in the JA4T implementation phase.
- eBPF/XDP-level PROXY protocol handling.
