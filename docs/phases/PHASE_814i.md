# Pentest: Network and DMZ Edge

## Goal

Execute an adversarial penetration test and security verification of JA4proxy's network perimeter, DMZ boundary, upstream proxy integrations, and backend routing invariants (Personas P1: Network Attacker, P2: Protocol Attacker). Rigorously re-test from scratch against the Go dataplane (`internal/server/`, `internal/proxy/`, `cmd/ja4pd/`) and management boundary (`management/api/auth.py`) the critical vulnerability classes discovered during the Python era (specifically PROXY protocol smuggling L1-018, fragmentation bypass L1-019, and XFF IP spoofing L4-028). Evaluate direct-to-`ja4pd` reachability bypassing HAProxy, PROXY protocol v1/v2 parser anomalies and edge cases, header doubling/chaining/smuggling across TCP packet boundaries, trusted CIDR enforcement (IPv4, IPv6, IPv4-mapped IPv6, zone-scoped addresses), DMZ port scanning or SSRF via backend dial redirection, TCP reset (RST) and timing oracles, and exhaustively verify the core architectural invariant: **no network path reaches backend forwarding without passing through a security scoring decision**.

## Scope

### In Scope

1. **Direct-to-`ja4pd` Reachability & Perimeter Boundary:**
   - Testing direct external TCP connections to `ja4pd` bypassing upstream load balancers (e.g. HAProxy, AWS NLB).
   - Ingress behavior when `proxy_protocol: true` is enabled: analyze permissive mode (direct TLS connections allowed if PROXY preamble is absent) vs strict perimeter mode (`proxy_protocol_required: true`), where any connection from an untrusted client or any connection lacking a valid PROXY header is immediately dropped.
   - Header stripping semantics: when an untrusted client supplies a PROXY header directly, does the proxy safely strip the spoofed header without adopting the spoofed IP?
   - Backend PROXY forwarding (`write_proxy_protocol: true`): verify that `s.Forward` constructs a new PROXY header using `connCtx.ClientIP` (the real socket IP), ensuring the backend never receives the attacker's claimed IP.

2. **PROXY Protocol v1/v2 Smuggling, Doubling & Fragmentation (L1-018 & L1-019):**
   - **Multi-packet Smuggling at `server.go:430`:** Header doubling split across TCP segments (Packet 1: valid PROXY header; Packet 2: injected/smuggled PROXY header before TLS payload). Probing the vulnerability where Packet 1 is stripped down to 0 bytes, and the secondary read at line 430 reads Packet 2 without re-running any anti-smuggling check.
   - **Chained Headers in Single Buffer:** Consecutive v1 or v2 PROXY headers within the initial read buffer (testing `smuggling_blocked` counter and connection termination).
   - **PROXY Header Fragmentation (C-4 False Positive Hazard):** Legitimate upstreams sending PROXY headers fragmented across TCP packets (e.g., partial preamble or split CRLF). Testing whether connections are prematurely killed by TLS protocol lockdown (`data[0] != 0x16`), and implementing `ReassembleProxyHeader` to buffer partial preambles up to 107 bytes (v1) or header length (v2) before evaluation.
   - **PROXY v1 Spec Conformance:** Enforcing the HAProxy PROXY v1 107-byte line length bound, transport protocol token validation (strictly `TCP4` or `TCP6`, rejecting `PROXY BOGUS`), and port bounds (`0..65535`).
   - **PROXY v2 LOCAL Command Handling:** Fixing `v2CmdLOCAL` in `ReadProxyProtocolV2WithLength` so health check connections discard the 16-byte header and proceed with socket IP, instead of returning `ok = false` which causes TLS lockdown to drop health checks.
   - **PROXY v2 TLV Length Bounding:** Lifting the arbitrary 256-byte `addrLen` cap to buffer capacity to support legitimate AWS NLB and HAProxy SSL/metadata TLVs.
   - **Internal Destination Injection:** Attacker-controlled destination IPs/ports in PROXY v1 (`PROXY TCP4 1.2.3.4 127.0.0.1 1234 80\r\n`) and v2 binary headers. Verification that JA4proxy's backend dialer never uses attacker-supplied destination IPs or ports.

3. **X-Forwarded-For (XFF) vs PROXY Protocol Precedence & Spoofing (L4-028):**
   - Dataplane TLS passthrough verification: confirm Go dataplane never decrypts or inspects HTTP headers inside encrypted TLS streams.
   - Management API XFF parsing (`management/api/auth.py:275`): fix the active vulnerability where `forwarded_for.split(",")[0].strip()` extracts the leftmost (attacker-controlled) IP behind trusted reverse proxies (`MANAGEMENT_TRUSTED_PROXY_CIDRS`). Enforce rightmost untrusted client IP extraction and validate IP syntax with `ipaddress.ip_address` to prevent rate limiter bypass and Redis key pollution.

4. **Trusted-CIDR Correctness Across IP Families & Edge Encodings:**
   - Dynamic vs static CIDR provider synchronization (`s.GetTrustedCIDRs()` vs `TrustedUpstreamSources.StaticCIDRs` vs `Proxy.UpstreamTrust.TrustedCIDRs`).
   - IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1` vs `10.0.0.0/8`, and `10.0.0.1` vs `::ffff:10.0.0.0/104`).
   - IPv6 zone identifiers / link-local scoped addresses (`fe80::1%eth0` or zone-scoped socket addresses).
   - Wildcard CIDRs (`0.0.0.0/0`, `::/0`) and malformed CIDR error handling (fail-open vs fail-closed security properties).

5. **DMZ Scanning & SSRF Invariants via Backend Forwarding:**
   - Verification that `backendAddr` is strictly immutable from runtime traffic and derived solely from validated proxy configuration.
   - Probing SNI, ALPN, and PROXY destination fields for any injection or redirection into backend dialing.

6. **TCP RST, FIN, and Timeout Oracles:**
   - Side-channel analysis of connection termination behavior across decision states:
     - Policy Block/Ban: Immediate TCP RST (`SetLinger(0)`).
     - Backend Down / Connection Refused: Delayed FIN or RST.
     - Backend Connect Timeout: Delayed close after `connection_timeout`.
     - Tarpit: Prolonged connection hold with delayed byte trickling.
   - Information leakage: profile whether an adversary can distinguish between IP bans and backend downtime.

7. **Backend Forwarding Security Gate Invariant & Tarpit Overflow:**
   - Exhaustive static and dynamic code verification that `s.Forward(...)` is NEVER reachable without passing through `s.Pipeline.Process(ctx, connCtx)`:
     - Audit main handler `handleConn` in `internal/server/server.go`.
     - Audit tarpit overflow path in `internal/server/tarpit.go:48` (`overflowAction == "allow"` forwarding previously blocked connections).
   - Behavior when TLS parsing fails (`ParseClientHello` returns error, truncated record, non-TLS content): fail-open vs fail-closed properties, metric emission, and protocol lockdown enforcement.

### Out of Scope

- Physical network tapping or layer-2 ARP spoofing on host interfaces.
- Exploiting kernel-level TCP stack vulnerabilities (Linux TCP backlog bugs).
- Attacking remote NetBox IPAM servers directly (covered under supply chain / integration testing).

---

## Implementation Plan

### Step 1: L0 Static Architecture & Invariant Audit
1. Audit `internal/server/server.go`:
   - Trace `handleConn` from socket accept to `Forward`.
   - Audit PROXY protocol handling: single-buffer read limitations, post-PROXY `len(data) == 0` secondary read at line 430, anti-smuggling check coverage.
   - Audit `ProtocolLockdownEnabled` interactions with PROXY header stripping and fragmented preambles.
2. Audit `internal/proxy/proxy_protocol.go`:
   - Spec compliance of `ReadProxyProtocol` (v1 line length limit 107 bytes, transport protocol token validation `TCP4`/`TCP6`, port range parsing).
   - Spec compliance of `ReadProxyProtocolV2WithLength` (LOCAL command discarding, TLV length handling up to buffer capacity).
   - Audit `isTrustedIP` for IPv4-mapped IPv6 addresses and zone-scoped addresses.
3. Audit `management/api/auth.py`:
   - Audit `_client_ip` for leftmost vs rightmost XFF parsing vulnerability (L4-028) and IP validation.
4. Audit `internal/server/tarpit.go`:
   - Audit `overflowAction == "allow"` routing to `s.Forward`.

### Step 2: L1 Adversarial Test Suite for Dataplane Network & PROXY Invariants
1. Author `tests/adversarial/network/pentest_network_dmz_test.go` (Go native execution):
   - **Test 1: Multi-Packet PROXY Smuggling:** Send initial PROXY header in segment 1 (stripped to 0 bytes), followed by a second PROXY header in segment 2. Assert that secondary PROXY headers read at line 430 are detected, dropped, and increment `proxy_protocol_smuggling`.
   - **Test 2: PROXY Header Fragmentation:** Send PROXY v1/v2 header split across multiple 4-byte TCP packets before the TLS ClientHello. Assert that `ReassembleProxyHeader` reassembles the header and processes the connection without false-positive drops under TLS lockdown.
   - **Test 3: Untrusted PROXY Stripping & Source IP Integrity:** Send spoofed PROXY header from untrusted source IP. Assert that spoofed IP is rejected, socket IP is retained for security scoring, and backend receives clean traffic.
   - **Test 4: PROXY v1 RFC Conformance & Malformed Fields:** Feed malformed transport tokens (`PROXY BOGUS ...`), overlong lines (>107 bytes), invalid ports (>65535 or non-numeric), and IPv4/IPv6 mismatches.
   - **Test 5: PROXY v2 LOCAL Command Handling:** Send PROXY v2 LOCAL header followed by TLS ClientHello. Assert header is discarded and connection proceeds using socket IP rather than being dropped by TLS lockdown.
   - **Test 6: PROXY v2 Extended TLVs (>256 bytes):** Send valid PROXY v2 header with 512 bytes of TLVs. Assert valid parsing.
   - **Test 7: Trusted CIDR IPv4-Mapped IPv6 & Zone Scope:** Test matching of `::ffff:10.0.0.1` against `10.0.0.0/8`, link-local addresses, and default routes.
   - **Test 8: Backend Forwarding Gate & Tarpit Overflow Invariant:** Trace all code execution branches. Assert that zero paths reach `s.Forward` without executing `s.Pipeline.Process`, and evaluate `tarpit.go` overflow.
   - **Test 9: TCP Reset / Timing Oracle Profiling:** Measure time-to-close and TCP flags for blocked vs backend-offline vs tarpitted connections.

### Step 3: L1 Management API XFF Spoofing Adversarial Tests
1. Author `tests/adversarial/network/test_management_xff_spoofing.py` (Container-strict execution via `ja4proxy-tools`):
   - Send requests with multiple XFF entries (`X-Forwarded-For: 1.1.1.1, 203.0.113.50`) through a trusted proxy IP.
   - Assert that client IP extraction takes the rightmost untrusted client IP, preventing spoofing of rate limit buckets or audit logs.
   - Verify IP validation prevents arbitrary string injection into Redis key paths.

### Step 4: Vulnerability Registration, TDD Fixes & Regression Proofs
1. Register all identified vulnerabilities in `docs/security/findings.yaml` with allocated `JA4PROXY-2026-NNNN` IDs and open linked GitHub issues.
2. Implement TDD fixes in `internal/server/server.go`, `internal/proxy/proxy_protocol.go`, and `management/api/auth.py`.
3. Verify all fixes with two-state regression proofs (`scripts/verify_revert.sh`).

---

## Test Strategy

- **L0 Static Verification:** Code path tracing proving no backend forwarding occurs without a pipeline decision, and auditing tarpit overflow paths.
- **L1 In-Process Network Simulation:** Loopback TCP clients and servers simulating multi-segment TCP packet fragmentation, multi-packet PROXY smuggling, untrusted client spoofing, and PROXY v2 LOCAL commands.
- **Container Parity:** Go tests run natively with `GOROOT=/snap/go/current /snap/go/current/bin/go`; Python tests run inside pinned `ja4proxy-tools` Docker container (`make test-unit`).
- **Regression Invariants:** Strict adherence to zero-regression floor (`make test`, `make test-unit`, `make lint`).
- **Two-State Regression Proofs:** Every security finding must have a corresponding verification script verifying FAIL on unpatched code and PASS on patched code.

---

## Acceptance Criteria

1. **Multi-Packet Smuggling Immunity:** Multi-packet PROXY protocol smuggling attempts (including post-line-430 secondary reads) are reliably detected and dropped, emitting `smuggling_blocked` metrics.
2. **Fragmentation Reassembly (Zero False Positives):** Fragmented PROXY headers from legitimate upstreams are properly reassembled before protocol lockdown evaluation.
3. **Spec-Compliant Parsing:** PROXY v1 enforces 107-byte line bounds, valid protocol tokens (`TCP4`/`TCP6`), and port bounds. PROXY v2 correctly handles LOCAL commands and TLVs > 256 bytes.
4. **Untrusted Spoof Resistance:** Untrusted clients sending PROXY headers are stripped of spoofed metadata, and their real socket IP is strictly enforced across scoring and backend forwarding.
5. **XFF Parsing Hardening:** Management API extracts client IPs securely using rightmost untrusted hop parsing and validates IP formats.
6. **Architectural Decision Invariant Verified:** Mathematically and empirically verified that 100% of forwarded traffic undergoes security pipeline evaluation.
7. **All Tests Green:** Clean run of `make preflight` and CI gates.
