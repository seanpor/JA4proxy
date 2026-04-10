# Network Layer & Evasion Resistance Review

**Date:** 2026-04-08 (recalibrated 2026-04-08 v2)  
**Scope:** PROXY protocol handling, TLS passthrough, tarpit, geoip, blocklists, TAP/eBPF, connection forwarding  
**Severity scale:** CRITICAL → HIGH → MEDIUM → LOW · **[Go-PROD]** = production gap · **[Python-deprecated]** = maintenance debt

> **Production context:** Go (`cmd/proxy/`, `internal/proxy/`) is production. Python is deprecated. Go-only gaps are production issues.

## Findings Summary

| # | Severity | Finding | Scope | File(s) |
|---|----------|---------|-------|---------|
| 1 | **CRITICAL** | Go proxy trusts PROXY protocol from ANY source — no trust check | **[Go-PROD]** | `cmd/proxy/main.go:289-296`, `internal/proxy/proxy_protocol.go` |
| 2 | **HIGH** | Go proxy lacks PROXY protocol v2 support | **[Go-PROD]** | `internal/proxy/proxy_protocol.go` |
| 3 | MEDIUM | Tarpit server has no server-side resource limits | [Both] | `tarpit/tarpit-server.py:44-73` |
| 4 | MEDIUM | Tarpit overflow "allow" forwards malicious traffic to backend | [Both] | `proxy.py:2524-2533`, `cmd/proxy/main.go:458-465` |
| 5 | MEDIUM | JA4 is fully forgeable; ALPN bypass skips ALL security checks | [Both] | `internal/security/pipeline.go:368-371` |
| 6 | LOW-MEDIUM | Python PROXY v2 `addr_len` trusted without bounds check | [Python-deprecated] | `proxy.py:2387-2445` |
| 7 | LOW | Go allocates buffer per connection (no `sync.Pool`) | **[Go-PROD]** | `cmd/proxy/main.go:264,413` |
| 8 | LOW-MEDIUM | XDP/eBPF blocking is IPv4 only | [Infra] | `ebpf/ja4block.c:71-75` |
| 9 | LOW | Blocklist feed download has no size limit | [Both] | `src/security/blocklists.py:377-383` |
| 10 | LOW | GeoIP uses Country DB only (no proxy/VPN detection) | [Both] | `cmd/proxy/main.go:299-304` |
| 11 | LOW | Single `Read()` may not capture full ClientHello | **[Go-PROD]** | `cmd/proxy/main.go:264` |
| 12 | LOW | Tarpit capacity not shared across proxy instances | [Both] | `proxy.py:2506-2514`, `cmd/proxy/main.go:447-455` |

---

## Critical Findings

### Finding 1 — CRITICAL (Go-PROD): Go Proxy Trusts PROXY Protocol from Any Source

**Files:** `cmd/proxy/main.go`, lines 289-296; `internal/proxy/proxy_protocol.go`, lines 12-33

The Python proxy guards PROXY protocol parsing with `_is_trusted_proxy_source()` which validates the peer IP against a configurable `trusted_cidrs` list. **The Go proxy has no equivalent trust check.**

```go
if p.cfg.Proxy.ProxyProtocol {
    if realIP, ok := proxypkg.ReadProxyProtocol(data); ok {
        connCtx.ClientIP = realIP
```

**Attack scenario:** An attacker from a blocked country sends `PROXY TCP4 8.8.8.8 ...` as the first bytes. The Go proxy treats the connection as coming from 8.8.8.8 (US), bypassing:
- GeoIP country blocking
- CIDR block checks
- Rate limiting by IP
- ASN classification
- DNS enrichment
- AbuseIPDB lookups
- Static IP allowlist (if victim IP is whitelisted)

**Remediation:** Implement the same `_is_trusted_proxy_source()` logic in Go. Add `trusted_cidrs` to the Go config and check `remoteIP(conn)` before trusting the PROXY header.

---

## High Findings

### Finding 2 — HIGH (Go-PROD): Go Proxy Lacks PROXY Protocol v2 Support

The Python implementation supports both v2 (binary, 12-byte magic) and v1 (text). Go only supports v1. If a load balancer sends PROXY protocol v2 (default for modern HAProxy and AWS NLB), the Go proxy silently ignores it and uses the LB's IP as the client IP, breaking all per-IP security controls.

### Finding 3 — Tarpit Server Has No Resource Limits

The tarpit uses `asyncio.Semaphore(TARPIT_MAX_CONNECTIONS)` (default 1000), but each connection holds a writer for 60 seconds. An attacker triggering 1000+ tarpit connections fills the semaphore, and subsequent legitimate tarpit-bound connections hit the overflow handler.

### Finding 4 — Tarpit Overflow "allow" Defeats Security Decision

When tarpit capacity is exhausted, the `overflow_action` can be `allow`, which forwards to the backend unfiltered. An attacker can deliberately saturate tarpit slots, then all subsequent malicious traffic goes straight through.

**Remediation:** Default `overflow_action` should be `block`, not `allow`.

### Finding 5 — JA4 Fingerprint Is Fully Forgeable; ALPN Bypass Skips All Checks

JA4 is computed entirely from ClientHello fields the client controls. An attacker using a custom TLS library can set ALPN to `h2`, which triggers the ALPN browser bypass:

```go
if p.cfg.ALPNBrowserBypass && (conn.ALPN == "h2" || conn.ALPN == "h1") {
    return true, "alpn_browser"
}
```

This bypasses the entire pipeline — no JA4 blacklist check, no rate limiting, no blocklist check, no scoring.

**Remediation:** Add TCP-level fingerprinting (JA4T) to the bypass check. Validate that the JA4 fingerprint is internally consistent with known browser patterns.

---

## Low Findings

### Finding 6 — Python PROXY v2 `addr_len` Trusted Without Bounds Check

A malicious trusted proxy could set `addr_len` to 65535. TLV parsing has safe bounds checking but the initial trust in `addr_len` could cause issues with a compromised load balancer.

### Finding 7 — Go Allocates Buffer Per Connection

`buf := make([]byte, p.cfg.Proxy.BufferSize)` per connection generates GC pressure under high concurrency. Use `sync.Pool` for buffer reuse.

### Finding 8 — XDP/eBPF Blocking Is IPv4 Only

```c
if (eth->h_proto != __constant_htons(ETH_P_IP))
    return XDP_PASS;
```

IPv6 traffic bypasses the kernel-level drop entirely.

### Finding 9 — Blocklist Feed Download Has No Size Limit

30-second timeout but no max bytes limit. A compromised feed URL could serve an infinitely large response, consuming memory during `await resp.text()`.

### Finding 10 — GeoIP Uses Country DB Only

No `is_anonymous_proxy`, `isHostingProvider`, or `isAnonymous` detection. An attacker using VPN/hosting IPs is not flagged at the GeoIP level.

### Finding 11 — Single `Read()` May Not Capture Full ClientHello

Only one `Read()` is performed. If the client sends more than `BufferSize` bytes before the proxy connects to the backend, excess bytes are lost.

### Finding 12 — Tarpit Capacity Not Shared Across Instances

In multi-instance deployments, each instance maintains its own count. If 3 instances each have `max_concurrent = 500`, the effective global limit is 1500.
