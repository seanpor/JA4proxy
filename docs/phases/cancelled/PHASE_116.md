# Phase 116 — Protocol Parser Hardening

> **Status:** PROPOSED
> **Size:** SMALL (2-3 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L1-017]

---

## Goal

Harden the proxy's protocol handling logic to prevent protocol confusion and smuggling attacks on trusted connections.

---

## 116a. Fail-Closed PROXY Protocol Parsing

### Problem
If `ProxyProtocol` is enabled and a trusted source fails to provide a valid header, the proxy falls through to TLS parsing, leading to potential stream corruption or smuggling.

### Fix
1.  In `cmd/proxy/main.go:handleConn`, modify the trust check logic.
2.  If the source IP is trusted AND `ProxyProtocol: true` is configured:
    *   The proxy MUST successfully parse a PROXY header (v1 or v2).
    *   If `ReadProxyProtocolV2` and `ReadProxyProtocol` both return `ok=false`, the proxy MUST close the connection immediately and log a security event.
    *   Do NOT allow the connection to fall through to `ParseClientHello` with the unstripped PROXY bytes.

---

## Acceptance Criteria
- [ ] Test: Trusted source sends a malformed PROXY header (e.g., `PROXY TCP4 ...` without `\r\n`); connection is dropped.
- [ ] Test: Trusted source sends non-PROXY traffic; connection is dropped.
- [ ] Test: Untrusted source sends non-PROXY traffic; connection proceeds to TLS parsing (scored without JA4).
