# Phase 109 — PROXY Protocol Hardening & Scrubbing

> **Status:** PROPOSED
> **Size:** MEDIUM (3-5 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L1-001], [L1-002]

---

## Goal

Harden the Go proxy's PROXY protocol implementation to prevent IP spoofing from untrusted sources and handle partial header delivery gracefully.

---

## 109a. PROXY Protocol Scrubbing for Untrusted Sources

### Problem
If a source IP is not in `trusted_cidrs`, the proxy currently ignores the PROXY header but leaves it in the `data` buffer. This "leaks" the attacker's header to the backend, which may trust it.

### Fix
In `cmd/proxy/main.go`, if `ProxyProtocol` is enabled:
1.  Always check for the presence of a PROXY header (v1 or v2).
2.  If a header is found:
    *   If the source is **Trusted**: parse and use the real IP, then strip the header.
    *   If the source is **Untrusted**: **STRIP THE HEADER** but do not use the IP. Log the attempt as a potential spoofing attack.

---

## 109b. Robust PROXY Parsing (Handling Partial Reads)

### Problem
The current implementation peeks once and fails if the full header isn't in the first read.

### Fix
Implement a small state-machine or a buffered reader for the initial connection phase:
1.  Read until `\r\n` (for v1) or the length indicated in the v2 header is reached.
2.  Enforce a `ProxyHeaderTimeout` (e.g., 500ms) to prevent Slow-loris attacks on the PROXY header.
3.  If a partial header is received and times out, drop the connection — do not fall through to TLS parsing with a corrupted stream.

---

## 109c. Unified Blocklist Logic (IP + Fingerprint)

### Problem
The Go proxy currently checks `ja4:blacklist` against the fingerprint only. IP-based entries in the blocklist are ignored.

### Fix
1.  **Redis Schema Split**: Split `ja4:blacklist` into `ja4:blacklist:fp` (SET of fingerprints) and `ja4:blacklist:cidr` (SET of IP/CIDR strings).
2.  **Management API Update**: Update `canonical_lists.py` to route blocklist entries to the correct SET based on whether they look like an IP/CIDR.
3.  **Proxy Core Update**: In `internal/security/pipeline.go`, ensure `UpdateSets` handles the split and `checkHardBlocks` checks the `dynamicCIDR` ranger for all IP blocks.

---

## Acceptance Criteria
- [ ] Test: Add `1.2.3.4` to blocklist; connection from `1.2.3.4` is blocked.
- [ ] Test: Add `t13d15...` to blocklist; connection with that fingerprint is blocked.
- [ ] Test: Untrusted source sends PROXY v1 header; backend receives raw TLS, not PROXY header.
- [ ] Test: Untrusted source sends PROXY v2 header; backend receives raw TLS.
- [ ] Test: Trusted source sends PROXY v1 in two separate TCP packets; proxy correctly extracts IP.
- [ ] Test: Malformed PROXY header from any source results in connection close, not fallthrough.
