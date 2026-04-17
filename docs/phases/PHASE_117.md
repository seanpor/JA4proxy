# Phase 117 — DMZ Network Hardening & Anti-Smuggling

> **Status:** PROPOSED
> **Size:** MEDIUM (4-6 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L1-018], [L1-019], [L4-028]

---

## Goal

Harden the proxy against sophisticated external network-layer attacks, specifically targeting DMZ bypasses and fragmentation evasion.

---

## 117a. Anti-Smuggling (Second Header Check)

### Problem
Attackers can smuggle a second `PROXY` header immediately after the legitimate one, which the proxy forwards to the backend, enabling DMZ scanning.

### Fix
1.  In `cmd/proxy/main.go`, after stripping the legitimate PROXY header:
2.  Explicitly check if the remaining `data` buffer starts with the byte string `PROXY ` (v1) or the v2 binary signature.
3.  If a second header is detected, drop the connection immediately and log a "PROXY smuggling attempt" alert.

---

## 117b. Robust TLS Handshake Reassembly

### Problem
Attackers can bypass JA4 fingerprinting by fragmenting the ClientHello at the TCP layer, causing `ParseClientHello` to return `ErrTruncated`.

### Fix
1.  Implement a reassembly loop in `handleConn`:
2.  Read the first 5 bytes to determine the TLS record length.
3.  Use `io.ReadFull` (or a loop) to wait until the number of bytes specified in the record header has been received.
4.  Apply a strict `ProxyReadTimeout` (e.g., 200ms) to the entire reassembly process to prevent DoS.

---

## 117c. X-Forwarded-For Hardening

### Problem
The Python proxy extracts the first IP from XFF, allowing attackers to spoof their IP by sending their own header.

### Fix
1.  Modify `_extract_client_ip_from_http` in `proxy.py`.
2.  Iterate through the XFF header values from **right to left**.
3.  The rightmost IP added by our own HAProxy is the only one that should be trusted as the "real" client IP.

---

## Acceptance Criteria
- [ ] Test: Smuggled PROXY header (two headers in a row) results in connection drop.
- [ ] Test: Fragmented ClientHello (sent in 3 packets) is correctly reassembled and JA4 is generated.
- [ ] Test: Sending `X-Forwarded-For: 1.2.3.4` from the client; verify the proxy identifies the real client IP (appended by HAProxy) rather than `1.2.3.4`.
