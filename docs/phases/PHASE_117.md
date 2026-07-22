# Phase 117 — DMZ Network Hardening & Anti-Smuggling

> **Status:** SUPERSEDED by Phase 118 — rescoped under Phase 121e
> **Size:** MEDIUM (4-6 engineer-days)
> **Triggered by:** Phase 108 Pentest Finding [L1-018], [L1-019], [L4-028]
> **Superseded by:** `docs/phases/complete/PHASE_118.md` (§118a PROXY anti-smuggling, §118b TLS reassembly + protocol lockdown, §118c XFF hardening)

---

## Rescoped against canonical register (Phase 121e, 2026-04-19)

Every finding 117a/b/c listed below already has a canonical entry in
`docs/security/findings.yaml` via `source_refs.report: PHASE_117` and is
implemented under Phase 118's corresponding sub-phase. This file is kept as
a historical pointer; do not add new findings here.

| 117 local ID | Implemented under | Source-of-truth entry |
|---|---|---|
| 117a PROXY anti-smuggling | 118a | register (grep `PHASE_117` / `117a`) |
| 117b TLS reassembly + protocol lockdown | 118b | register (`PHASE_117` / `117b`) |
| 117c X-Forwarded-For hardening | 118c | register (`PHASE_117` / `117c`) |

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

## 117b. Robust TLS Handshake Reassembly & Protocol Lockdown

### Problem
Attackers can bypass JA4 fingerprinting by fragmenting the ClientHello at the TCP layer, or smuggle headers by hiding them just outside the initial read buffer.

### Fix
1.  **Reassembly Loop**: Implement a reassembly loop in `handleConn`. The proxy must read the first 5 bytes to determine the TLS record length, then use `io.ReadFull` to wait until the full handshake record is received (up to a 16KB limit).
2.  **Strict Next-Byte Validation (The "Seal")**: Immediately after reassembling the handshake and stripping any PROXY headers, the proxy MUST validate the first byte of the resulting payload. 
    *   If the byte is NOT `0x16` (TLS Handshake), the connection MUST be dropped.
    *   This prevents attackers from smuggling raw HTTP, SSH, or subsequent PROXY headers behind the initial scrubbed layer.
3.  **Timeout Enforcement**: Apply a strict `ProxyReadTimeout` (e.g., 200ms) to the entire reassembly process to prevent "Slow-loris" style resource exhaustion.

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
- [ ] Test: Byte-level smuggling; sending `[Legit PROXY][Scrubbed Bytes][GET / HTTP/1.1]` results in immediate drop due to non-0x16 byte.
- [ ] Test: Sending `X-Forwarded-For: 1.2.3.4` from the client; verify the proxy identifies the real client IP (appended by HAProxy) rather than `1.2.3.4`.
