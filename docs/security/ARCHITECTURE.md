# Security Architecture: JA4proxy

This document outlines the defense-in-depth architecture of JA4proxy, detailing how the system protects backends against automated threats, impersonation, and protocol-level attacks.

---

## 1. Multi-Layer Defense Model

JA4proxy operates a prioritized enforcement pipeline that follows the "Fail-Fast" principle.

### Layer 1: Protocol Lockdown (Content-Type Verification)
*   **Mechanism:** Immediate byte-level inspection of the first data packet after PROXY-header stripping.
*   **Enforcement:** Connections that do not begin with `0x16` (TLS Handshake) are dropped instantly.
*   **Defense Against:** HTTP smuggling, SSH-over-HTTPS injection, and PROXY-header re-injection.

### Layer 2: Hard Block (Known Identity & Reputation)
*   **Mechanism:** High-speed lookup against Redis-backed sets.
*   **Enforcement:** Immediate TCP Reset (RST) for matches in:
    *   **JA4 Blacklist:** Fingerprints of known C2 agents (Cobalt Strike, Sliver).
    *   **Geo-IP Blocklist:** High-risk origin countries.
    *   **Spamhaus DROP:** Known malicious subnets.

### Layer 3: Risk Scoring (Signal Intelligence)
*   **Mechanism:** Weighted scoring of multiple TLS and network signals.
*   **Signals:**
    *   **malicious_sni:** (Score 100) RFC-non-compliant or shell-injection SNI hostnames.
    *   **ja4_tls_mismatch:** (Score 35) JA4 claims TLS 1.3, but the handshake negotiates lower.
    *   **no_ptr:** (Score 15) Missing reverse DNS record.
    *   **dga_detection:** (Score up to 40) Algorithmic hostname generation detection.
*   **Enforcement:** Decision based on cumulative score vs. adaptive thresholds.

---

## 2. Operational Security & Integrity

### Signed Dial (Control Plane Protection)
The "Dial" (enforcement strictness) is protected by an HMAC-SHA256 signature.
*   If the signature in Redis is missing or invalid, the proxy **fails closed** to Dial 0 (Monitor Mode) to prevent unauthorized mass-blocking or bypass.

### Sandboxing & Least Privilege
*   **Seccomp:** Restricted syscall set prunes unused filesystem and process management calls (e.g., `mkdir`, `chmod`, `ptrace`).
*   **AppArmor:** Mandatory Access Control (MAC) limits filesystem access to strictly necessary configuration and socket paths.
*   **Immutable Supply Chain:** All production base images are pinned to immutable SHA256 digests.

### Cardinality Guard
Protects the monitoring stack from "Cardinality Explosion" attacks by capping the number of unique Prometheus label values (SNI/JA4) that can be emitted.

---

## 3. Data Integrity & Privacy
*   **Fail-Closed Rate Limiting:** Redis connectivity failure defaults to strict, safe enforcement levels.
*   **SSRF Protection:** Webhook delivery module strictly blocks loopback, private, and link-local IP targets for alert notifications.

---
**Version:** 2.0 (Go Implementation)
**Audited:** 2026-06-03
