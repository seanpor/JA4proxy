# Phase 34: APT Resilience & Infrastructure Hardening

Status: PROPOSED
**Estimated Duration:** 4 Weeks
**Priority:** High (Post-Audit)

---

## 28a: Parser Isolation & Robustness (Week 1)
**Goal:** Prevent memory-unsafe parsing logic in Scapy from compromising the proxy process.
- [ ] **Implementation:** Move `TLSParser.parse_client_hello` calls into a `ProcessPoolExecutor` with a restricted memory limit (RLIMIT_AS).
- [ ] **Hardening:** Implement a `depth` counter in extension parsing to prevent deeply nested TLS extensions from causing stack exhaustion.
- [ ] **Verification:** Use `multiprocessing` mocks to ensure the proxy survives a SIGSEGV in the parser process.

## 28b: Secure State & Zero-Trust Redis (Week 2)
**Goal:** Secure the "Brain" of the system (Redis) against lateral movement.
- [ ] **Implementation:** Enable `ssl=True` and `ssl_cert_reqs='required'` in all Redis clients.
- [ ] **Cryptographic Signing:** Add a `signature` field to all Redis-stored security lists (`ja4:blacklist`, `config:thresholds`). Reject unsigned updates.
- [ ] **Least Privilege:** Transition from a single Redis user to ACLs (e.g., Proxy user can only `GET`/`SET` specific keys; Analytics user can only `XADD`).

## 28c: Advanced Detection & Anti-Evasion (Week 3)
**Goal:** Detect "Low and Slow" attacks that bypass standard beaconing detection.
- [ ] **Subnet-Level Correlation:** Implement cross-IP signal aggregation where a /24 subnet sharing a rare JA4 fingerprint is scored more aggressively.
- [ ] **Entropy-Based SNI Scoring:** Detect high-entropy (likely DGA) hostnames in the SNI field even if they aren't in known blocklists.
- [ ] **Anti-Fingerprint Spoofing:** Track "JA4 vs TLS Version" mismatches (e.g., a Chrome 120 fingerprint claiming to use TLS 1.0).

## 28d: Runtime Hardening & Container Security (Week 4)
**Goal:** Minimize the "Blast Radius" of a compromised container.
- [ ] **AppArmor/Seccomp:** Implement a strict profile that forbids the `proxy.py` process from spawning any shells or initiating outbound connections except to `backend_host` and `redis_host`.
- [ ] **Capabilities:** Drop all Linux capabilities (`CAP_CHOWN`, `CAP_SETUID`, etc.) from the container runtime.
- [ ] **Immutable Infrastructure:** Enforce `read_only: true` in Docker Compose for the proxy service root.

---

## Verification Plan
- **Red Team Simulation:** Attempt to bypass the "Progressive Dial" by manipulating Redis directly (should fail due to signatures).
- **Crash Test:** Send 10,000 malformed TLS packets designed to crash Scapy; proxy throughput should remain stable.
- **Syscall Audit:** Use `strace` to verify that no forbidden syscalls are attempted during normal operation.
