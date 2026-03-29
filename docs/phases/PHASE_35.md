# Phase 35: Advanced APT Countermeasures & Integrity Enforcement

Status: PROPOSED
**Estimated Duration:** 4 Weeks
**Priority:** High (Post-Hardening)

---

## 29a: Supply Chain & Configuration Integrity (Week 1)
**Goal:** Ensure the proxy only runs authorized code and uses untampered configurations.
- [ ] **Implementation:** Create a `ConfigSigner` utility to generate RSA/Ed25519 signatures for `proxy.yml` and GeoIP databases.
- [ ] **Enforcement:** The `ProxyServer` must verify the signature of its configuration on startup and refuse to run if invalid.
- [ ] **Integrity Monitoring:** Implement a background task that periodically re-verifies the checksum of the `proxy.py` and `src/` directory to detect on-disk tampering.
- [ ] **Audit:** Log all integrity check results to an immutable, cryptographically-chained local log.

## 29b: Kernel-Level Enforcement (eBPF/XDP) (Week 2)
**Goal:** Offload high-volume blocking to the kernel to prevent CPU exhaustion and proxy-level bypass.
- [ ] **Implementation:** Develop a simple eBPF/XDP program to drop packets from blacklisted IPs at the NIC driver level.
- [ ] **Synchronization:** Create a `RedisToEbpf` sync service that pushes "Critical" blacklisted IPs from Redis sets into eBPF maps.
- [ ] **Resilience:** This provides "fail-closed" security even if the `proxy.py` userspace process is overwhelmed or crashing.
- [ ] **Metrics:** Export eBPF-level drop statistics to Prometheus for visibility into "Deep Perimeter" blocking.

## 29c: Deceptive Defense & Honey-Assets (Week 3)
**Goal:** Flush out sophisticated adversaries by "poisoning" their scanning and research tools.
- [ ] **Honey-Fingerprints:** Define a set of "Deception JA4" fingerprints in `config/deception.yml`. These are fingerprints that should never appear in legitimate traffic.
- [ ] **Honey-SNIs:** Configure the proxy to respond to specific deceptive hostnames (e.g., `admin-dev-portal.internal`).
- [ ] **Immediate Escalation:** If any client uses a Honey-Fingerprint or Honey-SNI, they are immediately promoted to the `BAN` tier with an "APT: DECEPTION_TRIGGERED" tag.
- [ ] **No-Feedback Blocking:** Use silent drops (no TCP RST) for deception triggers to slow down the attacker's discovery process.

## 29d: Post-Exploitation Persistence Defense (Week 4)
**Goal:** Prevent an attacker from gaining a permanent foothold if they achieve code execution.
- [ ] **Two-Stage Seccomp:** Implement a "Startup" profile (allows file loading, socket binding) and a "Runtime" profile (forbids `execve`, `fork`, and most file writes).
- [ ] **Process Isolation:** Use `unshare` or similar to move the `ProxyServer` into a dedicated network and PID namespace, isolating it from the rest of the container.
- [ ] **Self-Termination:** Implement a "Dead-Man's Switch" where the proxy terminates if it cannot reach its internal integrity-monitoring service for more than 5 minutes.
- [ ] **Ephemeral Filesystem:** Enforce a `tmpfs` overlay for all writable paths (`/tmp`, `/var/run`), ensuring reboot-persistence is impossible.

---

## Verification Plan
- **Integrity Test:** Manually modify a line in `proxy.yml` and verify the proxy fails to start.
- **Performance Audit:** Verify that eBPF-level drops result in 0% CPU increase for the `proxy.py` process during a 100k pps syn-flood from blacklisted IPs.
- **Red Team Deception:** Simulate an attacker scanning the environment with a custom TLS stack; verify they are tagged and blacklisted immediately upon hitting a honey-fingerprint.
- **Syscall Lockdown:** Use `strace` to confirm that `execve` is blocked after the proxy enters its "Runtime" phase.
