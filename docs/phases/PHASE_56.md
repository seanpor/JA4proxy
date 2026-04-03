# Phase 56: Advanced APT - Phase 2: Deceptive Defense & Persistence Defense

Priority: HIGH (Post-Phase 35)

## Goal
Deploy deceptive "Honey-Assets" to identify attackers during the research phase and implement kernel-level isolation to prevent post-exploitation persistence.

## Sub-Tasks

### 56a — Honey-Fingerprints & Honey-SNIs
- [ ] **Implementation:** Define "Deception JA4" fingerprints in `config/deception.yml` that should never appear in legitimate traffic.
- [ ] **Detection:** Configure the proxy to monitor for specific deceptive hostnames (e.g., `admin-dev-portal.internal`).
- [ ] **Escalation:** If a honey-asset is hit, immediately promote the IP to `BAN` status with an `APT: DECEPTION_TRIGGERED` tag.
- [ ] **Silent Drops:** Implement "No-Feedback Blocking" (silent drops) for deception triggers to slow down attacker discovery.

### 56b — Runtime Persistence Defense
- [ ] **Two-Stage Seccomp:** Implement a startup Seccomp profile (permissive for binding) and a runtime profile (forbids `execve`, `fork`, and most file writes).
- [ ] **Namespace Isolation:** Move the `ProxyServer` into a dedicated network and PID namespace after initial socket binding.
- [ ] **Dead-Man's Switch:** Implement an internal integrity service that the proxy must heart-beat to; proxy self-terminates if heartbeat fails.

### 56c — Ephemeral Filesystem
- [ ] **tmpfs Overlays:** Configure `docker-compose.prod.yml` to use `tmpfs` for all writable paths (`/tmp`, `/var/run`).
- [ ] **Read-Only Root:** Enforce an immutable filesystem root for the proxy container.

## Acceptance Criteria
- [ ] Attacker using a Honey-Fingerprint is immediately blacklisted without feedback.
- [ ] Syscall lockdown confirmed via `strace` (no `execve` allowed during runtime).
- [ ] Persistence is impossible across container restarts due to `read_only` and `tmpfs`.
- [ ] Integrity heartbeat correctly triggers self-termination on failure.
