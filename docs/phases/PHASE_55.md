# Phase 55: APT Hardening - Phase 2: Advanced Detection & Container Security

Priority: HIGH (Post-Phase 34)

## Goal
Implement advanced subnet-level signal correlation and strict container-level sandbox enforcement to detect and contain sophisticated adversaries.

## Sub-Tasks

### 55a — Subnet-Level Signal Correlation
- [ ] **Implementation:** Add logic to `src/security/pipeline.py` to check for "Rare Fingerprint Clusters" within /24 (IPv4) or /48 (IPv6) subnets.
- [ ] **Scoring:** If multiple unique IPs in the same subnet share a rare/malicious JA4, escalate the risk score for the entire subnet.
- [ ] **Metrics:** Add `ja4proxy_subnet_correlation_events_total` metric.

### 55b — Anti-Evasion & SNI Entropy
- [ ] **Entropy Scoring:** Implement hostname entropy calculation for SNI fields to detect high-entropy DGAs (Domain Generation Algorithms).
- [ ] **JA4/TLS Mismatch:** Detect and score mismatches between the JA4 fingerprint's claimed browser version and the actual TLS version used.

### 55c — Strict Container Sandbox (Seccomp/AppArmor)
- [ ] **Seccomp Profile:** Create `config/seccomp_profile.json` that forbids `execve`, `fork`, and `clone`.
- [ ] **AppArmor Profile:** Define a profile that limits file access to specific read-only paths and denies all outbound networking except to configured backend/redis.
- [ ] **Deployment:** Update `docker-compose.prod.yml` to apply these security options.

## Acceptance Criteria
- [ ] Strict Seccomp/AppArmor profiles enforced in production environment.
- [ ] Subnet-level signal correlation functional and verified with test corpus.
- [ ] DGA-like SNIs correctly identified and scored.
- [ ] Zero false positives on legitimate modern browser traffic.
