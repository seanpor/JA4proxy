# Phase 55: APT Hardening - Phase 2: Advanced Detection & Container Security

**Status:** PROPOSED
**Priority:** HIGH (Post-Phase 34)
**Prerequisite:** Phase 34

## Goal

Implement advanced subnet-level signal correlation and strict container-level sandbox
enforcement to detect and contain sophisticated adversaries.

## Sub-Tasks

### 55a — Subnet-Level Signal Correlation

- [ ] **Implementation:** Add logic to `src/security/pipeline.py` to detect "Rare Fingerprint
      Clusters" — multiple unique IPs in the same /24 (IPv4) or /48 (IPv6) subnet sharing a
      rare or malicious JA4 fingerprint within a rolling time window.
- [ ] **Scoring:** Escalate risk score for the entire subnet once the cluster threshold is met.
- [ ] **Metrics:** Add `ja4proxy_subnet_correlation_events_total` metric.

### 55b — Anti-Evasion & SNI Entropy

- [ ] **Entropy Scoring:** Implement hostname entropy calculation for SNI fields to detect
      high-entropy DGAs (Domain Generation Algorithms) not in any blocklist.
- [ ] **JA4/TLS Mismatch:** Detect and score mismatches between the JA4 fingerprint's implied
      browser/client version and the actual TLS version negotiated.

### 55c — Strict Container Sandbox (Seccomp/AppArmor)

> `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and `/tmp`
> tmpfs are already in place in `docker-compose.poc.yml`. What remains is writing and loading
> the explicit Seccomp and AppArmor profile files.

- [x] `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, `/tmp` tmpfs — all services.
      *(docker-compose.poc.yml)*
- [ ] **Seccomp Profile:** Create `config/seccomp/proxy.json` forbidding `execve`, `fork`, and
      `clone`. Apply via `security_opt: [seccomp:config/seccomp/proxy.json]` in both
      `docker-compose.poc.yml` and `docker/docker-compose.prod.yml`.
- [ ] **AppArmor Profile:** Define `config/apparmor/ja4proxy` — restrict file access to
      read-only paths; deny all outbound connections except to `$BACKEND_HOST` and
      `$REDIS_HOST`. Apply in both compose files.

## Acceptance Criteria

- [ ] Seccomp/AppArmor profiles enforced in both poc and prod compose stacks.
- [ ] Subnet-level signal correlation functional and verified with test corpus.
- [ ] DGA-like SNIs correctly identified and scored.
- [ ] Zero false positives on legitimate modern browser traffic (Tranco top-10k).
