# Phase 55: APT Hardening - Phase 2: Advanced Detection & Container Security

**Status:** PROPOSED
**Priority:** HIGH (Post-Phase 34)
**Prerequisite:** Phase 34

## Goal

Implement advanced subnet-level signal correlation and strict container-level sandbox
enforcement to detect and contain sophisticated adversaries.

## Sub-Tasks

### 55a — Subnet-Level Signal Correlation

- [x] **Detection logic:** `CampaignDetector` in `src/analytics/detection.py:35–106` tracks
      block rates and fingerprint clusters per /24 (IPv4) and /48 (IPv6) subnet. *(Phase 12)*
- [ ] **Pipeline integration:** Wire subnet correlation findings from the analytics node into
      the live `src/security/pipeline.py` scoring path so per-connection scores are elevated
      when a cluster threshold is met.
- [ ] **Metrics:** Add `ja4proxy_subnet_correlation_events_total` metric.

### 55b — Anti-Evasion & SNI Entropy

- [x] **Entropy Scoring:** Shannon entropy + vowel-ratio DGA detection in
      `src/security/sni_analyzer.py:73–148`. Signal registered in `config/signal_scores.yml`
      as `dga`. *(Phase 4 / Phase 65)*
- [ ] **JA4/TLS Mismatch:** Detect and score mismatches between the JA4 fingerprint's implied
      browser/client version and the actual TLS version negotiated. Not yet implemented.

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

## Verification Plan

- [ ] Seccomp/AppArmor profiles enforced in both poc and prod compose stacks.
- [ ] Subnet-level signal correlation functional and verified with test corpus.
- [ ] DGA-like SNIs correctly identified and scored.
- [ ] Zero false positives on legitimate modern browser traffic (Tranco top-10k).
