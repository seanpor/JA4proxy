# Phase 56: Advanced APT - Phase 2: Deceptive Defense & Persistence Defense

**Status:** PROPOSED
**Priority:** HIGH (Post-Phase 35)
**Prerequisite:** Phase 35

## Goal

Deploy deceptive "Honey-Assets" to identify attackers during the reconnaissance phase and
implement kernel-level isolation to prevent post-exploitation persistence.

## Sub-Tasks

### 56a — Honey-Fingerprints & Honey-SNIs

- [ ] **Config:** Define "Deception JA4" fingerprints in `config/deception.yml` — fingerprints
      that should never appear in legitimate traffic.
- [ ] **Detection:** Configure the proxy to monitor for deceptive hostnames in the SNI field
      (e.g., `admin-dev-portal.internal`, `internal-api.corp`).
- [ ] **Escalation:** Any client triggering a honey-asset is immediately promoted to `BAN` tier
      with tag `APT:DECEPTION_TRIGGERED` and a 7-day TTL. Write to Redis: `ban:{ip}`.
- [ ] **Silent Drops:** No TCP RST sent — silent drop only. Absence of response slows the
      attacker's discovery loop.

### 56b — Runtime Persistence Defense

- [ ] **Two-Stage Seccomp:** Startup profile (allows file loading, socket binding) transitions
      to a Runtime profile (forbids `execve`, `fork`, most file writes) once the proxy has
      fully initialized and accepted its first connection.
- [ ] **Namespace Isolation:** Use `unshare(CLONE_NEWNET | CLONE_NEWPID)` to move
      `ProxyServer` into a dedicated network and PID namespace after initial socket binding.
- [ ] **Dead-Man's Switch:** Async heartbeat task — proxy self-terminates if the integrity
      monitor (Phase 35a) has not confirmed a clean check within 5 minutes.

### 56c — Ephemeral Filesystem

> `/tmp` tmpfs and `read_only: true` are **already in place** in `docker-compose.poc.yml`.
> What remains is applying `/var/run` tmpfs and ensuring the prod compose matches.

- [x] `/tmp` tmpfs (`noexec,nosuid,nodev`) — proxy, redis, backend, tarpit.
      *(docker-compose.poc.yml)*
- [x] `read_only: true` root filesystem — all services. *(docker-compose.poc.yml)*
- [ ] **`/var/run` tmpfs:** Add `tmpfs: [/var/run:noexec,nosuid,nodev,size=10m]` to the
      proxy service in both `docker-compose.poc.yml` and `docker/docker-compose.prod.yml`.
- [ ] **Prod parity:** Ensure `docker/docker-compose.prod.yml` matches poc on all ephemeral
      filesystem settings.

## Acceptance Criteria

- [ ] Client using a Honey-Fingerprint is immediately banned with `APT:DECEPTION_TRIGGERED`
      tag; no RST is sent (silent drop confirmed via tcpdump).
- [ ] Syscall lockdown confirmed via `strace -e trace=execve,fork` — both blocked after
      Runtime Seccomp profile is applied.
- [ ] Persistence impossible across container restarts (`read_only`, `tmpfs` verified).
- [ ] Dead-Man's Switch triggers self-termination within 5 minutes of integrity monitor
      failure (chaos test).
