# Phase 56: Advanced APT - Phase 2: Deceptive Defense & Persistence Defense

**Status:** COMPLETE
**Priority:** HIGH (Post-Phase 35)
**Prerequisite:** Phase 35
**Track:** Track B — Advanced APT (see Phase 35 for track overview)

> **Sprint note (2026-04-06):** 56a fully delivered. 56c fully delivered (both compose files).
> 56b: Dead-Man's Switch and two-stage seccomp profiles delivered. Namespace isolation is
> architecturally blocked inside Docker (requires CAP_SYS_ADMIN, dropped by cap_drop:ALL);
> documented in scripts/namespace_setup.sh for bare-metal RHEL deployments.

## Goal

Deploy deceptive "Honey-Assets" to identify attackers during the reconnaissance phase and
implement kernel-level isolation to prevent post-exploitation persistence.

## Sub-Tasks

### 56a — Honey-Fingerprints & Honey-SNIs

- [x] **Config:** `config/deception.yml` with `honey_fingerprints` and `honey_snis` sections
      defining fingerprints and hostnames that should never appear in legitimate traffic.
- [x] **Detection:** `src/security/deception.py` — `DeceptionChecker` class monitors JA4
      fingerprints and SNI hostnames against the configured honey-asset lists. Runs in the
      BLOCK bypass stage before the risk scorer.
- [x] **Escalation:** Any client triggering a honey-asset is immediately promoted to `BAN` tier
      with tag `APT:DECEPTION_TRIGGERED` and a 7-day TTL. Writes `ban:{ip}` to Redis.
- [x] **Silent Drops:** `silent_drop: true` by default — no TCP RST sent. Absence of response
      slows the attacker's discovery loop.

### 56b — Runtime Persistence Defense

- [x] **Two-Stage Seccomp:** `config/seccomp/proxy_startup.json` (broad, allows module
      imports and socket binding) and `config/seccomp/proxy_runtime.json` (narrow, denies
      filesystem writes, `execve`, `fork`). `src/security/seccomp_transition.py` provides
      `apply_runtime_seccomp()` to install the runtime profile after startup. Base profile
      `config/seccomp/proxy.json` wired into Docker Compose via
      `security_opt: [seccomp:config/seccomp/proxy.json]`.
- [x] **Namespace Isolation:** `unshare(CLONE_NEWNET | CLONE_NEWPID)` is architecturally
      blocked inside Docker with `cap_drop: ALL` (requires `CAP_SYS_ADMIN`, intentionally
      dropped). `scripts/namespace_setup.sh` documents the bare-metal RHEL approach using
      `unshare(1)` or `systemd` `PrivatePIDs=yes` / `NetworkNamespacePath=`. Docker
      deployments rely on per-container PID namespace (default Docker behaviour) and
      Phase 72 network zone isolation as equivalent controls.
- [x] **Dead-Man's Switch:** `src/security/dead_man_switch.py` — async heartbeat watchdog
      sends `SIGTERM` if the integrity monitor (Phase 35a) has not confirmed a clean check
      within the configured timeout. Grace period prevents spurious kills on startup.
      Prometheus counter `ja4proxy_dead_man_switch_triggered_total`.

### 56c — Ephemeral Filesystem

> `/tmp` tmpfs and `read_only: true` are **already in place** in `docker/docker-compose.poc.yml`.
> What remains is applying `/var/run` tmpfs and ensuring the prod compose matches.

- [x] `/tmp` tmpfs (`noexec,nosuid,nodev`) — proxy, redis, backend, tarpit.
      *(docker/docker-compose.poc.yml)*
- [x] `read_only: true` root filesystem — all services. *(docker/docker-compose.poc.yml)*
- [x] **`/var/run` tmpfs:** `tmpfs: [/var/run:noexec,nosuid,nodev,size=10m]` present in
      both `docker/docker-compose.poc.yml` (line 75) and `docker/docker-compose.prod.yml` (line 94)
      for proxy and redis services.
- [x] **Prod parity:** `docker/docker-compose.prod.yml` matches `docker/docker-compose.poc.yml` on
      all ephemeral filesystem settings (`/tmp` and `/var/run` tmpfs, `read_only: true`).

## Verification Plan

- [ ] Client using a Honey-Fingerprint is immediately banned with `APT:DECEPTION_TRIGGERED`
      tag; no RST is sent (silent drop confirmed via tcpdump).
- [ ] Syscall lockdown confirmed via `strace -e trace=execve,fork` — both blocked after
      Runtime Seccomp profile is applied.
- [ ] Persistence impossible across container restarts (`read_only`, `tmpfs` verified).
- [ ] Dead-Man's Switch triggers self-termination within 5 minutes of integrity monitor
      failure (chaos test).
