# Phase 35: Advanced APT Countermeasures & Integrity Enforcement

**Status:** PROPOSED
**Estimated Duration:** 4 Weeks
**Priority:** High (Post-Hardening)
**Prerequisite:** Phase 34
**Sequel:** Phase 56 (Advanced APT - Phase 2: Deceptive Defense & Persistence)

---

## 35a: Supply Chain & Configuration Integrity (Week 1)

**Goal:** Ensure the proxy runs only authorized code and uses untampered configuration.

- [ ] **ConfigSigner utility:** Create `scripts/config-signer.py` to generate Ed25519 signatures
      for `config/proxy.yml` and GeoIP databases. Signed artifacts stored alongside the config
      (`config/proxy.yml.sig`, `config/geoip.mmdb.sig`).
- [ ] **Startup verification:** `ProxyServer.__init__` must verify the Ed25519 signature of
      `config/proxy.yml` before accepting any connections. Exit 1 (fail closed) if the signature
      is absent or invalid.
- [ ] **Background integrity monitor:** Async task that re-computes SHA-256 checksums of
      `proxy.py` and `src/` every 60 s. On mismatch: emit
      `ja4proxy_integrity_violation_total` (Prometheus critical), log at ERROR, and optionally
      trigger a graceful shutdown.
- [ ] **Cryptographic audit log:** All integrity check results written to an append-only local
      log (`/var/log/ja4proxy/integrity.log`). Each entry includes the SHA-256 of the previous
      entry, forming a hash chain that cannot be silently tampered with.

---

## 35b: Kernel-Level Enforcement (eBPF/XDP) (Week 2)

**Goal:** Offload high-volume blocking to the kernel to prevent CPU exhaustion and proxy-level
bypass.

- [ ] **eBPF/XDP program:** Develop `ebpf/ja4block.c` — an XDP program that drops packets from
      IPs in a BPF hash map. Compile with `clang -O2 -target bpf`. Load at startup via
      `ip link set dev eth0 xdpgeneric obj ja4block.o sec xdp`.
- [ ] **RedisToEbpf sync service:** `scripts/redis-to-ebpf.py` reads `ja4:blacklist` and
      `ban:*` keys from Redis and populates the BPF map via `bpftool map update`. Runs as a
      sidecar with a 5 s poll interval.
- [ ] **Prometheus metrics:** Export eBPF-level drop counters via the XDP stats map.
      Metric: `ja4proxy_ebpf_drops_total{reason="blacklist|ban"}`.
- [ ] **Graceful fallback:** If eBPF attach fails (non-root, missing kernel support, no
      `CAP_BPF`), log a WARNING and continue — proxy startup must not be blocked.

---

## 35c: Deceptive Defense & Honey-Assets (Week 3)

**Goal:** Flush out sophisticated adversaries by poisoning their scanning and reconnaissance
tools.

> These assets are **specified here** and **implemented in Phase 56a** (the designated sequel).
> Phase 56 depends on Phase 35 completing first.

- [ ] **Honey-Fingerprints** *(Phase 56a)*: Define a set of "Deception JA4" fingerprints in
      `config/deception.yml` — fingerprints that should never appear in legitimate traffic.
      Any client presenting a honey-fingerprint is immediately promoted to the `BAN` tier with
      tag `APT:DECEPTION_TRIGGERED` and a 7-day TTL.
- [ ] **Honey-SNIs** *(Phase 56a)*: Configure the proxy to recognise specific deceptive
      hostnames (e.g., `admin-dev-portal.internal`). Triggers the same immediate BAN +
      silent drop (no TCP RST, to slow the attacker's discovery loop).
- [ ] **No-Feedback policy** *(Phase 56a)*: Silent drops (no RST or ICMP) for all
      deception-triggered connections.

---

## 35d: Post-Exploitation Persistence Defense (Week 4)

**Goal:** Prevent an attacker from gaining a permanent foothold if they achieve code execution.

> These controls are **specified here** and **implemented in Phase 56b**.

- [ ] **Two-Stage Seccomp** *(Phase 56b)*: "Startup" profile (allows file loading, socket
      binding) transitions to a locked-down "Runtime" profile (forbids `execve`, `fork`, most
      file writes) once the proxy has fully initialized.
- [ ] **Process Isolation** *(Phase 56b)*: Use `unshare(CLONE_NEWNET | CLONE_NEWPID)` to move
      `ProxyServer` into a dedicated network and PID namespace, isolating it from the rest of
      the container.
- [ ] **Dead-Man's Switch** *(Phase 56b)*: Proxy self-terminates if it cannot reach its
      internal integrity-monitoring service for more than 5 minutes.
- [ ] **Ephemeral Filesystem** *(Phase 56b)*: Enforce tmpfs overlays for all writable paths
      (`/tmp`, `/var/run`). Note: `/tmp` tmpfs is already applied in `docker-compose.poc.yml`;
      `/var/run` tmpfs needs to be added.

---

## Verification Plan

- **Integrity test:** Manually modify a line in `config/proxy.yml`; verify proxy exits with
  code 1 on the next startup attempt.
- **Hash-chain audit:** Verify each entry in `/var/log/ja4proxy/integrity.log` correctly
  includes the SHA-256 of the previous entry.
- **eBPF performance:** During a 100k pps SYN-flood from blacklisted IPs, CPU usage of the
  proxy process must not increase (drops handled entirely in the kernel).
- **eBPF fallback:** Start the proxy as a non-root user without `CAP_BPF`; verify it starts
  successfully with a WARNING log and no eBPF attachment.
- **Red-team deception** *(Phase 56)*: Connect with a custom TLS stack presenting a
  honey-fingerprint; verify immediate BAN with `APT:DECEPTION_TRIGGERED` tag in Redis and a
  silent drop (no RST visible to the attacker).
- **Syscall lockdown** *(Phase 56)*: Use `strace -e trace=execve,fork` to confirm both are
  blocked after the proxy enters its Runtime Seccomp phase.

---

## Dependencies

Phase 35 must complete before Phase 56 (deceptive defense, persistence) can begin. Phase 35
is independent of Phase 34, but both should be completed before Phase 55 and 56 are started.
