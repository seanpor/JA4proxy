# Phase 35: Advanced APT Countermeasures & Integrity Enforcement

**Status:** PROPOSED
**Estimated Duration:** 4 Weeks
**Priority:** High (Post-Hardening)
**Prerequisite:** Phase 34 (recommended, but 35 can run concurrently with 34)
**Sequel:** Phase 56 (Advanced APT - Phase 2: Deceptive Defense & Persistence)

> **Note:** Phase 56 covers deceptive defense and persistence — Phase 35 owns supply chain
> integrity and kernel-level enforcement only.

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

## 35c: eBPF Metrics & Observability (Week 3)

**Goal:** Make kernel-level drop activity visible to operators and alert on volumetric attacks.

- [ ] **Prometheus metric wiring:** Ensure `ja4proxy_ebpf_drops_total{reason="blacklist|ban"}`
      is scraped by the Prometheus instance and visible in the metrics endpoint at
      `/metrics`. Counter increments must be sourced from the XDP stats map populated in 35b.
- [ ] **Grafana panel:** Add a "Kernel-Level Drop Rate" panel to the main Grafana dashboard
      showing `rate(ja4proxy_ebpf_drops_total[1m])` broken out by `reason` label.
- [ ] **Alert rule:** Configure an Alertmanager rule:
      - **Condition:** eBPF drop rate > 10,000 drops/s **and** proxy process CPU < 5%.
      - **Meaning:** High-volume traffic is being dropped at kernel level but the proxy itself
        is not under load — indicates a volumetric (DDoS/SYN-flood) attack where eBPF is
        absorbing the burst.
      - **Severity:** `critical`
      - **Annotation:** "Possible volumetric attack — kernel absorbing burst, proxy CPU nominal."

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
- **Metrics visibility:** Confirm `ja4proxy_ebpf_drops_total` appears in `/metrics` output
  and the Grafana panel renders the correct time-series.
- **Alert firing:** Simulate > 10k drops/s (via BPF map injection) with proxy idle; confirm
  Alertmanager fires the volumetric-attack alert within one evaluation interval.

---

## Dependencies

Phase 35 must complete before Phase 56 (deceptive defense, persistence) can begin. Phase 35
is independent of Phase 34, but Phase 34 baseline container hardening should be complete
before Phase 56 is started.
