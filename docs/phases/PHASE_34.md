# Phase 34: APT Hardening - Phase 1: Parser Isolation & Redis Security

**Status:** PROPOSED
**Estimated Duration:** 3 Weeks (reduced from 4 — 34a substantially completed by Phase 65)
**Priority:** High (Post-Audit)
**Sequel:** Phase 55 (APT Hardening - Phase 2: Advanced Detection & Container Security)

---

## 34a: Parser Isolation & Robustness (Week 1)

**Goal:** Prevent memory-unsafe parsing logic from compromising the proxy process.

> **Phase 65 update:** The original plan called for moving Scapy's `TLSParser.parse_client_hello`
> into a `ProcessPoolExecutor` with `RLIMIT_AS`. Phase 65 delivered a superior solution: a
> pure-Python ClientHello parser (`src/tls/parser.py`) that eliminates the Scapy dependency
> entirely, removing the unsafe parsing surface with zero IPC overhead. Phase 69 then replaced
> the `ProcessPoolExecutor` fallback with `ThreadPoolExecutor`. The remaining work is the
> depth-counter hardening below.

- [x] **Parser replacement:** Pure-Python TLS ClientHello parser (`src/tls/parser.py`) replaces
      Scapy — no IPC, no unsafe C extension on the hot path. *(Phase 65)*
- [x] **Executor safety:** `ThreadPoolExecutor` fallback replaces the original `ProcessPoolExecutor`
      plan. *(Phase 69)*
- [ ] **Depth counter:** Add a `depth` counter to extension parsing in `src/tls/parser.py` to
      prevent deeply nested TLS extensions from causing stack exhaustion.
- [ ] **Fuzz verification:** Send 10,000 malformed ClientHello packets; proxy throughput must
      remain stable and not raise unhandled exceptions.

---

## 34b: Secure State & Zero-Trust Redis (Week 2)

**Goal:** Secure Redis (the system's shared brain) against lateral movement.

- [ ] **TLS transport:** Enable `ssl=True` and `ssl_cert_reqs='required'` in all Redis clients
      (`src/security/*.py`, analytics node, Go proxy `internal/redis/`).
- [ ] **Cryptographic signing:** Add an HMAC `signature` field to security-critical Redis keys
      (`ja4:blacklist`, `config:dial`, `config:thresholds`). The pipeline must reject writes
      that lack a valid signature.
- [ ] **Least-privilege ACL users:** Create per-service Redis ACL users:
  - `proxy` user: read/write only proxy keyspace (`ratelimit:*`, `ban:*`, `beacon:*`).
  - `analytics` user: `XADD` to event streams only.
  - `admin` user: full access (management UI only).

---

## 34c: Advanced Detection & Anti-Evasion (Week 3)

**Goal:** Detect "Low and Slow" attacks that bypass standard beaconing detection.

> These signals are **specified here** and **implemented in Phase 55** (the designated sequel).
> Phase 55 depends on Phase 34 completing first.

- [ ] **Subnet-Level Correlation** *(Phase 55a)*: Aggregate signals across IPs in a /24 (IPv4)
      or /48 (IPv6) subnet that share a rare JA4 fingerprint. Score the subnet more aggressively
      after N IPs trigger the same pattern within a rolling window.
- [ ] **Entropy-Based SNI Scoring** *(Phase 55b)*: Score high-entropy hostnames in the SNI
      field as likely DGA targets, even when absent from blocklists.
- [ ] **Anti-Fingerprint Spoofing** *(Phase 55b)*: Detect JA4 vs TLS version mismatches
      (e.g., a Chrome 120 fingerprint presenting TLS 1.0).

---

## 34d: Runtime Hardening & Container Security (Week 3, concurrent with 34c)

**Goal:** Minimise the blast radius of a compromised container.

> `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and `tmpfs:`
> mounts are **already implemented** in `docker-compose.poc.yml` for all services. What remains
> is writing explicit Seccomp/AppArmor profile files and wiring them in.

- [x] **Immutable filesystem:** `read_only: true` for all services. *(docker-compose.poc.yml)*
- [x] **Capability drop:** `cap_drop: [ALL]` + selective `cap_add` where required.
      *(docker-compose.poc.yml)*
- [x] **No new privileges:** `security_opt: [no-new-privileges:true]` on every service.
      *(docker-compose.poc.yml)*
- [x] **Ephemeral tmpfs:** `/tmp` on `noexec,nosuid,nodev` tmpfs for proxy, redis, backend,
      tarpit. *(docker-compose.poc.yml)*
- [ ] **Seccomp profile:** Write `config/seccomp/proxy.json` allowing only the syscalls required
      by the proxy. Wire into `docker-compose.poc.yml`:
      `security_opt: [seccomp:config/seccomp/proxy.json]`.
- [ ] **AppArmor profile:** Write `config/apparmor/ja4proxy` forbidding shell spawning and
      outbound connections to any host other than `$BACKEND_HOST` and `$REDIS_HOST`.

---

## Verification Plan

- **Depth exhaustion:** Send a ClientHello with 500 nested extensions; `src/tls/parser.py` must
  not stack-overflow.
- **Redis signing:** Manually `SET ja4:blacklist somevalue` without a valid HMAC signature;
  pipeline must reject the write.
- **ACL breach:** Attempt `XADD` to an event stream using the `proxy` ACL user; Redis must
  return `NOPERM`.
- **Seccomp audit:** Use `strace -c` during normal operation; confirm no forbidden syscalls
  (`execve`, outbound `connect` to non-whitelisted hosts).
- **Fuzz stability:** 10,000 malformed TLS packets processed without throughput degradation or
  unhandled exceptions.

---

## Dependencies

Phase 34 must complete before Phase 55 (subnet correlation, AppArmor/Seccomp implementation)
and Phase 56 (deception, persistence defense) can begin.
