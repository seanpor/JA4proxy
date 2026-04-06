# Phase 34: APT Hardening - Phase 1: Parser Isolation & Redis Security

**Status:** COMPLETE
**Priority:** High (Post-Audit)
**Sequel:** ~~Phase 55 (cancelled — absorbed)~~ Phase 56 (deception, persistence defense)

> **Sprint note (2026-04-05):** Phase 55 has been cancelled and its remaining work absorbed
> here. The remaining open items are: Redis ACL users (34b), JA4/TLS mismatch detection
> (34c), proxy Seccomp JSON profile (34d), AppArmor profile (34d), subnet correlation
> pipeline wiring (34c), fuzz test (34a).

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
- [x] **Memory limit:** `RLIMIT_AS` applied to the parser process at `proxy.py:165` to bound
      memory consumption.
- [x] **Depth counter (N/A):** The pure-Python parser in `src/tls/parser.py` uses a single
      linear pass (non-recursive). Stack exhaustion via nested extensions is architecturally
      impossible — no depth counter needed.
- [ ] **Fuzz verification:** Send 10,000 malformed ClientHello packets; proxy throughput must
      remain stable and not raise unhandled exceptions.

---

## 34b: Secure State & Zero-Trust Redis (Week 2)

**Goal:** Secure Redis (the system's shared brain) against lateral movement.

- [x] **TLS transport:** `ssl=True` and `ssl_cert_reqs='required'` implemented in Redis client
      initialisation at `proxy.py:1580, 1622–1625`. *(configurable via `config/proxy.yml`)*
- [x] **Cryptographic signing:** HMAC-SHA256 `_verify_signature()` at `proxy.py:862–885` verifies
      `ja4:blacklist` and `ja4:whitelist` writes. Signing key read from Redis config at
      `proxy.py:1751`.
- [ ] **Least-privilege ACL users:** Create per-service Redis ACL users:
  - `proxy` user: read/write only proxy keyspace (`ratelimit:*`, `ban:*`, `beacon:*`).
  - `analytics` user: `XADD` to event streams only.
  - `admin` user: full access (management UI only).

---

## 34c: Advanced Detection & Anti-Evasion (Week 3)

**Goal:** Detect "Low and Slow" attacks that bypass standard beaconing detection.

> Previously some items in this section were deferred to Phase 55. Phase 55 has been
> cancelled; all remaining items are now owned by Phase 34 directly.

- [x] **Subnet-Level Correlation:** `CampaignDetector` in `src/analytics/detection.py:35–106`
      tracks /24 (IPv4) and /48 (IPv6) subnet-level aggregation of block rates and fingerprint
      clusters. Implemented as part of Phase 12 (Analytics).
- [x] **Entropy-Based SNI Scoring:** Shannon entropy + vowel-ratio analysis at
      `src/security/sni_analyzer.py:73–148` scores DGA-like hostnames. Signal registered in
      `config/signal_scores.yml` as `dga`. *(Phase 4 / Phase 65)*
- [ ] **Subnet correlation pipeline wiring:** Wire `CampaignDetector` findings into the live
      scoring pipeline so subnet-level block signals contribute to per-connection risk scores.
- [ ] **Anti-Fingerprint Spoofing:** Detect JA4 vs TLS version mismatches (e.g., a Chrome 120
      fingerprint presenting TLS 1.0). Not yet implemented.

---

## 34d: Runtime Hardening & Container Security (Week 3, concurrent with 34c)

**Goal:** Minimise the blast radius of a compromised container.

> `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and `tmpfs:`
> mounts are **already implemented** in `docker-compose.poc.yml` for all services. What remains
> is writing explicit Seccomp/AppArmor profile files and wiring them in. These items were
> previously listed under Phase 55; Phase 55 has been cancelled and they are now owned here.

- [x] **Immutable filesystem:** `read_only: true` for all services. *(docker-compose.poc.yml)*
- [x] **Capability drop:** `cap_drop: [ALL]` + selective `cap_add` where required.
      *(docker-compose.poc.yml)*
- [x] **No new privileges:** `security_opt: [no-new-privileges:true]` on every service.
      *(docker-compose.poc.yml)*
- [x] **Ephemeral tmpfs:** `/tmp` on `noexec,nosuid,nodev` tmpfs for proxy, redis, backend,
      tarpit. *(docker-compose.poc.yml)*
- [x] **TAP-mode Seccomp:** `config/seccomp_tap.json` exists with a comprehensive syscall
      allowlist for the TAP sensor. *(Phase 20)*
- [ ] **Proxy Seccomp profile:** Write `config/seccomp/proxy.json` for the main proxy process
      (distinct from the TAP seccomp). Wire into `docker-compose.poc.yml` and
      `docker/docker-compose.prod.yml`.
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

Phase 34 must complete before Phase 56 (deception, persistence defense) can begin. Phase 55
has been cancelled — its remaining items (subnet correlation wiring, Seccomp, AppArmor) are
now part of Phase 34 itself.
