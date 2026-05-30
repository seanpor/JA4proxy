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
- [x] **Fuzz verification:** `tests/unit/test_tls_parser_fuzz.py` — 15 test functions covering
      empty inputs, truncation, random bytes, 500 nested extensions (stack exhaustion), length
      overflows, and non-handshake record types. All pass without unhandled exceptions.

---

## 34b: Secure State & Zero-Trust Redis (Week 2)

**Goal:** Secure Redis (the system's shared brain) against lateral movement.

- [x] **TLS transport:** `ssl=True` and `ssl_cert_reqs='required'` implemented in Redis client
      initialisation at `proxy.py:1580, 1622–1625`. *(configurable via `config/proxy.yml`)*
- [x] **Cryptographic signing:** HMAC-SHA256 `_verify_signature()` at `proxy.py:862–885` verifies
      `ja4:blacklist` and `ja4:whitelist` writes. Signing key read from Redis config at
      `proxy.py:1751`.
- [x] **Least-privilege ACL users:** `config/redis/users.acl` defines `ja4proxy`, `admin`,
      `monitor`, and `backup` users with scoped keyspace access. `scripts/redis-acl-setup.sh`
      applies them. Wired in `config/redis/redis.conf` (`aclfile`) and `config/proxy.yml`
      (`redis.acl_users`). Enabled via `acl_users.enabled: true`.

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
- [x] **Subnet correlation pipeline wiring:** `src/security/pipeline.py:438–502` reads
      `analytics:campaign:{subnet}` and `analytics:slowscan:{subnet}` keys and emits
      `subnet_campaign` and `slowscan` `RiskSignal`s into the live scoring pipeline.
- [x] **Anti-Fingerprint Spoofing:** `check_ja4_tls_mismatch()` in
      `src/security/tls_enforcer.py:175` detects JA4 vs TLS version mismatches; wired into
      pipeline at `src/security/pipeline.py:852`. Prometheus counter
      `ja4proxy_ja4_tls_mismatch_total` tracks detections.

---

## 34d: Runtime Hardening & Container Security (Week 3, concurrent with 34c)

**Goal:** Minimise the blast radius of a compromised container.

> `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and `tmpfs:`
> mounts are **already implemented** in `docker/docker-compose.poc.yml` for all services. What remains
> is writing explicit Seccomp/AppArmor profile files and wiring them in. These items were
> previously listed under Phase 55; Phase 55 has been cancelled and they are now owned here.

- [x] **Immutable filesystem:** `read_only: true` for all services. *(docker/docker-compose.poc.yml)*
- [x] **Capability drop:** `cap_drop: [ALL]` + selective `cap_add` where required.
      *(docker/docker-compose.poc.yml)*
- [x] **No new privileges:** `security_opt: [no-new-privileges:true]` on every service.
      *(docker/docker-compose.poc.yml)*
- [x] **Ephemeral tmpfs:** `/tmp` on `noexec,nosuid,nodev` tmpfs for proxy, redis, backend,
      tarpit. *(docker/docker-compose.poc.yml)*
- [x] **TAP-mode Seccomp:** `config/seccomp_tap.json` exists with a comprehensive syscall
      allowlist for the TAP sensor. *(Phase 20)*
- [x] **Proxy Seccomp profile:** `config/seccomp/proxy.json` exists. Wired into
      `docker/docker-compose.poc.yml` at `security_opt: [seccomp:config/seccomp/proxy.json]`.
- [x] **AppArmor profile:** `config/apparmor/ja4proxy` — denies shell/ptrace execution,
      allows Python runtime + redis Unix socket + TCP stream. Wired (commented) into
      docker/docker-compose.poc.yml and docker/docker-compose.prod.yml with host-load instructions.
      Note: outbound IP whitelisting is at nftables level (Phase 72); AppArmor handles
      exec/ptrace denial.

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
