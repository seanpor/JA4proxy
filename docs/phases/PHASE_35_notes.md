# Phase 35 — Implementation Notes

**Branch:** `feat/phase-35-apt-integrity-ebpf`
**Date:** 2026-04-05
**Team:** Test writer agent, code writer agent, critical reviewer agent, coordinator

---

## What Was Built

### 35a — Supply Chain & Configuration Integrity

- `src/security/integrity_monitor.py` — `IntegrityMonitor` class:
  - `verify_config_signature()` — Ed25519 startup verification. Fails open (returns True)
    if the `cryptography` library is absent; fails closed (returns False → caller exits 1)
    if sig is present but invalid. Default config has `verify_on_startup: false` so
    first-deploy behaviour is always monitor-only.
  - `start_background_monitor()` — async task hashing monitored paths every N seconds.
    Exception handling is inside the while loop so a single hash error does not kill
    the monitor permanently.
  - `append_audit_log()` — append-only JSON-line log with SHA-256 hash chain. Hash is
    computed over the line text WITHOUT the trailing newline (documented in docstring).
- `scripts/config-signer.py` — CLI: `genkey` / `sign` / `verify`. Keys stored as
  base64-encoded raw 32 bytes. Private key written with `O_CREAT|O_EXCL|0o600` —
  no TOCTOU window.
- `proxy.py` wiring — startup verification gated by `integrity.verify_on_startup: false`.
  Background monitor launched as asyncio task in `start()`, cancelled in shutdown.

### 35b — eBPF/XDP Kernel-Level Blocking

- `ebpf/ja4block.c` — XDP program. Parses Ethernet + IPv4 headers, looks up source IP
  in `blocked_ips` (BPF_MAP_TYPE_HASH), increments per-CPU drop counter, returns
  XDP_DROP. IPv6 intentionally not supported (would need `__u128` key map — documented).
- `scripts/redis-to-ebpf.py` — async sidecar polling Redis every 5s. Sources IPs from
  `ban:*` (Phase 0 schema) and `ip:blacklist` SET (Phase 35, now in REDIS_SCHEMA.md).
  Graceful fallback: FileNotFoundError / PermissionError / CalledProcessError from
  bpftool → logs WARNING, continues without eBPF. Redis client closed in finally block.
- `ebpf/Makefile` — `clang -O2 -target bpf` build target.

### 35c — Metrics & Observability

- `monitoring/alertmanager/rules/ebpf_attack.yml` — fires when eBPF drop rate > 10k/s
  AND `rate(process_cpu_seconds_total[1m]) < 0.05` (proxy CPU < 5%). Detects volumetric
  attacks absorbed entirely by the kernel while the proxy is idle.

---

## Notable Decisions

| Decision | Rationale |
|---|---|
| `verify_on_startup: false` default | Fail-open on first deploy; operator must consciously enable after signing |
| Hash chain hashes line WITHOUT `\n` | Simpler to reason about and test; documented in docstring |
| New files post-baseline log at WARNING | A new file could be a planted backdoor; INFO would silently accept it |
| eBPF uses combined counter (index 0) | XDP cannot distinguish blacklist vs ban at packet level; sidecar tracks reason |
| Redis client closed in `finally` | Prevents resource leak when `_sync_loop` is cancelled |
| `logging.basicConfig` guarded | Module-level basicConfig would poison root logger when imported by tests |
| `asyncio.CancelledError` re-raised in sync loop | `task.cancel()` callers must receive CancelledError for correct asyncio cleanup |

---

## Review Findings Addressed

A critical reviewer agent identified 5 critical, 6 high, and 6 medium issues.
Full details in `docs/phases/details/PHASE_35_review.md`.

Key fixes applied during/after review:
- Constructor signature mismatch (tests used 0 args, impl required 1) → made optional
- Hash chain encoding inconsistency → standardised on no-newline hashing
- CLI flag name mismatch (`--key` vs `--privkey`) → aligned
- Key format incompatibility (PEM vs raw base64) → aligned
- `PermissionError` not caught in bpftool calls → added
- All `test_ebpf_sync.py` tests silently skipping → rewrote to test actual API
- `__pycache__` hashing causing false positives → skip filter added
- Deleted files re-alerting every cycle → `del baseline[path]` after first alert
- `asyncio.CancelledError` swallowed in sync loop → changed to `raise`
- Alertmanager PromQL bug (`process_cpu_seconds_total < 0.05` is a counter, not rate) → fixed to `rate(...[1m]) < 0.05`
- Redis client leak → `finally: await redis_client.aclose()`
- `logging.basicConfig` at module level in script → guarded with handler check

---

## Known Limitations

- eBPF XDP enforcement is IPv4 only. IPv6 bans are enforced by the proxy layer only.
  Adding IPv6 XDP support requires a separate `BPF_MAP_TYPE_HASH` with `__u128` keys
  and a separate userspace sync path.
- The audit log hash chain detects in-line tampering but cannot detect truncation.
  Full truncation resistance requires OS-level append-only attributes (`chattr +a`)
  or shipping logs to a remote SIEM. This is documented in the class docstring.
- `shutdown_on_violation` calls `sys.exit(1)` inside an async context, which
  terminates the entire process (asyncio event loop included). This is intentional
  for the tamper-detected shutdown scenario.
