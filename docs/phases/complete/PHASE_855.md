<!--
title: eBPF Volumetric Drop Daemon Invariants & Synchronization Hardening
audience: developer
last_reviewed: 2026-10-29
phase: 855
-->

# eBPF Volumetric Drop Daemon Invariants & Synchronization Hardening

> **Size:** SMALL
> **Dependencies:** [854]
> **Branch:** `phase-855-ebpf-sync-hardening`

---

## Goal

Harden the Redis-to-eBPF synchronization daemon (`scripts/redis-to-ebpf.py`) against malformed Redis key corruption, unhandled network disconnects, bpftool execution errors, and metric counter resets, ensuring robust fail-open daemon operation without requiring privileged kernel access or root privileges.

---

## Junior Dev Feasibility & Sizing

- **Verdict:** **SMALL (Scoped strictly to userspace daemon robustness)**.
- **Why it fits:** Focuses entirely on Python error handling, Redis connection resilience, and mocked `bpftool` execution in `scripts/redis-to-ebpf.py`.
- **Junior Dev Protections:** Does NOT touch C kernel code, XDP bytecode, or Linux kernel capabilities (`CAP_BPF`). All property tests run inside the containerized pytest environment (`ja4proxy-tools`) with mocked subprocess and Redis clients.

---

## Scope

### In Scope
1. **Redis Key & Value Invariants (`tests/unit/security/test_ebpf_sync_hardening.py`)**:
   - Verify `scripts/redis-to-ebpf.py` safely filters non-UTF-8 bytes, invalid IP strings, empty keys, and corrupt Redis data types without crashing `_sync_loop`.
   - Verify `_ip_to_hex` correctly handles malformed IPv4 and non-IPv4 addresses.
2. **Subprocess Resilience & Fail-Open Verification**:
   - Test mocked `bpftool` command executions: timeouts, non-zero return codes, and malformed JSON output from `bpftool map dump`.
   - Ensure exceptions are caught, logged, increment `EBPF_SYNC_ERRORS`, and never terminate the sync loop.
3. **Redis Connection Drop & Recovery Invariant**:
   - Verify that Redis `ConnectionError` or connection drop mid-scan triggers backoff and clean reconnection without leaking sockets or thread resources.
4. **Drop Counter Monotonicity**:
   - Verify drop counter delta calculations handle zero-resets or counter wraps gracefully without negative rate anomalies.
5. **Smoke Gate Integration**:
   - Passes cleanly in `make test-unit`.

### Out of Scope
- Writing or compiling C eBPF/XDP kernel programs.
- Kernel filesystem pin map migrations (`/sys/fs/bpf`) or kernel LPM trie tables (deferred to future architectural phases).

---

## Implementation Plan

1. **Step 1: Remote Lease & Manifest Registration**
   - Claim `phase-855-ebpf-sync-hardening`.
   - Update `docs/phases/manifest.yaml` marking Phase 855 `IN_PROGRESS`.
2. **Step 2: Test Implementation (`tests/unit/security/test_ebpf_sync_hardening.py`)**
   - Author property-based unit tests for malformed Redis keys, mocked `bpftool` errors, and Redis reconnection loops.
3. **Step 3: Daemon Hardening (`scripts/redis-to-ebpf.py`)**
   - Address any edge cases discovered by tests to ensure zero-crash fail-open behavior.
4. **Step 4: Closeout**
   - Move phase doc to `docs/phases/complete/PHASE_855.md`.
   - Update manifest (`COMPLETE`), news fragment, `make preflight`, PR, auto-merge.

---

## Acceptance Criteria
- [ ] Comprehensive unit and property tests added in `tests/unit/security/test_ebpf_sync_hardening.py`.
- [ ] `scripts/redis-to-ebpf.py` verified fail-open against corrupt Redis data, connection drops, and `bpftool` failures.
- [ ] All tests run 100% in user space inside `ja4proxy-tools` with zero kernel privileges.
- [ ] `make test-unit` and `make preflight` pass 100% green.
