# Phase 65 — Performance Hardening & Go/Python Parity

**Status:** COMPLETE
**Date:** 2026-04-03

## Goal
Optimize the Python proxy hot path, close remaining Go configuration gaps, and establish a permanent cross-language parity mechanism via binary fixtures and a shared score registry.

## 65a. Python Hot Path Optimization
- Implement a pure-Python TLS ClientHello parser to eliminate Scapy IPC overhead (~1.5ms per connection).
- Move GREASE value filtering to an O(1) frozenset lookup.
- Reduce redundant filtering in `JA4Generator.generate_ja4`.
- Optimize connection logging by hashing only the first 64 bytes of ClientHello data.

## 65b. Go Configuration Completion
- Add missing YAML configuration structs for all signal modules (Groups 4–6).
- Wire all signal parameters in `cmd/proxy/main.go`.
- Ensure default values align with the Python implementation.

## 65c. Parity Tooling
- Establish `tests/fixtures/clienthello/known_ja4.json` as the cross-language ground truth.
- Create `config/signal_scores.yml` as the authoritative source for both implementations.
- Implement `scripts/check-signal-scores.py` to prevent score drift.
- Implement `scripts/parity-check.py` for end-to-end decision verification.

## Acceptance Criteria

### A — Python parser
- [x] `src/tls/parser.py` passes all adversarial inputs in `tests/fixtures/clienthello/` without raising
- [x] Output dict is compatible with Scapy's `TLSParser` for all `.bin` fixtures
- [x] `_analyze_tls_handshake` uses `parse_client_hello` directly (no executor call)
- [x] Python baseline_latency mean latency improves by ≥ 1ms vs pre-phase benchmark

### B — JA4 correctness fixes
- [x] `_is_grease` replaced by module-level frozenset check
- [x] GREASE filtering occurs exactly once per JA4 computation (not twice)
- [x] All existing JA4 tests still pass

### C + D — Go config wiring (Completed in Phase 15 Close-out)
- [x] All 7 signal modules have YAML struct types in `loader.go`
- [x] `buildPipelineConfig` populates all fields
- [x] Go proxy loaded with reference `proxy.yml` has non-zero scores for datacenter IPs, bots with missing SNI, and rate-limited IPs

### E — Binary fixtures
- [x] Real browser `.bin` files captured and committed (`curl_tls13.bin`)
- [x] `tests/fixtures/clienthello/known_ja4.json` established as the ground truth
- [x] Python test: `parse_client_hello(fixture)` produces correct JA4 for all files
- [x] Go test: `tls.ComputeJA4(tls.ParseClientHello(fixture))` matches ground truth

### F — Signal score registry
- [x] `config/signal_scores.yml` covers all signals in `docs/STYLE_GUIDE.md §1f`
- [x] `scripts/check-signal-scores.py` exits 0 on clean codebase
- [x] `make check-scores` added and passing

### G — Parity harness
- [x] `scripts/parity-check.py` established for payload delivery comparison
- [x] All `.bin` fixtures can be delivered to both proxies simultaneously
- [x] `make parity-check` added to Makefile
