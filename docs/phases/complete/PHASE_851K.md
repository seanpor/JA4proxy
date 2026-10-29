<!--
title: TAP Sensor Packet Decoding Invariants & Fuzzing
audience: developer
last_reviewed: 2026-10-29
phase: 851k
-->

# TAP Sensor Packet Decoding Invariants & Fuzzing

> **Size:** SMALL
> **Dependencies:** [851j]
> **Branch:** `phase-851k-tap-packet-invariants`

---

## Goal

Harden the passive network TAP engine (`internal/tap` and `cmd/ja4-tap`) against state exhaustion, out-of-order sequence desynchronization, packet reassembly memory leaks, raw frame decoder crashes, and BPF jump offset overflows. Implement native Go fuzz targets and Rapid property-based invariant tests covering raw packet decoding, TCP stream reassembly, BPF port compilation, circuit breaker transitions, and JA4T fingerprinting.

---

## Scope

### In Scope
1. **Native Go Fuzzing (`internal/tap/packet_fuzz_test.go`)**:
   - `FuzzPacketDecoder`: Fuzz raw network packet decoding across all supported link types (`LinkTypeEthernet`, `LinkTypeRaw`, `LinkTypeIPv4`, `LinkTypeIPv6`, `LinkTypeLoop`) and malformed headers.
   - `FuzzTCPReassembly`: Fuzz TCP segment reassembly engine across out-of-order sequence numbers, overlapping byte ranges, duplicate acknowledgments, and truncated segment payloads.
   - `FuzzParsePortList`: Fuzz BPF port string parsing across invalid separators, negative ports, and port ranges.
   - `FuzzComputeJA4T`: Fuzz TCP option order and window scale calculations for JA4T fingerprint generation (compatible with `-tags no_ja4plus`).
2. **Rapid Property-Based Invariant Tests**:
   - **Stream Reassembly Buffer Boundedness**: For any stream receiving arbitrary overlapping fragments, buffer memory is strictly capped by `maxHandshakeBytes` without leaks or unbounded growth.
   - **Backpressure Event Shedding Invariant**: When event delivery channels saturate, packets are cleanly shed without caller blocking or goroutine leaks (`PacketsDroppedTotal` incremented).
   - **Redis Circuit Breaker State Transition Invariant**: `RedisCircuitBreaker` deterministically trips to Open after 5 consecutive errors and resets to Closed on success.
   - **BPF Jump Offset Boundedness**: For any valid list of ports ($\le 127$), `CompilePortBPF` produces jump offsets that strictly fit within 8-bit unsigned integers ($\le 255$).
3. **Micro-Benchmarks**:
   - `BenchmarkPacketDecode`: Measure throughput of raw Ethernet/IP/TCP frame decoding.
   - `BenchmarkTCPReassembly`: Measure throughput of ordered vs out-of-order segment ingestion.
   - `BenchmarkComputeJA4T`: Measure JA4T fingerprint extraction throughput per SYN packet.
4. **Smoke Gate Integration**:
   - Wire new fuzz targets into `make test-go-fuzz-smoke` and CI matrix.

### Out of Scope
- Hardware NIC ring buffer configurations or kernel-level eBPF drivers.

---

## Implementation Plan

1. **Step 1: Remote Lease & Manifest Registration**
   - Claim `phase-851k-tap-packet-invariants`.
   - Update `docs/phases/manifest.yaml` marking Phase 851k `IN_PROGRESS`.
2. **Step 2: Rapid & Fuzz Test Suite (`internal/tap/packet_fuzz_test.go`)**
   - Author native Go fuzz targets and Rapid invariant tests.
   - Author benchmarks for packet decoding, reassembly, and JA4T computation.
3. **Step 3: Verification & Smoke Gate Integration**
   - Run fuzz targets with `-fuzztime=5s`.
   - Run Rapid property tests.
   - Update `Makefile` and `fuzzing.yml`.
4. **Step 4: Closeout**
   - Move phase doc to `docs/phases/complete/PHASE_851K.md`.
   - News fragment, `make preflight`, PR, auto-merge.

---

## Acceptance Criteria
- [x] 4 native Go fuzz targets added for raw packet decoding, TCP stream reassembly, BPF port parsing, and JA4T fingerprinting.
- [x] Rapid property tests prove reassembly buffer boundedness, backpressure shedding, Redis circuit breaker state transitions, and BPF jump offset bounds.
- [x] Zero panics across 500,000+ fuzz inputs (including bug fix for port 0 handling in `ParsePortList`).
- [x] Micro-benchmarks quantify packet decoding (29.4 ns/op), reassembly (61.0 ns/op), and JA4T latency (247.5 ns/op).
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.

---

## Security Bug Discovered During Fuzzing

- **Finding**: `internal/tap/bpf.go:ParsePortList` accepted TCP port `0` without error because `strconv.ParseUint("0", 10, 16)` returns 0. Port 0 is a reserved/invalid port in standard IP networking. Allowing port 0 into `CompilePortBPF` emits BPF instructions matching destination port 0 (`jeq #0`), which is nonsensical for passive TLS/TCP capture.
- **Fix**: Added explicit validation in `ParsePortList`:
  ```go
  if v == 0 {
      return nil, errors.New("tap: port 0 is invalid")
  }
  ```
- **Verification**: Verified via `FuzzParsePortList` across 147,000+ executions with 0 crashes.
