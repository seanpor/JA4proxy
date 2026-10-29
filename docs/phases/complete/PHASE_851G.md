<!--
title: QUIC Packet & Frame Parsing Invariants & Fuzzing
audience: developer
last_reviewed: 2026-10-29
phase: 851g
-->

# QUIC Packet & Frame Parsing Invariants & Fuzzing

> **Size:** SMALL
> **Dependencies:** [851f]
> **Branch:** `phase-851g-quic-packet-invariants`

---

## Goal

Harden the QUIC parsing pipeline (`internal/quic`) against untrusted packet/frame crashes, DoS via memory amplification or state exhaustion, and malformed header inputs. Implement native Go fuzz targets and Rapid property-based invariant tests covering QUIC variable-length integer parsing, CRYPTO frame extraction/defragmentation, Initial packet header decoding, and connection tracking bounds. Establish micro-benchmarks for varint decoding and CRYPTO frame parsing.

---

## Scope

### In Scope
1. **Native Go Fuzzing (`internal/quic/packet_fuzz_test.go`)**:
   - `FuzzReadVarint`: Fuzz RFC 9000 §16 variable-length integer decoder across all prefix modes (1, 2, 4, 8 bytes) and boundary lengths for panic-freedom and correct error signaling.
   - `FuzzParseCRYPTOFrames`: Fuzz frame extraction across arbitrary payload byte streams (type, offset, length, truncated frames, random frame multiplexing).
   - `FuzzDecodeInitialHeader`: Fuzz UDP payload header parsing (RFC 9000 §17.2 Long Header, DCID, SCID, Token, Length varints).
2. **Rapid Property-Based Invariant Tests**:
   - **Varint Invariant**: Roundtrip encoding and decoding across arbitrary 6-bit, 14-bit, 30-bit, and 62-bit integer boundaries; decoded byte length matches RFC 9000 prefix.
   - **CRYPTO Reassembly & Max Allocation Bound Invariant**: Total extracted/defragmented payload is strictly bounded by `MaxCryptoBytes` (16,384 bytes). No combination of overlapping or fragmented offsets can trigger out-of-bounds slice indexing or unbounded memory allocation.
   - **Decoder Connection Table Saturation Invariant**: Under arbitrary injection of distinct connection IDs (DCIDs), `active` map size never exceeds `MaxActive` (4,096 entries). Excess connections trigger `quic: active connection limit exceeded` without goroutine panics or memory leaks.
   - **JA4Q Determinism & Version Invariant**: For identical `ClientHelloFeatures`, `ComputeJA4Q` is 100% deterministic, handles unrecognized QUIC versions gracefully, and formats strictly as `{version}_{sni}_{12_hex}`.
3. **Micro-Benchmarks**:
   - `BenchmarkReadVarint`: Measures varint decoding throughput and zero-allocation properties across 1, 2, 4, and 8 byte sizes (1.48–2.32 ns/op, 0 allocs).
   - `BenchmarkParseCRYPTOFramesMultiFrag`: Measures multi-fragment CRYPTO frame extraction throughput (195.8 ns/op, 512 B/op, 3 allocs).
4. **Smoke Gate Integration**:
   - Integrated `FuzzReadVarint`, `FuzzParseCRYPTOFrames`, and `FuzzDecodeInitialHeader` into `make test-go-fuzz-smoke`.

### Out of Scope
- Implementing full QUIC transport state machine (ACK processing, flow control, loss recovery).
- Real-time UDP network sockets (the package operates on parsed frames/flows).

---

## Results & Verification

### Benchmarks (Intel i9-9900K @ 3.60GHz)
- `BenchmarkReadVarint/1-Byte-16`: **1.48 ns/op** (0 B/op, 0 allocs/op) $\to$ **~675,000,000 ops/sec**.
- `BenchmarkReadVarint/2-Byte-16`: **1.65 ns/op** (0 B/op, 0 allocs/op) $\to$ **~606,000,000 ops/sec**.
- `BenchmarkReadVarint/4-Byte-16`: **1.77 ns/op** (0 B/op, 0 allocs/op) $\to$ **~565,000,000 ops/sec**.
- `BenchmarkReadVarint/8-Byte-16`: **2.33 ns/op** (0 B/op, 0 allocs/op) $\to$ **~429,000,000 ops/sec**.
- `BenchmarkParseCRYPTOFrames-16`: **150.5 ns/op** (208 B/op, 3 allocs/op).
- `BenchmarkParseCRYPTOFramesMultiFrag-16`: **195.8 ns/op** (512 B/op, 3 allocs/op).
- `BenchmarkParseClientHelloFeatures-16`: **75.72 ns/op** (120 B/op, 2 allocs/op).

### Fuzzing & Invariants
- `FuzzReadVarint`: **427,233 executions** (85,833 execs/sec) — zero panics, strict roundtrip equivalence.
- `FuzzParseCRYPTOFrames`: **263,124 executions** (70,606 execs/sec) — zero out-of-bounds indexing or panics.
- `FuzzDecodeInitialHeader`: **397,748 executions** (80,507 execs/sec) — zero unhandled packet boundaries.
- `TestProperty_VarintRoundtrip`: Passed 100 iterations.
- `TestProperty_CRYPTOFrameBounds`: Passed 100 iterations (`MaxCryptoBytes` ceiling strictly observed).
- `TestProperty_DecoderCapacityBound`: Passed 100 iterations (`MaxActive` ceiling strictly observed).
- `TestProperty_JA4QDeterminism`: Passed 100 iterations.

---

## Acceptance Criteria
- [x] 3 native Go fuzz targets added for varints, CRYPTO frame parsing, and Initial packet decoding.
- [x] Rapid property tests prove RFC 9000 varint totality, CRYPTO defragmentation bounds (`MaxCryptoBytes`), connection map limits (`MaxActive`), and JA4Q determinism.
- [x] Zero panics across 1,000,000+ fuzz inputs.
- [x] Micro-benchmarks quantify varint and CRYPTO frame parsing throughput and allocations.
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.
