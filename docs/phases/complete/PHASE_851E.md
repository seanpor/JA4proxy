<!--
title: Redis Pub/Sub & Cluster State Invariant Fuzzing
audience: developer
last_reviewed: 2026-10-28
phase: 851e
-->

# Redis Pub/Sub & Cluster State Invariant Fuzzing

> **Size:** SMALL
> **Dependencies:** [851d]
> **Branch:** `phase-851e-redis-pubsub-invariants`

---

## Goal

Harden the Redis Pub/Sub control channel and cluster synchronization layer (`internal/redis/pubsub.go`) against adversarial injection, malformed envelopes, signature forgery, and message tampering. Verify mathematical security invariants using Rapid property testing and native Go fuzzing, and benchmark message verification and dispatch throughput.

---

## Implementation Details

1. **Native Go Fuzzing (`internal/redis/pubsub_fuzz_test.go`)**:
   - `FuzzVerifyPubSubHMAC`: Tests verification totality across arbitrary payloads, channel names, and keys. Guarantees zero panics, clean error reporting, and resistance to malformed JSON envelopes.
   - `FuzzPubSubEnvelopeRoundtrip`: Validates that valid UTF-8 messages signed with `SignPubSubMessage` always verify successfully under matching secrets and fail under mismatched secrets.
   - `FuzzPubSubHandlerDispatch`: Fuzzes `PubSubHandler.handleMessage` across channel names, payloads, and secret configurations to guarantee panic-free dispatch under all channel permutations.
2. **Rapid Property-Based Invariant Tests**:
   - `TestProperty_HMAC_SignatureTamperingSensitivity`: Proves that any byte or bit flip in `Type`, `Value`, or `Signature` strictly causes verification to fail.
   - `TestProperty_CriticalChannelEnforcement`: Proves that critical channels (`config:reload`, `config:dial:change`, `ja4:blacklist:*`, `ja4:whitelist:*`, `geoip:cidr:update`) strictly drop unsigned messages when secret is configured, and drop unsigned messages when unset unless `allowUnsigned` is explicitly true (JA4PROXY-2026-0019 / JA4PROXY-2026-0121).
   - `TestProperty_SinglePurposeChannelTypeFallback`: Proves that empty `type` fields in single-purpose channel envelopes safely fall back to the channel name without signature confusion.
3. **Hardening in `SignPubSubMessage`**:
   - Added validation via `utf8.ValidString` on `msgType` and `value`. Previously, raw strings with invalid UTF-8 bytes were signed directly, but when serialized with `json.Marshal`, Go replaces invalid UTF-8 with `\uFFFD`, causing HMAC digest mismatch on deserialization.
4. **Smoke Gate Integration**:
   - Added `FuzzVerifyPubSubHMAC`, `FuzzPubSubEnvelopeRoundtrip`, and `FuzzPubSubHandlerDispatch` to `make test-go-fuzz-smoke`.

---

## Performance & Allocation Metrics

Tested on Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz:

| Benchmark | Latency (ns/op) | Memory (B/op) | Allocations (allocs/op) | Throughput |
|---|---|---|---|---|
| `BenchmarkVerifyPubSubHMAC` | 2,222 ns/op | 746 B/op | 10 allocs/op | ~450k msgs/sec |
| `BenchmarkSignPubSubMessage` | 2,069 ns/op | 1,121 B/op | 13 allocs/op | ~483k msgs/sec |
| `BenchmarkPubSubHandlerDispatch` | 2,903 ns/op | 1,277 B/op | 16 allocs/op | ~344k msgs/sec |

---

## Acceptance Criteria Verification

- [x] 3 native Go fuzz targets added for Pub/Sub HMAC verification, envelope roundtrip, and handler dispatch.
- [x] Rapid property tests prove signature tampering sensitivity, critical channel enforcement, and channel fallback invariants.
- [x] Zero panics across 250,000+ fuzz inputs.
- [x] Micro-benchmarks quantify verification and dispatch latency and allocations.
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.
