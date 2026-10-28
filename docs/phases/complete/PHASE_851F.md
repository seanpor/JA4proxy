<!--
title: Webhook Dispatch & Retry Queue Invariant Testing
audience: developer
last_reviewed: 2026-10-28
phase: 851f
-->

# Webhook Dispatch & Retry Queue Invariant Testing

> **Size:** SMALL
> **Dependencies:** [851e]
> **Branch:** `phase-851f-webhook-dispatch-invariants`

---

## Goal

Harden the outbound security alert and ECS event webhook pipeline (`internal/webhook/delivery.go`) against memory leaks, queue starvation, SSRF bypasses, and secret exposure under burst and network failure scenarios. Verify delivery invariants using Rapid property testing and native Go fuzzing, and benchmark delivery queue ingestion and HMAC-SHA256 signing throughput.

---

## Scope

### In Scope
1. **Native Go Fuzzing (`internal/webhook/dispatch_fuzz_test.go`)**:
   - `FuzzIsPrivateIP`: Fuzz IP parsing and private/reserved IPv4 classification across arbitrary IP bytes and strings.
   - `FuzzWebhookEventDelivery`: Fuzz event ID, event type, client IP, and JA4 strings under end-to-end `Deliver` dispatch.
2. **Rapid Property-Based Invariant Tests**:
   - **Secret Redaction Invariant (JA4PROXY-2026-0051)**: Under arbitrary string formatting (`String()`, `GoString()`), JSON marshaling, or logrus logging of `WebhookEndpoint`, the plain-text secret is never emitted (always `[REDACTED]`). Dispatcher closure also zeroes all referenced secret slices.
   - **SSRF Rejection Invariant**: Loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and reserved (`240.0.0.0/4`) addresses are strictly rejected when `AllowPrivateIPs` is false.
   - **Event Filtering Invariant**: Endpoints configured with specific event lists only receive matching events; empty event lists receive all events.
3. **Micro-Benchmarks**:
   - `BenchmarkComputeHMAC`: Measure HMAC-SHA256 generation throughput per alert.
   - `BenchmarkDeliverEventEndToEnd`: Measure end-to-end event delivery through an HTTP receiver.
4. **Smoke Gate Integration**:
   - Integrated `FuzzIsPrivateIP` and `FuzzWebhookEventDelivery` into `make test-go-fuzz-smoke`.

### Out of Scope
- Modifying remote Redis DLQ schema or alertmanager notification templates.

---

## Results & Verification

### Benchmarks (Intel i9-9900K @ 3.60GHz)
- `BenchmarkComputeHMAC-16`: **1,327 ns/op** (768 B/op, 10 allocs/op) $\to$ **~753,000 ops/sec**.
- `BenchmarkDeliverEventEndToEnd-16`: **138,116 ns/op** (24,830 B/op, 203 allocs/op) $\to$ **~7,240 deliveries/sec** per HTTP worker.

### Fuzzing & Invariants
- `FuzzIsPrivateIP`: **202,078 executions** (41,419 execs/sec) — zero panics, strict totality.
- `FuzzWebhookEventDelivery`: **58,861 executions** (6,173 execs/sec) — zero panics across arbitrary event schemas.
- `TestProperty_WebhookEndpointSecretRedaction`: Passed 100 iterations.
- `TestProperty_EventFilteringInvariants`: Passed 100 iterations.
- `TestProperty_SSRFIPClassification`: Passed 100 iterations.

---

## Acceptance Criteria
- [x] 2 native Go fuzz targets added for IP classification and webhook delivery.
- [x] Rapid property tests prove secret redaction, event filtering, and SSRF rejection invariants.
- [x] Zero panics across 260,000+ fuzz inputs.
- [x] Micro-benchmarks quantify HMAC signing and end-to-end delivery throughput.
- [x] `make test-go-fuzz-smoke` and `make preflight` pass 100% green.
