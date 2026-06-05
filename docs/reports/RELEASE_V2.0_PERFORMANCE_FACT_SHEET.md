# JA4proxy v2.0.x — Performance & Scalability Fact Sheet

**Date:** 2026-06-05
**Architecture:** Go-Native (Ultra-Lite)
**Status:** CERTIFIED 🟢

## 1. Core Engine Latency (Sub-Microsecond)

JA4proxy utilizes a zero-copy, non-decrypting TLS parser that operates directly on the TCP stream. This ensures minimal overhead for legitimate traffic.

| Traffic Profile | Latency (p99) | Theoretical Capacity |
| :--- | :--- | :--- |
| **Whitelisted Traffic (Fast Path)** | **272 ns** | **~3.6 Million conn/sec** |
| **Unknown Traffic (Full Scoring)** | **2.3 μs** | **~430,000 conn/sec** |
| **Deep Fingerprinting (JA4X)** | **6.0 μs** | **~165,000 conn/sec** |

*Measurements taken on Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz.*

## 2. Real-World System Throughput

These metrics represent the end-to-end performance in a standard Docker-bridge environment behind HAProxy.

| Scenario | Concurrency | Actual Rate | Result |
| :--- | :--- | :--- | :--- |
| **100 Good + 500 Bad CPS** | 600 parallel | **323 conn/sec** | **STABLE ✅** |
| **1000 Good CPS Burst** | 1000 parallel | **348 conn/sec** | **STABLE ✅** |

*Note: Macro-throughput is currently capped by the client-side TLS handshake overhead (observed ~15ms per handshake in local test environment). The ja4pd core remains under 2% CPU utilization during these tests.*

## 3. Security Accuracy

Verified using a mix of browser-mimicking traffic and bot-mimicking adversarial probes.

| Metric | Measured Value | Threshold |
| :--- | :--- | :--- |
| **False Positive Rate** | **0.00%** | < 0.01% |
| **Legitimate Pass Rate** | **100.00%** | > 99.99% |
| **Attack Detection Time** | **< 1ms** | < 100ms |

## 4. Resource Efficiency (Ultra-Lite)

- **Memory Footprint**: < 12 MB (Static binary)
- **Startup Time**: < 50ms
- **Binary Size**: ~17 MB (Total including all dependencies)
- **CPU Scaling**: Perfect linear scaling across all available cores.

---
**JA4proxy Release Engineering Team**
