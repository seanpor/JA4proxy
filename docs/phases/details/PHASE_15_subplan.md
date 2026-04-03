# Phase 15 Sub-Plan: Closing the Go Rewrite

## Current Status (April 3, 2026)
Implementation is 100% complete. Core proxy, TLS parsing, and all 14 signal modules are functional with full configuration parity and dynamic list support.

## Remaining Tasks

### 1. Implement Dynamic Redis Security Lists (Priority: HIGH)
The Go proxy must parity the Python proxy's ability to check Redis for real-time blocks/allows.
- [x] **Add Redis Set support**: Add `SMembers`, `SAdd`, `SRem` to `internal/redis/client.go`.
- [x] **Thread-safe Pipeline Lists**: Add mutex-protected maps to `internal/security/pipeline.go` for JA4 lists.
- [x] **Redis Pre-population**: Update `cmd/proxy/main.go` to seed Redis from `../../config/proxy.yml` on startup (parity with `proxy.py`).
- [x] **Dynamic CIDR Blocking**: Implement `geoip:blocked_cidrs` check in Go.

### 2. Enhance Pub/Sub & Hot-Reload (Priority: MEDIUM)
- [x] **Granular Pub/Sub**: Update `internal/redis/pubsub.go` to handle `ja4_blacklist_add`, `ja4_whitelist_add`, and `config:dial:change`.
- [x] **Instant Cache Invalidation**: Ensure specific JA4/IP cache entries are cleared when pub/sub messages arrive.

### 3. Validation & Performance
- [x] **Parity Suite**: Run `make go-parity` and ensure 100% of tests pass.
- [x] **Formal Benchmark**: Run `tests/performance/test_bench_go_proxy.py` and document results.
- [x] **Chaos Testing**: Verify HAProxy failover and adversarial ClientHello handling.

### 4. Final Documentation
- [x] **ADR-015**: Why Go was chosen over Rust (Verified).
- [x] **Migration Runbook**: Zero-downtime cutover procedure (Verified).
- [x] **Completion Report**: Final throughput and latency metrics.

## Verified Acceptance Criteria
- [x] Compiles with Go 1.23+
- [x] Decodes TLS 1.2 and 1.3 ClientHellos
- [x] Correct JA4 fingerprint generation
- [x] Prometheus metrics integrated
- [x] Tarpit action functional
- [x] HAProxy PROXY protocol support
- [x] GeoIP integration parity
- [x] Signal decision parity
