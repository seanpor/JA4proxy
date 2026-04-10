# Security Remediation — Go Missing Signals (JA4T, ja4_tls_mismatch, Weak Ciphers, DGA, Health Check)

## Goal

Close five production-critical signal gaps in the Go proxy: (1) JA4T implementation is
a stub returning empty string, removing TCP-level evasion detection; (2) `ja4_tls_mismatch`
signal not implemented, allowing TLS version spoofing; (3) weak cipher suite coverage
only 13 vs Python's 37+; (4) DGA detection algorithm diverges from Python (less effective);
(5) Go health check is superficial (Redis-only), missing GeoIP/connections/queue checks.

## Scope

Files to create or modify:
- `internal/tls/ja4t.go` — implement JA4T computation (was stub returning `""`)
- `internal/security/tls_enforcer.go` — add `ja4_tls_mismatch` signal
- `internal/security/tls_enforcer.go` — expand `weakCipherSet` to match Python's 37+
- `internal/security/sni_analyzer.go` — align DGA algorithm with Python
- `cmd/proxy/main.go` — deepen health check endpoint
- `tests/unit/test_ja4t.go` — JA4T unit tests
- `tests/unit/test_tls_enforcer.go` — add mismatch + cipher tests
- `tests/unit/test_sni_analyzer.go` — DGA parity tests vs Python
- `tests/unit/test_health_check.go` — deep health check tests

## Implementation Plan

### A — JA4T implementation (Go)

1. Implement `ComputeJA4T(ttl uint8, mss uint16, windowSize uint16, options []byte) string`
   in `internal/tls/ja4t.go`:
   - Format: `{ttl}_{mss}_{window_size}_{options_hash[:8]}`
   - Hash the TCP options bytes (first 8 hex chars of MD5/SHA256)
   - Match Python's `generate_ja4t()` output exactly
2. Wire JA4T extraction into the TLS parser — extract TTL, MSS, window size,
   and TCP options from the initial connection.
3. If PROXY protocol v2 is enabled, extract TTL from TLV fields (Phase 200 adds
   v2 support; the TLV fields carry the original TCP metadata).
4. Set `connCtx.JA4T` in the connection context.

### B — ja4_tls_mismatch signal (Go)

1. Add `checkJA4TLSTMismatch(ja4 string, actualTLSVersion string) RiskSignal` to
   `internal/security/tls_enforcer.go`.
2. Parse the TLS version from the JA4 fingerprint (first segment: `t13` = TLS 1.3,
   `t12` = TLS 1.2, etc.).
3. Compare with the actual negotiated TLS version.
4. If mismatch: return `RiskSignal{name: "ja4_tls_mismatch", score: 35}`.
5. Score of 35 matches `config/signal_scores.yml` `score_cap: 35`.

### C — Expand weak cipher coverage (Go)

1. Read Python's `WEAK_CIPHERS` frozenset from `src/security/tls_enforcer.py`.
2. Sync Go's `weakCipherSet` in `internal/security/tls_enforcer.go` to include ALL:
   - NULL ciphers (0x0000, 0x0001, 0x0002, 0x003B)
   - EXPORT ciphers (0x0003, 0x0006, 0x0008, 0x000B, 0x000E, 0x0011, 0x0014, 0x0017, 0x0019)
   - RC4 ciphers (0x0004, 0x0005, 0x0018, 0xC007, 0xC011, 0xC016)
   - DES ciphers (0x0009, 0x000A, 0x000C–0x000F, 0x0012, 0x0015, 0x001A)
   - DH_anon ciphers (0x0017, 0x0018, 0x0019, 0x001A, 0x001B, 0xC015–C019)
   - ECDH_anon ciphers
   - Non-PFS RSA ciphers (0x002F, 0x0035, 0x0041, 0x0084)
3. Total: 37+ suites matching Python.

### D — Align DGA algorithm with Python

1. Read Python's `dga_score()` from `src/security/sni_analyzer.py`:
   - Entropy threshold: `ent >= 3.8` adds up to 0.40
   - No vowels = +0.30; ratio > 5:1 and len >= 10 = +0.20
   - Label length >= 20 = +0.20; >= 16 = +0.10
   - `\d{4,}` consecutive digits = +0.10
   - `_get_primary_label()` strips common prefixes (`www`, `api`, `cdn`, `mail`, `smtp`, etc.)
2. Rewrite Go's `dgaConfidence()` in `internal/security/sni_analyzer.go` to match:
   - Same entropy thresholds
   - Same vowel analysis
   - Same label length thresholds
   - Same digit detection
   - Same prefix stripping via `_get_primary_label()` equivalent
3. Add parity test: feed identical hostnames to Python and Go, assert same score
   within ±0.05 tolerance (floating point differences acceptable).

### E — Deepen Go health check

1. Extend `handleHealth` in `cmd/proxy/main.go` to check:
   - Redis connectivity (existing)
   - GeoIP database file existence and readability
   - Active connections vs `max_connections` config
   - Tarpit saturation level (current vs max)
   - Enrichment queue depth (if applicable)
2. Return structured JSON response with all component statuses.
3. Return 503 if any critical dependency (Redis, GeoIP) is unhealthy.
4. Return 200 if all critical dependencies are healthy (degraded = 200 with warning).
5. Add anti-flap hysteresis: require N consecutive failures before marking unhealthy.

## Acceptance Criteria

- [ ] `ComputeJA4T()` returns non-empty string matching Python output for same inputs
- [ ] JA4T unit tests pass with fixture-based assertions
- [ ] `ja4_tls_mismatch` fires when JA4 claims TLS 1.3 but actual is TLS 1.2
- [ ] `weakCipherSet` contains 37+ suites matching Python's `WEAK_CIPHERS`
- [ ] DGA parity test: Python and Go scores match within ±0.05 for 100+ test hostnames
- [ ] Go health check returns structured JSON with all component statuses
- [ ] Health check returns 503 when Redis or GeoIP is down
- [ ] Anti-flap hysteresis prevents status flapping on transient errors
- [ ] `make go-test` passes with zero failures
- [ ] `make check-scores` still exits 0 (score drift not reintroduced)
- [ ] CHANGELOG.md entry written

## Out of Scope

- Deception checker (honey-fingerprint/SNI) — that's Phase 56 and a larger feature.
- PROXY protocol v2 TLV-based TTL extraction — belongs in Phase 200 (PROXY v2 support).
- Python DGA algorithm changes — Python is deprecated; Go matches Python's current behavior.
