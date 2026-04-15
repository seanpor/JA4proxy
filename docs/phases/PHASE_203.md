# Security Remediation — Go Missing Signals (JA4T, ja4_tls_mismatch, Weak Ciphers, DGA, Health Check)

> **Status:** PROPOSED
> **Parent Size:** LARGE — split into 5 SMALL sub-phases below.
> **Last revised:** 2026-04-11 (sub-phase breakdown for junior engineer handoff).

## Goal

Close five production-critical signal gaps in the Go proxy: (1) JA4T implementation is
a stub returning empty string, removing TCP-level evasion detection; (2) `ja4_tls_mismatch`
signal not implemented, allowing TLS version spoofing; (3) weak cipher suite coverage
only 13 vs Python's 37+; (4) DGA detection algorithm diverges from Python (less effective);
(5) Go health check is superficial (Redis-only), missing GeoIP/connections/queue checks.

---

## Sub-phase index

| ID | Sub-phase | Repo area | Size | Depends on |
|---|---|---|---|---|
| **203a** | JA4T implementation (Go) | `internal/tls/ja4t.go` | S | none |
| **203b** | ja4_tls_mismatch signal | `internal/security/tls_enforcer.go` | XS | none |
| **203c** | Expand weak cipher coverage | `internal/security/tls_enforcer.go` | XS | none |
| **203d** | Align DGA algorithm with Python | `internal/security/sni_analyzer.go` | S | none |
| **203e** | Deepen Go health check | `cmd/proxy/main.go` | S | none |

All sub-phases are fully independent — no dependencies between any of them. A team of
five could work all sub-phases in parallel with zero merge conflicts (each touches
different files or different functions within the same file).

---

## Sub-phase 203a — JA4T implementation (S)

**Goal:** Implement `ComputeJA4T()` in Go to match Python's `generate_ja4t()` output.

**Why this matters:** JA4T provides TCP-level fingerprinting (TTL, MSS, window size,
TCP options). Without it, the proxy cannot detect evasive clients that spoof TLS
fingerprints but leave TCP stack defaults unchanged.

**Files to modify/create:**
- `internal/tls/ja4t.go` — implement `ComputeJA4T` (currently returns `""`)
- `tests/unit/test_ja4t.go` — JA4T unit tests with fixture-based assertions

**Steps:**
1. Read Python's `generate_ja4t()` in `src/tls/ja4t.py` to understand the format:
   - Output: `{ttl}_{mss}_{window_size}_{options_hash[:8]}`
   - Hash the TCP options bytes (first 8 hex chars of SHA256)
   - TTL is normalized (0→"0", 32→"32", 64→"64", 128→"128", 255→"255")
   - MSS and window size are decimal integers
2. Implement `ComputeJA4T(ttl uint8, mss uint16, windowSize uint16, options []byte) string`
   in `internal/tls/ja4t.go`.
3. Write unit tests in `tests/unit/test_ja4t.go` with these concrete test vectors:
   - `ttl=64, mss=1460, windowSize=65535, options=[0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x03,0x03,0x07]` → `"64_1460_65535_<first-8-hex-of-sha256>"` (compute the hash to get the exact expected value)
   - `ttl=128, mss=536, windowSize=8192, options=[0x02,0x04,0x02,0x18]` → `"128_536_8192_<hash>"`
   - `ttl=255, mss=0, windowSize=0, options=[]` → `"255_0_0_<hash-of-empty>"`
4. Wire the call site: TCP metadata is available in `internal/proxy/proxy.go` at the `handleConnection()` function where `connCtx` is populated. Look for the section after the TLS handshake completes — add `connCtx.JA4T = tls.ComputeJA4T(...)` using the TCP connection's socket options. Specifically, use `tcpConn.RemoteAddr()` and the raw `syscall.GetsockoptInt` for TTL/MSS/window size.

   **⚠️ Platform note:** `syscall.GetsockoptInt` for `TCP_INFO` (to read TTL/MSS) is Linux-specific.
   Add `//go:build linux` to the file that contains the syscall code, and provide a stub for
   non-Linux platforms that returns default values (`ttl=64, mss=1460, windowSize=65535, options=[]`).
   The test file should also use `//go:build linux` so it only runs on Linux CI runners.

5. Run `make go-test` — must pass.
6. Run `make check-scores` — must exit 0 (ensure no score drift).

**Acceptance criteria:**
- [ ] `ComputeJA4T()` returns non-empty string matching Python output for same inputs
- [ ] `//go:build linux` build tag guards syscall-dependent code; non-Linux stub returns defaults
- [ ] JA4T unit tests pass with fixture-based assertions
- [ ] `connCtx.JA4T` is set in the connection context
- [ ] `make go-test` passes
- [ ] `make check-scores` exits 0
- [ ] PHASE_203a_notes.md written

**Out of scope:** PROXY protocol v2 TLV extraction (Phase 200), TCP options parsing changes.

---

## Sub-phase 203b — ja4_tls_mismatch signal (XS)

**Goal:** Add `ja4_tls_mismatch` signal to detect TLS version spoofing.

**Why this matters:** An attacker can craft a JA4 fingerprint claiming TLS 1.3 while
actually negotiating TLS 1.2. This signal catches the mismatch and scores it.

**Files to modify:**
- `internal/security/tls_enforcer.go` — add `checkJA4TLSTMismatch()` method

**Steps:**
1. Add `checkJA4TLSTMismatch(ja4 string, actualTLSVersion string) RiskSignal` to
   `internal/security/tls_enforcer.go`.
2. Parse the TLS version from the JA4 fingerprint (first segment: `t13` = TLS 1.3,
   `t12` = TLS 1.2, `t11` = TLS 1.1, `t10` = TLS 1.0).
3. Compare with the actual negotiated TLS version.
4. If mismatch: return `RiskSignal{name: "ja4_tls_mismatch", score: 35}`.
   Score of 35 matches `config/signal_scores.yml` `score_cap: 35`.
5. Wire the call site: after TLS negotiation completes, call this check with the
   JA4 fingerprint and the actual negotiated version.
6. Write tests:
   - JA4 says t13, actual is TLS 1.3 → no mismatch
   - JA4 says t13, actual is TLS 1.2 → mismatch, score 35
   - JA4 says t12, actual is TLS 1.1 → mismatch, score 35
   - JA4 says t10, actual is SSL 3.0 → mismatch, score 35
7. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] `ja4_tls_mismatch` fires when JA4 claims TLS 1.3 but actual is TLS 1.2
- [ ] No false positives when JA4 and actual TLS version match
- [ ] Score is 35 (matches `config/signal_scores.yml`)
- [ ] Tests cover match and mismatch cases
- [ ] `make go-test` passes
- [ ] PHASE_203b_notes.md written

**Out of scope:** Other spoofing signals, JA4 fingerprint computation changes.

---

## Sub-phase 203c — Expand weak cipher coverage (XS)

**Goal:** Sync Go's `weakCipherSet` to match Python's 37+ weak cipher suites.

**Why this matters:** The Go proxy only flags 13 weak ciphers while Python flags 37+.
NULL, EXPORT, DH_anon, ECDH_anon, and non-PFS ciphers slip through undetected.

**Files to modify:**
- `internal/security/tls_enforcer.go` — expand `weakCipherSet`

**Steps:**
1. Read Python's `WEAK_CIPHERS` frozenset from `src/security/tls_enforcer.py`.
2. Expand Go's `weakCipherSet` in `internal/security/tls_enforcer.go` to include ALL:
   - NULL ciphers (0x0000, 0x0001, 0x0002, 0x003B)
   - EXPORT ciphers (0x0003, 0x0006, 0x0008, 0x000B, 0x000E, 0x0011, 0x0014, 0x0017, 0x0019)
   - RC4 ciphers (0x0004, 0x0005, 0x0018, 0xC007, 0xC011, 0xC016)
   - DES ciphers (0x0009, 0x000A, 0x000C–0x000F, 0x0012, 0x0015, 0x001A)
   - DH_anon ciphers (0x0017, 0x0018, 0x0019, 0x001A, 0x001B, 0xC015–C019)
   - ECDH_anon ciphers
   - Non-PFS RSA ciphers (0x002F, 0x0035, 0x0041, 0x0084)
3. Total should be 37+ suites matching Python.
4. Write a parity test: enumerate all ciphers in Python's set and assert each
   exists in Go's set.
5. Run `make go-test` — must pass.
6. Run `make check-scores` — must exit 0.

**Acceptance criteria:**
- [ ] `weakCipherSet` contains 37+ suites matching Python's `WEAK_CIPHERS`
- [ ] Parity test: every Python weak cipher exists in Go set
- [ ] `make go-test` passes
- [ ] `make check-scores` exits 0
- [ ] PHASE_203c_notes.md written

**Out of scope:** Cipher negotiation logic, TLS 1.3 cipher suite changes.

---

## Sub-phase 203d — Align DGA algorithm with Python (S)

**Goal:** Rewrite Go's DGA detection to match Python's scoring exactly.

**Why this matters:** The Go DGA algorithm diverges from Python, producing different
scores for the same hostnames. This reduces detection effectiveness for
domain-generation-algorithm-based malware C2 domains.

**Files to modify:**
- `internal/security/sni_analyzer.go` — rewrite `dgaConfidence()`
- `tests/unit/test_sni_analyzer.go` — DGA parity tests vs Python

**Steps:**
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
3. Add parity tests in `tests/unit/test_sni_analyzer.go`. **Test fixture file:** Create
   `tests/fixtures/dga/hostnames.txt` with 100+ hostnames (one per line). Use this canonical
   set — read the Python test data from `src/security/sni_analyzer.py` (the `KNOWN_DGA_DOMAINS`
   and `LEGIT_DOMAINS` lists used in the Python tests, ~80 entries). Supplement with 10 edge
   cases from the existing `tests/unit/test_sni_analyzer.py` (single-label, numeric-only, very
   long). If you need more entries, generate synthetic DGA domains with:
   `python3 -c "import random; [print(f'{random.randbytes(20).hex()}.com') for _ in range(30)]"`.
   The ±0.05 tolerance applies to the **final confidence score** (0.0–1.0), not intermediate
   sub-scores.
4. Test vectors should include:
   - Known DGA domains (random-looking, high entropy, no vowels)
   - Legitimate domains (google.com, github.com)
   - Edge cases (single-label, very long labels, numeric-only)
5. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] DGA parity test: Python and Go scores match within ±0.05 for 100+ test hostnames
- [ ] Go DGA uses same entropy thresholds, vowel analysis, label length checks
- [ ] Prefix stripping matches Python behavior
- [ ] `make go-test` passes
- [ ] PHASE_203d_notes.md written

**Out of scope:** Python DGA algorithm changes (Python is deprecated; Go matches current behavior),
new DGA detection heuristics.

---

## Sub-phase 203e — Deepen Go health check (S)

**Goal:** Extend the Go health check endpoint to verify all critical dependencies.

**Why this matters:** The current Go health check only tests Redis connectivity.
If GeoIP is missing, the tarpit is saturated, or the enrichment queue is backed up,
the health check still reports "healthy" — masking real problems.

**Files to modify:**
- `cmd/proxy/main.go` — extend `handleHealth` handler
- `tests/unit/test_health_check.go` — deep health check tests

**Steps:**
1. Extend `handleHealth` in `cmd/proxy/main.go` to check:
   - Redis connectivity (existing)
   - GeoIP database file existence and readability
   - Active connections vs `max_connections` config
   - Tarpit saturation level (current vs max)
   - Enrichment queue depth (if applicable)
2. Return structured JSON response with all component statuses:
   ```json
   {
     "status": "healthy",
     "components": {
       "redis": {"status": "ok", "latency_ms": 1},
       "geoip": {"status": "ok", "db_size_mb": 65},
       "connections": {"status": "ok", "active": 150, "max": 10000},
       "tarpit": {"status": "ok", "active": 5, "max": 1000},
       "queue": {"status": "ok", "depth": 0}
     }
   }
   ```
3. Return 503 if any critical dependency (Redis, GeoIP) is unhealthy.
4. Return 200 if all critical dependencies are healthy (degraded = 200 with warning).
5. Add anti-flap hysteresis: require **N=3** consecutive failures before marking a component unhealthy.
   Track a per-component failure counter in a struct (e.g., `healthState.failedChecks[component]`).
   Increment on each failure, reset to 0 on success. When counter reaches 3, mark component unhealthy.
6. The health endpoint path is `GET /health` (same as the existing handler in `cmd/proxy/main.go`).
   **Redis latency measurement:** use `time.Since(start)` around the `client.Ping(ctx)` call. This
   gives you the round-trip latency in microseconds. Convert to milliseconds for the JSON response.
   **Enrichment queue:** the Go proxy does NOT currently have an enrichment queue (that's a Python
   concept). Omit the queue check from the Go health endpoint — it's not applicable. If a queue is
   added later, wire it in as a separate sub-phase.
7. Write tests:
   - All healthy → 200 with all "ok"
   - Redis down → 503
   - GeoIP missing → 503
   - Connections near limit → 200 with "degraded" warning
   - Anti-flap: single failure doesn't flip status
7. Run `make go-test` — must pass.

**Acceptance criteria:**
- [ ] Go health check returns structured JSON with all component statuses
- [ ] Health check returns 503 when Redis or GeoIP is down
- [ ] Anti-flap hysteresis prevents status flapping on transient errors
- [ ] Tests cover healthy, unhealthy, and degraded states
- [ ] `make go-test` passes
- [ ] PHASE_203e_notes.md written

**Out of scope:** Prometheus metrics (those are Phase 86), management API health endpoints,
Python health check changes.

---

## Full Phase Acceptance Criteria (all sub-phases)

- [ ] All 5 sub-phases complete (see individual acceptance criteria above)
- [ ] `ComputeJA4T()` returns non-empty string matching Python output for same inputs
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
