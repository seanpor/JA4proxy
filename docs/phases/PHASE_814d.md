# Decision-Logic and False-Positive Weaponisation

## Goal

Execute Phase 814d adversarial security assessment against JA4proxy's scoring and decision engine (`internal/security/`). Hunt the product's crown-jewel vulnerability: **inducing false positives at scale** (Severity Rubric Clause C-4), where an unauthenticated remote attacker can force the proxy to block, tarpit, or ban legitimate users and browser traffic. Measure attacker cost per vector, verify fail-open invariants during subsystem degradation, audit decision cache isolation, and benchmark real-world browser exposure at `dial=100` against the Tranco corpus.

## Scope

- **Crown-Jewel Mass FP Weaponisation:**
  - Shared-state poisoning: HyperLogLog per `/24` and `/48`, beaconing sorted sets, return-visitor hashes, and connection counters.
  - Ban expansion against shared egress IPs (CGNAT, corporate proxies, VPNs).
  - Threat-intel feed poisoning and CDN domain/IP collision risks.
  - Compute and document the empirical "Attacker Cost to Induce One Blocked Legitimate User".
- **Decision Cache Abuse & Isolation:**
  - Multi-tenant / shared-client isolation under the `clientIP|JA4` cache keying model.
  - Verify cache entry eviction cost, sticky BLOCK abuse, and local-cache vs. Redis precedence during reloads and connection flaps.
- **Scorer Sensitivity & Boundary Edge Testing:**
  - Analyze scoring weight leverage: identify which signals provide the highest score movement per attacker dollar/packet.
  - Exact boundary validation across action thresholds (ALLOW / CHALLENGE / TARPIT / BLOCK).
- **Fail-Open Inversion Invariants:**
  - Fault injection across external dependencies: DNS enrichment, AbuseIPDB, RDAP, Redis, and threat feed downlinks.
  - Assert that all dependency outage paths fail-open (never fail-closed into a denial of service).
- **Tranco Real-Browser Corpus Benchmark at Dial=100:**
  - Measure false-positive exposure across modern browser ClientHellos with `alpn_browser_bypass` disabled.
- **Dial=0 Invariant Verification:**
  - Prove that `dial=0` is strictly non-blocking across 100% of pipeline code paths (including hard-blocks and expired bans).

## Implementation Plan

### Step 1: Shared-State & Mass FP Weaponisation Suite
1. Build `tests/unit/test_pentest_fp_weaponisation.go` / Go test harnesses in `internal/security/`:
   - Simulate attacker flooding spoofed TLS ClientHellos into `/24` and `/48` subnet buckets to trigger threshold trips on legitimate IPs.
   - Test beaconing detector sorted-set poisoning: can an attacker inject jittered timestamps to frame a co-located host or shared proxy?
   - Test feed collision handling: verify how the pipeline handles threat feed entries overlapping major CDN and public DNS ranges.
2. Measure and record the quantitative attacker packet/request cost required to trigger a blocking decision on an innocent third party.

### Step 2: Decision Cache Abuse & Precedence Testing
1. Author tests in `internal/security/` verifying cache isolation:
   - Ensure an attacker sharing a public IP (e.g. CGNAT) cannot prime a BLOCK entry that attaches to a legitimate user's distinct JA4 fingerprint.
   - Verify cache eviction behavior: ensure high-volume attacker query spam cannot prematurely purge active ALLOW cache entries for legitimate traffic.
   - Test cache state consistency across simulated Redis server flaps and SIGHUP configuration reloads.

### Step 3: Scorer Leverage Analysis & Boundary Invariants
1. Implement property-based and table-driven boundary tests for `RiskScorer` and `ActionDecider`:
   - Enumerate all individual signals (`SignalASNDataCenter`, `SignalTorExit`, `SignalDirectIP`, `SignalTLSMismatch`, `SignalBeaconing`, etc.) and calculate their score-delta-to-attacker-effort ratio.
   - Test exact decision boundary transitions: `Score == Threshold - 1`, `Score == Threshold`, `Score == Threshold + 1`.

### Step 4: Fail-Open Inversion Harness
1. Implement chaos / fault-injection tests (`internal/security/fail_open_test.go`):
   - Mock upstream timeouts, network resets, and corrupted JSON payloads from DNS, AbuseIPDB, RDAP, and Redis clients.
   - Assert the pipeline security decision defaults to ALLOW, emits appropriate failure telemetry counters (`metrics.XxxDroppedTotal.Inc()`), and never panics or drops into an accidental BLOCK.
   - *Note on Telemetry Sinks & LogTide (Phase 840/841):* The production telemetry switch from Loki/Promtail to the first-party LogTide sidecar is evaluated in Phase 840 and scheduled for migration in Phase 841. In this phase, verify the proxy pipeline invariant that downstream telemetry sink degradation (whether Loki or LogTide sidecar backpressure/stalls over UDS/stdout/socket) never blocks the synchronous connection evaluation path and strictly fails-open with zero false positives.


### Step 5: Tranco Corpus False-Positive Benchmark (`tests/fp_corpus/`)
1. Extend `tests/fp_corpus/test_good_traffic_profile.py` / Go benchmark runner:
   - Run Tranco top browser fingerprint profiles through `Pipeline.Process()` at `dial=100` with `alpn_browser_bypass=false`.
   - Record exact false-positive rate and identify any anomalous signals triggered by standard browser handshakes.

### Step 6: Dial=0 Mathematical Non-Blocking Proof
1. Author exhaustive test `internal/security/dial_zero_test.go`:
   - Run all edge cases (hard-block list hit, manual ban hit, threat feed hit, rate limit trip, high anomaly score) through `Pipeline.Process()` with `dial: 0`.
   - Assert that the returned action is strictly `ActionAllow` (or monitoring-only flag) and that no connection drop or tarpit occurs.

### Step 7: Documentation & Finding Registration
1. If any structural flaws or fail-closed regressions are identified, log them immediately to `docs/security/findings.yaml` using `python3 scripts/findings_register.py add`.
2. Generate the FP-induction report section for `docs/security/pentest/WORKSTREAMS.md`.
3. Move `docs/phases/PHASE_814d.md` to `docs/phases/complete/PHASE_814d.md` and mark `814d: COMPLETE` in `docs/phases/manifest.yaml`.

## Test Strategy

- **Go Invariant & Chaos Tests:** Native execution (`GOROOT=/snap/go/current /snap/go/current/bin/go test -race ./internal/security/...`).
- **Python FP Corpus Tests:** Containerized execution inside `ja4proxy-tools` via `make test-unit` or `pytest tests/fp_corpus/`.
- **Preflight Validation:** Full `make preflight` gate (lint, scan, test, test-race) passing with 0 errors.

## Acceptance Criteria

1. Mass FP induction tests demonstrate whether subnet/beaconing state poisoning is possible, with documented attacker cost metrics.
2. Cache abuse tests prove `clientIP|JA4` keys prevent cross-session poisoning and resist eviction spam.
3. Fail-open invariant proven: 100% of simulated dependency outage paths result in ALLOW (no fail-closed outages).
4. `dial=0` verified strictly non-blocking across 100% of pipeline paths.
5. Real-browser Tranco corpus benchmark executed at `dial=100` and FP rate measured.
6. Any discovered vulnerabilities logged in `docs/security/findings.yaml`.
7. `make preflight` and `make lint-phases` pass cleanly.

## Out of Scope

- Modifying the core JA4 hashing algorithm itself (FoxIO specification compliance).
- Testing external third-party services directly (mocking/simulating their protocol behaviors locally).
