# Phase 203 — Critical Review

**Reviewer:** Cybersecurity / DevOps / SRE / Architect lens, independent.
**Date:** 2026-04-15
**Phase doc:** `docs/phases/PHASE_203.md`
**Target runtime:** **Go (production)** — all five sub-phases live under
`internal/` or `cmd/proxy/`. Python is read-only reference.

## Status of dependencies

`docs/phases/manifest.yaml` lists Phase 203's only dependency as Phase 200.
**Phase 200 status: not COMPLETE in the manifest** — verify before any work
begins. If 200 is incomplete, only 203a is materially blocked (it asks for
PROXY-protocol-derived TCP options); the other four sub-phases (203b–e) can
proceed independently.

> Note: Phase 201 just merged. The manifest entry I'm reading may be stale on
> your branch — re-pull `main` and re-check `manifest.yaml: 200.status` first.

---

## Phase doc premise — verification

I verified each of the five gap claims against the actual Go and Python source
on `main` after the phase-201 merge (`d28b298`). Three are accurate, one is
half-accurate, **one is built on a false architectural premise**.

| Sub-phase | Claim | Verified? |
|---|---|---|
| 203a | `internal/tls/ja4t.go` `ComputeJA4T()` returns `""` | **TRUE** but **wrong reason** (see below) |
| 203b | `ja4_tls_mismatch` not implemented in Go | TRUE — `grep -rn 'tls_mismatch' internal/` returns nothing |
| 203c | Go has 13 weak ciphers, Python has 37+ | NEAR — Go has **12**; Python has **42** |
| 203d | DGA algorithms diverge | TRUE — different entropy thresholds (Go 3.5/4.0 vs Python 3.8 sliding), Go has consecutive-consonant rule Python lacks, Python has prefix stripping Go lacks |
| 203e | Go health check is Redis-only | **HALF TRUE** — `/health` is Redis-only by design (k8s liveness probe), but `/health/deep` already returns dial / active_connections / connections_total / block_rate_pct / active_bans / cert_days_remaining (see `cmd/proxy/main.go:669-773`) |

---

## CRITICAL FINDING — 203a (JA4T) is built on a false architectural premise

The phase doc proposes:

> `ComputeJA4T(ttl uint8, mss uint16, windowSize uint16, options []byte) string`
> Format: `{ttl}_{mss}_{window_size}_{options_hash[:8]}`
> Wire it from `handleConnection()` using `syscall.GetsockoptInt` for TTL/MSS/window size.

Three problems, any one of which is blocking:

1. **The format is wrong.** Python's actual JA4T format
   (`src/tap/fingerprints/ja4t.py:32-44`) is
   `{window_size}_{mss}_{options_order}_{window_scale}` (e.g.
   `"65535_1460_MSTNW_8"`). It encodes the *order of TCP options as letters*,
   not a SHA hash. The phase doc is describing a different fingerprint.
2. **The existing Go stub uses yet another concept** —
   `ComputeJA4T(alertCodes []uint8) string` claims to fingerprint TLS alert
   codes (`internal/tls/ja4t.go:1-11`). Three definitions of "JA4T" coexist
   in this repo. Pick one *before* writing code.
3. **Critically: a Go TCP listener cannot read SYN-packet TCP options after
   `accept()`.** The kernel consumes the SYN, completes the three-way
   handshake, and hands you a connected socket whose options reflect the
   *negotiated* state. `syscall.GetsockoptInt` returns the *current* socket
   state, not the client's original SYN options. The proxy can read its own
   send-side TTL, not the client's. JA4T as Python defines it is **only
   computable from raw packet capture** — which is why `ja4t.py` lives under
   `src/tap/fingerprints/` (TAP/SPAN mode), not the inline proxy. A live
   inline proxy gets JA4T only via:
   - **PROXY protocol v2 TLVs** carrying the upstream LB's captured SYN data
     (genuine plan; see Phase 200), **or**
   - **eBPF / XDP hook** before the kernel three-way-handshake completes
     (large project on its own).

   Neither is in scope. The phase doc's wiring step ("use
   `syscall.GetsockoptInt` for TTL/MSS/window size") will compile but return
   the wrong data — silently, with no test that would catch it because the
   fixtures supply hand-crafted bytes rather than live socket state.

**Recommendation:** Either drop 203a from this phase entirely (defer until
Phase 200's PROXY-v2 TLV channel exists), or *severely rescope* it to: "port
the existing `src/tap/fingerprints/ja4t.py` parsing logic to Go for use by a
future TAP/PROXY-v2 path, with no hot-path wiring." Don't ship a function
that compiles to wrong output.

---

## Other premise issues

### 203c — cipher counts

The phase doc says "13 vs 37+". Actual Go count before 203c: **12**.
Python count: **42** by the review's eyeball count — **actual unique
entry count is 40** (re-verified during implementation, 2026-04-15).
Acceptance criterion updated to "**40 suites, matching Python
`WEAK_CIPHERS` exactly**" — exact parity is the only unambiguous
done-condition.

> **Resolution (2026-04-15):** `internal/security/tls_enforcer.go`
> `weakCipherSet` now has exactly 40 entries; `cipher_parity_test.go`
> hard-codes the authoritative list and fails loudly on drift.

Also note: the listed cipher ranges in 203c step 2 *partially overlap* the
existing 12 Go entries. A junior engineer copy-pasting from the doc will
duplicate keys (Go map literals are tolerant — last write wins, no compile
error — but the ranges should be checked against `internal/security/tls_enforcer.go:7-20` first).

The doc also lists **0x0017** under both EXPORT and DH_anon. It's
`TLS_DH_anon_EXPORT_WITH_RC4_40_MD5` — both labels are correct, but only one
map entry is needed.

### 203d — DGA divergence is real

Confirmed by reading both:

- `internal/security/sni_analyzer.go:111-195` (Go)
- `src/security/sni_analyzer.py:80-150` (Python)

Real differences (each one would cause score drift):

| Heuristic | Python | Go |
|---|---|---|
| Entropy threshold | `ent >= 3.8`, sliding score `min(0.40, (ent-3.8)*2.0)` | `> 3.5 → +0.35`, `> 4.0 → +0.15` |
| Vowel rule | `vowel_count==0 and alpha>=6 → +0.30`; `alpha>=10 and ratio>5 → +0.20` | `vowel_ratio < 0.10 → +0.30` (no length gate) |
| Length | `>=20 → +0.20`, `>=16 → +0.10` | `>15 → +0.15` |
| Consecutive consonants | not used | `>=4 runs → +0.20` (Go-only) |
| Digits | regex `\d{4,}` → `+0.10` | digit ratio `>0.30 → +0.20` |
| Primary label | strips `www`, `api`, `cdn`, `mail`, `smtp` (`_get_primary_label`) | leftmost label only |

The doc's ±0.05 tolerance is **not achievable** without rewriting Go to
match Python line-for-line. Acceptable. But: the doc requires juniors to
generate the test corpus (`tests/fixtures/dga/hostnames.txt`) themselves
from "Alexa top-1000 random samples" — Alexa shut down 2022-05-01. Use
**Tranco** (already used elsewhere in the repo per `tests/fp_corpus/`).

### 203e — `/health` vs `/health/deep`

The phase doc says "Go health check only tests Redis — no GeoIP / connections
/ queue checks". This describes **only `/health`** (the shallow k8s liveness
endpoint). `/health/deep` (cmd/proxy/main.go:669-773) already returns dial,
active_connections, connections_total, block_rate_pct, active_bans, redis
latency, and cert expiry.

So the question is: should we deepen `/health` to include component checks,
or extend `/health/deep` with GeoIP / tarpit / queue, or both?

**Recommendation:** **don't deepen `/health`.** That endpoint exists to
answer "should the load balancer keep sending traffic to me?" — a fast,
tight, Redis-or-die check. Adding GeoIP-file-stat to a 1-Hz liveness probe
on every replica is a needless syscall storm and risks flapping under disk
contention. Extend `/health/deep` instead, and only add "GeoIP DB
present + readable" if the Go proxy actually loads a GeoIP DB (which I did
not see in the proxy source — verify before specifying). Anti-flap
hysteresis (N=3) makes sense on `/health` only if the load-balancer probe
interval is short (say, sub-5s) and you want to ride out single dropped PINGs.

---

## Six-Lens Critical Review

### A. Security
- **203b** — `ja4_tls_mismatch` is a real anti-evasion signal; score 35 is
  consistent with `config/signal_scores.yml` and Python parity. No new
  attack surface.
- **203c** — strictly tightening detection. No risk.
- **203d** — re-aligning to Python is a *behaviour change*. If Tranco-top-10k
  FP rate degrades (Go currently flags some legitimate domains Python doesn't
  because of the consonant-run rule), removing that rule is a small **gain in
  safety** (fewer false positives → core asymmetry preserved). Add an
  explicit FP-rate test: `tests/fp_corpus/test_dga_fp_rate_go.go` — must
  stay <1% on Tranco top 10k.
- **203e** — health endpoints are unauthenticated by convention. Don't echo
  back internals (GeoIP DB path, queue depths) at high cardinality without
  considering an attacker scraping `/health/deep` to reconnoitre. Already
  the case for `/health/deep` so no regression, but the phase doc adds
  `db_size_mb` — this is fine; just don't add `db_path`.

### B. DevOps
- All sub-phases compile-time changes only. No Docker/Compose/Helm changes.
- No new config keys (203b's score is already in `config/signal_scores.yml`).
- Rollback: revert the commit. Score-drift gate (`make check-scores`) catches
  unintended changes.
- No feature flag needed for 203b/c/d/e — they tighten behaviour the same way
  Python already does. **203a, if attempted, MUST be behind a feature flag**
  because it can return wrong data (see CRITICAL FINDING).

### C. SRE
- New metric for 203b: `ja4proxy_ja4_tls_mismatch_total{action}` — Python
  emits this (see `src/security/tls_enforcer.py:112`). Go must too.
- 203e: deepening `/health/deep` with GeoIP-stat / tarpit-saturation adds
  ≤ 1 ms per call. Negligible if the endpoint is polled at 0.1–1 Hz; with
  N=3 hysteresis the *time-to-detect* a real failure becomes 3× the probe
  interval — document this trade-off in the runbook.
- Capacity: no new Redis keys or unbounded growth.
- No runbook updates needed for 203b/c/d. **203e must update
  `docs/runbooks/go_proxy_operations.md`** with the new health JSON shape.

### D. Architecture
- 203a: see CRITICAL FINDING.
- 203b: clean fit — runs alongside existing `tls_enforcer.Check()`.
  Wire it from `internal/proxy/proxy.go` after TLS negotiation completes.
  **Concurrency:** stateless function; no race risk.
- 203c: pure data change.
- 203d: stateless rewrite. Watch the `_get_primary_label` port —
  Python does `hostname.lower().rstrip(".").split(".")` and skips
  `_SKIP_PREFIXES` set. Read that set; don't re-derive it.
- 203e: extends an existing handler. No new boundaries. Anti-flap state
  (per-component failure counter) needs an `atomic.Int64` or a mutex —
  the handler is called concurrently. The phase doc doesn't mention this.

### E. Testing
- 203a: as written, untestable end-to-end (you can't simulate live socket
  state to verify "JA4T was set on this connCtx"). Drop or rescope.
- 203b: 4 vector tests + parity test against Python output (run Python's
  `check_ja4_tls_mismatch` for the same inputs and assert score equality).
- 203c: parity test enumerating Python's `WEAK_CIPHERS` and asserting Go set
  contains each. **Also assert size equality** so future Python additions
  fail loudly.
- 203d: ±0.05 tolerance won't hold (see analysis). Either rewrite Go to
  exact Python parity (recommend) or relax tolerance to ±0.20 with explicit
  rationale. Tranco corpus, not Alexa.
- 203e: needs `httptest.NewRecorder` for handler tests + a fake `redis` /
  GeoIP injectable. The handler currently reads `p.redis` directly; a junior
  may need to introduce a small interface to mock.
- **No `test_pages.py` / `test_container_config.py` needed** — these are Go
  internal tests, no web-page surface added.

### F. Documentation
- CHANGELOG — one entry per sub-phase OR one consolidated entry (prefer
  consolidated; sub-phases are tightly related).
- `docs/REDIS_SCHEMA.md` — no changes (no new keys).
- `docs/runbooks/go_proxy_operations.md` — update for 203e.
- ADRs — none required if 203a is dropped. If retained, **must** have an
  ADR explaining the JA4T-from-accepted-socket limitation.

---

## Resolution summary (2026-04-15 — end of phase)

All findings resolved by the implemented phase:

| # | Finding | Resolution |
|---|---|---|
| 1, 2, 3 | 203a JA4T architectural unsoundness, three-definitions-of-JA4T | **Resolved.** 203a rescoped to TAP-consumer (`internal/security/tap_consumer.go`); Go does not compute JA4T. `internal/tls/ja4t.go` stub and test deleted. ADR-203a captures the decision. |
| 4 | "37+ ciphers" stale count | **Resolved.** Real count is 40 (not 42); parity test hard-codes the 40-entry list. |
| 5 | DGA ±0.05 tolerance not achievable | **Resolved.** Exact Python re-port; golden file at `tests/fixtures/dga/expected_scores.json` asserts equality. |
| 6 | Alexa corpus reference | **Resolved.** Tranco corpus used (reusing `tests/fp_corpus/` infra). |
| 7 | DGA rule divergence (consonant runs, digit ratio, skip prefixes) | **Resolved.** Go-only rules removed; `_SKIP_PREFIXES` and `getPrimaryLabel` ported verbatim. |
| 8, 10 | `/health/deep` already rich; GeoIP existence unverified | **Resolved.** `/health` left intact; `/health/deep` extended with tarpit + geoip presence. GeoIP presence-only (reader exists in `p.geoIP`). |
| 9 | Anti-flap state concurrency | **Resolved.** `internal/health.State` uses `sync.RWMutex`; covered by `-race` tests. |
| 11 | 203b missing Prometheus counter | **Resolved.** `ja4proxy_ja4_tls_mismatch_total{action}` registered and emitted. |
| 12 | Runbook delta for 203e | **Resolved.** `docs/runbooks/go_proxy_operations.md` documents JSON shape, status-code table, anti-flap time-to-detect, degraded-vs-503 rule. |
| 13 | Phase 200 dependency | **Not a blocker.** 203a chosen path (TAP consumer) does not require Phase 200; ADR-203a notes a future revisit if/when 200 lands. |

---

## Risk Summary

| # | Finding | Severity | Lens | Recommendation |
|---|---------|----------|------|----------------|
| 1 | 203a JA4T format conflicts with Python (`{window}_{mss}_{order}_{wscale}` vs phase doc's `{ttl}_{mss}_{window}_{hash}`) | **CRITICAL** | Architecture | Rewrite 203a to Python's actual format, OR drop 203a from this phase |
| 2 | 203a syscall.GetsockoptInt cannot recover client SYN options from accept()'d socket | **CRITICAL** | Architecture | Drop 203a or scope to "port Python's parser; no hot-path wiring" |
| 3 | Three different definitions of "JA4T" exist in repo (TAP-mode, Go alert-codes stub, phase-doc TTL-hash) | HIGH | Architecture | Pick canonical definition (Python TAP) and document in ADR |
| 4 | 203c expected count "37+" stale — Python actually has 42, Go has 12 | LOW | Testing | Update acceptance criterion to "exactly 42, full parity"; assert set-size equality in test |
| 5 | 203d ±0.05 tolerance not achievable without exact Python re-port | HIGH | Testing | Either rewrite Go to exact parity OR relax tolerance with documented rationale |
| 6 | 203d test fixture instructions reference Alexa (defunct since 2022) | MEDIUM | Testing | Use Tranco; reuse `tests/fp_corpus/` infra |
| 7 | 203d Go has consecutive-consonant rule + digit-ratio that Python lacks; Python has `_get_primary_label` skip-prefix that Go lacks | HIGH | Architecture | Port `_SKIP_PREFIXES` set verbatim from Python |
| 8 | 203e premise treats `/health` as the only endpoint; `/health/deep` already exists with rich data | MEDIUM | SRE | Extend `/health/deep`, not `/health`. Don't add GeoIP-stat to liveness probe |
| 9 | 203e anti-flap state shared across concurrent handler invocations — needs atomic counter or mutex | MEDIUM | Concurrency | Specify `atomic.Int64` per-component in the doc; add a race test (`-race` flag) |
| 10 | 203e specifies "GeoIP DB" check but Go proxy may not load one — verify | MEDIUM | SRE | Grep `internal/` for MaxMind / geoip2; if absent, drop GeoIP from acceptance criteria |
| 11 | 203b missing Prometheus counter `ja4proxy_ja4_tls_mismatch_total` (Python emits it) | HIGH | Observability | Add to acceptance criteria; emit on every call |
| 12 | No runbook delta in phase doc for 203e (new health JSON shape) | LOW | Documentation | Add `docs/runbooks/go_proxy_operations.md` update to 203e acceptance criteria |
| 13 | Phase 200 dependency status not verified | MEDIUM | Pre-flight | Confirm `manifest.yaml: 200.status == COMPLETE` before starting 203a |

---

## Recommended Reshape Before Implementation

**Drop 203a** from Phase 203. It is the only sub-phase that is architecturally
unsound on a Go inline proxy. Capture the work as a sub-task of Phase 200
(PROXY-protocol v2 TLV support), where TCP-stack info is already on the
table. Or open a fresh phase for "TAP-mode JA4T → Go" once the TAP crate
exists in Go.

That leaves Phase 203 as four sub-phases — **203b, 203c, 203d, 203e** — all
independently mergeable, no cross-deps, all defensive parity work against
the Python reference. This is a clean, low-risk phase.

If the user *insists* on 203a in this phase: rescope to "port
`src/tap/fingerprints/ja4t.py` to `internal/tls/ja4t.go` with the correct
format (`{window_size}_{mss}_{options_order}_{window_scale}`), include a
`// TODO(phase-200): wire from PROXY v2 TLV` marker, do **not** wire it
from `handleConnection()`, and add a feature flag `ja4t.enabled: false`."

---

## Sub-Task Decomposition

Numbering assumes 203a is dropped. If retained, slot it as 203a-rescope at
the start of group 2 (core logic) with the rescoped instructions above.

### Group 1 — Scaffolding (parallel-safe)

#### Sub-task 1.1: Add `ja4_tls_mismatch` score to canonical config
**Size:** XS (15 min)
**Depends on:** none
**Files:** `config/signal_scores.yml`
**What to do:** Verify `signals.ja4_tls_mismatch.score: 35` exists. If not,
add it under the existing `signals:` block with `score_cap: 35`.
**Done when:**
- [ ] `grep ja4_tls_mismatch config/signal_scores.yml` returns a line
- [ ] `make check-scores` exits 0
**Watch out for:** key may already exist (Python uses it).

#### Sub-task 1.2: Empty test files
**Size:** XS
**Depends on:** none
**Files:** `internal/security/tls_mismatch_test.go`, `internal/security/dga_parity_test.go`, `tests/fixtures/dga/hostnames.txt`
**What to do:** Create empty Go test files with package decl + one
`func TestPlaceholder(t *testing.T) { t.Skip("filled in 2.x") }`. Create
empty hostnames fixture file with a header comment.
**Done when:**
- [ ] Files exist
- [ ] `go build ./...` passes

### Group 2 — Core logic (parallel-safe within group)

#### Sub-task 2.1 (203b): `CheckJA4TLSMismatch` in tls_enforcer
**Size:** S (1.5 h)
**Depends on:** 1.1, 1.2
**Parallel with:** 2.2, 2.3
**Files:** `internal/security/tls_enforcer.go`, `internal/security/tls_mismatch_test.go`, `internal/metrics/metrics.go`
**What to do:**
- Add `func (e *TLSEnforcer) CheckJA4TLSMismatch(ja4 string, actualTLSVersion uint16) *RiskSignal` returning `nil` on match, `*RiskSignal` on mismatch.
- Parse JA4 first segment: `ja4[0:3]` → `t13`/`t12`/`t11`/`t10`/`s30`. Map to uint16. Reject malformed JA4 with `nil` (fail-open).
- New Counter `ja4proxy_ja4_tls_mismatch_total` with label `action`. Register via `MustRegister` (this repo's pattern).
- Wire into `internal/proxy/proxy.go` *after* TLS handshake but before scoring. Append non-nil signal to the slice fed to RiskScorer.
- Tests: 4 vectors (t13/1.3 ok, t13/1.2 mismatch, t12/1.1 mismatch, t10/SSLv3 mismatch), 1 malformed-JA4 fail-open vector, 1 metric-incremented assertion.

**Done when:**
- [ ] All 6 test cases pass
- [ ] `make go-test` passes
- [ ] `make check-scores` exits 0
- [ ] Counter visible in `/metrics`

**Watch out for:**
- Don't return signal with score 0 on match — return `nil`. The pipeline
  treats 0-score signals differently (they're appended; nil is dropped).

#### Sub-task 2.2 (203c): Expand weakCipherSet to full Python parity
**Size:** XS (45 min)
**Depends on:** 1.2
**Parallel with:** 2.1, 2.3
**Files:** `internal/security/tls_enforcer.go`, `internal/security/cipher_parity_test.go`
**What to do:**
- Read `src/security/tls_enforcer.py:50-92` and copy every cipher into Go's
  `weakCipherSet`. Preserve the comment for each (`// TLS_RSA_WITH_NULL_MD5`).
- Final size must be **42**. Don't add ciphers Python doesn't have.
- Parity test: assert `len(weakCipherSet) == 42`, then enumerate Python's
  list (hardcoded in the test) and assert each is `weakCipherSet[c] == true`.

**Done when:**
- [ ] `len(weakCipherSet) == 42`
- [ ] Parity test passes
- [ ] `make go-test` passes
- [ ] `make check-scores` exits 0

**Watch out for:**
- Don't trust the cipher list in the phase doc (it has dupes and a wrong
  `0x0017` double-listing). Use `src/security/tls_enforcer.py` as truth.
- Existing 12 entries already cover some — dedupe, don't re-add.

#### Sub-task 2.3 (203d): Re-port DGA to exact Python parity
**Size:** S (3 h)
**Depends on:** 1.2
**Parallel with:** 2.1, 2.2
**Files:** `internal/security/sni_analyzer.go`, `internal/security/dga_parity_test.go`, `tests/fixtures/dga/hostnames.txt`
**What to do:**
- Replace `dgaConfidence` body to mirror `src/security/sni_analyzer.py:93-150` *exactly*:
  - Sliding entropy `min(0.40, (ent - 3.8) * 2.0)` when `ent >= 3.8`
  - Vowel rules: `vowel_count==0 && alpha>=6 → +0.30`; `alpha>=10 && (alpha/vowel) > 5 → +0.20`
  - Length: `>=20 → +0.20`, `>=16 → +0.10`
  - Digit regex `\d{4,}` → `+0.10`
  - **Remove** the consecutive-consonant rule (Go-only invention)
  - **Remove** the digit-ratio rule (Go-only invention)
- Add `_SKIP_PREFIXES` set (read from `src/security/sni_analyzer.py`) and
  port `_get_primary_label`. Use leftmost non-skip label.
- Fixture: 30 known DGA + 50 Tranco top-50 + 20 edge cases. **Source from
  `tests/fp_corpus/` (Tranco), not Alexa.**
- Parity test: for each fixture hostname, call Python (via subprocess
  `python3 -c "from src.security.sni_analyzer import dga_score; ..."`) and
  Go, assert |go - py| ≤ 0.05. **If exact port: should be 0.0**.
- FP corpus test: ≤ 1% Go score ≥ 0.5 over Tranco top-10k.

**Done when:**
- [ ] `dga_parity_test.go` passes for all fixture hostnames
- [ ] FP rate test < 1% on top-10k
- [ ] `make go-test` passes

**Watch out for:**
- Python uses `re.search(r"\d{4,}", label)` — Go equivalent is
  `regexp.MustCompile("[0-9]{4,}").MatchString(label)`. Don't recompile in
  the hot path; declare the regexp as a package-level `var`.
- Python's `_shannon_entropy` uses `math.log2`. Go has `math.Log2`. Same
  semantics. Watch for empty-string edge case (Python returns 0.0).

#### Sub-task 2.4 (203e): Extend `/health/deep` with component checks + anti-flap
**Size:** S (3 h)
**Depends on:** 1.2
**Parallel with:** 2.1, 2.2, 2.3
**Files:** `cmd/proxy/main.go`, `cmd/proxy/health_test.go`, `internal/health/state.go` (new)
**What to do:**
- **Do NOT modify `/health`.** Leave it as-is (k8s liveness — Redis only).
- Extend `handleHealthDeep` to add:
  - `tarpit: {active, max, status}` — read from existing tarpit metric
  - `geoip: {present, status}` — only if Go proxy loads a GeoIP DB. **Verify
    first** with `grep -rn 'geoip\|maxmind\|GeoLite' internal/ cmd/proxy/`.
    If no GeoIP loader, skip this entirely.
- Anti-flap: package `internal/health` with `type State struct { mu sync.RWMutex; failures map[string]int }` and methods `RecordFailure(component) bool` (returns true when ≥ 3 consecutive), `RecordSuccess(component)`. **Use atomic operations or RWMutex; do not access map without lock.**
- Tests: healthy / Redis-down / GeoIP-missing / single-failure-doesn't-flip / three-failures-do-flip / success-resets-counter. Run with `-race`.

**Done when:**
- [ ] `/health/deep` returns new fields
- [ ] `/health` unchanged
- [ ] `go test -race ./cmd/proxy/...` passes
- [ ] Runbook `docs/runbooks/go_proxy_operations.md` updated with new JSON shape

**Watch out for:**
- Concurrent handler invocations share `State`. Without proper locking the
  `-race` flag will fail.
- N=3 hysteresis on `/health/deep` means 3× probe interval to detect failure
  — document in runbook.

### Group 3 — Documentation

#### Sub-task 3.1: CHANGELOG + manifest
**Size:** XS
**Depends on:** 2.1, 2.2, 2.3, 2.4
**Files:** `CHANGELOG.md`, `docs/phases/manifest.yaml`
**What to do:** One consolidated entry; mark phase 203 status COMPLETE.
**Done when:**
- [ ] `CHANGELOG.md` has phase-203 entry
- [ ] `make sync` regenerates TODO/PROJECT_STATUS without diff conflict

#### Sub-task 3.2: Phase notes file
**Size:** XS
**Depends on:** 2.1–2.4
**Files:** `docs/phases/PHASE_203_notes.md`
**What to do:** Consolidated notes summarising what was done in 203b/c/d/e
and what was deferred (203a → Phase 200).

---

## Summary

- **Total sub-tasks:** 8 (1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 3.1, 3.2).
- **Estimated total effort:** ~10 hours of focused work; team of 4 in
  parallel can finish Group 2 in ~3 h wall-clock.
- **Critical blockers before any implementation begins:**
  1. **Drop or rescope 203a.** Do not implement as written.
  2. **Verify Phase 200 dependency status** in `manifest.yaml`.
  3. **Verify whether the Go proxy loads a GeoIP DB** before specifying it
     in 203e acceptance criteria (sub-task 2.4 step 1).
- **Recommended scope for /run-phase 203:** sub-tasks 1.1, 1.2, 2.1, 2.2,
  2.3, 2.4, 3.1, 3.2. **Skip 203a entirely.**

If the user agrees with this scope, the phase is small, tightly scoped, and
all four remaining sub-phases run safely in parallel — well-suited for the
multi-agent run-phase orchestration.
