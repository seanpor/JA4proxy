# Phase 203 — Go Missing Signals (TAP-derived JA4T, ja4_tls_mismatch, Weak Ciphers, DGA, Health)

> **Status:** PROPOSED (re-scoped 2026-04-15 after critical review;
> see `PHASE_203_review.md`).
> **Parent size:** MEDIUM — five fully-independent sub-phases.
> **Target runtime:** Go production proxy (`internal/`, `cmd/proxy/`).
> Python references are read-only oracles for parity.
> **Hard dependency:** Phase 20 (TAP mode) for sub-phase 203a only;
> 203b/c/d/e have no dependencies.

## Goal

Close five production-critical signal gaps in the Go proxy:

1. **203a — TAP-consumed JA4T:** Surface JA4T-derived OS-class signal in the
   Go proxy by *reading* Phase-20 TAP fingerprints from Redis (the proxy
   itself cannot compute JA4T — see Architectural Decision below). Detects
   evasive clients whose TLS fingerprint claims one OS class but whose TCP
   stack behaviour reveals another.
2. **203b — `ja4_tls_mismatch`:** Catch TLS-version spoofing where the JA4
   prefix (`t13`/`t12`/...) disagrees with the negotiated TLS version.
3. **203c — Weak cipher parity:** Sync Go's `weakCipherSet` to **exactly**
   match Python's `WEAK_CIPHERS` (40 suites — verified count, not "37+").
4. **203d — DGA algorithm parity:** Re-port `dgaConfidence()` to match
   Python's `dga_score()` rule-for-rule.
5. **203e — Deepen `/health/deep`:** Add component checks (tarpit
   saturation, optionally GeoIP) to the existing rich health endpoint with
   anti-flap hysteresis. **Leave `/health` untouched** — it is the k8s
   liveness probe and must stay tight.

---

## Architectural Decision — JA4T on the inline Go proxy

JA4T fingerprints TCP-stack behaviour from the **client's SYN packet**:
window size, MSS, options order, window scale (Python format:
`{window_size}_{mss}_{options_order}_{window_scale}` —
see `src/tap/fingerprints/ja4t.py`).

A Go inline TCP listener **cannot** compute JA4T. By the time `accept()`
returns, the kernel has consumed the SYN, completed the three-way
handshake, and handed the proxy a connected socket whose state reflects the
*negotiated* connection — not the client's original SYN options.
`syscall.GetsockoptInt(SOL_TCP, …)` returns the proxy's own send-side
parameters. There are exactly three ways to recover client SYN data on a
running production proxy:

| Mechanism | Status in this repo |
|---|---|
| Passive TAP/SPAN port + AF_PACKET capture | **Phase 20 — implemented in Python.** Already writes `fp:conn:{id}` Hash and `fp:os:ip:{ip}` String to Redis. |
| PROXY-protocol v2 TLVs from upstream LB | Phase 200 (proposed). Not landed. |
| eBPF/XDP hook before kernel handshake | Not planned; large project. |

The right answer for Phase 203a is therefore **not** "compute JA4T in the
Go proxy" but **"consume Phase 20's TAP-produced JA4T from Redis."** The
TAP node sees raw packets and computes the fingerprint; the inline proxy
reads the result on `accept()` keyed by client IP, and emits a signal when
the JA4-claimed OS-class disagrees with the TAP-observed OS-class.

This preserves the Python-is-prototype / Go-is-production split: the
Python TAP node continues to be the right tool for the packet-capture job
(Python is fine here because it's *not the proxy* — it's an
out-of-band signal-enrichment service, and CLAUDE.md explicitly allows
Python for "services that are not the proxy"). The Go proxy stays inline,
fast, and free of CAP_NET_RAW or eBPF dependencies.

### Operational consequences

| Concern | Effect |
|---|---|
| **TAP not deployed** | Signal silently dormant. Redis lookup returns nil → no signal emitted → fail-open behaviour preserved. The proxy continues to function exactly as today. |
| **TAP deployed but fingerprint stale** | Configurable `max_age_seconds` (default 300) discards stale lookups. Stale data → no signal. |
| **Hot-path Redis GET** | One additional `GET fp:os:ip:{client_ip}` per non-bypassed connection. Sub-ms with local Redis; cached in `LocalCache` for `cache_ttl_seconds` (default 60). |
| **No new Redis keys** | Reads only Phase-20 keys (`fp:os:ip:{ip}`, optionally `fp:conn:{id}`). Schema unchanged. |
| **Privilege** | Go proxy still runs unprivileged. Only the TAP node needs CAP_NET_RAW. |
| **Failure mode** | Redis down → no signal (already handled by existing fail-open Redis path). |
| **Documentation** | Runbook must state: "to enable JA4T-OS-mismatch detection, deploy the Phase 20 TAP node alongside this proxy." |

### Withdrawn from original phase doc

- ❌ `ComputeJA4T(ttl, mss, windowSize, options) string` — wrong format,
  unimplementable from accept()'d socket.
- ❌ `syscall.GetsockoptInt` wiring in `handleConnection()` — would silently
  return wrong data.
- ❌ Three-different-definitions-of-JA4T situation — the Go stub
  `internal/tls/ja4t.go` (TLS-alert-codes flavour) is dead code; remove it.

### Existing dead code to delete

- `internal/tls/ja4t.go` — the `ComputeJA4T(alertCodes []uint8) string`
  stub and its test file. Unrelated to the real JA4T concept; never wired
  in; misleading. Delete during 203a.

---

## Sub-phase index

| ID | Sub-phase | Repo area | Size | Depends on |
|---|---|---|---|---|
| **203a** | TAP-consumed JA4T-OS-mismatch signal | `internal/security/tap_consumer.go` (new), `internal/proxy/proxy.go` | S | Phase 20 (deployment); none for code |
| **203b** | `ja4_tls_mismatch` signal | `internal/security/tls_enforcer.go` | XS | none |
| **203c** | Weak cipher parity (exactly 40) | `internal/security/tls_enforcer.go` | XS | none |
| **203d** | DGA algorithm exact-port to Python | `internal/security/sni_analyzer.go` | S | none |
| **203e** | Deepen `/health/deep` (NOT `/health`) | `cmd/proxy/main.go`, `internal/health/state.go` (new) | S | none |

All five sub-phases are independent (different files / different functions
within the same file). A team of five can work in parallel with no merge
conflicts.

---

## Sub-phase 203a — TAP-consumed JA4T-OS-mismatch signal (S)

**Goal:** Emit a `tap_os_mismatch` RiskSignal when the OS class implied by
the JA4 TLS fingerprint disagrees with the OS class observed by the TAP
node from the client's TCP SYN.

**Why this matters:** A bot that spoofs Chrome-on-Windows JA4 but actually
runs on Linux will leave a Linux-shaped TCP SYN. JA4 and JA4T-derived OS
class disagree → high-confidence evasion signal.

**Files to create/modify:**
- `internal/security/tap_consumer.go` — new module
- `internal/security/tap_consumer_test.go` — unit tests
- `internal/proxy/proxy.go` — wire the call site after JA4 computed
- `internal/cache/local.go` — add `TapOSCache` LRU (small)
- `config/proxy.yml` — add `tap_consumer:` block
- `internal/config/loader.go` — add struct fields
- `internal/metrics/metrics.go` — add Prometheus counter
- `internal/tls/ja4t.go` + `internal/tls/ja4t_test.go` — **delete** (dead code)

**Steps:**

1. **Delete the dead stub.** `git rm internal/tls/ja4t.go internal/tls/ja4t_test.go`.
   Search for any references and remove them: `grep -rn 'ComputeJA4T' .` —
   should be empty after deletion.
2. **Define the JA4 → claimed-OS mapping.** In `internal/security/tap_consumer.go`,
   add a small static table mapping JA4 prefix patterns to OS class:
   ```go
   // ja4OSClass returns the claimed OS class from a JA4 fingerprint prefix.
   // Returns "" for unknown / ambiguous JA4s — caller treats as no-signal.
   func ja4OSClass(ja4 string) string { ... }
   ```
   Use a small set of well-known mappings (Chrome-on-Windows, Chrome-on-macOS,
   Safari, Firefox, curl, etc.) — derive from Phase 20's `config/os_fingerprints.yml`
   and the existing JA4 dataset documented at `https://github.com/FoxIO-LLC/ja4`.
   For Phase 203a the table can be small (5–10 entries); document that
   gaps are intentional fail-open.
3. **Implement the consumer.** New `TapConsumer` with:
   ```go
   type TapConsumer struct {
       cfg     *TapConsumerConfig
       redis   redisClient   // existing interface
       cache   *cache.TapOSCache
       log     *logrus.Logger
   }
   func (t *TapConsumer) GetSignal(ctx context.Context, clientIP, ja4 string) *RiskSignal
   ```
   Inside `GetSignal`:
   - If `!cfg.Enabled` or `ja4 == ""` → return nil
   - Compute `claimed := ja4OSClass(ja4)`. If empty → return nil
   - Check `t.cache.Get(clientIP)` first. On miss, do `redis.Get(ctx, "fp:os:ip:" + clientIP)`
   - Wrap Redis call in `context.WithTimeout(ctx, cfg.RedisTimeout)` (default 50 ms)
   - On Redis error or nil → return nil (fail open; increment `tap_lookups_total{result="miss"}`)
   - On hit → check `observed := value`; cache result for `cfg.CacheTTL` (default 60s)
   - If `claimed == observed` → return nil
   - Else → return `&RiskSignal{Name: "tap_os_mismatch", Score: cfg.SignalScore, Reason: fmt.Sprintf("JA4 claims %s, TAP observed %s", claimed, observed), Weight: 1.0}`
   - Increment `tap_lookups_total{result="hit_match|hit_mismatch|miss|error"}`
4. **Wire the call site.** In `internal/proxy/proxy.go` `handleConnection()`,
   after JA4 is computed and bypass checks have not fired, call
   `signal := tapConsumer.GetSignal(ctx, clientIP, ja4)` and append to
   the signal slice if non-nil. **Order matters:** call this BEFORE the
   scorer aggregates signals, AFTER the JA4 whitelist bypass check.
5. **Config block** in `config/proxy.yml`:
   ```yaml
   tap_consumer:                 # phase-203a
     enabled: false              # default OFF — requires Phase 20 TAP node deployed
     signal_score: 30            # score added to RiskScorer when mismatch detected
     redis_timeout_ms: 50        # short to keep hot path fast; fail open on timeout
     cache_ttl_seconds: 60       # LocalCache TTL for per-IP lookup result
     max_age_seconds: 300        # ignore TAP fingerprints older than this
   ```
   Add inline comments explaining: "Set enabled: true ONLY if the Phase 20
   TAP node is deployed and writing to the same Redis."
6. **`signal_score` validated**: `signal_score` must appear in
   `config/signal_scores.yml` under `signals.tap_os_mismatch.score: 30,
   score_cap: 30`. Add it.
7. **Metrics**: in `internal/metrics/metrics.go`:
   - `ja4proxy_tap_lookups_total{result}` counter (`hit_match`, `hit_mismatch`, `miss`, `error`)
   - `ja4proxy_tap_signal_total{action}` counter (existing pattern: `flag`, `block`, etc.)
8. **Tests** in `internal/security/tap_consumer_test.go`:
   - Disabled config → returns nil
   - JA4 unknown to mapping → returns nil
   - Redis miss → returns nil, increments `result="miss"`
   - Redis hit, claimed==observed → returns nil, increments `result="hit_match"`
   - Redis hit, claimed!=observed → returns signal, increments `result="hit_mismatch"`
   - Redis timeout → returns nil, increments `result="error"`, **does NOT block hot path** (assert call duration < 100 ms with a `time.Sleep(1*time.Second)` mock)
   - LocalCache short-circuits a second lookup for the same IP
   - Concurrent `GetSignal` calls are race-free (`go test -race`)

**Acceptance criteria:**
- [x] `internal/tls/ja4t.go` and its test deleted; no dangling references
- [x] `tap_consumer` config block in `config/proxy.yml` with `enabled: false` default
- [x] `tap_os_mismatch` score 30 in `config/signal_scores.yml`
- [x] `TapConsumer.GetSignal()` returns correct values for all 8 test scenarios above
- [x] Wired into `proxy.go` after JA4 computation, before scorer aggregation
- [x] `ja4proxy_tap_lookups_total` and `ja4proxy_tap_signal_total` counters registered and incremented
- [x] `go test -race ./internal/security/...` passes
- [x] `make check-scores` exits 0
- [x] `docs/runbooks/go_proxy_operations.md` updated: "Enabling JA4T-OS-mismatch requires Phase 20 TAP node"
- [x] ADR-203a written documenting the TAP-consumer architecture
- [x] `PHASE_203a_notes.md` written

**Out of scope:**
- Computing JA4T in the Go proxy (architecturally impossible — see decision above)
- Updating the Phase 20 TAP node (already writes the keys we need)
- Expanding the JA4-to-OS mapping table beyond a starter set (a follow-up
  signal-quality phase will widen it once we have production telemetry)

**Watch out for:**
- The Redis `GET` is on the hot path. `redis_timeout_ms: 50` is the cap; the
  `cache.TapOSCache` LRU should bring most calls to sub-microsecond. Add a
  histogram if latency becomes a concern.
- Don't read `fp:conn:{id}` (the full Hash) — `fp:os:ip:{ip}` is a single
  String GET and contains exactly what we need. The Hash is for analytics.
- IPv6: client IP must be in canonical form (matches what Phase 20 writes).
  Use the existing `internal/proxy` IP normalisation helper.

---

## Sub-phase 203b — `ja4_tls_mismatch` signal (XS)

**Goal:** Emit `ja4_tls_mismatch` (score 35) when the JA4 prefix
disagrees with the negotiated TLS version.

**Files to modify:**
- `internal/security/tls_enforcer.go` — new method `CheckJA4TLSMismatch`
- `internal/security/tls_mismatch_test.go` — new
- `internal/proxy/proxy.go` — wire call site
- `internal/metrics/metrics.go` — add counter
- `config/signal_scores.yml` — verify `ja4_tls_mismatch.score: 35` exists
  (Python already defines it; Go just consumes)

**Steps:**

1. Add method:
   ```go
   func (e *TLSEnforcer) CheckJA4TLSMismatch(ja4 string, actualTLSVersion uint16) *RiskSignal
   ```
   Returns `nil` on match or unparseable JA4 (fail open). Returns
   `*RiskSignal{Name:"ja4_tls_mismatch", Score: 35, Weight: 1.0}` on mismatch.
2. Parse JA4 first 3 chars: `t13` → `0x0304`, `t12` → `0x0303`,
   `t11` → `0x0302`, `t10` → `0x0301`, `s30` → `0x0300`.
3. If JA4 too short or prefix unknown → return nil (fail open).
4. New counter `ja4proxy_ja4_tls_mismatch_total{action}` registered via
   `MustRegister` (this repo's pattern; not promauto).
5. Wire from `internal/proxy/proxy.go`: after TLS handshake completes and
   JA4 is computed, call this check; append non-nil signal to the slice.
6. Tests (`internal/security/tls_mismatch_test.go`):
   - `t13` + 0x0304 → nil
   - `t13` + 0x0303 → signal score 35
   - `t12` + 0x0302 → signal score 35
   - `t10` + 0x0300 → signal score 35
   - `""`, `"x"` (malformed) → nil
   - `"abc"` (unknown prefix) → nil
   - Counter increments on mismatch only

**Acceptance criteria:**
- [x] All 7 test cases pass
- [x] Counter `ja4proxy_ja4_tls_mismatch_total` registered and visible at `/metrics`
- [x] Wired in `proxy.go`
- [x] `make go-test` passes
- [x] `make check-scores` exits 0
- [x] `PHASE_203b_notes.md` written

**Out of scope:** other anti-spoofing signals; JA4 computation changes.

---

## Sub-phase 203c — Weak cipher parity (XS)

**Goal:** Make Go's `weakCipherSet` **exactly equal** to Python's
`WEAK_CIPHERS` (40 suites).

**Files to modify:**
- `internal/security/tls_enforcer.go` — expand `weakCipherSet`
- `internal/security/cipher_parity_test.go` — new

**Steps:**

1. Open `src/security/tls_enforcer.py` lines 50–92 (the `WEAK_CIPHERS`
   frozenset). Treat it as the authoritative list.
2. Replace Go's `weakCipherSet` body with all 40 entries, preserving the
   per-line comment from Python verbatim (`// TLS_RSA_WITH_NULL_MD5` etc.).
3. **Do not** add any cipher Python lacks. Do not invent new ones.
4. Parity test (`cipher_parity_test.go`):
   - `assert len(weakCipherSet) == 40`
   - For each of the 40 hex codes, assert `weakCipherSet[c] == true`
   - Hardcode the list in the test (not in a fixture file) so a Python-side
     change forces a Go-side update.
5. Run `make go-test` and `make check-scores`.

**Acceptance criteria:**
- [x] `len(weakCipherSet) == 40`
- [x] Parity test enumerates all 40 ciphers from Python and asserts presence
- [x] No extras; no duplicates (Go map literal won't catch dupes — assert
      via test counting unique entries from the source)
- [x] `make go-test` passes
- [x] `make check-scores` exits 0
- [x] `PHASE_203c_notes.md` written

**Out of scope:** Cipher negotiation logic, TLS 1.3 cipher set changes.

**Watch out for:**
- Existing 12 entries already cover 0x0001, 0x0002, 0x0004, 0x0005, 0x000A,
  0x002F, 0x0035, 0x003C, 0x003D, 0x0018, 0x0033, 0x0039. Diff against the
  Python list before pasting; some of those Python doesn't include
  (e.g. 0x0033, 0x0039, 0x003C, 0x003D are CBC-mode but PFS — Python
  considers them OK). Match Python exactly: the Go set may *shrink* in
  some entries while gaining ~30 new ones. Net result: **40 entries**.

---

## Sub-phase 203d — DGA algorithm exact-port to Python (S)

**Goal:** Rewrite Go's `dgaConfidence()` to match Python's `dga_score()`
rule-for-rule, byte-for-byte equivalent output for any given input.

**Files to modify:**
- `internal/security/sni_analyzer.go` — replace `dgaConfidence()` body and
  add `_get_primary_label` equivalent + `_SKIP_PREFIXES` set
- `internal/security/dga_parity_test.go` — new
- `tests/fixtures/dga/hostnames.txt` — new (Tranco-derived; **not Alexa**)

**Steps:**

1. Read `src/security/sni_analyzer.py` lines 80–150. The authoritative rules:
   - Use `_get_primary_label`: lowercase, rstrip `.`, split, return first
     non-skip-prefix label. Skip set lives in `_SKIP_PREFIXES`.
   - If `len(label) < _MIN_DGA_LABEL_LEN` → return 0.0
   - Entropy: `if ent >= 3.8: score += min(0.40, (ent - 3.8) * 2.0)`
   - Vowels: `if alpha_count >= 6 and vowel_count == 0: score += 0.30`
     elif `alpha_count >= 10 and (alpha_count / vowel_count) > 5.0: score += 0.20`
   - Length: `>= 20 → +0.20`, `>= 16 → +0.10`
   - Digits: `re.search(r"\d{4,}", label) → +0.10`
   - Return `min(1.0, score)`
2. **Remove** Go's current consonant-run rule (Go invention, not in Python).
3. **Remove** Go's current digit-ratio `>0.30 → +0.20` rule (Go invention).
4. **Replace** Go's current entropy thresholds (`>3.5 → +0.35` etc.) with
   Python's sliding-scale rule above.
5. **Add** `var _SKIP_PREFIXES = map[string]bool{...}` populated from
   Python's `_SKIP_PREFIXES` constant. Keep them sync'd with a comment
   pointing to the Python source line.
6. **Add** `func getPrimaryLabel(hostname string) string` mirroring Python.
7. Pre-compile the `\d{4,}` regex as a package var.
8. Build fixture file `tests/fixtures/dga/hostnames.txt` (one host per line):
   - 50 Tranco top-50 (legitimate; reuse `tests/fp_corpus/` infrastructure)
   - 30 known-DGA samples from `security/known_dga_domains.txt` if present,
     otherwise standard public DGA samples (Conficker, Cryptolocker patterns)
   - 20 edge cases: `localhost`, single-label, numeric-only `12345678.com`,
     very-long label (40+ chars), emoji-domains (UTS-46 normalisation)
9. Parity test:
   - For each fixture host, invoke Python via
     `python3 -c "from src.security.sni_analyzer import dga_score; print(dga_score('host'))"`
     and Go's `dgaConfidence(host)`. Assert `|go - py| < 1e-9` (exact match,
     not the original ±0.05 — exact port should produce exact equality).
   - Subprocess overhead ~30 ms per host × 100 hosts = 3 s; cache the
     Python output to a `.golden` file on first run, then assert against
     the golden in subsequent runs (no Python required in CI). Provide a
     `make dga-regenerate-golden` Makefile target for refresh.
10. FP-rate test: ≤ 1% of Tranco top-10k score ≥ 0.5 (Python guarantees this;
    Go must match).

**Acceptance criteria:**
- [x] `dgaConfidence` matches `dga_score` exactly for all 100+ fixture hosts
- [x] `_SKIP_PREFIXES` and `getPrimaryLabel` ported verbatim
- [x] Tranco top-10k FP rate ≤ 1%
- [x] Golden file committed to `tests/fixtures/dga/expected_scores.json`
- [x] `make go-test` passes
- [x] `PHASE_203d_notes.md` written

**Out of scope:**
- Changes to Python's algorithm (Python is the reference)
- New DGA heuristics

**Watch out for:**
- Python's `re.search(r"\d{4,}", label)` matches *anywhere* in the label;
  Go's `regexp.MustCompile("[0-9]{4,}").MatchString` does likewise. Don't
  use `^`/`$`.
- Empty string, single-char strings: Python returns 0.0 (length gate).
  Match this.
- Unicode: Python uses `c.isalpha()` which is Unicode-aware; Go's
  `unicode.IsLetter`. Use that, not the ASCII-only `'a'-'z'` check the
  current Go code uses.

---

## Sub-phase 203e — Deepen `/health/deep` with anti-flap (S)

**Goal:** Extend the existing `/health/deep` endpoint with tarpit and
optional GeoIP component checks, plus N=3 anti-flap hysteresis. **Do not
modify `/health`** — that endpoint is the k8s liveness probe and must
remain a tight Redis-or-die check.

**Files to modify:**
- `cmd/proxy/main.go` — extend `handleHealthDeep`
- `internal/health/state.go` — new package for anti-flap state
- `internal/health/state_test.go` — new
- `cmd/proxy/health_test.go` — new (integration)
- `docs/runbooks/go_proxy_operations.md` — document new JSON shape

**Steps:**

1. **Pre-flight**: `grep -rn 'geoip\|maxmind\|GeoLite' internal/ cmd/proxy/`.
   - If the Go proxy loads a GeoIP DB → include the GeoIP check
   - If not → omit GeoIP entirely from this sub-phase. Do not specify a
     check for a dependency that doesn't exist.
2. New package `internal/health`:
   ```go
   type State struct {
       mu       sync.RWMutex
       failures map[string]int
       cfg      Config
   }
   type Config struct {
       FailThreshold int  // default 3
   }
   func New(cfg Config) *State
   func (s *State) RecordFailure(component string) (unhealthy bool)  // true once threshold reached
   func (s *State) RecordSuccess(component string)                   // resets counter
   func (s *State) IsUnhealthy(component string) bool
   ```
   All methods must be safe under concurrent access (`-race` tested).
3. Extend `handleHealthDeep` (cmd/proxy/main.go:669) with new fields:
   - `tarpit: {active, max, status}` — read existing tarpit metric or
     proxy.activeTarpits if exposed
   - `geoip: {present, status}` — only if step 1 found a GeoIP loader
   - Apply hysteresis: each check increments `state.RecordFailure(component)`
     on error, `RecordSuccess` on success. Component reported as
     `"unhealthy"` only after threshold (3) consecutive failures.
4. HTTP status code:
   - 200 if no critical component is `"unhealthy"`
   - 503 if `redis` or `geoip` (when applicable) is `"unhealthy"`
   - Tarpit-saturated → 200 with `"degraded"` warning, never 503
5. Update runbook with the full JSON shape and the time-to-detect
   trade-off (3 × probe interval).

**Acceptance criteria:**
- [x] `/health` byte-for-byte unchanged
- [x] `/health/deep` returns new fields when components configured
- [x] Anti-flap: 1 failure does NOT flip status; 3 do
- [x] Anti-flap: 1 success after 2 failures resets the counter
- [x] `go test -race ./internal/health/... ./cmd/proxy/...` passes
- [x] Runbook updated
- [x] `PHASE_203e_notes.md` written

**Out of scope:**
- New Prometheus metrics (alerting is a separate phase)
- Modifying `/health` (intentional — see goal)
- Management-API health endpoints

**Watch out for:**
- Concurrent handler invocations share `*health.State` — `-race` will
  catch missing locks. Use `sync.RWMutex` (RLock for `IsUnhealthy`, Lock
  for record/reset).
- N=3 hysteresis means time-to-detect is `3 × probe_interval`. Document
  this in the runbook so on-call doesn't get surprised.

---

## Full-phase Acceptance Criteria

- [x] All five sub-phases (203a–e) complete with their individual criteria
- [x] `internal/tls/ja4t.go` deleted (dead stub)
- [x] `tap_os_mismatch`, `ja4_tls_mismatch` signals registered in `config/signal_scores.yml` and emitted from Go pipeline
- [x] `weakCipherSet` exactly matches Python (40 entries)
- [x] DGA parity test passes against Python golden file for 100+ hosts
- [x] `/health` unchanged; `/health/deep` extended with anti-flap
- [x] All Go tests pass under `-race`
- [x] `make check-scores` exits 0
- [x] `make test` (full Python+Go gate) passes
- [x] `CHANGELOG.md` entry written
- [x] `docs/decisions/ADR-203a.md` written documenting the TAP-consumer architecture
- [x] `docs/runbooks/go_proxy_operations.md` updated for 203a (TAP requirement) and 203e (health JSON shape)

## Out of Scope (whole phase)

- **Computing JA4T inside the Go inline proxy** — architecturally impossible
  from accept()'d socket; deferred indefinitely or to Phase 200
  (PROXY-protocol v2 TLVs).
- **eBPF/XDP packet-capture in the Go proxy** — large project, separate phase.
- **Honey-fingerprint deception** — Phase 56.
- **Python algorithm changes** — Python is the parity reference.
- **Expanding the JA4-to-OS mapping table** — starter set only; widen in a
  follow-up signal-quality phase informed by production telemetry.
- **Modifying `/health`** — intentional non-goal (see 203e).

---

## Close-out notes

Status at close: all five sub-phases landed; all acceptance criteria ticked.
Items worth flagging for future readers / reviewers:

- **Weak-cipher count corrected 42 → 40.** The review estimated 42 by
  frozenset-reading Python, but the real unique-entry count in
  `WEAK_CIPHERS` is 40. `weakCipherSet` in
  `internal/security/tls_enforcer.go` is exactly 40 entries, and
  `cipher_parity_test.go` hard-codes the 40-entry authoritative list.
  The CHANGELOG, ADR-203a notes, and this doc all use 40 going forward.
- **`CheckJA4TLSMismatch` fail-open when `actualTLSVersion == 0`.** A
  zero-valued negotiated version means the proxy never observed the
  handshake result (e.g. the path recorded the JA4 but did not record
  the negotiated version). Absence is not evidence of mismatch, so the
  check returns `nil`. This is the non-obvious invariant that prevents
  spurious signals on malformed / mid-parse paths.
- **JA4→OS mapping is a starter set of 7 entries** (windows / macos /
  linux / ios variants, via the FoxIO-LLC/ja4 corpus). Unknown JA4
  prefixes → `claimed == ""` → no signal. A follow-up signal-quality
  phase will widen this once production telemetry gives us confident
  mappings; gaps are intentional fail-open, not misses.
- **Tarpit saturation → HTTP 200 + `status="degraded"`, not 503.** Only
  Redis unhealthy after N=3 consecutive failures returns 503 from
  `/health/deep`. This prevents load balancers from flapping a proxy out
  when the slow path is at capacity but the fast path is still serving —
  under load we want *more* LB traffic shedding elsewhere, not less
  capacity by pulling a working proxy.
- **GeoIP is presence-only.** The Go proxy does load a GeoIP reader
  (`p.geoIP` in `cmd/proxy/main.go`), so `/health/deep` reports
  `geoip.present: true/false` plus a static `status: "ok"`. It is **not**
  actively probed on every deep health call — that would be a syscall
  storm at typical probe cadences. Active probing with its own anti-flap
  is follow-up work.
- **Existing `/health/deep` Redis-down test updated.** `TestHealthDeep_RedisDown`
  now hits the endpoint three times to exhaust anti-flap before asserting
  503. This is an intentional contract change introduced by 203e; old
  expectations of "one failure → 503" are obsolete.
- **Deleted dead code:** `internal/tls/ja4t.go` (the TLS-alert-codes
  `ComputeJA4T` stub) and its test file are gone. `grep -rn ComputeJA4T`
  in the repo returns nothing.
