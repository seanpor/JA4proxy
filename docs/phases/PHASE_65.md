# Performance Hardening & Go/Python Parity

## Overview

This phase addresses two related problems surfaced by the April 2026 benchmark analysis
and Go rewrite audit:

1. **Python proxy performance**: The `ProcessPoolExecutor` + Scapy TLS parsing pipeline
   adds 1–1.5ms of unavoidable IPC overhead to every connection. A hand-rolled pure-Python
   ClientHello parser eliminates this, plus three code-correctness bugs in the JA4 generator
   that cause redundant work on every connection.

2. **Go config gap**: Seven signal modules (ASN, DNS, blocklists, beaconing, AbuseIPDB,
   RDAP, JA4X) are fully implemented in Go but have no config structs in `loader.go` and
   are not wired in `buildPipelineConfig`. The Go proxy therefore runs with all seven
   disabled, scoring every connection zero and blocking nothing. The Phase 15 manifest
   entry `COMPLETE` is incorrect until this is fixed.

3. **Cross-proxy parity mechanism**: Two complete implementations of the same proxy will
   drift apart. This phase establishes permanent tooling — binary fixtures, a shared signal
   score registry, and a parity test harness — so that divergence is caught automatically
   rather than discovered through benchmark surprises.

---

## Background and Findings

### Why Scapy in a subprocess is expensive

Phase 28a introduced `ProcessPoolExecutor` to isolate Scapy's TLS parser from the main
asyncio process. The security motivation is sound: Scapy is a general-purpose protocol
parser that can consume unbounded memory on adversarial inputs. The cost is that every
TLS connection crosses a process boundary twice via pickle serialisation:

```
main process: pickle(raw_bytes) → IPC pipe → worker
worker: TLS(data) → TLSParser().parse_client_hello() → dict
main process: unpickle(dict) → JA4Generator.generate_ja4()
```

Measured overhead: ~0.4–0.8ms IPC + ~0.3–0.8ms Scapy parse = **0.7–1.5ms per
connection** before any signal work begins. On a 5.7ms total connection time, this
is 12–26% of budget.

A hand-rolled pure-Python ClientHello parser:
- Runs directly in the asyncio event loop (no executor needed — it completes in <0.1ms)
- Has statically bounded memory: one linear pass over the byte buffer
- Eliminates the process boundary entirely
- Does not need `RLIMIT_AS` because it cannot be made to recurse or allocate unboundedly

The Go proxy already demonstrates this is safe: `internal/tls/parser.go` is a hand-rolled
parser that handles all adversarial inputs and has never panicked in testing.

### Three correctness bugs in JA4Generator

**Bug 1 — GREASE as a list literal rebuilt on every call:**
```python
def _is_grease(self, value: int) -> bool:
    grease_values = [0x0A0A, 0x1A1A, ...]   # new list object every call
    return value in grease_values             # O(16) linear scan
```
Should be a module-level `frozenset` — allocated once, O(1) lookup.

**Bug 2 — GREASE filtered twice per connection:**
`generate_ja4()` filters GREASE from raw lists, producing `ciphers` and `exts`.
These filtered lists are then passed to `_hash_cipher_suites(ciphers)` and
`_hash_extensions(exts)`, which apply the same GREASE filter again:
```python
def _hash_cipher_suites(self, cipher_suites: List[int]) -> str:
    filtered_suites = [cs for cs in cipher_suites if not self._is_grease(cs)]  # again!
```
The double filtering is dead work. Fix: remove the filter from the hash functions and
trust the input is already filtered, or remove the filter from `generate_ja4` and let
the hash functions own it — not both.

**Bug 3 — SHA-256 over the full ClientHello buffer for a 16-char log field:**
```python
client_hello_hash=hashlib.sha256(data).hexdigest()[:16]
```
`data` is up to `buffer_size` bytes (default 4096). The first 64 bytes are sufficient
for deduplication purposes and cost 5× less to hash.

### Go config gap

`buildPipelineConfig()` in `cmd/proxy/main.go` (lines 445–526) populates:
- ✅ TLS enforcer, SNI analyzer, TCP analyzer, rate limiter

It does NOT populate:
- ❌ ASN classifier (8 fields)
- ❌ DNS enrichment (6 fields)
- ❌ Blocklist feeds (1 field — list of feeds)
- ❌ Beaconing detector (5 fields)
- ❌ AbuseIPDB (7 fields, including API key)
- ❌ RDAP enrichment (8 fields)
- ❌ JA4X config (4 fields)
- ❌ Static IP allowlist IPs (2 fields)
- ❌ Country blacklist set (1 field)

`internal/config/loader.go` has no YAML struct types for those modules, so they cannot
be read from `proxy.yml` at all. All seven modules are instantiated by `NewPipeline` but
run disabled because their `Enabled` field is `false` (Go zero value).

This is why the April 2026 benchmark showed Go blocking 0% of bot traffic.

---

## Work Plan

### A — Python: Replace Scapy parser (highest-value change)

Write `src/tls/parser.py` — a pure-Python TLS ClientHello parser:

```python
def parse_client_hello(data: bytes) -> dict | None:
    """
    Parse a raw TLS ClientHello record into the same dict schema as
    TLSParser._extract_client_hello_fields().

    Returns None on any parse error (fail open). Never raises.
    Memory: O(len(data)) — single linear pass, no recursion.
    """
```

The parser must produce output byte-for-byte compatible with the existing
`_extract_client_hello_fields()` dict schema so that `JA4Generator.generate_ja4()`
needs no changes.

Wire-in change in `proxy.py` `_analyze_tls_handshake()`:

```python
# BEFORE
client_hello_fields = await loop.run_in_executor(
    self.executor, _parse_tls_task, data
)

# AFTER
client_hello_fields = parse_client_hello(data)  # direct call, no executor
```

The `ProcessPoolExecutor` can be retained as a fallback for any edge case the
pure-Python parser cannot handle (return `None` → fall back to Scapy via executor).
If the fallback is never triggered in 30 days of production traffic, remove Scapy
entirely.

Acceptance: parser output must be identical to Scapy for all inputs in
`tests/fixtures/clienthello/*.bin`.

### B — Python: Fix JA4Generator correctness bugs

In `proxy.py`:

1. Move GREASE values to a module-level `frozenset`:
   ```python
   _GREASE_VALUES: frozenset[int] = frozenset({0x0A0A, 0x1A1A, ...})
   ```
   Replace `_is_grease(self, value)` with a standalone function or inline check.

2. Remove the GREASE filter from `_hash_cipher_suites()` and `_hash_extensions()`.
   Document in the function docstrings that the input is expected pre-filtered.

3. Change `hashlib.sha256(data)` to `hashlib.sha256(data[:64])` for the
   `client_hello_hash` log field only. The JA4 computation hashes are unaffected
   (they hash string representations of sorted integers, not the raw buffer).

### C — Go: Add config structs for missing signal modules

In `internal/config/loader.go` add YAML struct types:

```go
type ASNClassifierConfigYAML struct {
    Enabled         bool     `yaml:"enabled"`
    DBPath          string   `yaml:"asn_db_path"`
    TorExitListPath string   `yaml:"tor_exit_list_path"`
    DatacenterScore int      `yaml:"datacenter_score"`
    TorScore        int      `yaml:"tor_score"`
    VPNScore        int      `yaml:"vpn_score"`
    UnknownScore    int      `yaml:"unknown_score"`
    DatacenterASNs  []uint   `yaml:"datacenter_asns"`
    DatacenterOrgs  []string `yaml:"datacenter_orgs"`
}

type DNSEnrichmentConfigYAML struct { ... }
type BlocklistsConfigYAML    struct { ... }
type BeaconingConfigYAML     struct { ... }
type AbuseIPDBConfigYAML     struct { ... }
type RDAPConfigYAML          struct { ... }
type JA4XConfigYAML          struct { ... }
```

Add these to the top-level `Config` struct with appropriate `yaml:` tags matching
the Python `proxy.yml` key names exactly.

Add sensible defaults in `defaultConfig()` matching Python proxy defaults.

### D — Go: Wire config into buildPipelineConfig

In `cmd/proxy/main.go` extend `buildPipelineConfig()` to populate:
- All ASN fields from `cfg.ASNClassifier`
- All DNS fields from `cfg.DNSEnrichment`
- All blocklist feeds from `cfg.Blocklists`
- All beaconing fields from `cfg.Beaconing`
- All AbuseIPDB fields from `cfg.AbuseIPDB`
- All RDAP fields from `cfg.RDAP`
- JA4X enabled/score flags from `cfg.JA4X`
- Static IP allowlist IPs from `cfg.StaticIPAllowlistConfig`
- Country blacklist set from `cfg.GeoIP.CountryBlacklist`

### E — Parity mechanism: binary ClientHello fixtures

Capture real ClientHello bytes from Chrome, Firefox, Safari, curl, and common
bot user-agents using `scripts/capture_clienthello.py`. Store as:

```
tests/fixtures/clienthello/
  chrome_130_macos.bin
  firefox_120_linux.bin
  safari_17_ios.bin
  curl_8_tls12.bin
  python_requests_tls13.bin
  bot_noalpn.bin
  bot_garbage.bin    ← adversarial
  immediate_close.bin
  tls10_only.bin
  README.md          ← expected JA4 for each file
```

`README.md` format (machine-parseable):
```
# ClientHello JA4 Fixture Catalogue
| file | expected_ja4 | notes |
```

Both the Python and Go test suites parse every `.bin` file and assert the produced
JA4 string matches the expected value in `README.md`. This is the ground truth for
cross-language correctness.

### F — Parity mechanism: shared signal score registry

Create `config/signal_scores.yml` — the single authoritative source for all signal
score values used in both proxies:

```yaml
# Signal score registry — authoritative for both Python and Go proxies.
# Both implementations must use values from this file.
# Run: python3 scripts/check-signal-scores.py

signals:
  missing_sni:           { score: 30, description: "No SNI extension in ClientHello" }
  ip_literal_sni:        { score: 25, description: "SNI is an IP address, not hostname" }
  dga_hostname:          { score_cap: 40, description: "DGA-like SNI hostname" }
  unexpected_sni:        { score: 15, description: "SNI not in expected_hostnames list" }
  tls12_flag:            { score: 10, description: "TLS 1.2 (informational)" }
  weak_cipher:           { score: 35, description: "Weak or null cipher suite" }
  asn_datacenter:        { score: 20, description: "IP belongs to cloud/datacenter ASN" }
  asn_tor:               { score: 60, description: "IP is a Tor exit node" }
  asn_vpn:               { score: 25, description: "IP belongs to known VPN ASN" }
  rdap_known_bad_org:    { score: 45, description: "RDAP org matches known-bad list" }
  rdap_new_netblock:     { score: 20, description: "Netblock registered < N days ago" }
  analytics_campaign:    { score: 35, description: "Cross-instance campaign activity" }
  analytics_slowscan:    { score: 30, description: "Cross-instance slow-scan activity" }
  # ... all signals from docs/STYLE_GUIDE.md §1f
```

Write `scripts/check-signal-scores.py`:
- Reads `config/signal_scores.yml`
- Greps Python source (`src/security/`) for each signal name and its hardcoded score
- Greps Go source (`internal/security/`) for each signal name and its hardcoded score
- Reports any signal where Python score ≠ registry value or Go score ≠ registry value
- Exit 0 = clean, Exit 1 = drift detected

Add `make check-scores` target. Add to `make lint-phases` and CI.

### G — Parity mechanism: live decision comparison harness

Write `scripts/parity-check.py`:

```
python3 scripts/parity-check.py [--python-port 8080] [--go-port 8082]
```

Sends a fixed set of synthetic TLS connections (using the `.bin` fixtures as payloads)
to both proxies simultaneously and compares:
- JA4 fingerprint extracted (from logs or a header)
- Pipeline action (allow / block / flag / rate_limit)
- Score (within ±5 tolerance for timing-sensitive signals like beaconing)

Reports divergences as a table:
```
FIXTURE               PYTHON_ACTION  GO_ACTION  PYTHON_SCORE  GO_SCORE  STATUS
chrome_130_macos      allow          allow       12            12        ✅
bot_noalpn            block          allow       72            0         ❌ DIVERGE
```

Exit 1 if any divergence. Add `make parity-check` target. This script becomes the
permanent gate that must pass before any future phase can be marked COMPLETE.

### H — Update manifest and Phase 15 status

Phase 15 must be reopened (`IN_PROGRESS`) until steps C, D, E, and G are all green.
The manifest entry should have `gaps` listing the config wiring and fixture work.

Once steps C + D are done, re-run `make bench` and update the analysis in
`reports/benchmark/`.

---

## Files to Create / Modify

| File | Change |
|------|--------|
| `src/tls/__init__.py` (new) | Package init |
| `src/tls/parser.py` (new) | Pure-Python ClientHello parser |
| `tests/unit/test_tls_parser.py` (new) | Parser unit tests against all fixtures |
| `proxy.py` | Wire `src/tls.parser.parse_client_hello`; fix GREASE bugs |
| `internal/config/loader.go` | Add 7 config struct types + defaults |
| `cmd/proxy/main.go` | Wire new config fields in `buildPipelineConfig` |
| `tests/fixtures/clienthello/` (new) | Binary `.bin` files + `README.md` catalogue |
| `config/signal_scores.yml` (new) | Authoritative signal score registry |
| `scripts/check-signal-scores.py` (new) | Score drift linter |
| `scripts/parity-check.py` (new) | Live decision comparison harness |
| `scripts/capture_clienthello.py` (new) | ClientHello capture utility |
| `Makefile` | Add `check-scores`, `parity-check`, `capture-fixtures` targets |
| `docs/phases/manifest.yaml` | Phase 15 → `IN_PROGRESS`; add Phase 65 |
| `AGENTS.md` | Add parity-check to phase closeout checklist |

---

## Acceptance Criteria

### A — Python parser

- [ ] `src/tls/parser.py` passes all adversarial inputs in `tests/fixtures/clienthello/` without raising
- [ ] Output dict is byte-for-byte identical to Scapy for all `.bin` fixtures
- [ ] `_analyze_tls_handshake` uses `parse_client_hello` directly (no executor call)
- [ ] Python baseline_latency mean latency improves by ≥ 1ms vs pre-phase benchmark

### B — JA4 correctness fixes

- [ ] `_is_grease` replaced by module-level frozenset check
- [ ] GREASE filtering occurs exactly once per JA4 computation (not twice)
- [ ] All existing JA4 tests still pass

### C + D — Go config wiring

- [ ] All 7 signal modules have YAML struct types in `loader.go`
- [ ] `buildPipelineConfig` populates all fields
- [ ] Go proxy loaded with reference `proxy.yml` has non-zero scores for datacenter IPs,
      bots with missing SNI, and rate-limited IPs
- [ ] `make bench` re-run: Go attack_500 blocks > 0% of bot traffic

### E — Binary fixtures

- [ ] ≥ 5 real browser `.bin` files captured and committed
- [ ] `tests/fixtures/clienthello/README.md` has expected JA4 for each
- [ ] Python test: `parse_client_hello(fixture) == expected_ja4` for all files
- [ ] Go test: `tls.ComputeJA4(tls.ParseClientHello(fixture)) == expected_ja4` for all files
- [ ] Chrome and Firefox fixtures produce identical JA4 to Python Scapy reference

### F — Signal score registry

- [ ] `config/signal_scores.yml` covers all signals in `docs/STYLE_GUIDE.md §1f`
- [ ] `scripts/check-signal-scores.py` exits 0 on clean codebase
- [ ] `make check-scores` added and passing in CI

### G — Parity harness

- [ ] `scripts/parity-check.py` exits 0 with both proxies running reference config
- [ ] All `.bin` fixtures produce identical (action, score±5) in both proxies
- [ ] `make parity-check` documented in AGENTS.md closeout checklist

### Phase 15 re-verification

- [ ] `PHASE_15.md` acceptance criteria all ticked, including integration tests
- [ ] Phase 15 manifest entry updated to `COMPLETE` with `completed:` date
- [ ] `docs/phases/manifest.yaml` Phase 65 set to `COMPLETE`

---

## What This Does Not Cover

- Implementing the Rust/C native parser (PyO3 / cffi): the pure-Python parser delivers
  most of the benefit at a fraction of the maintenance cost. If profiling after this phase
  shows the parser is still a bottleneck, a native extension is the next step.
- Replacing the Redis sliding-window rate limiter with an in-process counter: valid
  future optimisation but loses cross-instance rate-limit accuracy.
- The 1,000 conn/s Phase 15 target: this phase gets Python from ~350 to ~430 conn/s and
  confirms the Go ceiling with all signals enabled. Re-evaluating the target against real
  hardware/network conditions is a separate decision.
- Go signal module logic improvements: this phase only wires config — it does not improve
  the signal implementations themselves.
