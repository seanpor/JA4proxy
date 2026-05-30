# Phase 62 — Go Fuzzing, Adversarial & Chaos Test Parity

> **Status:** PROPOSED
> **Size:** L
> **Owner files:** `cmd/proxy/fuzz_test.go`, `internal/tls/parser_test.go`, `internal/tls/ja4_fp_corpus_test.go`, `internal/security/pipeline_chaos_test.go`, `internal/security/property_test.go`, `cmd/proxy/bench_test.go`, `scripts/generate_validation_report.py`, `tests/fuzz/README.md`, `Makefile` (new targets only)
> **Independent of:** Phase 61, 63, 64
> **Last rewritten:** 2026-04-09

---

## What this phase is

Close the **test-category gap** between Python and Go. The Python proxy has
fuzzing, adversarial input tests, FP-corpus regression, chaos/resilience
tests, and property-based tests. The Go production proxy has none of these.
This phase adds them as native Go tests so the Go binary has the same defensive
coverage Python had before deprecation.

It also keeps the **pre-enterprise validation report generator** from the
previous version of this phase — that script is still useful and survives
unchanged.

## What this phase is NOT

This phase **does not** add Python regression tests for Phase 27 findings.
The previous version of Phase 62 was scoped around `tests/security_regression/`
guarding the five Python pentest findings (IP spoofing, sync/async Redis,
sync TLS on event loop, Prometheus cardinality, log injection). All five are
**Python-specific** and the Python proxy is now experimental — guarding it
against regressions that can never reach production is dead work.

The Go-side equivalents of those five findings are owned by other phases:

| Python finding (Phase 27) | Go equivalent | Owning phase |
|---|---|---|
| IP spoofing via PROXY protocol | `_is_trusted_proxy_source` for Go | [Phase 200](PHASE_200.md) |
| Sync redis in async context | n/a — Go has no async/sync split | — |
| TLS parsing on event loop | n/a — Go uses goroutines | — |
| Prometheus cardinality (`fingerprint` label) | already correct in `internal/metrics/metrics.go` | done |
| Log injection / `_sanitize_log` | already correct in Go (`zap` structured logger) | done |

If a junior contributor is tempted to add `tests/security_regression/` files
back, redirect them to Phase 200 / 201 / 203 instead.

## What this phase does NOT include from the previous version

| Removed item | Why |
|---|---|
| `tests/security_regression/test_*_regression.py` (six files) | Python proxy is deprecated — see table above |
| `tests/fuzz/fuzz_clienthello.py` (atheris) | Replaced by Go native `cmd/proxy/fuzz_test.go` |
| `tests/fuzz/fuzz_proxy_protocol.py` (atheris) | Replaced by Go native `FuzzReadProxyProtocol` and `FuzzReadProxyProtocolV2` |
| `tests/fuzz/fuzz_config.py` (atheris) | Go config loader is `gopkg.in/yaml.v3` — already covered by upstream fuzzing; the project loader has unit tests |
| `atheris>=2.3.0` in `requirements.txt` | No longer needed |
| Break-glass procedure for Phase 27 findings | Findings are in deprecated code; verification has no value |

---

## What already exists on disk

Read first, before writing anything:

```bash
ls cmd/proxy/                       # main.go only — no fuzz_test.go, no bench_test.go
ls internal/tls/                    # parser.go, ja4.go, ja4_test.go, ja4t.go, ja4t_test.go, ja4x.go, ja4x_test.go, bench_test.go
ls internal/security/               # 16 *.go + 14 *_test.go — no pipeline_chaos_test.go, no property_test.go
ls tests/adversarial/corpus/        # 13 .bin files + README.md
```

Key facts:

- **`internal/tls/parser.go`** is the production ClientHello parser. It has
  no dedicated `parser_test.go` — it is exercised only indirectly via
  `ja4_test.go` against valid fixtures. No adversarial coverage today.
- **`tests/adversarial/corpus/`** has 13 binary fixtures already (empty,
  truncated, overflow length, all-GREASE, etc.) but **only Python tests
  consume them**. Go has no FP-corpus regression test reading this directory.
- **`internal/tls/bench_test.go`** exists for the parser. There is no
  pipeline-level Go bench (`cmd/proxy/bench_test.go`).
- **`internal/security/pipeline_test.go`** is a happy-path unit test only.
  No chaos/fault-injection tests against Redis or external services.
- **No Go property-based tests** exist anywhere. The `pgregory.net/rapid`
  library is not yet a dependency.
- **Existing Python coverage that has no Go equivalent:**
  - `tests/fuzz/` (atheris) — Python ClientHello/PROXY/config fuzzers
  - `tests/adversarial/test_clienthello_adversarial.py` — drives the corpus
  - `tests/adversarial/test_*_fp.py` — Tranco top-10k FP rate tests for
    several signals (AbuseIPDB, beaconing, ASN, etc.)
  - `tests/chaos/test_*.py` — Redis outage, partial outage, external API
    failure, dial flip
  - `tests/property/test_*.py` (Hypothesis) — risk scorer monotonicity,
    action decider idempotence, IP normalisation
  - `tests/performance/test_*.py` — pipeline throughput

The six Go-side gaps below close the categories that matter most for a TLS
parser and a hot-path security pipeline.

---

## Implementation checklist

The six steps are independent of each other. A junior contributor can land
them in any order, one PR per step.

### Step 1 — `cmd/proxy/fuzz_test.go` (Go native fuzzers)

Three fuzz targets, one file. Run via `go test -fuzz=FuzzXxx -fuzztime=60s`.

```go
// cmd/proxy/fuzz_test.go
package main

import (
    "bytes"
    "testing"

    "github.com/<owner>/ja4proxy/internal/proxy"
    tlsparse "github.com/<owner>/ja4proxy/internal/tls"
)

// FuzzClientHello drives the production TLS parser with arbitrary bytes.
// The parser must never panic on any input. It may return an error or a
// partial *HelloInfo — both are acceptable.
func FuzzClientHello(f *testing.F) {
    // Seed corpus from the existing adversarial fixtures.
    seeds, _ := filepath.Glob("../../tests/adversarial/corpus/*.bin")
    for _, p := range seeds {
        if data, err := os.ReadFile(p); err == nil {
            f.Add(data)
        }
    }
    // Plus a known-valid record for coverage seeding.
    f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})

    f.Fuzz(func(t *testing.T, data []byte) {
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("ParseClientHello panicked on %x: %v", data, r)
            }
        }()
        _, _ = tlsparse.ParseClientHello(data)
    })
}

// FuzzReadProxyProtocol drives the v1 PROXY protocol header reader.
func FuzzReadProxyProtocol(f *testing.F) {
    f.Add([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n"))
    f.Add([]byte("PROXY UNKNOWN\r\n"))
    f.Add([]byte(""))
    f.Add([]byte("PROXY"))

    f.Fuzz(func(t *testing.T, data []byte) {
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("ReadProxyProtocolV1 panicked on %x: %v", data, r)
            }
        }()
        _, _, _ = proxy.ReadProxyProtocolV1(bytes.NewReader(data))
    })
}

// FuzzReadProxyProtocolV2 drives the v2 binary header reader. This entry
// point is added by Phase 200 — if Phase 200 has not landed yet, gate the
// test with a build tag and remove the gate when 200 merges.
func FuzzReadProxyProtocolV2(f *testing.F) {
    // 12-byte v2 signature + minimal header
    f.Add([]byte{
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        0x21, 0x11, 0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0, 80, 0, 443,
    })
    f.Add([]byte{})

    f.Fuzz(func(t *testing.T, data []byte) {
        defer func() {
            if r := recover(); r != nil {
                t.Fatalf("ReadProxyProtocolV2 panicked on %x: %v", data, r)
            }
        }()
        _, _, _ = proxy.ReadProxyProtocolV2(bytes.NewReader(data))
    })
}
```

Verify with:

```bash
GOROOT=/snap/go/current go test -fuzz=FuzzClientHello -fuzztime=10s ./cmd/proxy/
GOROOT=/snap/go/current go test -fuzz=FuzzReadProxyProtocol -fuzztime=10s ./cmd/proxy/
```

The `defer recover()` pattern converts a panic into a test failure, which the
native fuzzer reports as a crash and saves the input under
`testdata/fuzz/FuzzClientHello/`.

### Step 2 — `internal/tls/parser_test.go` (adversarial unit tests)

A table-driven test that drives `ParseClientHello` with the same 13 fixtures
that already live in `tests/adversarial/corpus/`. This is the
deterministic counterpart to Step 1's coverage-guided fuzzer — it runs in
the standard `go test ./...` pass and gives a stable signal that the parser
handles every known-bad input shape.

```go
// internal/tls/parser_test.go
package tls

import (
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestParseClientHello_AdversarialCorpus(t *testing.T) {
    matches, err := filepath.Glob("../../tests/adversarial/corpus/*.bin")
    if err != nil || len(matches) == 0 {
        t.Fatalf("no adversarial fixtures found: %v", err)
    }
    for _, path := range matches {
        path := path
        name := filepath.Base(path)
        t.Run(name, func(t *testing.T) {
            data, err := os.ReadFile(path)
            if err != nil {
                t.Fatalf("read %s: %v", path, err)
            }
            done := make(chan struct{})
            go func() {
                defer close(done)
                defer func() {
                    if r := recover(); r != nil {
                        t.Errorf("parser panicked on %s: %v", name, r)
                    }
                }()
                _, _ = ParseClientHello(data)
            }()
            select {
            case <-done:
            case <-time.After(100 * time.Millisecond):
                t.Errorf("parser hung on %s (>100ms)", name)
            }
        })
    }
}
```

Acceptance: every fixture either returns an error or a partial `*HelloInfo`.
None panic. None take longer than 100 ms.

### Step 3 — `internal/tls/ja4_fp_corpus_test.go` (FP-corpus regression)

A regression test that loads the **valid** ClientHello fixtures from
`tests/fixtures/clienthello/` (already used by Python tests), computes the
JA4 fingerprint via the Go implementation, and asserts the resulting
fingerprint string matches a checked-in golden file. This catches any silent
behavioural drift in the Go parser or hash routine — the FP-rate
equivalent of "did we change a real browser's JA4?".

```go
// internal/tls/ja4_fp_corpus_test.go
package tls

import (
    "bufio"
    "os"
    "strings"
    "testing"
)

// TestJA4_FPCorpus_NoRegression locks in the Go-computed JA4 for every
// known-good ClientHello fixture. The golden file is generated once and
// committed; any future change that perturbs a real-browser fingerprint
// fails this test loudly.
func TestJA4_FPCorpus_NoRegression(t *testing.T) {
    golden := loadGolden(t, "testdata/ja4_fp_golden.txt")  // map[fixture]ja4
    for fixture, want := range golden {
        fixture, want := fixture, want
        t.Run(fixture, func(t *testing.T) {
            data, err := os.ReadFile("../../tests/fixtures/clienthello/" + fixture)
            if err != nil {
                t.Skipf("fixture missing: %v", err)
            }
            info, err := ParseClientHello(data)
            if err != nil {
                t.Fatalf("parse: %v", err)
            }
            got := ComputeJA4(info)
            if got != want {
                t.Errorf("JA4 drift on %s:\n  want %s\n  got  %s", fixture, want, got)
            }
        })
    }
}

func loadGolden(t *testing.T, path string) map[string]string {
    t.Helper()
    f, err := os.Open(path)
    if err != nil { t.Fatalf("open golden: %v", err) }
    defer f.Close()
    out := map[string]string{}
    s := bufio.NewScanner(f)
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if line == "" || strings.HasPrefix(line, "#") { continue }
        parts := strings.SplitN(line, " ", 2)
        if len(parts) == 2 { out[parts[0]] = parts[1] }
    }
    return out
}
```

Generate the golden file once with a `-update` flag (standard Go testing
idiom) and commit it as `internal/tls/testdata/ja4_fp_golden.txt`. Each line
is `<fixture-filename> <ja4-string>`. Format:

```
chrome_120.bin t13d1516h2_8daaf6152771_b186095e22b6
firefox_115.bin t13d1715h2_5b57614c22b0_3d5424432f57
# ... one line per real-browser fixture
```

### Step 4 — `internal/security/pipeline_chaos_test.go`

Drive the production `pipeline.Pipeline` against a fault-injecting Redis
client to verify fail-open behaviour. Three scenarios at minimum:

```go
// internal/security/pipeline_chaos_test.go
package security

import (
    "context"
    "errors"
    "testing"
)

// TestPipeline_RedisOutage_FailsOpen verifies that when every Redis call
// returns an error, the pipeline still produces an ALLOW decision rather
// than crashing or blocking. This is the load-bearing core of the asymmetry
// doctrine in CLAUDE.md.
func TestPipeline_RedisOutage_FailsOpen(t *testing.T) {
    redis := &faultyRedis{failEvery: 1}
    p := newTestPipeline(t, redis)
    res, err := p.Process(context.Background(), validClientHello())
    if err != nil {
        t.Fatalf("pipeline returned error during outage: %v", err)
    }
    if res.Action != ActionAllow {
        t.Fatalf("expected ALLOW during Redis outage, got %v", res.Action)
    }
}

// TestPipeline_PartialOutage_AllowBypassesStillWork verifies that when
// Redis is partially up (random ~50% failures) the bypass checks for
// h2/h1 ALPN and JA4 whitelist still produce ALLOW.
func TestPipeline_PartialOutage_AllowBypassesStillWork(t *testing.T) {
    redis := &faultyRedis{failEvery: 2}
    p := newTestPipeline(t, redis)
    for i := 0; i < 50; i++ {
        res, err := p.Process(context.Background(), h2BrowserClientHello())
        if err != nil || res.Action != ActionAllow {
            t.Fatalf("h2 ALPN bypass failed under partial outage: action=%v err=%v", res.Action, err)
        }
    }
}

// TestPipeline_DialFlip_NoStaleDecisions verifies that flipping the dial
// from 0 → 100 mid-flight does not produce a stale ALLOW for a request
// that arrives after the flip.
func TestPipeline_DialFlip_NoStaleDecisions(t *testing.T) {
    p := newTestPipeline(t, &faultyRedis{})
    p.Dial.Set(0)
    _, _ = p.Process(context.Background(), maliciousClientHello())
    p.Dial.Set(100)
    res, _ := p.Process(context.Background(), maliciousClientHello())
    if res.Action == ActionAllow {
        t.Fatalf("dial flip 0→100 produced stale ALLOW")
    }
}

// faultyRedis is a minimal RedisClient implementation that returns errors
// on a fixed cadence. failEvery=1 fails every call; failEvery=2 fails every
// other call; failEvery=0 never fails.
type faultyRedis struct{ failEvery, count int }

func (f *faultyRedis) Get(ctx context.Context, key string) (string, error) {
    f.count++
    if f.failEvery > 0 && f.count%f.failEvery == 0 {
        return "", errors.New("simulated redis outage")
    }
    return "", nil
}
// ... implement the rest of the RedisClient interface as no-ops returning nil errors
```

The `newTestPipeline`, `validClientHello`, `h2BrowserClientHello`, and
`maliciousClientHello` helpers should be reused from existing
`internal/security/*_test.go` files where possible. If they don't exist,
add them in a small `pipeline_test_helpers.go` (in the test package only).

### Step 5 — `internal/security/property_test.go` (rapid)

Property-based tests for the two pieces of pure logic in the security
package: `RiskScorer.Score` and `ActionDecider.Decide`. Use
[`pgregory.net/rapid`](https://github.com/flyingmutant/rapid) — the
mainstream Go property-testing library. Add to `go.mod`:

```bash
GOROOT=/snap/go/current go get pgregory.net/rapid@latest
```

```go
// internal/security/property_test.go
package security

import (
    "testing"
    "pgregory.net/rapid"
)

// PropertyScoreInRange — for any list of RiskSignals, the composite score
// is in [0, 100] inclusive. The scorer caps and floors; this test asserts
// the cap and floor cannot be bypassed by adversarial signal combinations.
func TestProperty_ScoreInRange(t *testing.T) {
    rapid.Check(t, func(rt *rapid.T) {
        signals := rapid.SliceOf(genRiskSignal()).Draw(rt, "signals")
        score := NewRiskScorer().Score(signals).TotalScore
        if score < 0 || score > 100 {
            rt.Fatalf("score out of range: %d for %v", score, signals)
        }
    })
}

// PropertyScoreMonotonic — adding a positive-weight signal never decreases
// the score (until the cap is hit).
func TestProperty_ScoreMonotonic(t *testing.T) {
    rapid.Check(t, func(rt *rapid.T) {
        base := rapid.SliceOf(genRiskSignal()).Draw(rt, "base")
        extra := genPositiveRiskSignal().Draw(rt, "extra")
        before := NewRiskScorer().Score(base).TotalScore
        after := NewRiskScorer().Score(append(base, extra)).TotalScore
        if before < 100 && after < before {
            rt.Fatalf("adding positive signal decreased score: %d → %d", before, after)
        }
    })
}

// PropertyDecisionIdempotent — calling Decide twice on the same input
// returns the same action.
func TestProperty_DecisionIdempotent(t *testing.T) {
    rapid.Check(t, func(rt *rapid.T) {
        score := rapid.IntRange(0, 100).Draw(rt, "score")
        dial := rapid.IntRange(0, 100).Draw(rt, "dial")
        d := NewActionDecider(testThresholds())
        a := d.Decide(score, dial)
        b := d.Decide(score, dial)
        if a != b {
            rt.Fatalf("Decide not idempotent: %v vs %v", a, b)
        }
    })
}

// PropertyDialZeroNeverBlocks — at dial=0 (monitor mode), no score, however
// high, results in a blocking action. This is the load-bearing invariant
// from CLAUDE.md: "Default dial is 0. The proxy never blocks on first deploy."
func TestProperty_DialZeroNeverBlocks(t *testing.T) {
    rapid.Check(t, func(rt *rapid.T) {
        score := rapid.IntRange(0, 100).Draw(rt, "score")
        d := NewActionDecider(testThresholds())
        a := d.Decide(score, 0)
        if a == ActionBlock || a == ActionBan || a == ActionTarpit {
            rt.Fatalf("dial=0 produced blocking action %v at score=%d", a, score)
        }
    })
}
```

`genRiskSignal`, `genPositiveRiskSignal`, and `testThresholds` are small
generator helpers — define them inline in this file.

### Step 6 — `cmd/proxy/bench_test.go`

Pipeline-level throughput benchmark. The Python equivalent is
`tests/performance/test_pipeline_throughput.py`, which gives a 2,184 conn/s
baseline number. The Go bench should produce a comparable number that the
phase 86 capacity calculator can use as a starting point.

```go
// cmd/proxy/bench_test.go
package main

import (
    "context"
    "testing"
)

func BenchmarkPipeline_Allow(b *testing.B) {
    p := newBenchPipeline(b)
    hello := h2BrowserClientHello()  // bypass path
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = p.Process(context.Background(), hello)
    }
}

func BenchmarkPipeline_Score(b *testing.B) {
    p := newBenchPipeline(b)
    hello := suspiciousClientHello()  // full scoring path
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = p.Process(context.Background(), hello)
    }
}
```

Run with:

```bash
GOROOT=/snap/go/current go test -bench=. -benchmem -run=^$ ./cmd/proxy/
```

Acceptance: both benches run to completion. Record the ns/op number in
`PHASE_62_notes.md` — Phase 86 will lock it in as a baseline. Do **not**
add a CI gate on the number; benches are noisy on shared GitHub runners.

---

## Pre-enterprise validation report (carried over)

The `scripts/generate_validation_report.py` from the previous version of
this phase is still useful and survives **mostly** unchanged. Update it to:

1. Drop the `run_security_regression_tests()` section (no longer applicable).
2. Replace the "Phase 27 remediation commits" section with a "Go security
   findings" section that runs `git log --grep='phase-20[0-3]' --all` to
   surface Phase 200/201/202/203 remediation commits.
3. Keep `pip-audit` for the Python services that are still production
   (Management API, analytics node).
4. Keep `govulncheck` for the Go proxy.
5. Add a new section that runs `make fuzz` and reports new-crash count.

The output file path is unchanged: `docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md`.

The `make validation-report` target is unchanged.

---

## Makefile targets

Add to the bottom of `Makefile`:

```makefile
## Phase 62 targets

test-go-fuzz-smoke:
	GOROOT=/snap/go/current go test -fuzz=FuzzClientHello -fuzztime=30s ./cmd/proxy/
	GOROOT=/snap/go/current go test -fuzz=FuzzReadProxyProtocol -fuzztime=30s ./cmd/proxy/
	GOROOT=/snap/go/current go test -fuzz=FuzzReadProxyProtocolV2 -fuzztime=30s ./cmd/proxy/

test-go-property:
	GOROOT=/snap/go/current go test -run=TestProperty ./internal/security/

test-go-chaos:
	GOROOT=/snap/go/current go test -run=TestPipeline_.*Outage -run=TestPipeline_DialFlip ./internal/security/

bench-go-pipeline:
	GOROOT=/snap/go/current go test -bench=BenchmarkPipeline -benchmem -run=^$$ ./cmd/proxy/

validation-report:
	python3 scripts/generate_validation_report.py
```

Each target is independent and can be run on its own.

---

## Acceptance criteria

- [ ] `cmd/proxy/fuzz_test.go` exists with `FuzzClientHello`, `FuzzReadProxyProtocol`, `FuzzReadProxyProtocolV2`
- [ ] `make test-go-fuzz-smoke` runs each target for 30 s without crashes
- [ ] Any crash inputs found are committed to `cmd/proxy/testdata/fuzz/FuzzXxx/` and the parser is fixed
- [ ] `internal/tls/parser_test.go` exists with `TestParseClientHello_AdversarialCorpus` driving all 13 corpus fixtures
- [ ] None of the 13 fixtures cause a panic or a >100 ms hang
- [ ] `internal/tls/ja4_fp_corpus_test.go` exists with golden file at `internal/tls/testdata/ja4_fp_golden.txt`
- [ ] Golden file covers every fixture in `tests/fixtures/clienthello/`
- [ ] Test fails loudly if any real-browser fingerprint changes
- [ ] `internal/security/pipeline_chaos_test.go` exists with the three Redis-fault scenarios
- [ ] Pipeline returns `ActionAllow` under total Redis outage (fail-open invariant)
- [ ] `internal/security/property_test.go` exists with the four property tests using `pgregory.net/rapid`
- [ ] `pgregory.net/rapid` is added to `go.mod`
- [ ] Property tests pass with default `rapid` configuration (200 cases per test)
- [ ] `cmd/proxy/bench_test.go` exists with `BenchmarkPipeline_Allow` and `BenchmarkPipeline_Score`
- [ ] Both benches run to completion under `make bench-go-pipeline`
- [ ] Bench numbers recorded in `PHASE_62_notes.md` (no CI gate)
- [ ] `scripts/generate_validation_report.py` updated per Section "Pre-enterprise validation report (carried over)"
- [ ] `make validation-report` runs to completion and writes the report
- [ ] All new tests run as part of `go test ./...` (i.e. not gated behind a build tag, except `FuzzReadProxyProtocolV2` if Phase 200 is not yet merged)
- [ ] `CHANGELOG.md` entry written
- [ ] `tests/fuzz/README.md` rewritten to point at the new Go fuzz targets and describe quarterly long-form fuzzing procedure (`-fuzztime=24h` per target)

## Verify

```bash
# Step 1: Go fuzz targets exist and run
GOROOT=/snap/go/current go test -list '.*' ./cmd/proxy/ | grep ^Fuzz

# Step 2: adversarial corpus test discovers all 13 fixtures
GOROOT=/snap/go/current go test -v -run TestParseClientHello_AdversarialCorpus ./internal/tls/ | grep -c "RUN.*\.bin"

# Step 3: golden file exists and is non-empty
test -s internal/tls/testdata/ja4_fp_golden.txt && echo OK

# Step 4: chaos tests run
GOROOT=/snap/go/current go test -v -run "TestPipeline_(.*Outage|DialFlip)" ./internal/security/

# Step 5: property tests run
GOROOT=/snap/go/current go test -v -run TestProperty ./internal/security/

# Step 6: bench runs
GOROOT=/snap/go/current go test -bench=BenchmarkPipeline -benchtime=1x -run=^$ ./cmd/proxy/
```

---

## Out of scope — handed to other phases

| Concern | Phase that owns it |
|---|---|
| Add `_is_trusted_proxy_source` equivalent to Go | [200](PHASE_200.md) |
| Implement `ReadProxyProtocolV2` (binary parser) | [200](PHASE_200.md) |
| Lock in pipeline throughput as a published baseline | [86](PHASE_86.md) |
| Capacity calculator that consumes the bench number | [86](PHASE_86.md) |
| Python regression tests for Phase 27 findings | **dropped — Python is deprecated** |
| Atheris Python fuzzers | **dropped — replaced by Go native fuzzers** |
| Break-glass procedure for Phase 27 findings | **dropped — verifies code that is no longer production** |

If you find yourself adding `tests/security_regression/` files or installing
`atheris`, stop — that work belongs to the previous version of this phase
that was deliberately retired in the 2026-04-09 rewrite.
