# Test Infrastructure, Baseline & Invariant-Plan Rewrite

> **Audience:** a junior developer implementing this phase, and the SecOps
> reviewers who sign it off. Every step tells you **which file to touch**,
> **what to type**, **how to check it worked**, and **what to do if it doesn't**.
> If a step says *"verify"*, stop and confirm the fact in code before going on.
> Do not guess. If what you find disagrees with this document, the code wins:
> write the discrepancy in the PR description and tell the reviewer.

---

## Goal

Build the foundations that every later 606 sub-phase depends on, then rewrite
the 606a–g plans so they describe **the code that actually exists**.

Phase 606 exists to raise system reliability. It does that by replacing
point-in-time assertions with **invariants**: properties that must hold for
*all* inputs. It also pushes coverage up, measured by a ratchet rather than a
vanity number. This phase delivers:

1. **A measured baseline.** Per-package Go and Python coverage, plus mutation
   score for the security-critical packages, all committed to the repo.
2. **A coverage ratchet.** CI fails if any package's coverage goes *down*.
3. **Shared invariant-testing tooling.** A ClientHello fixture builder, a
   `rapid` generator for structurally valid ClientHellos, `goleak`, and
   `testing/synctest` conventions.
4. **An invariant registry.** A machine-checked catalogue of every invariant
   test, so a test cannot silently "pass" by never running.
5. **Rewritten 606a–g phase docs** against the verified API surface, plus new
   phases for the coverage gaps the original plan missed.

## Background — why this phase exists

A critical review of the first 606a–g drafts (October 2026) found:

| Problem | Example |
|---|---|
| Docs call APIs that don't exist | `proxy.New()`, `proxy.Start()`, `fingerprint.ComputeJA4(bytes)`, `ratelimit.NewLimiter`, `security.NewScorer`, `ParseQUICInitial` |
| Docs test features that don't exist | token bucket (606d), risk-score temporal decay (606f), JA4_r duality (606a) |
| Docs duplicate existing work | 606f invariants 1–2 already exist in `internal/security/property_test.go` (Phase 62) |
| Silent green | five `go test -run X` filters matched **zero** test names, so they report `PASS` with nothing run |
| Dangerous test code | 606g sent `SIGHUP` to the test process. With no handler registered, Go's default action **kills the test binary**. |
| Coverage ignored | no doc mentioned coverage; the lowest packages (0–57%) were not in scope |
| Dated/flaky tooling | `testing/quick` (frozen), hand-rolled goroutine counts, `time.Sleep` synchronisation, `t.Skip` |

The root cause: the plans were written **without checking the code**. This
phase fixes that and adds tooling so it can't happen silently again.

### Measured baseline (Go, `go test -short -cover`, `main` @ `13766c5b`)

| Package | Coverage | | Package | Coverage |
|---|---|---|---|---|
| `internal/cluster/sync` | **0.0%** | | `internal/backup` | 84.1% |
| `internal/cli/engine` | **0.0%** | | `internal/metrics` | 84.5% |
| `cmd/ja4p` | **0.0%** | | `internal/webhook` | 86.5% |
| `internal/quic` | **55.5%** | | `internal/proxy` | 87.3% |
| `cmd/ja4-tap` | **57.0%** | | `internal/config` | 87.6% |
| `internal/tap` | 79.9% | | `internal/tls` | 88.8% |
| `cmd/ja4pd` | 80.1% | | `internal/security` | 90.6% |
| | | | `internal/redis` | 91.7% |
| | | | `internal/fingerprint` | 100% |

---

## Scope

### Part A — Test infrastructure (code)

| ID | Deliverable | Files |
|---|---|---|
| A1 | Go coverage aggregation + ratchet script and baseline | `scripts/coverage_ratchet.py`, `docs/testing/coverage-baseline.json`, Makefile `cover-check` |
| A2 | Python coverage baseline, containerised; fix stale `lint-coverage` target | Makefile `cover-python`, same baseline JSON |
| A3 | `goleak` dependency + usage conventions | `go.mod`, `go.sum` |
| A4 | Shared ClientHello fixture builder + `rapid` generator | `internal/testutil/tlsfixture/` |
| A5 | Guard: production code must never import `internal/testutil` | `tests/unit/test_testutil_import_guard.py` |
| A6 | Invariant registry + checker + `make test-invariants` | `docs/testing/invariants.yaml`, `tests/unit/test_invariant_registry.py`, Makefile |
| A7 | `testing/synctest` exemplar test | one new test, see Step A7 |
| A8 | Mutation-testing baseline (advisory, not a CI gate) | Makefile `mutation`, `docs/testing/MUTATION_BASELINE.md` |
| A9 | Invariant-testing handbook | `docs/testing/INVARIANT_TESTING.md` |

### Part B — Rewrite 606a–g (docs)

Rewrite each `docs/phases/PHASE_606{a..g}.md` against the
[Verified API map](#appendix-a--verified-api-map) and the
[mandatory doc template](#b1--mandatory-sections-for-every-606-sub-phase-doc).

### Part C — Re-plan the manifest

Remove the artificial a→b→…→g chain, and add phases for the coverage gaps
(606h–606k). Record the server-extraction decision (606s).

## Out of scope

- Writing the invariant tests themselves. That is 606a–k.
- Refactoring existing tests to use the new fixture package. That is
  allowed later, opportunistically, and never in this phase.
- Extracting the proxy server out of `cmd/ja4pd/main.go`. Proposed as 606s;
  see [Open decisions](#open-decisions-need-maintainer-sign-off).
- Implementing JA4_r or risk-score decay. These are product features. If
  wanted, raise them as their own feature phases.
- Changing any production behaviour. **This phase adds tests, tooling and
  docs only.** If you find a bug, register it (see
  [When you find a bug](#when-you-find-a-bug)). Do not fix it here.

---

## Implementation plan

Work in this order. Each step is one commit
(`type(606-0): …`, signed `Co-Authored-By: Gemini <noreply@google.com>`).
TDD applies: for every script, **write its unit tests first**, see them fail,
then implement.

### Step A1 — Go coverage ratchet

**Why:** "99.9% coverage" can't be enforced without first knowing where we
are and stopping any slide backwards. A ratchet only moves up.

**How Go coverage files work.** `make test` already writes
`coverage.txt` (`-coverprofile=coverage.txt -covermode=atomic ./...`). Each
line after the `mode:` header looks like:

```
github.com/seanpor/ja4proxy/internal/tls/parser.go:42.33,45.2 3 1
#                     file                    :start,end  stmts count
```

Coverage of a package = Σ statements in blocks with `count > 0` ÷ Σ all
statements, over files in that package's directory. **The same block can
appear more than once** (e.g. when tests from several packages run).
De-duplicate by `file:start,end` and keep the **maximum** count.

1. **Write the tests first:** `tests/unit/test_coverage_ratchet.py`. Use small
   synthetic profiles written to `tmp_path`. Required cases:
   - `test_aggregates_per_package`: two files in one dir, one in another.
     Assert exact percentages.
   - `test_duplicate_blocks_take_max_count`: the same block at count 0 and
     count 3 counts as covered.
   - `test_drop_below_baseline_fails`: baseline 80.0, current 79.8, so the
     exit code is non-zero and the package name is in the message.
   - `test_tolerance`: a drop of ≤ 0.1 percentage points passes. Atomic-mode
     jitter from timing-dependent branches is real.
   - `test_rise_passes_and_reports`: suggests running `--update`.
   - `test_update_never_lowers`: `--update` with a lower current value keeps
     the old baseline value.
   - `test_new_package_is_added_on_update` and
     `test_removed_package_warns_not_fails`.
2. **Implement** `scripts/coverage_ratchet.py`: stdlib only, typed, passes
   ruff and mypy in the tools image.
   - `check --profile coverage.txt --baseline docs/testing/coverage-baseline.json --lang go`
   - `update` (same args) rewrites the JSON, sorted keys, upward only.
3. **Baseline JSON shape** (shared with Python, A2):
   ```json
   {
     "go":     {"internal/tls": 88.8, "cmd/ja4pd": 80.1},
     "python": {"management/api": 0.0},
     "targets": {"internal/*": 95.0, "cmd/*": 85.0, "management/*": 90.0}
   }
   ```
   `targets` is **informational**. It is the destination, not a gate. The
   gate is "never go down".
4. **Makefile:**
   ```make
   cover-check: tools-image ## Fail if any package's coverage dropped below baseline
   	@$(TOOLS_RUN) python3 scripts/coverage_ratchet.py check --lang go \
   		--profile coverage.txt --baseline docs/testing/coverage-baseline.json
   ```
   Wire `cover-check` to run **after** the Go step of `make test`, so it is in
   `preflight` and CI. Do **not** add `-short` to `make test` to make things
   faster: the baseline must be measured the same way CI runs.
5. **Generate the baseline:** `make test`, then
   `$(TOOLS_RUN) python3 scripts/coverage_ratchet.py update --lang go ...`.
   Commit the JSON.

**Done when:** tests pass, `make cover-check` passes on a clean tree, and
deleting one test function (try it locally, don't commit) makes it fail.

### Step A2 — Python coverage, containerised

The existing `lint-coverage` target is **stale and violates the container
rule**:
- it runs `$(PYTHON) -m pytest` on the **host**;
- it measures `--cov=proxy`, but `proxy.py` was deleted.

1. Verify `pytest-cov` is in the tools image:
   `docker run --rm ja4proxy-tools python -c "import pytest_cov"`. If that
   fails, add it to the tools image requirements (find the file that
   `Dockerfile.tools` installs from) and pin the version.
2. Replace `lint-coverage` with:
   ```make
   cover-python: tools-image ## Python coverage (management + src), containerised
   	@$(TOOLS_RUN) pytest tests/unit/ management/tests/ -n auto --dist=loadfile \
   		--timeout=60 --cov=management --cov=src --cov-append --cov-report=json:coverage-python.json \
   		--cov-report=term-missing:skip-covered
   ```
   Note: `--cov-append` is mandatory under `pytest-xdist` (`-n auto`) to ensure parallel worker coverage reports are safely merged.
   Leave a `lint-coverage: cover-python` alias so nobody's muscle memory
   breaks.
3. Extend `coverage_ratchet.py` with `--lang python`. It reads
   `coverage-python.json` (`files[*].summary.num_statements` /
   `covered_lines`) and aggregates per top-level package directory
   (`management/api`, `src/analytics`, …). Write its tests first, as in A1.
4. Add the Python numbers to the baseline JSON.
5. Add `coverage-python.json` and `coverage.txt` to `.gitignore` if they are
   not already there.

### Step A3 — `goleak`

**Why:** counting `runtime.NumGoroutine()` with a "+2 slack" is flaky and can
hide a one-goroutine-per-connection leak. `go.uber.org/goleak` reports
**which** goroutine leaked, with its stack.

1. `GOROOT=/snap/go/current /snap/go/current/bin/go get go.uber.org/goleak@latest`,
   then `go mod tidy`. Commit `go.mod` and `go.sum`.
2. **Convention (put this in the handbook, A9):** new leak invariants use
   `defer goleak.VerifyNone(t, goleak.IgnoreCurrent())` at the top of the
   test. `IgnoreCurrent()` snapshots the goroutines that already exist
   (miniredis, logrus hooks, Prometheus), so only goroutines created *by
   this test* are checked. Note: if a background worker spawns new child goroutines during test execution, use `goleak.IgnoreTopFunction(...)` to explicitly ignore known background workers.
3. **Do not** add `goleak.VerifyTestMain` to existing packages in this phase.
   It will very likely fail on pre-existing background goroutines. Doing it
   is 606c's job, and every ignore needs a justification.
4. The `make lint`/dependency audit (govulncheck) must still pass.

### Step A4 — Shared ClientHello fixtures: `internal/testutil/tlsfixture`

**Why:** at least **six** private ClientHello builders exist today, each
slightly different:

| File | Builder |
|---|---|
| `cmd/ja4pd/lifecycle_test.go:931` | `buildTLSClientHello()` |
| `cmd/ja4pd/pentest_fragmentation_regression_test.go:129` | `buildChromeLikeClientHello()` |
| `cmd/ja4pd/pentest_pooled_buffer_alias_test.go:14` | `buildClientHelloWithSNIALPN()` |
| `cmd/ja4pd/pentest_reassembly_oversized_test.go:128` | `buildLargeClientHelloBody()` |
| `internal/tls/bench_test.go:179` | `generateTestClientHello()` |
| `internal/tap/tlsparse_test.go` | (inline) |

Go cannot import `_test.go` files across packages, so shared helpers must
live in a **normal** package. Read all six before writing anything.

**Also:** property tests over *random bytes* are close to useless for a
parser. Almost no random input is a valid ClientHello, so a property like
"if it parses, the JA4 is well-formed" is tested on ~0 cases and passes
vacuously. You need a generator that produces **structurally valid**
ClientHellos.

Package layout:

```
internal/testutil/tlsfixture/
  doc.go          // package doc: "TEST-ONLY. Never import from production code."
  builder.go      // Spec struct + Build(Spec) []byte
  grease.go       // GREASE table (RFC 8701) + helpers
  corpus.go       // loads tests/fixtures/clienthello/*.bin + known_ja4.json
  gen.go          // rapid generators
  builder_test.go
  corpus_test.go
  gen_test.go
```

API (keep it this small, and grow it only when a 606 phase needs more):

```go
// Spec describes a ClientHello. Zero value = minimal valid TLS 1.3 hello.
type Spec struct {
    LegacyVersion uint16      // record + legacy_version, default 0x0303
    Ciphers       []uint16    // wire order
    Extensions    []Extension // wire order; Build does NOT sort
    SNI           string      // "" = no server_name extension
    ALPN          []string    // nil = no ALPN extension
    SupportedVers []uint16    // supported_versions ext; nil = omit
}
type Extension struct{ Type uint16; Data []byte }

func Build(s Spec) []byte                     // full TLS record (type 0x16 …)
func WithGREASE(s Spec, g uint16) Spec        // inserts g as cipher, ext, group
func ShuffleExtensions(s Spec, seed int64) Spec
func Split(record []byte, sizes ...int) [][]byte // TCP-segment simulation

var GREASE = [16]uint16{0x0a0a, 0x1a1a, /* … */ 0xfafa}

type CorpusEntry struct{ Name string; Raw []byte; WantJA4 string }
func Corpus(t testing.TB) []CorpusEntry      // reads known_ja4.json; t.Fatal on error

func GenSpec() *rapid.Generator[Spec]         // structurally valid specs
```

**Write these tests first** (`builder_test.go`, `corpus_test.go`, `gen_test.go`):

1. `TestBuild_ParsesWithProductionParser`: `tlsparse.ParseClientHello(Build(Spec{}))`
   returns no error. Import the parser as
   `tlsparse "github.com/seanpor/ja4proxy/internal/tls"`, the same alias the
   repo uses everywhere, because `tls` clashes with `crypto/tls`.
2. `TestBuild_RoundTripsFields`: SNI, ALPN, cipher list and extension order
   survive a parse.
3. `TestCorpus_MatchesKnownJA4`: for every corpus entry,
   `tlsparse.ComputeJA4(info) == WantJA4`. Read
   `tests/fixtures/clienthello/README.md` first for how `known_ja4.json` was
   produced.
4. `TestWithGREASE_AllSixteenValuesParse`.
5. `TestGenSpec_ParseRateIsTotal`: run `GenSpec()` through `rapid.Check`.
   **Every** generated hello must parse. A generator that sometimes produces
   invalid hellos makes downstream properties vacuous.
6. `TestSplit_ConcatenationIsIdentity`: `bytes.Join(Split(r, …), nil) == r`
   (use `rapid` for the sizes).

### Step A5 — Import guard

`tests/unit/test_testutil_import_guard.py`: walk every `*.go` file that does
**not** end in `_test.go` and is **not** under `internal/testutil/`. Fail if
any contains the import path `github.com/seanpor/ja4proxy/internal/testutil`.
Also test the guard itself: write a temp offending file in `tmp_path`, point
the function at it, and assert it is detected.

### Step A6 — Invariant registry (kills "silent green")

**Why:** `go test -run SomeTypo` exits 0 and prints `ok`. A reviewer reading
"tests pass" has no way to know nothing ran. The registry makes the set of
invariants **explicit, auditable, and machine-checked in both directions**.

1. `docs/testing/invariants.yaml`:
   ```yaml
   # Every TestInvariant_* / FuzzInvariant_* function MUST be listed here, and
   # every entry here MUST exist in code. Checked by
   # tests/unit/test_invariant_registry.py (runs in `make test`).
   invariants:
     - id: INV-TLS-001
       phase: 606a
       package: internal/tls
       test: TestInvariant_TLS_GREASEIndependence
       statement: >
         Inserting any RFC 8701 GREASE value as a cipher, extension or group
         does not change the JA4 fingerprint.
       mutation_check: "remove GREASE filtering in parser.go → test fails"
   ```
   It starts with **one** entry: the exemplar from A7.
2. `tests/unit/test_invariant_registry.py` (write first):
   - Every entry's `test` exists as `func <test>(` in a `_test.go` file
     under `package`.
   - Every `func TestInvariant_` / `func FuzzInvariant_` in the repo is
     registered.
   - `id`s are unique and match `^INV-[A-Z]+-\d{3}$`. `phase` exists in
     `manifest.yaml`.
   - Same rules for Python: `def test_invariant_` in `management/tests/` and
     `tests/unit/`.
3. `make test-invariants`: runs `go test -count=1 -v -run '^(TestInvariant_|FuzzInvariant_)' ./...`
   and **fails if the number of top-level `=== RUN   (TestInvariant_|FuzzInvariant_)[^/]+$` lines is less
   than the number of Go registry entries**. Using exact top-level regex matching prevents subtests (`t.Run`) from over-counting as separate invariant functions. Add it to `make test`.
4. **Naming rule:** `TestInvariant_<Area>_<Property>`, where `<Area>` ∈
   `TLS, QUIC, Splice, Resource, Redis, Tap, Security, Telemetry, Config, Mgmt`.
   Phase docs filter with `-run '^TestInvariant_<Area>_'`. **Never** filter
   on a free-text word.

### Step A7 — `testing/synctest` exemplar

**Why:** tests with `time.Sleep` are slow and flaky. Go 1.26 (our toolchain:
`go 1.26.6`) ships `testing/synctest`. Inside `synctest.Test(t, func(t *testing.T){…})`,
time is **fake**: `time.Sleep`, timers and `time.Now` advance instantly once
every goroutine in the bubble is blocked.

1. Candidate: the tap Redis circuit breaker (`internal/tap`, see
   `TestRedisCircuitBreaker_ClosesAfterCooldown`). **Verify** that the breaker
   reads time via `time.Now()`/timers, not an injected clock. If it doesn't,
   pick another time-based component and write down why.
2. Write `TestInvariant_Tap_CircuitBreakerCooldownIsExact` in a new file. It
   asserts the breaker is open at `cooldown − 1ns` and closed at `cooldown`,
   with no real waiting.
3. Register it as `INV-TAP-001`.
4. Prove it: temporarily change the cooldown comparison (`>` → `>=`), see the
   test fail, revert. Write the result in the PR.
5. **Limitations (put these in the handbook):** synctest bubbles fake time for timers and channels, but **stall or deadlock on real OS TCP listeners and sockets (`net.Listen`, `net.Dial`)**. Use `net.Pipe()` for in-memory connections and **verify** it behaves inside a bubble before relying on it. Tests invoking `net.Listen` (such as `cmd/ja4pd` integration tests) cannot use synctest; give them short explicit deadline bounds instead.

### Step A8 — Mutation-testing baseline (advisory)

**Why:** coverage tells you a line *ran*, not that a test *checks* it. Mutation
testing changes the code (e.g. `<` → `<=`) and asks whether some test fails.
The percentage of mutants killed (the *efficacy*) is the best single number
for "does this test suite catch bugs". Invariant tests are exactly what raises
it.

1. Tool: `github.com/go-gremlins/gremlins`, version pinned. **Verify** it
   builds and runs with Go 1.26. Note: if AST generic parsing issues occur on Go 1.26 syntax structures, try `github.com/zimmski/go-mutesting` as fallback. Mutation testing is strictly advisory and non-blocking in CI. If neither works, record that in `MUTATION_BASELINE.md`, skip A8, and tell the reviewer. Don't burn more than half a day on this.
2. Makefile (advisory, **not** in `preflight` because it is slow):
   ```make
   mutation: ## Mutation test one package: make mutation PKG=./internal/tls
   	GOROOT=$(GOROOT) go run github.com/go-gremlins/gremlins/cmd/gremlins@<pin> unleash $(PKG)
   ```
3. Run it on `internal/tls`, `internal/security`, `internal/quic` and
   `internal/tap`. Record efficacy and mutant coverage per package in
   `docs/testing/MUTATION_BASELINE.md`, with the date and commit SHA.
4. List the **top 10 surviving mutants** for `internal/tls` and
   `internal/security`. They are free test ideas for 606a/606f.

### Step A9 — Handbook: `docs/testing/INVARIANT_TESTING.md`

Short, practical, with examples drawn from code written in this phase.
Required sections:

1. **What an invariant is**, and when an example test is still the right
   tool (specific regressions and known-answer vectors).
2. **Tool choice.**
   - `rapid` for properties over structured inputs (already in go.mod;
     it shrinks failures to a minimal example).
   - Native `func FuzzXxx` for untrusted byte parsers, with a committed seed
     corpus under `testdata/fuzz/`.
   - `testing/quick` is **banned** for new code.
3. **The non-vacuity rule.** A property guarded by `if err != nil { return true }`
   must also assert that the success path is exercised, either through a
   valid-by-construction generator (`tlsfixture.GenSpec`) or by counting
   successes.
4. **The "make it fail first" rule.** For every invariant, break the
   production code on purpose, see red, revert, and record the mutation in
   the registry's `mutation_check`. An invariant that has never failed has
   never been proven to test anything.
5. **Time.** No `time.Sleep` for synchronisation. Use `synctest`, channels,
   or `miniredis.FastForward`. Note that `sliding_window.lua` takes the
   timestamp as `ARGV[1]`, so the caller controls time there and no clock
   faking is needed.
6. **Leaks.** Use `goleak.VerifyNone(t, goleak.IgnoreCurrent())`.
7. **Platform-specific tests.** Use a `//go:build linux` file, **never**
   `t.Skip`. The zero-skip policy applies.
8. **Global Prometheus state.** Tests that read `internal/metrics` counters
   must not call `t.Parallel()`. Compare deltas
   (`testutil.ToFloat64` before/after), never absolute values.
9. **Budgets.** Any invariant test taking more than 2 s must check
   `testing.Short()` and use reduced iterations. Use `-rapid.checks` for
   deep local runs. Reproduce a failure with `-rapid.seed=<n>`.
10. **Naming and registry** (A6).
11. **When you find a bug** (below).

### When you find a bug

Invariant work *will* find real bugs. That is the point. When it happens:

1. **Do not fix it in the test PR,** and do not weaken the invariant to make
   it pass.
2. Register it: `python3 scripts/findings_register.py add …`. This
   creates a `JA4PROXY-YYYY-NNNN` ID and a GitHub issue.
3. Commit the test as a **known-failing** case only with an approved
   exception in `docs/security/EXCEPTIONS.md`, and reference the exception
   ID in a code comment. Otherwise keep it on a branch until the fix lands.

---

### Part B — Rewrite the 606a–g docs

#### B1 — Mandatory sections for every 606 sub-phase doc

Every rewritten doc **must** contain, in this order:

1. `# Title` (no phase number; Rule 1) and **Goal**.
2. **Read these first.** The existing tests and source files the
   implementer must read before writing code, with paths.
3. **Verified API surface.** Every function, type, metric and config field
   the doc mentions, each with `file:line`. Copy from
   [Appendix A](#appendix-a--verified-api-map) and **re-verify**. If a
   symbol is not in the code, it may not appear in the doc.
4. **Invariants.** Each has a registry ID (`INV-<AREA>-NNN`), a plain-English
   statement, the formal statement, and a "why this matters" line for
   SecOps.
5. **Step-by-step guide.** Code templates must **compile** against `main`.
   The rewriter must paste each template into a scratch `_test.go`, run
   `go vet`, then delete it. Write "templates compile-checked on <SHA>" in
   the doc.
6. **Make it fail first.** A table: invariant ID → the production change to
   make temporarily → expected failing test.
7. **Test commands.** Exact, using `-run '^TestInvariant_<Area>_'`, plus
   `make test-invariants`.
8. **Coverage target.** Baseline → target for each package touched. The
   ratchet makes the new value permanent.
9. **Acceptance criteria.** Checkboxes, including: registry updated;
   `make test-invariants` count increased by N; coverage delta met;
   mutation-check table filled in; CHANGELOG fragment
   `docs/fragments/phase-606x-<slug>.md`; `make preflight` green.
10. **Out of scope.**

Wording rule for SecOps docs: say **"property-checked over N generated cases
(with shrinking)"**. Never say "mathematically proven".

#### B2 — Per-doc rewrite instructions

**606a — TLS & QUIC parsing invariants**
- Package is `internal/tls` (alias `tlsparse`). API: `ParseClientHello(data []byte) (*ClientHelloInfo, error)`
  and `ComputeJA4(info *ClientHelloInfo) string`. **Delete** every
  `fingerprint.ComputeJA4` / `fingerprint.Compute` reference.
- **Drop `internal/fingerprint`.** It is already at 100%.
- **Drop the JA4_r duality invariant.** There is no JA4_r in Go. Replace it
  with: "permuting extension wire order never changes JA4", which *is*
  testable today.
- Use `tlsfixture.GenSpec()` + `rapid` instead of `testing/quick` over random
  bytes (non-vacuity rule). Keep the prefix-truncation totality test, since
  it is deterministic and cheap. Fold it into a `FuzzInvariant_TLS_Totality`
  seeded from the corpus.
- **Read first:** `internal/tls/fuzz_test.go`, `internal/tls/bench_test.go`
  (`clientHelloWithTruncation`), `tests/fixtures/clienthello/README.md`.
- SNI/ALPN normalisation: **first check what the parser actually does** (does
  it lowercase SNI? reject control bytes?). If the behaviour differs from the
  invariant, that is a decision for the reviewer, or a finding. Don't make
  the invariant match the code just to get green.
- QUIC: move to the new **606h** (below). 606a keeps only the shared
  JA4-grammar invariant applied to `quic.ComputeJA4Q` output.
- The JA4 regex must be justified against the FoxIO spec: `t`/`q` prefix (is
  `d` for DTLS supported? verify), and the ALPN two-character rule for
  non-alphanumeric values.

**606b — Transport splice & replay**
- Target is **`cmd/ja4pd`, `package main`** (internal test). `internal/proxy`
  only holds PROXY-protocol helpers.
- Harness: `newTestProxy(t)` (`lifecycle_test.go:31`), `startEchoServer`
  (`:81`), `startDiscardServer` (`:105`). **Do not** invent `proxy.New/Start/Stop`.
- **Read first:** `pentest_fragmentation_regression_test.go`,
  `pentest_pooled_buffer_alias_test.go`,
  `pentest_tls_protocol_lockdown_regression_test.go`,
  `pentest_reassembly_cap_test.go`, `reassemble_gaps_test.go`. Several
  invariants are already partly covered. Extend them rather than duplicating.
- The fixture's JA4 must be **allow-listed** in the test config, or the
  pipeline may block or tarpit it and the upstream never receives bytes.
- Each connection needs its own upstream result channel. The draft shared one
  channel across six connections.
- Backpressure: no "1 byte/second" upstream. Assert that the client's writes
  **stall before 64 MiB** when the upstream never reads (set small
  `SO_RCVBUF`/`SO_SNDBUF`). Do not measure process RSS; it is too noisy.
- Non-TLS lockdown: assert zero upstream bytes **and** an increment of
  `ja4proxy_connection_errors_total{reason="non_tls_dropped"}` (`main.go:652`).

**606c — Resource conservation**
- `cmd/ja4pd`, `package main`. Use `goleak` (A3), not `NumGoroutine` slack.
- **Read first:** `pentest_goroutine_leak_regression_test.go` (has
  `startEchoFinisher`), `pentest_tarpit_slot_exhaustion_regression_test.go`,
  `pentest_accept_loop_semaphore_regression_test.go`.
- Slowloris: the deadline is `cfg.Proxy.ReadTimeout` (seconds;
  `main.go:556`). There is no `HandshakeTimeout` field. Use `ReadTimeout: 1`
  and assert closure within `[1s, 1s + generous margin]`. Real sockets mean
  no synctest here.
- FD counting goes in a `//go:build linux` file. No `t.Skip`.
- This is where `goleak.VerifyTestMain` is attempted for `cmd/ja4pd`. Every
  ignore must be justified and logged in `EXCEPTIONS.md`.

**606d — Redis state & rate limiting**
- **There is no `internal/ratelimit` and no token bucket.** Target is
  `internal/redis`: `lua.go` embeds `scripts/sliding_window.lua`
  (`//go:embed`, `lua.go:9`), with miniredis (already a dependency).
- Delete invariants 1–2 (token bucket). New invariants:
  - **Window bound under concurrency:** N goroutines hitting the same key
    never see a count that exceeds the true number of requests in the window.
    This checks the Lua script is atomic.
  - **Expiry:** a request at time `t` counts for `[t, t+W)` and not at
    `t+W`. Time is `ARGV[1]`, so pass timestamps directly with no clock
    faking.
  - **TTL always set:** every key the script writes has a TTL ≤ `ARGV[3]`.
    GDPR data minimisation, stated in the script header.
  - **Script copies identical:** `scripts/sliding_window.lua` ==
    `internal/redis/scripts/sliding_window.lua` byte-for-byte (they are
    identical today). Find out who uses `scripts/`. If nobody does, propose
    deleting it instead.
  - **Redis-down behaviour:** **first find** what the code does on
    error (read `client.go`) and which metric it bumps. Then assert that
    behaviour. Don't assume "fail-open/fail-closed" config exists.
- CIDR containment (blocklists) moves to 606f, since it lives in
  `internal/security` (`BlocklistManager.Check`).

**606e — Passive TAP**
- Package is **`internal/tap`** (`reassembler.go`, `sensor.go`), not
  `cmd/ja4-tap`. The import path is **`github.com/gopacket/gopacket`**, not
  `google/gopacket`.
- Reordering and dedup are `gopacket/reassembly`'s job. Keep **one** smoke
  test for them. Spend the effort on **our** code:
  - the 16 KiB per-direction cap holds for every input;
  - `MarkGap` behaviour;
  - at most one HandshakeEvent is emitted per flow;
  - the `active_streams` gauge returns to its starting value after
    FIN/RST/inactivity (`InactivityTimeoutSeconds`, `loader.go:678`);
  - the packet decoder is total over malformed frames (fuzz).
- `cmd/ja4-tap` is at 57%: list its untested functions (`go tool cover -func`)
  and cover the testable ones. Coverage target ≥ 80%.
- Don't invent metrics (`tap_out_of_window_packets_total` doesn't exist).

**606f — Security decisions & telemetry conservation**
- **Remove** score-range and monotonicity: they already exist in
  `internal/security/property_test.go` (Phase 62). Extend that file instead:
  - **ActionDecider monotonicity:** a higher score never yields a *less
    severe* action, for a fixed dial (`ActionDecider.Decide(score, dial)`).
  - **Dial monotonicity:** a higher dial never yields a more severe action
    (verify the dial's direction first).
  - **DecisionCache bound:** the entry count never exceeds `limit`; entries
    expire after their TTL (`NewDecisionCache(limit, allowTTL, blockTTL)`).
  - **CIDR containment:** if CIDR `C` is in a feed, every IP in `C` gets the
    same `Check` result (`BlocklistManager.Check`).
- **Remove temporal decay.** No such feature exists.
- **Conservation law, rewritten for real metrics.** There is no "accepted"
  counter. Terminal accounting is `ja4proxy_connections_total{action}`
  (`main.go:696`) plus `ja4proxy_connection_errors_total{reason}`
  (`main.go:529, 563, 652, 899, 920`). Note that `backend_dial` errors
  happen **after** an allow decision was counted, so a naive sum
  double-counts. The rewriter must:
  1. Trace `handleConn` and list each exit path and the counter(s) it bumps.
  2. State the law precisely, e.g. "for N connections, Σ connections_total +
     Σ errors{pre-decision reasons} == N".
  3. If some exit path bumps **nothing**, that is a finding (silent drop,
     against the AGENTS.md rule).
  See [Open decisions](#open-decisions-need-maintainer-sign-off) on adding
  an accepted counter.
- The conservation test lives in `cmd/ja4pd` (it needs the harness) and
  must not use `t.Parallel()`.

**606g — Config reload & management API**
- Go side: **never send signals in tests.** Call `p.reload()` directly
  (`main.go:1092`). Assert `ja4proxy_config_reloads_total` /
  `ja4proxy_config_reload_failures_total` deltas.
- **Read first:** `pentest_reload_respects_config_path_regression_test.go`,
  `stream_reload_test.go`. First list which config fields are hot-reloadable
  (read `reload()`). The "atomic swap" invariant only applies to those.
- Python side:
  - Roles are **`auditor` < `analyst` < `operator` < `admin`**
    (`auth.py:513`). There is no "Viewer".
  - The app comes from `create_app()` (`main.py:386`).
  - Unauthenticated: **401** for `/api/*` or non-HTML `Accept`; **302 →
    `/login`** for browser requests (`auth.py:616`). Test both.
  - The public-route allow-list must be **explicit in the test**, and the
    test must fail when a new unauthenticated route appears. That's the
    point.
  - Fill path parameters with dummy values; `"/x/{id}"` literally gives 404.
  - Build a route × minimum-role matrix. Exclude `POST /login` and
    `/logout` explicitly.
  - Extend the existing route-walk in
    `management/tests/test_profile_bounds_and_readonly.py`.
  - Run with `make test-unit ARGS="-k invariant"`, never host pytest.

#### B3 — Stub docs for the new phases

Write a full B1-template doc for each:

| Phase | Title | Baseline → target |
|---|---|---|
| **606h** | QUIC Initial decoder invariants & coverage (`DecodeInitial`, `ParseCRYPTOFrames`, `ParseClientHelloFeatures`, `ComputeJA4Q`; CRYPTO-frame reassembly order-independence; decoder eviction bound via `ActiveCount`) | 55.5% → ≥ 85% |
| **606i** | Cluster sync agent tests (`internal/cluster/sync`) | 0% → ≥ 80% |
| **606j** | CLI tests (`cmd/ja4p`, `internal/cli/engine`) | 0% → ≥ 80% |
| **606k** | Python coverage push: `management/` + `src/`, plus model-based (stateful) tests for ban lifecycle via Hypothesis `RuleBasedStateMachine` | baseline (A2) → ≥ 90% |

#### B4 — Self-check before submitting Part B

For every rewritten doc:
- [ ] `rg` every backticked Go identifier in the doc and confirm it exists.
- [ ] Every code template compile-checked (B1.5).
- [ ] Every `-run` pattern matches ≥ 1 function **name planned in that doc**.
- [ ] No `testing/quick`, no `time.Sleep` synchronisation, no `t.Skip`, no
      "proven".

### Part C — Manifest re-plan

1. Add `'606-0'` (quoted string key; `sync-roadmap.py` sorts it before `606a`).
2. Dependencies. The packages are independent, so juniors can work in
   parallel:
   - `606a, 606d, 606e, 606g, 606h, 606i, 606j, 606k` → depend on `'606-0'` only.
   - `606b, 606c` → `'606-0'` (and `606s` if approved).
   - `606f` → `606b` (reuses its connection harness for the conservation law).
3. Add `606h`–`606k` (and `606s` if approved) with `status: PROPOSED`.
4. `make lint-phases` and `make sync` must exit 0.

---

## Test strategy (for this phase's own code)

| Component | Tests | Runs in |
|---|---|---|
| `coverage_ratchet.py` | `tests/unit/test_coverage_ratchet.py` (A1/A2 cases) | `make test` (tools image) |
| Import guard | `tests/unit/test_testutil_import_guard.py` | `make test` |
| Invariant registry | `tests/unit/test_invariant_registry.py` | `make test` |
| `tlsfixture` | `builder_test.go`, `corpus_test.go`, `gen_test.go` | `go test ./internal/testutil/...` |
| synctest exemplar | `TestInvariant_Tap_CircuitBreakerCooldownIsExact` | `make test-invariants` |
| Ratchet wiring | delete a test locally → `make cover-check` fails (manual, record in PR) | local |

All new Python passes `ruff` and `mypy` in the tools image. All new Go passes
`go vet` and `-race`. Run new tests with `-count=20` once to prove they are
not flaky, and record the result in the PR.

## Acceptance criteria

**Part A**
- [ ] `docs/testing/coverage-baseline.json` committed with Go **and** Python per-package numbers.
- [ ] `make cover-check` runs in `make test`; deleting a test function locally makes it fail (shown in PR).
- [ ] `lint-coverage` no longer runs host Python or references `proxy`.
- [ ] `go.uber.org/goleak` added; dependency audits green.
- [ ] `internal/testutil/tlsfixture` merged; corpus test reproduces every `known_ja4.json` entry; `GenSpec` parse rate is 100%.
- [ ] Import guard test merged and self-tested.
- [ ] `docs/testing/invariants.yaml` + registry test + `make test-invariants` merged; the run-count check fails when a registered test is renamed (shown in PR).
- [ ] synctest exemplar merged, registered, with its mutation check recorded.
- [ ] `MUTATION_BASELINE.md` committed (or a documented reason why the tool couldn't run).
- [ ] `docs/testing/INVARIANT_TESTING.md` covers all 11 sections.

**Part B / C**
- [ ] 606a–g rewritten to the B1 template; every symbol verified; templates compile-checked.
- [ ] 606h–606k docs written.
- [ ] Manifest dependencies flattened as in Part C; `make lint-phases` and `make sync` exit 0.

**Close-out**
- [ ] CHANGELOG fragment `docs/fragments/phase-606-0-test-infra.md`.
- [ ] `make preflight` green.
- [ ] Manifest `'606-0'` → `COMPLETE`, doc moved to `docs/phases/complete/` in the same commit.

## Risks

| Risk | Mitigation |
|---|---|
| Atomic coverage jitters between runs | 0.1 pp tolerance; investigate any package that flaps repeatedly |
| `gremlins` incompatible with Go 1.26 | Fallback tool; half-day timebox; advisory only |
| `goleak` noisy on existing packages | Only `VerifyNone(IgnoreCurrent())` in this phase; `VerifyTestMain` deferred to 606c |
| Coverage ratchet blocks unrelated PRs | Only *drops* fail; a deleted package only warns; `update` is a one-line command documented in the failure message |
| Rewrite copies new mistakes | B4 self-check plus compile-checked templates |

## Approved Architectural Decisions (Signed Off)

The maintainer has formally approved all three key architectural decisions for Phase 606:

1. **Approved — Phase 606s (Server Package Extraction):**
   Extracting the core proxy server struct from `cmd/ja4pd/main.go` (2,236 lines, `package main`) into `internal/server` is approved as a dedicated sub-phase `606s`. This isolates connection handling and server lifecycle into a clean, testable Go package so sub-phases `606b` (transport splice) and `606c` (resource conservation) can test the server directly without reaching into `cmd/ja4pd`.

2. **Approved — Telemetry Counter (`ja4proxy_connections_accepted_total`):**
   Adding the `ja4proxy_connections_accepted_total` Prometheus counter to `internal/metrics` is approved. This turns the Telemetry Conservation Law into an exact, single-line mathematical equality:
   $$\Delta\text{Accepted} \equiv \Delta\text{Forwarded} + \Delta\text{Blocked} + \Delta\text{Tarpitted} + \Delta\text{Dropped}$$
   without complex, brittle per-path error counter offset arithmetic.

3. **Approved — Coverage Targets & Ratchet Strategy:**
   The coverage targets (`internal/*` ≥ 95%, `cmd/*` ≥ 85%, `management/*` ≥ 90%) enforced monotonically via `scripts/coverage_ratchet.py` are approved. Pure statement coverage of 99.9% is explicitly rejected in favor of strict package ratchets and mutation testing efficacy, avoiding low-value tests written solely to hit unreachable OS error branches.

---

## Appendix A — Verified API map

Verified against `main` @ `13766c5b`, 2026-10-05. **Re-verify before use.**

| Area | Real symbol | Location |
|---|---|---|
| TLS parse | `ParseClientHello(data []byte) (*ClientHelloInfo, error)` | `internal/tls/parser.go` |
| JA4 | `ComputeJA4(info *ClientHelloInfo) string`, `ComputeJA4FromFields(...)` | `internal/tls` |
| JA4X | `ExtractJA4X(certDER []byte) string` | `internal/tls` |
| QUIC | `NewDecoder(*KeyLog)`, `(*Decoder).DecodeInitial`, `ActiveCount`, `FlushEvicted`, `ParseCRYPTOFrames`, `ParseClientHelloFeatures`, `ComputeJA4Q(version, *ClientHelloFeatures)`, `DeriveInitialKey`, `DecryptInitial` | `internal/quic` |
| Proxy server | unexported `proxy` struct: `newProxy`, `serve`, `admitConn`, `handleConn`, `reassembleClientHello`, `forward`, `tarpit`, `reload`, `drain` | `cmd/ja4pd/main.go` |
| Test harness | `newTestProxy`, `startEchoServer`, `startDiscardServer` | `cmd/ja4pd/lifecycle_test.go` |
| PROXY protocol | `ReadProxyProtocol`, `ReadProxyProtocolV2`, `BuildBackendProxyHeader`, `IsTrustedProxySource` | `internal/proxy` |
| Risk scoring | `NewRiskScorer`, `(*RiskScorer).Score([]RiskSignal) RiskAssessment` | `internal/security/risk_scorer.go` |
| Decisions | `NewActionDecider`, `(*ActionDecider).Decide(score, dial int) string` | `internal/security/action_decider.go` |
| Cache | `NewDecisionCache(limit, allowTTL, blockTTL)` | `internal/security` |
| Blocklists | `(*BlocklistManager).Check(net.IP) ([]RiskSignal, bool)` | `internal/security` |
| Pipeline | `NewPipeline`, `(*Pipeline).Process(ctx, *ConnectionContext)` | `internal/security/pipeline.go` |
| Redis | `redis.New(cfg, log)`, `SlidingWindowSHA()`; Lua embedded `lua.go:9` | `internal/redis` |
| Lua | `ARGV[1]` now (s), `ARGV[2]` window (s), `ARGV[3]` TTL (s) | `internal/redis/scripts/sliding_window.lua` |
| TAP | `reassembler.go`, `sensor.go`, `NewRedisCircuitBreaker` | `internal/tap` |
| Config | `config.Load(path)`, `DefaultConfig()`, `(*Config).Validate()`; `Proxy.ReadTimeout`, `Proxy.ConnectionTimeout`, `DrainTimeoutSeconds` | `internal/config/loader.go` |
| Metrics | `ja4proxy_connections_total{action}`, `ja4proxy_connection_errors_total{reason}`, `ja4proxy_active_connections`, `ja4proxy_config_reloads_total`, `ja4proxy_config_reload_failures_total` | `internal/metrics/metrics.go` |
| Mgmt app | `create_app()`; module-level `app` | `management/api/main.py:386` |
| Mgmt roles | `auditor < analyst < operator < admin` | `management/api/auth.py:513` |
| Mgmt unauth | 401 (API/non-HTML) or 302 → `/login` (browser) | `management/api/auth.py:616` |
| Libraries | `pgregory.net/rapid v1.3.0`, `github.com/alicebob/miniredis/v2`, `github.com/gopacket/gopacket` | `go.mod` |
| Toolchain | `go 1.26.6` (`testing/synctest` available) | `go.mod` |
