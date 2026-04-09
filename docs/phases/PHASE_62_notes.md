# Phase 62 — Notes

Branch: `claude/phase-62-go-test-parity`
Date: 2026-04-09

## Review-fix addendum (post external review)

External SRE/security review (2026-04-09) returned `APPROVE WITH FIXES`. One
blocking item, several non-blocking. Fixes applied in-branch:

1. **Blocker — `TestPipeline_DialFlip_NoStaleDecisions` was under-asserting.**
   The test only checked `res1.Dial == 100`; it never asserted that the
   propagated dial actually changed the action. Renamed to
   `TestPipeline_DialFlip_PropagatesAndChangesAction` and extended: after
   the dial flip, feed a synthetic threshold-crossing score (80) to
   `ActionDecider.Decide` together with the dial value the pipeline
   returned, and assert `allow` → non-`allow`. End-to-end contract is now
   locked: `dial → Redis → Pipeline → PipelineResult.Dial → ActionDecider →
   action change`. (ActionDecider × score correctness is exhaustively
   covered at the unit level by `TestActionDecider_FullBlocking`.)

2. **Acceptance criterion — `tests/fuzz/README.md` was missing.** Created.
   Documents the three Go fuzz targets, the fast smoke run, the quarterly
   24h `-fuzztime` operator procedure, and what to do when a target finds
   a crash.

3. **Acceptance criterion — `cmd/proxy/testdata/fuzz/<Target>/` directories
   missing.** Added `.gitkeep` files so future regression seeds (post-crash
   inputs Go writes here) have a committed home.

4. **Non-blocking findings filed under PHASE_101 cross-phase gap register
   as M15 (golden cross-check anchor), M16 (chaos right-answer-wrong-mechanism),
   M17 (V2 fuzz target hand-off to Phase 200), L9 (property generator
   weight semantics).** None block merge; each is small and independently
   actionable.

Tests: full `go test ./...` green after fix. The renamed dial-flip test
passes against the production `Pipeline` + `ActionDecider`.

## Summary

All six Go-side test gaps closed. No production code touched. No bugs found
by fuzzing or property tests.

## Per-step status

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | `cmd/proxy/fuzz_test.go` (3 fuzz targets) | DONE | All three targets ran 10 s × 16 workers panic-free in smoke testing |
| 2 | `internal/tls/parser_test.go` (adversarial corpus) | DONE | All 13 fixtures pass, none hang |
| 3 | `internal/tls/ja4_fp_corpus_test.go` + golden file | DONE | 5 fixtures locked in golden file |
| 4 | `internal/security/pipeline_chaos_test.go` | DONE | 3 scenarios, all pass |
| 5 | `internal/security/property_test.go` | DONE | 4 properties × 100 cases, all pass |
| 6 | `cmd/proxy/bench_test.go` | DONE | Both benches compile + run; numbers below |
| 7 | `scripts/generate_validation_report.py` | DONE | Emits markdown to `docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md` |
| 8 | Makefile targets | DONE | 5 new targets appended at bottom |
| 9 | CHANGELOG.md prepend | DONE | Phase 62 entry added at top |

## Critical findings

**None.** No fuzzer crashes, no property test failures, no panics.

## Benchmark numbers (Phase 86 baseline candidates)

Recorded on Intel Core i9-9900K @ 3.60 GHz, Linux 6.17.9, Go 1.26.1.
Two separate runs:

```
BenchmarkPipeline_Allow-16    2643183    469.0 ns/op   640 B/op    8 allocs/op
BenchmarkPipeline_Score-16     582862   1908   ns/op   882 B/op   19 allocs/op
```

```
BenchmarkPipeline_Allow-16    2016064    573.1 ns/op   640 B/op    8 allocs/op
BenchmarkPipeline_Score-16     501981   2482   ns/op   882 B/op   19 allocs/op
```

Throughput estimate (single-threaded):
- Allow path: ~1.7-2.1 M req/s
- Score path: ~400-525 k req/s

## Fuzz coverage observations

- `FuzzClientHello`: 16 baseline seeds (13 corpus + 3 manual). 11 s smoke
  produced ~915 k execs and 56 new-interesting inputs. No crashes.
- `FuzzReadProxyProtocol`: 14 baseline seeds. ~735 k execs over 11 s, 26
  new-interesting inputs. No crashes.
- `FuzzReadProxyProtocolV2`: 5 baseline seeds. Notably slower (~6 k execs
  over 10 s) — the v2-shaped seeds are large and the v1 reader rejects them
  early; coverage growth is correspondingly slow. Once Phase 200 lands its
  real V2 reader, the fuzz target should be repointed at it.

## Compatibility notes

- The phase doc proposed a Makefile target named `test-go-chaos`, but that
  name is already used by an unrelated Python-driven Go integration test
  target. The Phase 62 unit-test variant is named `test-go-chaos-unit` to
  avoid clobbering existing work.
- The phase doc proposed `proxy.ReadProxyProtocolV1` and
  `proxy.ReadProxyProtocolV2` as the fuzz entry points. Neither exists in
  the current Go tree — only `proxy.ReadProxyProtocol` (a v1 text reader
  that takes `[]byte`, not `io.Reader`). The fuzz file calls the actual
  function and notes the Phase 200 hand-off in its docstring.
- Per the Go test conventions, the `-update` flag for the JA4 golden file
  must be passed via `-args -update` so the Go test driver does not
  intercept it. Documented in the test file's package comment and in the
  golden file header.

## QA gate output

### `go build ./...`
```
BUILD-OK
```

### `go test ./...`
```
ok    github.com/anomalyco/ja4proxy/cmd/proxy
ok    github.com/anomalyco/ja4proxy/internal/security
ok    github.com/anomalyco/ja4proxy/internal/tls
... (all packages OK; full output captured below)
```

All packages pass. Cached run: 16 packages OK, 4 packages with no test files.

### `make test-go-fuzz-smoke`
All three fuzz targets ran 10 s panic-free.

### `make test-go-property`
4/4 properties pass (100 cases each).

### `make test-go-chaos-unit`
3/3 chaos scenarios pass.

### `make bench-go-pipeline`
Both benches compile and run (numbers above).

### `make validation-report`
Emits `docs/security/PRE_ENTERPRISE_VALIDATION_REPORT.md`. Counts:
- 274 unit tests
- 3 fuzz targets
- 8 benchmarks
- 4 property tests
- 3 chaos tests

`govulncheck` and `pip-audit` sections report environment-specific failures
(host snap Go GOROOT issue; bcc kernel package not on PyPI), not test
regressions. The script handles these gracefully and the report still
generates.

## Open questions for the reviewer

1. Should `cmd/proxy/bench_test.go` use the existing `internal/tls/bench_test.go`
   helpers (`generateTestClientHello`)? They live in a different package and
   currently the bench wires up `*ConnectionContext` directly without going
   through the ClientHello parser. If pipeline-realistic e2e numbers are
   needed (parse + score), we could extend.

2. The phase doc asked for `tests/fuzz/README.md` to be rewritten. That file
   does not exist on disk in this branch and the directory is owned by other
   phases. I have not created it; if the reviewer wants the README, please
   confirm the ownership boundary and I will add it as a follow-up.

3. The phase doc proposed `proxy.ReadProxyProtocolV1` and a separate v2
   reader. Do we want to (a) wait for Phase 200 before repointing the v2
   fuzz target, or (b) merge Phase 62 now with a TODO comment and have
   Phase 200 update both production and fuzz in the same PR?
