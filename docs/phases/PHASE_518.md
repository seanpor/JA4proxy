# Phase 518 — Race-Detector CI Gate + `cmd/ja4pd` Test-Race Fixes

## Status: OPEN

## Summary

The concurrency regression tests added in Phase 515 (config hot-reload snapshot
`JA4PROXY-2026-0088`, worker lifecycle `-0090`) and earlier (`forward()` config
capture `-0068`) only **detect** a regression when run under the Go race
detector. The required CI test gate (`make test`) runs `go test` **without**
`-race`, so a future revert of those fixes would pass CI undetected. There is a
separate workflow that runs `go test -race ./...`, but it is post-merge, not a
required PR check, and it was red anyway because of two pre-existing races in
`cmd/ja4pd` **test code**.

This phase makes `go test -race ./...` green and enforces it on every PR.

---

## Why Now?

Follow-up to Phase 515. Verified directly: reintroducing the `0088` racy read
makes `pipeline_reload_race_test.go` FAIL under `-race` but PASS without it — so
the regression test has no teeth in the required gate. Closing this gap is the
difference between "we wrote a test" and "the test actually guards `main`."

---

## Root Causes (both in `cmd/ja4pd` **test** code, not production)

1. **`TestClientHelloFragmentation` — data race.** The test set the logger output
   to a plain `bytes.Buffer` and read it (`logBuf.String()`) from the test
   goroutine while the connection-handler goroutine wrote log lines to it via
   logrus. `bytes.Buffer` is not safe for concurrent read/write.

2. **`TestForward_ConfigLocalCapture` — flaky hang under `-race`.** Two problems:
   (a) it used `net.Pipe`, whose deadlines are serviced by a timer goroutine that
   is starved under the CPU contention of a whole-suite `-race` run, so the copy
   loop's read deadline could fail to fire within the test's 30s ceiling; and
   (b) an inherent ordering flaw — it started the config-reload goroutine (which
   swaps `ReadTimeout` to 100s) **before** `forward()` captured the config, so
   `forward()` could legitimately capture the swapped 100s value and hang. The
   `0068` production fix is correct; the test's premise was racy.

---

## Scope

### In scope
- `cmd/ja4pd/pentest_fragmentation_regression_test.go`: replace the shared
  `bytes.Buffer` with a mutex-guarded `syncBuffer` (Write + String both locked).
- `cmd/ja4pd/pentest_forward_config_local_capture_test.go`: switch to a real TCP
  socket pair (netpoller deadlines, reliable under load) and reorder so
  `forward()` captures the original timeout **before** the reload goroutine
  mutates `p.cfg`.
- `Makefile`: add a `test-race` target (`go test -race ./... -count=1`).
- `.github/workflows/ci.yml`: add a `race` job (`make test-race`) that runs on
  every PR.
- Confirm `go test -race ./...` is green across repeated whole-suite runs.

### Out of scope
- Making the `race` job a *required* status check — that is a branch-protection
  setting (`gh api .../branches/main/protection`), applied by the maintainer.
  This phase adds the job; flipping it to required is a one-line follow-up.
- Any production code change (none needed — all fixes are in test code / CI).

---

## Acceptance Criteria

- [ ] `go test -race ./...` passes, and is stable across ≥3 consecutive
      whole-suite runs (no `DATA RACE`, no timeout).
- [ ] `make test-race` exists, is in `.PHONY`, threads `GOROOT`, and passes.
- [ ] A `race` CI job runs `make test-race` on every PR (`ci.yml` valid YAML;
      meta-lint / `ci-verify` green).
- [ ] `TestClientHelloFragmentation` and `TestForward_ConfigLocalCapture` pass
      under `-race` in isolation **and** in the whole-suite run.
- [ ] The plain `make test` gate is unchanged and still green.
- [ ] News fragment `docs/fragments/phase-518-race-gate.md`.
- [ ] `manifest.yaml` entry set to COMPLETE at close-out.

### The test *is* the acceptance test
The new/repaired tests are themselves the deliverable: `test-race` run by the
`race` CI job enforces every existing Go concurrency regression test. The
`0088`/`0090` revert-sensitivity was verified by hand (reintroduce the racy read
→ `race` job fails).

---

## Notes / Follow-ups
- Marking `race` as a required check is recommended once it has a few green runs
  on `main`.
- A pre-existing, unrelated observation: `net.Pipe`-based tests are inherently
  fragile under `-race` load; prefer real sockets for anything that depends on
  deadline reaping.
