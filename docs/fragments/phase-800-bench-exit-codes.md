- **Make failed benchmarks actually fail (Phase 800)**: `ja4p test benchmark`
  computed a pass/fail verdict, printed it, and then exited 0 regardless — so
  `make bench-macro` reported success after making 0 connections and logging 2880
  `connection refused` errors, alongside a reassuring `0.00%` false-positive rate
  derived from zero samples. `RunBenchmark` now returns an error and the CLI exits
  non-zero. A latent hole is closed at the same time: the zero-connection check
  required `Errors > 0`, so a run with no connections *and* no errors reported
  PASSED. Rates now print `n/a` rather than `0.00%` when no traffic completed.
  Adds the package's first tests (`internal/test/bench/ja4bench_test.go`).
- **Remove `|| true` from `make bench-micro` (Phase 800)**: it was masking three
  permanently-failing `internal/tls` benchmarks (fixed in #408) — the package
  exited 1 on every run while the target reported success.
