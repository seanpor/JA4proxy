# Phase 86h — Close-out Notes

**Status:** COMPLETE
**Completed:** 2026-04-11
**Branch:** `claude/phase-86h-fixup`
**Depends on:** Phase 86 (86a–86g)
**Blocks:** Phase 86i (hardening)

---

## Summary

Phase 86h is pure defect repair for three correctness bugs that shipped in
Phase 86. It fixes 38 dead `runbook_url` values across 7 Alertmanager rule
files (35 `example.com` placeholders and 3 wrong-owner / wrong-case GitHub
URLs in `ti_feed.yml`), normalizes every `runbook_url:` annotation across the
full rules directory to the absolute `https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/<file>.md`
format that renders as a clickable link in every Alertmanager notification
sink, and makes the capacity calculator honest about the fact that its
hardcoded constants are engineering estimates rather than measured benchmarks
(loud `ESTIMATED — NOT MEASURED` banner, plus a `--require-measured` CLI
flag for CI guards). No feature work; no architectural change; no new
Redis keys. Phase 86i will follow with the substantive hardening work.

---

## Judgment calls made during implementation

- **`KernelLevelVolumetricAttack` (`ebpf_attack.yml`) brought into the mapping.**
  The phase spec counted 49 URLs to update (38 dead + 11 relative paths in
  `slo_alerts.yml`/`tls_alerts.yml`). While auditing the rules directory, the
  Coder found that `ebpf_attack.yml` already had a `runbook_url` pointing at a
  pre-existing relative path that did not resolve to a real file on disk. To
  avoid leaving a known-dead URL in-tree, that alert was folded into
  `PHASE_86h_runbook_mapping.yml` and a new stub
  `docs/runbooks/ebpf_volumetric_attack.md` was created following the standard
  stub format. This is in the spirit of the phase goal even though it nudges
  the count past the 49 stated in the spec.

- **`BenchmarkConstants` alias preserved alongside the new `EstimatedConstants`
  class.** The phase spec says to rename, but the pre-existing Phase 86c test
  `tests/unit/test_capacity_calculator.py` imports `BenchmarkConstants` by
  name. To keep the 4281 pre-existing tests green without touching Phase 86c
  test files (not in this phase's ownership), the Coder kept
  `BenchmarkConstants` as a module-level alias for `EstimatedConstants`.
  Phase 86i will collapse the alias when it replaces the estimates with real
  measurements.

- **Benchmark file override via env var, not CLI flag.** The TDD writer
  proposed exposing the benchmarks.md path as `JA4PROXY_BENCHMARKS_PATH` to
  keep unit tests hermetic without adding a test-only CLI argument. The Coder
  accepted that; production invocations still read the default path.

- **`--require-measured` uses exit code 2, not 1.** This distinguishes
  "benchmarks not measured" from generic argparse failures (exit code 2 is
  standard POSIX for "misuse / precondition not met"; argparse itself uses
  exit 2 for parse errors, which is acceptable because a missing-measurements
  failure is conceptually a precondition error, not a runtime failure). A
  CI guard wrapping `make lint-alert-urls`-style targets can branch on it
  cleanly.

---

## Stub runbooks created

From `git diff --name-status main...HEAD -- docs/runbooks/`:

- `docs/runbooks/ebpf_volumetric_attack.md` — new stub for the
  `KernelLevelVolumetricAttack` alert. Marked `**Status:** STUB — written in
  Phase 86h, to be expanded.` Cross-references existing DDoS / volumetric
  attack runbooks where relevant.

No other runbook files were created — every other alert in the mapping
resolved to an already-existing runbook in `docs/runbooks/`.

---

## Deferred to Phase 86i

Items that were tempting to fix while in the code but are explicitly out of
scope for this phase:

- **Datadog / Dynatrace Prometheus-first refactor.** Both integrations
  currently duplicate effort by re-scraping the Management API directly.
  Phase 86i will rework them to consume Prometheus as the canonical source.
- **Populating real benchmark numbers in `docs/performance/benchmarks.md`.**
  Requires running `make bench` against a representative fleet and will need
  its own review. Phase 86i will replace the `EstimatedConstants` with real
  measurements and remove the warning code path.
- **Grafana capacity dashboard (`dashboards/04_capacity.json`).** Pending the
  real measurements above.
- **Load test scenario rewrite.** The current scenarios were written to a
  rough shape; Phase 86i will redo them with measured baselines.
- **Expanding the `ebpf_volumetric_attack.md` stub.** Content quality is
  explicitly out of scope here.

---

## Test status

- 14 Phase 86h tests pass (unit + integration combined).
- 1 integration test skipped: `test_promtool_check_rules_all_files` —
  `promtool` is not installed in the CI image. Local run should still go
  green when the Prometheus toolchain is available.
- 4281 pre-existing unit tests remain green — no regressions introduced.

---

## Known cosmetic issue (not introduced by this phase)

The Coder noted that the Kafka exporter emits a stderr logging error at
shutdown during unrelated test teardown. This is a pre-existing condition
from prior phases and is flagged here only so that QA does not attribute it
to Phase 86h. It does not affect test outcomes and is not in scope to fix.
