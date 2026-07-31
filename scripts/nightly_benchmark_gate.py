#!/usr/bin/env python3
"""
nightly_benchmark_gate.py — Phase 805 nightly performance regression gate.

Compares a `ja4p test benchmark --output json` result against
docs/reports/nightly_benchmark_baseline.json and fails (exit 1) if:

  - throughput_cps drops more than --gate percent below the baseline, or
  - p95_latency_ms rises more than --gate percent above the baseline, or
  - the error rate (errors / total connections) exceeds the baseline's
    max_error_rate_percent.

p99_latency_ms is reported but not gated (see the baseline file's
tracked_not_gated_metrics comment — no historical baseline exists yet).

This is a sibling script to scripts/benchmark_comparison.py, not an
extension of it: that script's whole design is a Go-vs-Python dual-proxy
comparison, and the Python proxy it would compare against no longer exists.
See docs/phases/complete/PHASE_805.md's "Design correction" section for the full
reasoning.

Exit 0 = clean run (or informational-only skip).
Exit 1 = regression detected — details printed to stdout.

Run via:
    python3 scripts/nightly_benchmark_gate.py --result result.json \
        --baseline docs/reports/nightly_benchmark_baseline.json --gate 20
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def check_regression(result: dict, baseline: dict, gate_percent: float) -> list[str]:
    """Return a list of human-readable failure messages (empty = clean)."""
    failures: list[str] = []
    gated = baseline["gated_metrics"]

    throughput_baseline = gated["throughput_cps"]["baseline"]
    throughput_actual = result.get("throughput_cps", 0.0)
    throughput_floor = throughput_baseline * (1 - gate_percent / 100.0)
    if throughput_actual < throughput_floor:
        drop_pct = (1 - throughput_actual / throughput_baseline) * 100 if throughput_baseline else 100
        failures.append(
            f"throughput_cps regressed: {throughput_actual:.1f} conn/s is "
            f"{drop_pct:.1f}% below baseline {throughput_baseline:.1f} conn/s "
            f"(floor: {throughput_floor:.1f}, gate: {gate_percent:.0f}%)"
        )

    p95_baseline = gated["p95_latency_ms"]["baseline"]
    p95_actual = result.get("p95_latency_ms", 0.0)
    p95_ceiling = p95_baseline * (1 + gate_percent / 100.0)
    if p95_actual > p95_ceiling:
        rise_pct = (p95_actual / p95_baseline - 1) * 100 if p95_baseline else 100
        failures.append(
            f"p95_latency_ms regressed: {p95_actual:.2f}ms is {rise_pct:.1f}% "
            f"above baseline {p95_baseline:.2f}ms "
            f"(ceiling: {p95_ceiling:.2f}, gate: {gate_percent:.0f}%)"
        )

    max_error_rate = baseline["error_rate_gate"]["max_error_rate_percent"]
    total_good = result.get("total_good", 0)
    total_bad = result.get("total_bad", 0)
    errors = result.get("errors", 0)
    total_attempted = total_good + total_bad + errors
    error_rate = (errors / total_attempted * 100) if total_attempted else 0.0
    if error_rate > max_error_rate:
        failures.append(
            f"error rate too high: {errors}/{total_attempted} "
            f"({error_rate:.2f}%) exceeds max {max_error_rate:.2f}%"
        )

    return failures


def print_report(result: dict, baseline: dict, failures: list[str]) -> None:
    gated = baseline["gated_metrics"]
    print("=== Nightly Benchmark Regression Gate ===")
    print(f"  Baseline source: {baseline['source']['date']} "
          f"(SHA {baseline['source']['git_sha']}), {baseline['source']['method']}")
    print()
    print(f"  throughput_cps:   {result.get('throughput_cps', 0.0):.1f}  "
          f"(baseline {gated['throughput_cps']['baseline']:.1f})")
    print(f"  p95_latency_ms:   {result.get('p95_latency_ms', 0.0):.2f}  "
          f"(baseline {gated['p95_latency_ms']['baseline']:.2f})")
    print(f"  p99_latency_ms:   {result.get('p99_latency_ms', 0.0):.2f}  "
          f"(tracked, not gated)")
    print(f"  errors:           {result.get('errors', 0)}")
    print()
    if failures:
        print(f"REGRESSION DETECTED ({len(failures)} metric(s)):")
        for f in failures:
            print(f"  - {f}")
    else:
        print("No regression detected — all gated metrics within threshold.")
    print("==========================================")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--result", required=True, type=Path, help="ja4p test benchmark --output json result file")
    parser.add_argument("--baseline", required=True, type=Path, help="Baseline JSON (nightly_benchmark_baseline.json)")
    parser.add_argument("--gate", type=float, default=20.0, help="Regression gate percentage (default: 20)")
    args = parser.parse_args()

    result = load_json(args.result)
    baseline = load_json(args.baseline)

    failures = check_regression(result, baseline, args.gate)
    print_report(result, baseline, failures)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
