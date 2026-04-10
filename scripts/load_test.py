#!/usr/bin/env python3
"""Phase 86b — Load testing harness for JA4proxy.

Thin wrapper around the existing benchmark_comparison.py engine,
configured for single-target load testing (no Python vs Python comparison).

Usage:
    python3 scripts/load_test.py --target localhost:8080 --duration 60 --rps 1000 --scenario baseline
    make load-test LOAD_TEST_TARGET=localhost:8080 LOAD_TEST_RPS=1000 LOAD_TEST_DURATION=60 LOAD_TEST_SCENARIO=baseline

Scenarios:
    baseline      — Single-target baseline latency + throughput
    sustained     — Hold target RPS for duration
    ramp          — Linear ramp from 100 to target RPS over duration

Output:
    test-results/load-test/<timestamp>/report.json  — Raw results
    test-results/load-test/<timestamp>/summary.txt  — Human-readable summary
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
BENCH_PY = REPO_ROOT / "scripts" / "benchmark_comparison.py"


def run_benchmark(target: str, duration: int, rps: int, scenario: str) -> dict:
    """Run the benchmark engine and return parsed results."""
    host, port = target.rsplit(":", 1)
    port = int(port)

    # The benchmark_comparison.py engine handles the actual TLS connections.
    # We invoke it with the target as both Python and Go proxy
    # (since we're testing a single proxy, not comparing).
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    output_dir = REPO_ROOT / "test-results" / "load-test" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, str(BENCH_PY),
        "--python-host", host,
        "--python-port", str(port),
        "--go-host", host,
        "--go-port", str(port),
        "--proxy", "python",  # single target
        "--no-docker",
        "--skip-build",
        "--scenarios", "peak_throughput",
        "--duration-long", str(duration),
        "--output-dir", str(output_dir),
        "--connect-timeout", "2",
    ]

    start = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 120)
    elapsed = time.monotonic() - start

    # Parse results from the benchmark output
    report_md = output_dir / "report.md"
    raw_json = output_dir / "raw_results.json"

    report_text = report_md.read_text() if report_md.exists() else ""
    raw_data = json.loads(raw_json.read_text()) if raw_json.exists() else {}

    return {
        "target": target,
        "duration": duration,
        "target_rps": rps,
        "scenario": scenario,
        "timestamp": timestamp,
        "elapsed_seconds": round(elapsed, 1),
        "exit_code": proc.exitcode,
        "report_text": report_text[:2000] if report_text else "",
        "raw_data": {k: v for k, v in raw_data.items() if isinstance(v, (int, float, str))},
    }


def generate_summary(results: dict) -> str:
    """Generate a human-readable summary."""
    lines = [
        "JA4proxy Load Test Report",
        f"{'=' * 50}",
        f"Target:        {results['target']}",
        f"Scenario:      {results['scenario']}",
        f"Duration:      {results['duration']}s",
        f"Target RPS:    {results['target_rps']}",
        f"Elapsed:       {results['elapsed_seconds']}s",
        f"Exit code:     {results['exit_code']}",
        "",
    ]

    # Extract key metrics from raw data if available
    rd = results.get("raw_data", {})
    if rd:
        lines.append("Key Metrics:")
        for k, v in rd.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    if results.get("report_text"):
        lines.extend([
            "Benchmark Report Excerpt:",
            "-" * 50,
            results["report_text"],
        ])

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JA4proxy load testing harness (Phase 86b).",
    )
    parser.add_argument("--target", required=True,
                        help="Target proxy host:port (e.g. localhost:8080)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration per scenario in seconds (default: 60)")
    parser.add_argument("--rps", type=int, default=1000,
                        help="Target connections per second (default: 1000)")
    parser.add_argument("--scenario", default="baseline",
                        choices=["baseline", "sustained", "ramp"],
                        help="Test scenario (default: baseline)")
    parser.add_argument("--output", type=str, default=None,
                        help="Output directory (default: auto-generated)")
    args = parser.parse_args()

    print(f"Starting load test: target={args.target}, duration={args.duration}s, "
          f"rps={args.rps}, scenario={args.scenario}")

    results = run_benchmark(args.target, args.duration, args.rps, args.scenario)

    # Write report
    output_dir = Path(args.output) if args.output else (
        REPO_ROOT / "test-results" / "load-test" / results["timestamp"]
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = generate_summary(results)
    summary_file = output_dir / "summary.txt"
    summary_file.write_text(summary)

    results_file = output_dir / "report.json"
    results_file.write_text(json.dumps(results, indent=2))

    print(f"\nResults written to: {output_dir}")
    print(f"  Summary:  {summary_file}")
    print(f"  JSON:     {results_file}")
    print(f"\n{summary}")

    sys.exit(results["exit_code"])


if __name__ == "__main__":
    main()
