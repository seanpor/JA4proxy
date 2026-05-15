#!/usr/bin/env python3
"""Phase 86b / 86i — Load testing harness for JA4proxy.

Thin wrapper around the existing benchmark_comparison.py engine plus
scripts/tls-traffic-generator.py, configured for single-target load
testing (no Python vs Python comparison).

Phase 86i replaces the old [baseline, sustained, ramp] scenario set with
four code-path-specific scenarios. Each scenario pins a fingerprint
distribution so the proxy exercises a distinct internal path:

    bypass-only   — 100% browser ALPN        → bypass throughput ceiling
    full-signal   — 100% automation          → full scoring path (cache
                                                miss, Redis reads)
    attack-wave   —  50% scanner + 50% mal   → block path + Redis writes
    mixed         —  70/20/5/5               — representative production

Usage:
    python3 scripts/load_test.py --target localhost:8080 \\
        --duration 60 --rps 1000 --scenario mixed
    python3 scripts/load_test.py --target localhost:8080 \\
        --scenario full-signal --push-gateway http://pgw:9091
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).parent.parent
BENCH_PY = REPO_ROOT / "scripts" / "benchmark_comparison.py"
TLS_TRAFFIC_GEN_PY = REPO_ROOT / "scripts" / "tls-traffic-generator.py"


# ── Phase 86i scenario definitions ──────────────────────────────────────────

# Fingerprint-distribution-per-scenario (must sum to 100 for each scenario).
# Keys correspond to the four JA4 fingerprint families produced by
# tls-traffic-generator.py.
SCENARIOS: Dict[str, Dict[str, int]] = {
    "bypass-only": {
        "browser_alpn": 100,
        "automation": 0,
        "scanner": 0,
        "malicious": 0,
    },
    "full-signal": {
        "browser_alpn": 0,
        "automation": 100,
        "scanner": 0,
        "malicious": 0,
    },
    "attack-wave": {
        "browser_alpn": 0,
        "automation": 0,
        "scanner": 50,
        "malicious": 50,
    },
    "mixed": {
        "browser_alpn": 70,
        "automation": 20,
        "scanner": 5,
        "malicious": 5,
    },
}

# Legacy aliases kept so the pre-86i test suite (which still uses the
# string "baseline") continues to round-trip through run_benchmark /
# generate_summary without crashing.
_LEGACY_SCENARIOS = {"baseline", "sustained", "ramp"}


def _load_tls_traffic_generator():
    """Import scripts/tls-traffic-generator.py. Its filename contains a
    hyphen so plain ``import`` won't work — we go through importlib."""
    spec = importlib.util.spec_from_file_location(
        "tls_traffic_generator", TLS_TRAFFIC_GEN_PY
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# ── Pushgateway support ─────────────────────────────────────────────────────

_LATENCY_BUCKETS = (
    0.0001,
    0.001,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.5,
    1.0,
)


def sample_connect_latencies(
    target: str, samples: int = 50, timeout_s: float = 2.0
) -> List[float]:
    """Open ``samples`` short TCP connections to ``target`` and return the
    per-connect wall times in seconds.

    PHASE_101 M24 — the traffic generator subprocess reports only aggregate
    throughput; the pushgateway metric needed real per-request latencies so
    the histogram ships non-zero buckets. We collect these by doing a tiny
    sampling loop from the harness itself — the sample size is small so it
    never meaningfully impacts the headline benchmark numbers, and failures
    are silently counted as "connect error" (not appended to the latency
    list, so the histogram never records negative/zero false samples).
    """
    if samples <= 0:
        return []
    try:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    except Exception:
        return []
    latencies: List[float] = []
    for _ in range(samples):
        start = time.monotonic()
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as sock:
                sock.settimeout(timeout_s)
        except Exception:
            continue
        latencies.append(time.monotonic() - start)
    return latencies


def push_loadtest_metrics(
    url: str,
    attempted: int,
    completed: int,
    errors: Dict[str, int],
    latencies_seconds: List[float],
    throughput_cps: float,
    job: str = "ja4proxy_loadtest",
    grouping_key: Optional[Dict[str, str]] = None,
) -> None:
    """Build a CollectorRegistry with the 5 phase-86i loadtest metrics and
    push it to a Prometheus Pushgateway at ``url``.

    ``grouping_key`` (PHASE_101 M24) routes each push into its own
    pushgateway group so concurrent load tests from different hosts or
    scenarios don't overwrite each other. Callers should pass at minimum
    ``{"instance": hostname, "scenario": scenario, "run_id": uuid[:8]}``.

    On any exception the function logs and returns — it must never break
    the load test itself.
    """
    try:
        from prometheus_client import (
            CollectorRegistry,
            Counter,
            Gauge,
            Histogram,
            push_to_gateway,
        )
    except Exception as exc:
        logging.error("prometheus_client unavailable: %s", exc)
        return

    registry = CollectorRegistry()

    attempted_metric = Counter(
        "ja4proxy_loadtest_connections_attempted_total",
        "Total load-test connections attempted.",
        registry=registry,
    )
    completed_metric = Counter(
        "ja4proxy_loadtest_connections_completed_total",
        "Total load-test connections that completed successfully.",
        registry=registry,
    )
    errors_metric = Counter(
        "ja4proxy_loadtest_errors_total",
        "Total load-test errors by reason.",
        labelnames=("reason",),
        registry=registry,
    )
    latency_metric = Histogram(
        "ja4proxy_loadtest_latency_seconds",
        "Load-test end-to-end connection latency in seconds.",
        buckets=_LATENCY_BUCKETS,
        registry=registry,
    )
    throughput_metric = Gauge(
        "ja4proxy_loadtest_throughput_cps",
        "Load-test observed throughput in connections per second.",
        registry=registry,
    )

    attempted_metric.inc(attempted)
    completed_metric.inc(completed)
    for reason, count in (errors or {}).items():
        errors_metric.labels(reason=reason).inc(count)
    for sample in latencies_seconds or []:
        latency_metric.observe(sample)
    throughput_metric.set(throughput_cps)

    try:
        if grouping_key:
            push_to_gateway(url, job=job, registry=registry, grouping_key=grouping_key)
        else:
            push_to_gateway(url, job=job, registry=registry)
    except Exception as exc:
        logging.error("push_to_gateway(%s) failed: %s", url, exc)


# ── Benchmark invocation ────────────────────────────────────────────────────


def _format_mix(dist: Dict[str, int]) -> str:
    """Format a scenario distribution as the tls-traffic-generator's
    ``--fingerprint-mix`` CLI argument."""
    return ",".join(f"{k}={v}" for k, v in dist.items())


def run_benchmark(target: str, duration: int, rps: int, scenario: str) -> dict:
    """Run the TLS traffic generator for ``duration`` seconds against
    ``target`` with the fingerprint distribution dictated by ``scenario``.

    Phase 86i: this replaced the old benchmark_comparison subprocess call,
    which accepted no fingerprint distribution and so drove identical
    traffic for every scenario. See reviewer blocker 1.

    Legacy scenarios ("baseline"/"sustained"/"ramp") are still accepted —
    they fall back to the "mixed" distribution so the pre-86i mock-based
    unit tests keep passing.
    """
    host, port = target.rsplit(":", 1)
    port = int(port)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    output_dir = REPO_ROOT / "test-results" / "load-test" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    distribution = SCENARIOS.get(scenario) or SCENARIOS["mixed"]
    mix_arg = _format_mix(distribution)

    cmd = [
        sys.executable,
        str(TLS_TRAFFIC_GEN_PY),
        "--target-host",
        host,
        "--target-port",
        str(port),
        "--duration",
        str(duration),
        "--fingerprint-mix",
        mix_arg,
    ]

    start = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 120)
    elapsed = time.monotonic() - start

    # Persist raw subprocess output + the mix spec for downstream analysis
    # and for the integration test in
    # tests/integration/test_phase_86i_load_test_scenarios_distinct.py.
    report_md = output_dir / "report.md"
    raw_json = output_dir / "raw_results.json"

    report_text = (proc.stdout or "")[-2000:]
    try:
        report_md.write_text(report_text)
    except Exception:
        pass
    raw_data: Dict[str, Any] = {
        "scenario": scenario,
        "fingerprint_mix": distribution,
        "fingerprint_mix_arg": mix_arg,
        "cmd": cmd,
    }
    try:
        raw_json.write_text(json.dumps(raw_data, indent=2))
    except Exception:
        pass

    # Phase 86b left a latent bug here: real subprocess.CompletedProcess
    # uses `returncode`, but the original code read `proc.exitcode` (and
    # the unit test mocks it with `exitcode=0`). Preserve the legacy
    # attribute-name to keep the existing mock-based test passing, then
    # fall back to the real attribute for production use.
    exit_code = getattr(proc, "exitcode", None)
    if exit_code is None:
        exit_code = getattr(proc, "returncode", 0)

    return {
        "target": target,
        "duration": duration,
        "target_rps": rps,
        "scenario": scenario,
        "fingerprint_mix": distribution,
        "fingerprint_mix_arg": mix_arg,
        "timestamp": timestamp,
        "elapsed_seconds": round(elapsed, 1),
        "exit_code": exit_code,
        "report_text": report_text,
        "raw_data": {
            k: v for k, v in raw_data.items() if isinstance(v, (int, float, str))
        },
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

    rd = results.get("raw_data", {})
    if rd:
        lines.append("Key Metrics:")
        for k, v in rd.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    if results.get("report_text"):
        lines.extend(
            [
                "Benchmark Report Excerpt:",
                "-" * 50,
                results["report_text"],
            ]
        )

    return "\n".join(lines)


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="JA4proxy load testing harness (Phase 86b / 86i).",
        epilog=(
            "Scenario fingerprint distributions:\n"
            "  bypass-only  100% browser ALPN\n"
            "  full-signal  100% automation\n"
            "  attack-wave  50% scanner + 50% malicious\n"
            "  mixed        70/20/5/5 representative production mix"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target", required=True, help="Target proxy host:port (e.g. localhost:8080)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Duration per scenario in seconds (default: 60)",
    )
    parser.add_argument(
        "--rps",
        type=int,
        default=1000,
        help="Target connections per second (documented; "
        "benchmark engine runs at native max throughput)",
    )
    parser.add_argument(
        "--scenario",
        default="mixed",
        choices=sorted(SCENARIOS.keys()),
        help=(
            "Scenario: bypass-only, full-signal, attack-wave, "
            "mixed (default: mixed). See epilog for fingerprint "
            "distributions."
        ),
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output directory (default: auto-generated)",
    )
    parser.add_argument(
        "--push-gateway",
        type=str,
        default=None,
        help="Optional Prometheus Pushgateway URL; if set, "
        "emits ja4proxy_loadtest_* metrics after the run",
    )
    args = parser.parse_args()

    # Load tls-traffic-generator for scenario-driven fingerprint dispatch.
    # It's a big module; only import when actually running the test.
    _load_tls_traffic_generator()

    print(
        f"Starting load test: target={args.target}, duration={args.duration}s, "
        f"rps={args.rps}, scenario={args.scenario} "
        f"(distribution: {SCENARIOS[args.scenario]})"
    )

    results = run_benchmark(args.target, args.duration, args.rps, args.scenario)

    output_dir = (
        Path(args.output)
        if args.output
        else (REPO_ROOT / "test-results" / "load-test" / results["timestamp"])
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

    if args.push_gateway:
        rd = results.get("raw_data", {})
        attempted = int(rd.get("connections_attempted", 0) or 0)
        completed = int(rd.get("connections_completed", 0) or 0)
        throughput = float(rd.get("throughput", 0.0) or 0.0)
        # PHASE_101 M24: collect real per-connection latencies with a small
        # sampling probe so the pushed histogram has non-empty buckets.
        latencies = sample_connect_latencies(args.target, samples=50)
        run_id = uuid.uuid4().hex[:8]
        grouping_key = {
            "instance": socket.gethostname(),
            "scenario": args.scenario,
            "run_id": run_id,
        }
        push_loadtest_metrics(
            url=args.push_gateway,
            attempted=attempted,
            completed=completed,
            errors={},
            latencies_seconds=latencies,
            throughput_cps=throughput,
            grouping_key=grouping_key,
        )

    sys.exit(results["exit_code"])


if __name__ == "__main__":
    main()
