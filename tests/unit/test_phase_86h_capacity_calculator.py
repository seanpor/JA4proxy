"""Phase 86h — guard tests for capacity calculator honesty fix (Bug 3).

The calculator currently hardcodes `BenchmarkConstants` with numbers labelled
"sourced from docs/performance/benchmarks.md", but that file contains only
`_(measure)_` placeholders. Phase 86h makes the calculator loud about the
fact that the numbers are engineering estimates, not measurements.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
CALCULATOR = REPO_ROOT / "scripts" / "capacity_calculator.py"
REAL_BENCHMARKS = REPO_ROOT / "docs" / "performance" / "benchmarks.md"


BASE_ARGS = [
    "--peak-connections-per-second", "1000",
    "--p99-latency-budget-ms", "10",
    "--redis-node-count", "3",
    "--cloud-provider", "aws",
    "--region", "us-east-1",
]


def _run_calculator(*extra: str, env_benchmarks: Path | None = None,
                    cwd: Path | None = None) -> subprocess.CompletedProcess:
    assert CALCULATOR.exists(), f"{CALCULATOR} missing"
    import os
    env = os.environ.copy()
    if env_benchmarks is not None:
        env["JA4PROXY_BENCHMARKS_PATH"] = str(env_benchmarks)
    return subprocess.run(
        [sys.executable, str(CALCULATOR), *BASE_ARGS, *extra],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd else None,
    )


PLACEHOLDER_BENCHMARKS = """\
# JA4proxy Performance Benchmarks

## Go Proxy Benchmarks

### BYPASS PATH (h2/h1 ALPN → immediate allow)

| Metric | Value |
|--------|-------|
| Throughput | _(measure)_ conn/s |
| P50 latency | _(measure)_ ms |
| P99 latency | _(measure)_ ms |

### FULL SIGNAL PATH (all signal modules, Redis reads)

| Metric | Value |
|--------|-------|
| Throughput | _(measure)_ conn/s |
| P50 latency | _(measure)_ ms |
| P99 latency | _(measure)_ ms |
"""


REAL_NUMBERS_BENCHMARKS = """\
# JA4proxy Performance Benchmarks

## Go Proxy Benchmarks

> Run date: 2026-04-11
> Git SHA: deadbeef

### BYPASS PATH (h2/h1 ALPN → immediate allow)

| Metric | Value |
|--------|-------|
| Throughput | 18400 conn/s |
| P50 latency | 0.2 ms |
| P99 latency | 0.4 ms |

### FULL SIGNAL PATH (all signal modules, Redis reads)

| Metric | Value |
|--------|-------|
| Throughput | 6200 conn/s |
| P50 latency | 1.1 ms |
| P99 latency | 2.1 ms |
"""


def _write_benchmarks(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "docs" / "performance"
    p.mkdir(parents=True)
    target = p / "benchmarks.md"
    target.write_text(text)
    return target


# ---------------------------------------------------------------------------
# Placeholders present → warning + banner, but calculator still runs
# ---------------------------------------------------------------------------

def test_warning_printed_when_benchmarks_contain_placeholders(tmp_path: Path):
    bench = _write_benchmarks(tmp_path, PLACEHOLDER_BENCHMARKS)
    result = _run_calculator(env_benchmarks=bench)
    combined = (result.stderr + "\n" + result.stdout).lower()
    assert "estimated" in combined or "not measured" in combined, (
        "Calculator must print a warning mentioning ESTIMATED / NOT MEASURED "
        f"when benchmarks.md contains placeholders. stderr={result.stderr!r}"
    )
    assert "estimated" in result.stderr.lower() or "not measured" in result.stderr.lower(), (
        f"Warning must go to stderr. stderr={result.stderr!r}"
    )


def test_report_contains_estimated_banner_when_placeholders_present(tmp_path: Path):
    bench = _write_benchmarks(tmp_path, PLACEHOLDER_BENCHMARKS)
    result = _run_calculator(env_benchmarks=bench)
    assert "ESTIMATED — NOT MEASURED" in result.stdout, (
        "Report header must contain 'ESTIMATED — NOT MEASURED' banner when "
        f"placeholders are present. stdout={result.stdout!r}"
    )


def test_calculator_still_runs_without_flag_when_placeholders_present(tmp_path: Path):
    """Regression: the report must still be produced, just loudly."""
    bench = _write_benchmarks(tmp_path, PLACEHOLDER_BENCHMARKS)
    result = _run_calculator(env_benchmarks=bench)
    assert result.returncode == 0, (
        "Calculator must still exit 0 with placeholders when --require-measured "
        f"is NOT passed. stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # Some sizing output expected
    assert result.stdout.strip(), "Report should not be empty"


# ---------------------------------------------------------------------------
# --require-measured flag
# ---------------------------------------------------------------------------

def test_require_measured_flag_errors_on_placeholders(tmp_path: Path):
    bench = _write_benchmarks(tmp_path, PLACEHOLDER_BENCHMARKS)
    result = _run_calculator("--require-measured", env_benchmarks=bench)
    assert result.returncode != 0, (
        "--require-measured must exit non-zero when benchmarks.md has placeholders. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    combined = (result.stderr + result.stdout).lower()
    assert "make bench" in combined or "benchmark" in combined, (
        "Error message must point the operator at running the benchmark suite. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_require_measured_flag_succeeds_on_real_numbers(tmp_path: Path):
    bench = _write_benchmarks(tmp_path, REAL_NUMBERS_BENCHMARKS)
    result = _run_calculator("--require-measured", env_benchmarks=bench)
    assert result.returncode == 0, (
        "--require-measured must exit 0 when benchmarks.md has real numbers. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # Should NOT include the estimated banner
    assert "ESTIMATED — NOT MEASURED" not in result.stdout, (
        "Report must NOT contain the ESTIMATED banner when benchmarks are real. "
        f"stdout={result.stdout!r}"
    )
