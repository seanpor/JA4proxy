"""Tests for PHASE_101k: Capacity hardening.

H14 — Delete estimated banner dead code from capacity_calculator.py
"""

import subprocess
import sys


def test_estimated_banner_deleted():
    """_ESTIMATED_BANNER constant should not exist in capacity_calculator.py."""
    with open("scripts/capacity_calculator.py") as f:
        content = f.read()

    assert "_ESTIMATED_BANNER" not in content, "Dead code _ESTIMATED_BANNER should be deleted"
    assert "_print_estimated_warning" not in content, "Dead code _print_estimated_warning should be deleted"
    assert "report.estimated =" not in content, "Dead code report.estimated = should be deleted"


def test_require_measured_exits_zero():
    """--require-measured exits 0 when no placeholders present."""
    result = subprocess.run(
        [
            sys.executable,
            "scripts/capacity_calculator.py",
            "--require-measured",
            "--peak-connections-per-second",
            "1000",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"--require-measured should exit 0, got {result.returncode}: {result.stderr}"


def test_require_measured_exits_nonzero_on_placeholders(tmp_path):
    """--require-measured exits non-zero when placeholders present."""
    import shutil
    from pathlib import Path

    bench_file = tmp_path / "benchmarks.md"
    shutil.copy("docs/performance/benchmarks.md", bench_file)

    with open(bench_file, "a") as f:
        f.write("\n# _(PLACEHOLDER)_ test\n")

    result = subprocess.run(
        [
            sys.executable,
            "scripts/capacity_calculator.py",
            "--require-measured",
            "--bench",
            str(bench_file),
            "--peak-connections-per-second",
            "1000",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, "--require-measured should exit non-zero on placeholders"
