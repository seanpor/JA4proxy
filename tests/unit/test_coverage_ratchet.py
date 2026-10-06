"""
tests/unit/test_coverage_ratchet.py
Unit tests for scripts/coverage_ratchet.py
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
RATCHET_SCRIPT = ROOT / "scripts" / "coverage_ratchet.py"


def run_ratchet(args: list[str]) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(RATCHET_SCRIPT)] + args
    return subprocess.run(cmd, capture_output=True, text=True)


def test_go_coverage_aggregation_and_max_count(tmp_path: Path):
    """Test parsing Go coverage profile with duplicate blocks and multi-package statements."""
    profile_content = """mode: atomic
github.com/seanpor/ja4proxy/internal/tls/parser.go:10.1,15.2 5 1
github.com/seanpor/ja4proxy/internal/tls/parser.go:10.1,15.2 5 0
github.com/seanpor/ja4proxy/internal/tls/parser.go:16.1,20.2 5 0
github.com/seanpor/ja4proxy/cmd/ja4pd/main.go:1.1,10.2 10 1
"""
    prof_file = tmp_path / "coverage.txt"
    prof_file.write_text(profile_content)

    base_file = tmp_path / "baseline.json"
    base_file.write_text(json.dumps({"go": {"internal/tls": 50.0, "cmd/ja4pd": 100.0}}))

    # Check should pass (internal/tls: 5/10 = 50.0%, cmd/ja4pd: 10/10 = 100.0%)
    res = run_ratchet(["check", "--lang", "go", "--profile", str(prof_file), "--baseline", str(base_file)])
    assert res.returncode == 0
    assert "OK" in res.stdout


def test_drop_below_baseline_fails(tmp_path: Path):
    """Test that a drop > 0.1 pp below baseline fails."""
    profile_content = """mode: atomic
github.com/seanpor/ja4proxy/internal/tls/parser.go:10.1,15.2 5 1
github.com/seanpor/ja4proxy/internal/tls/parser.go:16.1,25.2 15 0
"""
    prof_file = tmp_path / "coverage.txt"
    prof_file.write_text(profile_content)

    base_file = tmp_path / "baseline.json"
    # Coverage is 5/20 = 25.0%, baseline is 80.0%
    base_file.write_text(json.dumps({"go": {"internal/tls": 80.0}}))

    res = run_ratchet(["check", "--lang", "go", "--profile", str(prof_file), "--baseline", str(base_file)])
    assert res.returncode != 0
    assert "internal/tls" in res.stderr or "internal/tls" in res.stdout


def test_tolerance(tmp_path: Path):
    """Test that a drop <= 0.1 pp passes."""
    profile_content = """mode: atomic
github.com/seanpor/ja4proxy/internal/tls/parser.go:10.1,20.2 999 1
github.com/seanpor/ja4proxy/internal/tls/parser.go:21.1,22.2 1 0
"""
    prof_file = tmp_path / "coverage.txt"
    prof_file.write_text(profile_content)

    base_file = tmp_path / "baseline.json"
    # Coverage is 999/1000 = 99.9%, baseline is 99.95% (drop is 0.05 pp <= 0.1)
    base_file.write_text(json.dumps({"go": {"internal/tls": 99.95}}))

    res = run_ratchet(["check", "--lang", "go", "--profile", str(prof_file), "--baseline", str(base_file)])
    assert res.returncode == 0


def test_update_never_lowers_and_adds_new(tmp_path: Path):
    """Test that --update adds new packages and never lowers existing baseline numbers."""
    profile_content = """mode: atomic
github.com/seanpor/ja4proxy/internal/tls/parser.go:10.1,20.2 50 1
github.com/seanpor/ja4proxy/internal/tls/parser.go:21.1,30.2 50 0
github.com/seanpor/ja4proxy/internal/quic/decoder.go:1.1,10.2 10 1
"""
    prof_file = tmp_path / "coverage.txt"
    prof_file.write_text(profile_content)

    base_file = tmp_path / "baseline.json"
    # Existing baseline for internal/tls is 80.0%, current coverage is 50.0%
    base_file.write_text(json.dumps({"go": {"internal/tls": 80.0}}))

    res = run_ratchet(["update", "--lang", "go", "--profile", str(prof_file), "--baseline", str(base_file)])
    assert res.returncode == 0

    updated = json.loads(base_file.read_text())
    assert updated["go"]["internal/tls"] == 80.0  # Keeps higher baseline
    assert updated["go"]["internal/quic"] == 100.0  # Adds new package


def test_python_coverage_aggregation(tmp_path: Path):
    """Test parsing Python JSON coverage report."""
    py_json = {
        "files": {
            "management/api/main.py": {
                "summary": {"num_statements": 100, "covered_lines": 80}
            },
            "management/api/auth.py": {
                "summary": {"num_statements": 50, "covered_lines": 50}
            },
            "src/analytics/engine.py": {
                "summary": {"num_statements": 50, "covered_lines": 25}
            }
        }
    }
    prof_file = tmp_path / "coverage-python.json"
    prof_file.write_text(json.dumps(py_json))

    base_file = tmp_path / "baseline.json"
    base_file.write_text(json.dumps({"python": {"management/api": 85.0, "src/analytics": 50.0}}))

    # management/api total: (80+50)/(100+50) = 130/150 = 86.67% >= 85.0%
    # src/analytics total: 25/50 = 50.0% == 50.0%
    res = run_ratchet(["check", "--lang", "python", "--profile", str(prof_file), "--baseline", str(base_file)])
    assert res.returncode == 0
