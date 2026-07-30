"""Phase 805 — unit tests for scripts/nightly_benchmark_gate.py.

Loads the script by path (its filename has underscores, so it *is* import-
able as a module, but it's not on any package path) and exercises the pure
comparison logic with synthetic "clean" and "regressed" result fixtures --
no real benchmark run or network access needed.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "nightly_benchmark_gate.py"
REAL_BASELINE = REPO_ROOT / "docs" / "reports" / "nightly_benchmark_baseline.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("nightly_benchmark_gate", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load_module()


@pytest.fixture
def baseline() -> dict:
    return {
        "gated_metrics": {
            "throughput_cps": {"baseline": 600.0},
            "p95_latency_ms": {"baseline": 290.0},
        },
        "error_rate_gate": {"max_error_rate_percent": 1.0},
        "source": {"date": "2026-06-10", "git_sha": "76504c83", "method": "make bench-macro"},
    }


def _result(**overrides) -> dict:
    base = {
        "total_good": 18000,
        "total_bad": 0,
        "errors": 0,
        "throughput_cps": 600.0,
        "p95_latency_ms": 290.0,
        "p99_latency_ms": 310.0,
    }
    base.update(overrides)
    return base


class TestCleanRun:
    def test_exact_baseline_is_clean(self, baseline):
        assert gate.check_regression(_result(), baseline, gate_percent=20.0) == []

    def test_small_improvement_is_clean(self, baseline):
        result = _result(throughput_cps=650.0, p95_latency_ms=250.0)
        assert gate.check_regression(result, baseline, gate_percent=20.0) == []

    def test_within_gate_tolerance_is_clean(self, baseline):
        # 15% throughput drop, 15% latency rise -- inside a 20% gate.
        result = _result(throughput_cps=600.0 * 0.85, p95_latency_ms=290.0 * 1.15)
        assert gate.check_regression(result, baseline, gate_percent=20.0) == []


class TestRegression:
    def test_throughput_drop_past_gate_fails(self, baseline):
        result = _result(throughput_cps=600.0 * 0.5)  # 50% drop
        failures = gate.check_regression(result, baseline, gate_percent=20.0)
        assert len(failures) == 1
        assert "throughput_cps regressed" in failures[0]

    def test_latency_rise_past_gate_fails(self, baseline):
        result = _result(p95_latency_ms=290.0 * 2)  # 100% rise
        failures = gate.check_regression(result, baseline, gate_percent=20.0)
        assert len(failures) == 1
        assert "p95_latency_ms regressed" in failures[0]

    def test_both_metrics_regressed_reports_both(self, baseline):
        result = _result(throughput_cps=100.0, p95_latency_ms=900.0)
        failures = gate.check_regression(result, baseline, gate_percent=20.0)
        assert len(failures) == 2

    def test_high_error_rate_fails(self, baseline):
        result = _result(total_good=9900, errors=100)  # 1% of 10000
        # error_rate_gate max is 1.0%; 100/10000 = 1.0% exactly -- not over.
        assert gate.check_regression(result, baseline, gate_percent=20.0) == []
        result = _result(total_good=9800, errors=200)  # 2%
        failures = gate.check_regression(result, baseline, gate_percent=20.0)
        assert len(failures) == 1
        assert "error rate too high" in failures[0]

    def test_zero_attempted_connections_does_not_divide_by_zero(self, baseline):
        result = _result(total_good=0, total_bad=0, errors=0)
        # Should not raise; throughput/latency likely also regressed (0.0 values).
        failures = gate.check_regression(result, baseline, gate_percent=20.0)
        assert isinstance(failures, list)


class TestMainExitCode:
    def test_clean_result_exits_zero(self, tmp_path, baseline, monkeypatch, capsys):
        result_path = tmp_path / "result.json"
        baseline_path = tmp_path / "baseline.json"
        result_path.write_text(json.dumps(_result()))
        baseline_path.write_text(json.dumps(baseline))
        monkeypatch.setattr(
            "sys.argv",
            ["nightly_benchmark_gate.py", "--result", str(result_path), "--baseline", str(baseline_path)],
        )
        assert gate.main() == 0
        assert "No regression detected" in capsys.readouterr().out

    def test_regressed_result_exits_one(self, tmp_path, baseline, monkeypatch, capsys):
        result_path = tmp_path / "result.json"
        baseline_path = tmp_path / "baseline.json"
        result_path.write_text(json.dumps(_result(throughput_cps=10.0)))
        baseline_path.write_text(json.dumps(baseline))
        monkeypatch.setattr(
            "sys.argv",
            ["nightly_benchmark_gate.py", "--result", str(result_path), "--baseline", str(baseline_path)],
        )
        assert gate.main() == 1
        assert "REGRESSION DETECTED" in capsys.readouterr().out


class TestRealBaselineFile:
    def test_real_baseline_is_well_formed_and_loads(self):
        data = gate.load_json(REAL_BASELINE)
        assert data["gated_metrics"]["throughput_cps"]["baseline"] == 600.0
        assert data["gated_metrics"]["p95_latency_ms"]["baseline"] == 290.0
        assert data["error_rate_gate"]["max_error_rate_percent"] == 1.0

    def test_real_baseline_passes_against_itself(self, baseline):
        # Use the real file's own numbers as a "current" result -- must be clean.
        real = gate.load_json(REAL_BASELINE)
        result = _result(
            throughput_cps=real["gated_metrics"]["throughput_cps"]["baseline"],
            p95_latency_ms=real["gated_metrics"]["p95_latency_ms"]["baseline"],
        )
        assert gate.check_regression(result, real, gate_percent=20.0) == []
