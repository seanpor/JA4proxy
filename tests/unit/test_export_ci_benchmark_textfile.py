"""Phase 805 — tests for scripts/export_ci_benchmark_textfile.sh.

Runs the real script as a subprocess (no mocking of curl/python3 — both are
baseline dependencies of the monitoring host it's meant to run on). Uses
file:// URLs instead of a real network fetch so the tests are hermetic and
fast; curl supports file:// natively, and the script only cares that
`curl -fsSL -o out url` behaves the same way for both schemes.
"""

from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "export_ci_benchmark_textfile.sh"

VALID_RESULT = {
    "total_good": 18000,
    "total_bad": 0,
    "errors": 0,
    "throughput_cps": 605.3,
    "p50_latency_ms": 8.0,
    "p95_latency_ms": 280.0,
    "p99_latency_ms": 305.0,
    "baseline_throughput_cps": 600.0,
    "baseline_p95_latency_ms": 290.0,
}


def _run_script(tmp_path: pathlib.Path, release_url: str) -> tuple[int, str, str, pathlib.Path]:
    textfile_dir = tmp_path / "textfile_collector"
    env = {
        "RELEASE_URL": release_url,
        "TEXTFILE_DIR": str(textfile_dir),
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }
    proc = subprocess.run(
        ["bash", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout, proc.stderr, textfile_dir / "ja4proxy_nightly_benchmark.prom"


class TestHappyPath:
    def test_writes_valid_prometheus_textfile(self, tmp_path):
        source = tmp_path / "result.json"
        source.write_text(json.dumps(VALID_RESULT))

        code, _out, err, out_file = _run_script(tmp_path, f"file://{source}")

        assert code == 0, err
        assert out_file.exists()
        content = out_file.read_text()
        assert "ja4proxy_loadtest_throughput_cps 605.3" in content
        assert "ja4proxy_loadtest_baseline_throughput_cps 600.0" in content
        assert "ja4proxy_loadtest_errors_total 0" in content
        assert "# TYPE ja4proxy_loadtest_connections_attempted_total counter" in content
        assert "# TYPE ja4proxy_loadtest_throughput_cps gauge" in content

    def test_computes_attempted_as_sum_of_good_bad_errors(self, tmp_path):
        source = tmp_path / "result.json"
        result = dict(VALID_RESULT, total_good=100, total_bad=20, errors=5)
        source.write_text(json.dumps(result))

        code, _out, err, out_file = _run_script(tmp_path, f"file://{source}")

        assert code == 0, err
        content = out_file.read_text()
        assert "ja4proxy_loadtest_connections_attempted_total 125" in content
        assert "ja4proxy_loadtest_connections_completed_total 120" in content


class TestFailOpen:
    def test_fetch_failure_leaves_existing_textfile_untouched(self, tmp_path):
        textfile_dir = tmp_path / "textfile_collector"
        textfile_dir.mkdir()
        out_file = textfile_dir / "ja4proxy_nightly_benchmark.prom"
        out_file.write_text("# stale but valid previous content\nja4proxy_loadtest_throughput_cps 999\n")

        # Nonexistent file:// path -- curl will fail to fetch it.
        code, _out, err, _ = _run_script(tmp_path, f"file://{tmp_path}/does-not-exist.json")

        assert code == 0, err  # fail open: script itself must not error
        assert out_file.read_text() == "# stale but valid previous content\nja4proxy_loadtest_throughput_cps 999\n"

    def test_malformed_json_leaves_existing_textfile_untouched(self, tmp_path):
        source = tmp_path / "result.json"
        source.write_text("{not valid json")
        textfile_dir = tmp_path / "textfile_collector"
        textfile_dir.mkdir()
        out_file = textfile_dir / "ja4proxy_nightly_benchmark.prom"
        out_file.write_text("# stale but valid previous content\n")

        code, _out, err, _ = _run_script(tmp_path, f"file://{source}")

        assert code == 0, err
        assert out_file.read_text() == "# stale but valid previous content\n"

    def test_missing_required_field_leaves_existing_textfile_untouched(self, tmp_path):
        source = tmp_path / "result.json"
        source.write_text(json.dumps({"throughput_cps": 1.0}))  # missing total_good/total_bad/errors
        textfile_dir = tmp_path / "textfile_collector"
        textfile_dir.mkdir()
        out_file = textfile_dir / "ja4proxy_nightly_benchmark.prom"
        out_file.write_text("# stale but valid previous content\n")

        code, _out, err, _ = _run_script(tmp_path, f"file://{source}")

        assert code == 0, err
        assert out_file.read_text() == "# stale but valid previous content\n"

    def test_first_run_with_no_prior_textfile_and_fetch_failure_creates_nothing(self, tmp_path):
        code, _out, err, out_file = _run_script(tmp_path, f"file://{tmp_path}/does-not-exist.json")

        assert code == 0, err
        assert not out_file.exists()


@pytest.mark.skipif(not SCRIPT.exists(), reason="script not found")
def test_script_is_executable():
    assert SCRIPT.stat().st_mode & 0o111, "export_ci_benchmark_textfile.sh must be executable (chmod +x)"
