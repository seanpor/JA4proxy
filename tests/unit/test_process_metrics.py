"""Unit tests for ``scripts/process_metrics.py``.

All tests use fixtures and ``unittest.mock`` to avoid network I/O. The on-disk
fixture under ``tests/fixtures/process_metrics/`` provides a deterministic
manifest covering both in-window and out-of-window completed phases.
"""

from __future__ import annotations

import datetime as _dt
import importlib.util
import io
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "process_metrics.py"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "process_metrics"


def _load_script():
    """Import scripts/process_metrics.py as a module."""
    spec = importlib.util.spec_from_file_location("process_metrics_mod", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def metrics_mod():
    return _load_script()


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_phase_throughput_from_manifest_fixture(metrics_mod) -> None:
    manifest = metrics_mod.load_manifest(FIXTURE_DIR / "manifest.yaml")
    # Reference date: 2026-04-24. Three completions in the trailing 90 days.
    today = _dt.date(2026, 4, 24)
    n = metrics_mod.phase_throughput(manifest, window_days=90, today=today)
    assert n == 3


def test_average_phase_duration_calculated(metrics_mod) -> None:
    manifest = metrics_mod.load_manifest(FIXTURE_DIR / "manifest.yaml")
    avg = metrics_mod.average_phase_duration_days(manifest)
    # Phase 900: 14 days, 901: 40 days, 902: 86 days, 903: 44 days
    # Mean = (14 + 40 + 86 + 44) / 4 = 46.0
    assert avg is not None
    assert abs(avg - 46.0) < 0.01


def test_ci_reliability_with_mocked_api(metrics_mod) -> None:
    fake_runs = {
        "workflow_runs": [
            {
                "conclusion": "success",
                "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "run_started_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            },
            {
                "conclusion": "failure",
                "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "run_started_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            },
            {
                "conclusion": "success",
                "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "run_started_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            },
            {
                "conclusion": "success",
                "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "run_started_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            },
        ]
    }

    fake_resp = mock.MagicMock()
    fake_resp.read.return_value = json.dumps(fake_runs).encode("utf-8")
    fake_resp.__enter__.return_value = fake_resp
    fake_resp.__exit__.return_value = False

    with mock.patch.object(
        metrics_mod.urllib.request, "urlopen", return_value=fake_resp
    ):
        ci, warn = metrics_mod.gather_ci_metrics(repo="test/repo", token="fake-token")

    assert warn is None
    assert ci is not None
    assert ci.total_runs == 4
    assert ci.green_runs == 3
    assert abs(ci.reliability_pct - 75.0) < 0.01


def test_graceful_degradation_no_github_token(
    metrics_mod, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    output = tmp_path / "metrics.md"
    rc = metrics_mod.main(
        [
            "--manifest",
            str(FIXTURE_DIR / "manifest.yaml"),
            "--output",
            str(output),
        ]
    )
    assert rc == 0
    text = output.read_text(encoding="utf-8")
    assert "GITHUB_TOKEN" in text
    # Warning emoji or "unavailable" must appear
    assert "unavailable" in text.lower()


def test_graceful_degradation_on_rate_limit(
    metrics_mod, tmp_path: Path, monkeypatch
) -> None:
    import urllib.error

    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")

    # Build a 403 with X-RateLimit-Remaining: 0
    fake_err = urllib.error.HTTPError(
        url="https://api.github.com/x",
        code=403,
        msg="rate limited",
        hdrs={"X-RateLimit-Remaining": "0"},  # type: ignore[arg-type]
        fp=io.BytesIO(b""),
    )

    def _raise(*args, **kwargs):
        raise fake_err

    output = tmp_path / "metrics.md"
    with mock.patch.object(metrics_mod.urllib.request, "urlopen", side_effect=_raise):
        rc = metrics_mod.main(
            [
                "--manifest",
                str(FIXTURE_DIR / "manifest.yaml"),
                "--output",
                str(output),
                "--repo",
                "test/repo",
            ]
        )
    assert rc == 0
    text = output.read_text(encoding="utf-8")
    assert "rate" in text.lower() or "unavailable" in text.lower()
    assert "⚠️" in text or "warning" in text.lower() or "unavailable" in text.lower()
