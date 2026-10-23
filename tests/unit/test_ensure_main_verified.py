"""
tests/unit/test_ensure_main_verified.py

Phase 849 — issue #622. GitHub does not dispatch workflows for events caused by
the default `GITHUB_TOKEN`, so a PR merged by the Actions app lands on `main`
with no `push` run. This script detects that and (with `--apply`) dispatches CI.

The cases that would silently break the point of the check:

  * a **failed** run must count as verified — otherwise the verifier loops,
    dispatching CI at a commit whose CI is already red;
  * a queued/in-progress run must count — otherwise every trigger during a run
    duplicates it;
  * a run belonging to **another workflow or commit** must not count;
  * `--sha` must never dispatch — a dispatch verifies main's tip, not an old
    commit, and pretending otherwise would put a false claim in the log.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import ensure_main_verified as ensure  # noqa: E402

SHA = "a" * 40


def _run(status="completed", conclusion="success", workflow="CI", head_sha=SHA):
    return {
        "workflowName": workflow,
        "status": status,
        "conclusion": conclusion,
        "headSha": head_sha,
        "url": "https://example.invalid/run/1",
    }


# ── decide(): the whole decision surface ────────────────────────────────────


def test_no_runs_is_unverified() -> None:
    verdict = ensure.decide([], SHA)
    assert verdict["verified"] is False
    assert "no CI run" in verdict["reason"]


def test_completed_success_is_verified() -> None:
    assert ensure.decide([_run()], SHA)["verified"] is True


def test_in_progress_is_verified_so_the_dispatch_is_not_duplicated() -> None:
    assert ensure.decide([_run(status="in_progress", conclusion="")], SHA)["verified"] is True


def test_a_failed_run_still_counts_as_verified() -> None:
    """Re-dispatching a red commit would loop; the red is already visible."""
    assert ensure.decide([_run(conclusion="failure")], SHA)["verified"] is True


def test_another_workflows_run_does_not_count() -> None:
    verdict = ensure.decide([_run(workflow="PR Cascade & Auto-Merge Refresh", conclusion="")], SHA)
    assert verdict["verified"] is False


def test_a_run_for_another_commit_does_not_count() -> None:
    assert ensure.decide([_run(head_sha="b" * 40)], SHA)["verified"] is False


# ── the gh plumbing ─────────────────────────────────────────────────────────


def _fake_subprocess(monkeypatch, *, stdout="", returncode=0, stderr="") -> dict:
    captured: dict[str, list[str]] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(ensure, "subprocess", types.SimpleNamespace(run=fake_run))
    return captured


def test_runs_for_queries_by_commit(monkeypatch) -> None:
    captured = _fake_subprocess(monkeypatch, stdout=json.dumps([_run()]))
    assert ensure.runs_for(SHA)[0]["workflowName"] == "CI"
    assert captured["argv"][:3] == ["gh", "run", "list"]
    assert SHA in captured["argv"]


def test_unparseable_run_list_is_an_error_not_an_empty_list(monkeypatch) -> None:
    _fake_subprocess(monkeypatch, stdout="not json")
    with pytest.raises(RuntimeError):
        ensure.runs_for(SHA)


def test_dispatch_targets_ci_on_main(monkeypatch) -> None:
    captured = _fake_subprocess(monkeypatch, stdout="")
    ensure.dispatch()
    assert captured["argv"][:5] == ["gh", "workflow", "run", "ci.yml", "--ref"]
    assert captured["argv"][-1] == "main"


def test_dispatch_failure_raises(monkeypatch) -> None:
    _fake_subprocess(monkeypatch, returncode=1, stderr="HTTP 403")
    with pytest.raises(RuntimeError, match="403"):
        ensure.dispatch()


# ── main(): the four outcomes ───────────────────────────────────────────────


def test_verified_tip_exits_zero(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ensure, "main_tip", lambda: SHA)
    monkeypatch.setattr(ensure, "runs_for", lambda sha: [_run()])
    dispatches: list[int] = []
    monkeypatch.setattr(ensure, "dispatch", lambda *a, **k: dispatches.append(1))

    assert ensure.main([]) == 0
    assert dispatches == []
    assert "verified" in capsys.readouterr().out


def test_unverified_tip_without_apply_exits_one_and_dispatches_nothing(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ensure, "main_tip", lambda: SHA)
    monkeypatch.setattr(ensure, "runs_for", lambda sha: [])
    dispatches: list[int] = []
    monkeypatch.setattr(ensure, "dispatch", lambda *a, **k: dispatches.append(1))

    assert ensure.main([]) == 1
    assert dispatches == []
    assert "pass --apply" in capsys.readouterr().err


def test_unverified_tip_with_apply_dispatches_once(monkeypatch, capsys) -> None:
    monkeypatch.setattr(ensure, "main_tip", lambda: SHA)
    monkeypatch.setattr(ensure, "runs_for", lambda sha: [])
    dispatches: list[int] = []
    monkeypatch.setattr(ensure, "dispatch", lambda *a, **k: dispatches.append(1))

    assert ensure.main(["--apply"]) == 0
    assert dispatches == [1]
    assert "dispatched" in capsys.readouterr().out


def test_an_explicit_sha_never_dispatches_even_with_apply(monkeypatch, capsys) -> None:
    """A dispatch verifies main's tip; claiming it verified an old commit is a lie."""
    monkeypatch.setattr(ensure, "main_tip", lambda: pytest.fail("--sha must not read main"))
    monkeypatch.setattr(ensure, "runs_for", lambda sha: [])
    dispatches: list[int] = []
    monkeypatch.setattr(ensure, "dispatch", lambda *a, **k: dispatches.append(1))

    assert ensure.main(["--sha", "b" * 40, "--apply"]) == 1
    assert dispatches == []
    assert "no CI run" in capsys.readouterr().err


def test_gh_failure_exits_two(monkeypatch, capsys) -> None:
    def broken():
        raise RuntimeError("gh not authenticated")

    monkeypatch.setattr(ensure, "main_tip", broken)
    assert ensure.main([]) == 2
    assert "not authenticated" in capsys.readouterr().err
