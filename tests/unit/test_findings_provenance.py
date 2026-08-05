"""Unit tests for the `found_against` provenance rule (Phase 814a).

PROGRAMME.md §13: every finding records the build it was found against.
Without it a retest cannot distinguish "we fixed it" from "it no longer
reproduces for an unrelated reason" — the two are indistinguishable in a
register, and one of them is a live vulnerability.

The rule is date-gated: findings discovered before the pentest range existed
are grandfathered rather than back-filled with guesses. These tests pin both
halves, because a rule that silently never fires is worse than no rule.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "findings_register", ROOT / "scripts" / "findings_register.py"
)
assert _spec and _spec.loader
fr = importlib.util.module_from_spec(_spec)
sys.modules["findings_register"] = fr
_spec.loader.exec_module(fr)


def _finding(**overrides) -> dict:
    """A minimally valid finding; overrides layer on top."""
    base = {
        "id": "JA4PROXY-2026-0500",
        "title": "Test finding",
        "severity": "HIGH",
        "severity_rationale": "H-3",
        "lane": "go-proxy",
        "owner": "@seanpor",
        "source_refs": [{"report": "PHASE_814d", "id": "814d-01", "discovered": "2026-08-06"}],
        "remediation_phases": [],
        "discovered": "2026-08-06",
        "due": "2026-09-05",  # HIGH = discovered + 30d
        "status": "OPEN",
        "supersedes": [],
        "depends_on": [],
        "regression_test": None,
        "notes": "",
    }
    base.update(overrides)
    return base


def _validate(
    tmp_path: Path,
    findings: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> str:
    """Run the register validator over a scratch register, return its output.

    Uses pytest's own `capsys` rather than contextlib.redirect_stdout: swapping
    sys.stdout underneath pytest fights its capture machinery and swallows
    tracebacks, which cost a debugging cycle here.
    """
    path = tmp_path / "findings.yaml"
    path.write_text(
        yaml.safe_dump({"schema_version": 1, "last_allocated_id": 500, "findings": findings})
    )

    # NOTE: patching fr.REGISTER_PATH is NOT enough, and failing to notice that
    # would make every test here pass vacuously against the real register.
    # `Register.load(path: Path = REGISTER_PATH)` binds its default at function
    # definition time, so rebinding the module attribute afterwards has no
    # effect. Patch the loader itself.
    real_load = fr.Register.load
    monkeypatch.setattr(
        fr.Register, "load", staticmethod(lambda *_a, **_kw: real_load(path))
    )

    fr.cmd_validate(argparse.Namespace())
    captured = capsys.readouterr()
    # cmd_validate writes its ERRORS to stderr and only its success line to
    # stdout, so reading .out alone silently returns "" for every failing case
    # -- which looks exactly like "the rule did not fire". Read both.
    return captured.out + captured.err


def test_new_finding_without_provenance_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The rule must actually fire — this is the failing half of the proof."""
    out = _validate(tmp_path, [_finding()], monkeypatch, capsys)
    assert "found_against" in out, f"expected a provenance error, got:\n{out}"


def test_new_finding_with_provenance_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _validate(
        tmp_path,
        [_finding(found_against={"git_sha": "40817695ba", "config_sha256": "266a8c65"})],
        monkeypatch,
        capsys,
    )
    assert "found_against" not in out, f"valid provenance should pass, got:\n{out}"


def test_historical_finding_is_grandfathered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The 94 findings that predate the range must not be retro-flagged.

    Back-filling them would mean inventing build identifiers, which is worse
    than an honest gap.
    """
    out = _validate(
        tmp_path,
        [
            _finding(
                discovered="2026-04-16",
                due="2026-05-16",
                source_refs=[
                    {"report": "LEADER_PENTEST", "id": "L1-018", "discovered": "2026-04-16"}
                ],
            )
        ],
        monkeypatch,
        capsys,
    )
    assert "found_against" not in out, f"pre-range finding should be exempt, got:\n{out}"


def test_provenance_must_be_a_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    out = _validate(tmp_path, [_finding(found_against="abc123")], monkeypatch, capsys)
    assert "must be a mapping" in out


def test_provenance_requires_git_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A provenance block without a commit identifies nothing."""
    out = _validate(
        tmp_path, [_finding(found_against={"config_sha256": "abc"})], monkeypatch, capsys
    )
    assert "git_sha is required" in out


def test_cutoff_is_not_quietly_moveable() -> None:
    """Guard the frozen baseline.

    Moving the cutoff forward would silently exempt new findings — the exact
    way a rule like this dies. If this date genuinely needs to change, that is
    a decision to argue for in review, not a one-character edit.
    """
    assert fr.PROVENANCE_REQUIRED_FROM.isoformat() == "2026-08-05"


def test_real_register_still_validates() -> None:
    """The shipped register must stay green — all 94 predate the cutoff."""
    assert fr.cmd_validate(argparse.Namespace()) == 0
