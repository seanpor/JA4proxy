"""
tests/unit/test_dead_waivers.py

Phase 848 — dead-waiver detection on the pip surface (issue #642).

A dead waiver is an `--ignore-vuln` for a finding no audit reports any more. It
reads as harmless and is not: the ignore outlives the finding, so a regression
back into the vulnerable range is suppressed silently.

These tests are written so that reverting the fix fails them:

  * the monitor must ask pip-audit for the **full** picture (`ignorefile=None`)
    and subtract the registry's waivers in process — a revert restores the
    filtered call and `test_the_monitor_audits_without_the_ignore_flags` fails;
  * a waived id that no finding names must surface as dead — a revert leaves
    `dead` empty;
  * an alias-only match must **not** be reported dead (the case a naive
    `set - set` gets wrong);
  * the required gates must keep their ignore flags — pinned both ways.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import render_waivers  # noqa: E402
import scan_baseline  # noqa: E402
import scan_baseline_monitor as monitor  # noqa: E402


def _deps(*vulns: tuple[str, list[str]]) -> list[dict]:
    """A pip-audit `dependencies` payload with one vulnerable dependency."""
    return [
        {
            "name": "mcp",
            "version": "1.29.0",
            "vulns": [
                {"id": vid, "aliases": aliases, "fix_versions": ["1.30.0"]}
                for vid, aliases in vulns
            ],
        }
    ]


# ── split_waived (the core decision) ────────────────────────────────────────


def test_waived_and_present_is_waived_not_dead() -> None:
    findings = scan_baseline.pypi_findings(_deps(("CVE-1", [])))
    unwaived, dead = scan_baseline.split_waived(findings, ["CVE-1"])
    assert unwaived == {}
    assert dead == []


def test_waived_and_absent_is_dead() -> None:
    """The whole point: an ignore that matches nothing is a live suppression."""
    findings = scan_baseline.pypi_findings(_deps(("CVE-1", [])))
    unwaived, dead = scan_baseline.split_waived(findings, ["CVE-1", "CVE-GONE"])
    assert dead == ["CVE-GONE"]


def test_unwaived_finding_stays_unwaived() -> None:
    findings = scan_baseline.pypi_findings(_deps(("CVE-1", [])))
    unwaived, dead = scan_baseline.split_waived(findings, [])
    assert list(unwaived) == ["CVE-1"]
    assert dead == []


def test_alias_only_match_is_live_not_dead() -> None:
    """A waiver naming a GHSA alias for a CVE-reporting finding is correct."""
    findings = scan_baseline.pypi_findings(_deps(("CVE-1", ["GHSA-aaaa-bbbb-cccc"])))
    aliases = scan_baseline.pypi_alias_map(_deps(("CVE-1", ["GHSA-aaaa-bbbb-cccc"])))
    unwaived, dead = scan_baseline.split_waived(findings, ["GHSA-aaaa-bbbb-cccc"], aliases)
    assert unwaived == {}, "an alias-waived finding must not be filed as unwaived"
    assert dead == [], "an alias-waived finding must not be called a dead waiver"


# ── the ignore file is read, never hard-coded ───────────────────────────────


def test_waived_ids_are_the_registry_pip_ids() -> None:
    """Reads the real generated file: a hard-coded list in the script fails here."""
    registry = render_waivers.load_registry()
    expected = {
        str(w["id"]) for w in registry["waivers"] if w.get("source") == "pip-audit"
    }
    assert set(scan_baseline.waived_pip_ids()) == expected


def test_ignore_parser_accepts_both_flag_spellings(tmp_path) -> None:
    path = tmp_path / "ignores"
    path.write_text("# header\n--ignore-vuln CVE-1\n--ignore-vuln=PYSEC-2\n", encoding="utf-8")
    assert scan_baseline.waived_pip_ids(str(path)) == ["CVE-1", "PYSEC-2"]
    assert scan_baseline.ignore_vuln_args(str(path)) == [
        "--ignore-vuln", "CVE-1", "--ignore-vuln", "PYSEC-2",
    ]


def test_ignore_parser_refuses_junk(tmp_path) -> None:
    """A waiver the parser cannot see is one the dead-entry check cannot see."""
    path = tmp_path / "ignores"
    path.write_text("--ignore-vuln\n", encoding="utf-8")
    with pytest.raises(scan_baseline.BaselineError):
        scan_baseline.waived_pip_ids(str(path))


# ── the required gate is untouched ──────────────────────────────────────────


def test_the_required_gate_still_applies_the_ignores() -> None:
    assert "--ignore-vuln" in scan_baseline.pip_audit_cmd()


def test_the_monitor_audits_without_the_ignore_flags(monkeypatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return types.SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"dependencies": _deps(("CVE-1", []))}),
            stderr="",
        )

    monkeypatch.setattr(scan_baseline, "subprocess", types.SimpleNamespace(run=fake_run))
    deps = scan_baseline.run_pip_audit(ignorefile=None)

    assert "--ignore-vuln" not in captured["argv"], (
        "the measurement audit must see every finding, or a waived id is filtered "
        "before it can be compared"
    )
    assert [d["name"] for d in deps] == ["mcp"]


# ── the monitor wires it end to end ─────────────────────────────────────────


def _wire_scan(monkeypatch, deps, waived, failures=()):
    monkeypatch.setattr(monitor, "third_party_image_refs", lambda paths: [])
    monkeypatch.setattr(monitor, "scan_gate_compose_paths", lambda: [])
    monkeypatch.setattr(monitor, "scan_image", lambda ref, first_party, cache, severities=None: ([], None))
    monkeypatch.setattr(monitor, "run_pip_audit", lambda ignorefile=None: deps)
    monkeypatch.setattr(monitor, "waived_pip_ids", lambda ignorefile=".pip-audit-ignores": list(waived))


def test_scan_surfaces_reports_the_dead_waiver_and_suppresses_the_live_one(monkeypatch) -> None:
    _wire_scan(
        monkeypatch,
        _deps(("CVE-LIVE", []), ("CVE-OPEN", [])),
        ["CVE-LIVE", "CVE-GONE"],
    )

    current, medium, failures, dead = monitor.scan_surfaces([], "/tmp/cache")

    assert failures == []
    assert list(current["pypi"]["findings"]) == ["CVE-OPEN"], (
        "the live waiver must still suppress its finding, exactly as pip-audit's "
        "--ignore-vuln did before"
    )
    assert dead == ["CVE-GONE"]


def test_a_failed_audit_is_a_failure_not_a_dead_waiver(monkeypatch) -> None:
    """Never-turn-a-broken-scan-into-findings-or-clean: it must stay a failure."""
    monkeypatch.setattr(monitor, "third_party_image_refs", lambda paths: [])
    monkeypatch.setattr(monitor, "scan_gate_compose_paths", lambda: [])
    monkeypatch.setattr(monitor, "scan_image", lambda ref, first_party, cache, severities=None: ([], None))

    def unreachable(ignorefile=None):
        raise RuntimeError("OSV unreachable")

    monkeypatch.setattr(monitor, "run_pip_audit", unreachable)

    current, medium, failures, dead = monitor.scan_surfaces([], "/tmp/cache")
    assert "pypi" not in current
    assert failures and "OSV unreachable" in failures[0]
    assert dead == []


def test_report_names_the_dead_waiver_and_the_command_that_removes_it() -> None:
    report = monitor.render_report({}, {"appeared": {}, "cleared": {}, "retagged": {}}, [], [], None, ["CVE-GONE"])
    assert "Dead pip waivers" in report
    assert "`CVE-GONE`" in report
    assert "render_waivers.py --drop CVE-GONE" in report


def test_report_omits_the_section_when_not_measuring() -> None:
    """`dead=None` means "not measured" — never a false all-clear."""
    report = monitor.render_report({}, {"appeared": {}, "cleared": {}, "retagged": {}}, [], [])
    assert "Dead pip waivers" not in report


# ── issue planning: one per id, reopen, and close the resolved ──────────────


def test_plan_files_one_issue_per_dead_waiver() -> None:
    planned = monitor.plan_dead_waiver_issues(["CVE-A", "CVE-B"], {})
    assert [p["title"] for p in planned] == ["[cve-waiver] CVE-A", "[cve-waiver] CVE-B"]
    assert all("reopen" not in p for p in planned)


def test_plan_does_not_re_file_an_open_dead_waiver() -> None:
    known = {"[cve-waiver] CVE-A": {"number": 7, "state": "OPEN"}}
    assert monitor.plan_dead_waiver_issues(["CVE-A"], known) == []


def test_plan_reopens_a_closed_dead_waiver() -> None:
    known = {"[cve-waiver] CVE-A": {"number": 7, "state": "CLOSED"}}
    assert monitor.plan_dead_waiver_issues(["CVE-A"], known) == [
        {"cve": "CVE-A", "title": "[cve-waiver] CVE-A", "reopen": 7}
    ]


def test_a_resolved_dead_waiver_closes_its_own_issue() -> None:
    known = {
        "[cve-waiver] CVE-GONE": {"number": 9, "state": "OPEN"},
        "[cve-waiver] CVE-STILL": {"number": 10, "state": "OPEN"},
    }
    assert monitor.plan_waiver_closures(["CVE-STILL"], known) == [
        {"number": 9, "cve": "CVE-GONE"}
    ]


def test_closures_leave_finding_issues_alone() -> None:
    """Only `[cve-waiver]` issues are this loop's to close."""
    known = {"[cve-baseline] CVE-1 image:redis": {"number": 3, "state": "OPEN"}}
    assert monitor.plan_waiver_closures([], known) == []


def test_apply_files_the_dead_waiver_and_closes_the_resolved_one(monkeypatch, capsys) -> None:
    monkeypatch.setattr(monitor, "third_party_image_refs", lambda paths: [])
    monkeypatch.setattr(monitor, "scan_gate_compose_paths", lambda: [])
    monkeypatch.setattr(monitor, "scan_surfaces", lambda refs, cache: ({}, {}, [], ["CVE-DEAD"]))
    monkeypatch.setattr(monitor, "issues_by_title", lambda: {
        "[cve-waiver] CVE-GONE": {"number": 9, "state": "OPEN"},
    })
    created: list[str] = []
    closed: list[int] = []
    monkeypatch.setattr(monitor, "create_issue", lambda title, body: created.append(title) or "url")
    monkeypatch.setattr(monitor, "close_issue", lambda number, body: closed.append(number) or "#9 (closed)")

    def no_baseline(path=None):
        raise monitor.BaselineError("no baseline in this test")

    monkeypatch.setattr(monitor, "load_baseline", no_baseline)

    assert monitor.main(["--apply"]) == 0
    assert created == ["[cve-waiver] CVE-DEAD"]
    assert closed == [9]
    out = capsys.readouterr().out
    assert "dead waiver" in out


# ── the remediation path: render_waivers --drop ─────────────────────────────


def _write_registry(path: Path, *ids: str) -> str:
    value = sorted(render_waivers.REACHABILITY_VALUES - render_waivers.ATTESTED_VALUES)[0]
    blocks = "".join(
        f"""  - id: {wid}
    scope: third-party
    severity: HIGH
    source: pip-audit
    reachability: {value}
    carriers: ["mcp"]
    rationale: dead on purpose
    created: 2026-10-01
    expires: 2026-12-30
"""
        for wid in ids
    )
    path.write_text(
        "version: 1\n"
        "policy:\n"
        "  max_window_days: 90\n"
        "  default_owner: security-oncall\n"
        "waivers:\n"
        "  # --- pip-audit ---\n" + blocks,
        encoding="utf-8",
    )
    return value


@pytest.fixture()
def isolated_registry(tmp_path, monkeypatch):
    reg = tmp_path / "waivers.yaml"
    _write_registry(reg, "CVE-2026-99999")
    monkeypatch.setattr(render_waivers, "REGISTRY", reg)
    monkeypatch.setattr(render_waivers, "THIRD_PARTY_IGNORE", tmp_path / ".trivyignore.third-party")
    monkeypatch.setattr(render_waivers, "FIRST_PARTY_IGNORE", tmp_path / ".trivyignore.first-party")
    monkeypatch.setattr(render_waivers, "PIP_AUDIT_IGNORES", tmp_path / ".pip-audit-ignores")
    return reg


def test_drop_removes_the_dead_waiver_and_regenerates_the_derived_files(
    isolated_registry, capsys
) -> None:
    assert render_waivers.main(["--registry", str(isolated_registry), "--drop", "CVE-2026-99999"]) == 0

    assert "CVE-2026-99999" not in isolated_registry.read_text(encoding="utf-8")
    assert "--ignore-vuln" not in render_waivers.PIP_AUDIT_IGNORES.read_text(encoding="utf-8")
    assert "Dropped 1 waiver" in capsys.readouterr().out


def test_drop_refuses_an_unknown_id_and_leaves_the_registry_alone(
    isolated_registry, capsys
) -> None:
    before = isolated_registry.read_text(encoding="utf-8")
    assert render_waivers.main(["--registry", str(isolated_registry), "--drop", "CVE-2026-00000"]) == 2
    assert isolated_registry.read_text(encoding="utf-8") == before
    assert "no registry entry" in capsys.readouterr().err
