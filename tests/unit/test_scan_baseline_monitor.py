"""
tests/unit/test_scan_baseline_monitor.py

Unit tests for the scheduled baseline monitor — Phase 847c.

The monitor is the half of the split that is allowed to be noisy, so the two
things that must not break are:

  * **deduplication** — a daily run must not re-file the same finding, or the
    tracker becomes the new reason to stop reading it;
  * **the drift diff** — "what appeared since the baseline" is the fact that
    used to redden every unrelated PR, and it now has exactly one place to land.

Issue creation itself is an external side effect and is not exercised here;
`--apply` is the only path that touches `gh`, and it is opt-in.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import scan_baseline_monitor as monitor  # noqa: E402


def _proc(returncode=0, stdout="", stderr=""):
    """A stand-in for subprocess.CompletedProcess."""
    return type("P", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()


def _entry(*cves, digest=None, fix=""):
    entry: dict = {
        "findings": {
            cve: {"severity": "HIGH", "package": "pkg", "installed": "1.0", "fixed": fix}
            for cve in cves
        }
    }
    if digest:
        entry["digest"] = digest
    return entry


def _baseline(**surfaces):
    return {"version": 1, "recorded_at": "t", "surfaces": surfaces}


class TestIssueIdentity:
    def test_title_is_stable_and_greppable(self):
        assert monitor.issue_title("image:redis", "CVE-2026-1") == "[cve-baseline] CVE-2026-1 image:redis"

    def test_body_names_the_fix(self):
        body = monitor.issue_body(
            "image:redis", "CVE-2026-1", {"severity": "HIGH", "package": "redis", "installed": "7.0", "fixed": "7.4.11"}
        )
        assert "7.4.11" in body
        assert "security/waivers.yaml" in body

    def test_body_says_when_there_is_no_fix(self):
        body = monitor.issue_body(
            "image:redis", "CVE-2026-1", {"severity": "HIGH", "package": "redis", "installed": "7.0", "fixed": ""}
        )
        assert "none published" in body


class TestDeduplication:
    def test_open_issue_is_not_refiled(self):
        current = {"image:redis": _entry("CVE-1")}
        title = monitor.issue_title("image:redis", "CVE-1")
        assert monitor.plan_issues(current, {title: {"number": 7, "state": "OPEN"}}) == []

    def test_missing_title_is_planned(self):
        current = {"image:redis": _entry("CVE-1")}
        planned = monitor.plan_issues(current, {})
        assert [p["cve"] for p in planned] == ["CVE-1"]
        assert "reopen" not in planned[0]

    def test_closed_issue_is_reopened_not_duplicated(self):
        """One issue per finding, forever: a closed one comes back, not a twin.

        Filtering to open issues only (the obvious implementation) re-files every
        finding whose issue a human closed, once per run — a daily duplicate
        flood, which is the plan's named adoption risk. Nothing is filed either
        if it went silent.
        """
        current = {"image:redis": _entry("CVE-1")}
        title = monitor.issue_title("image:redis", "CVE-1")
        planned = monitor.plan_issues(current, {title: {"number": 7, "state": "CLOSED"}})
        assert len(planned) == 1
        assert planned[0]["reopen"] == 7

    def test_critical_sorts_before_high(self):
        current = {
            "image:a": {
                "findings": {
                    "CVE-HIGH": {"severity": "HIGH", "package": "p", "installed": "1", "fixed": ""},
                    "CVE-CRIT": {"severity": "CRITICAL", "package": "p", "installed": "1", "fixed": ""},
                }
            }
        }
        assert [p["cve"] for p in monitor.plan_issues(current, {})] == ["CVE-CRIT", "CVE-HIGH"]

    def test_planning_is_deterministic(self):
        current = {"image:b": _entry("CVE-2"), "image:a": _entry("CVE-1")}
        assert monitor.plan_issues(current, {}) == monitor.plan_issues(current, {})


class TestFixableQueue:
    def test_only_findings_with_a_fix(self):
        current = {"image:redis": {"findings": {
            "CVE-1": {"severity": "HIGH", "package": "p", "installed": "1", "fixed": "2.0"},
            "CVE-2": {"severity": "HIGH", "package": "p", "installed": "1", "fixed": ""},
        }}}
        queue = monitor.fixable_queue(current)
        assert [(q["cve"], q["fix"]) for q in queue] == [("CVE-1", "2.0")]

    def test_empty_when_nothing_is_fixable(self):
        assert monitor.fixable_queue({"image:redis": _entry("CVE-1")}) == []


class TestDrift:
    def test_appeared(self):
        baseline = _baseline(**{"image:redis": {"findings": {"CVE-1": {}}}})
        current = {"image:redis": _entry("CVE-1", "CVE-2")}
        assert monitor.drift(baseline, current)["appeared"] == {"image:redis": ["CVE-2"]}

    def test_unrecorded_surface_is_all_new(self):
        baseline = _baseline()
        current = {"image:new": _entry("CVE-1")}
        assert monitor.drift(baseline, current)["appeared"] == {"image:new": ["CVE-1"]}

    def test_cleared(self):
        baseline = _baseline(**{"image:redis": {"findings": {"CVE-1": {}, "CVE-2": {}}}})
        current = {"image:redis": _entry("CVE-1")}
        assert monitor.drift(baseline, current)["cleared"] == {"image:redis": ["CVE-2"]}

    def test_retagged_digest(self):
        baseline = _baseline(**{"image:redis": {"digest": "sha256:old", "findings": {"CVE-1": {}}}})
        current = {"image:redis": _entry("CVE-1", digest="sha256:new")}
        assert monitor.drift(baseline, current)["retagged"] == {
            "image:redis": {"was": "sha256:old", "now": "sha256:new"}
        }

    def test_nothing_changed_is_empty(self):
        baseline = _baseline(**{"image:redis": {"digest": "sha256:x", "findings": {"CVE-1": {}}}})
        current = {"image:redis": _entry("CVE-1", digest="sha256:x")}
        assert monitor.drift(baseline, current) == {"appeared": {}, "cleared": {}, "retagged": {}}


class TestReport:
    def test_counts_and_steady_state(self):
        report = monitor.render_report({"image:redis": _entry()}, {"appeared": {}, "cleared": {}, "retagged": {}}, [], [])
        assert "**0**" in report
        assert "steady state" in report

    def test_lists_appeared_findings(self):
        drift = {"appeared": {"image:redis": ["CVE-9"]}, "cleared": {}, "retagged": {}}
        report = monitor.render_report({"image:redis": _entry("CVE-9")}, drift, [], [])
        assert "CVE-9" in report
        assert "appeared since the baseline" in report


class TestGitHubCalls:
    """`gh` is the only side effect; it must be loud on failure and idempotent."""

    def test_issues_by_title_reads_every_state_not_just_open(self, monkeypatch):
        calls: list[list[str]] = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return _proc(stdout=json.dumps([{"number": 3, "title": "t", "state": "CLOSED"}]))

        monkeypatch.setattr(monitor.subprocess, "run", fake_run)
        assert monitor.issues_by_title() == {"t": {"number": 3, "state": "CLOSED"}}
        # `--state open` would re-file every finding a human had closed.
        assert calls[0][:3] == ["gh", "issue", "list"]
        assert "all" in calls[0]

    def test_issues_by_title_fails_loudly(self, monkeypatch):
        monkeypatch.setattr(monitor.subprocess, "run", lambda *a, **k: _proc(1, stderr="gh is missing"))
        with pytest.raises(RuntimeError, match="gh is missing"):
            monitor.issues_by_title()

    def test_reopen_reopens_then_comments(self, monkeypatch):
        seen: list[list[str]] = []
        monkeypatch.setattr(monitor.subprocess, "run", lambda argv, **k: (seen.append(argv), _proc())[1])

        assert "7" in monitor.reopen_issue(7, "the evidence")

        assert seen[0][:3] == ["gh", "issue", "reopen"]
        assert seen[1][:3] == ["gh", "issue", "comment"]
        assert "the evidence" in seen[1]

    def test_reopen_failure_is_not_swallowed(self, monkeypatch):
        monkeypatch.setattr(monitor.subprocess, "run", lambda *a, **k: _proc(1, stderr="denied"))
        with pytest.raises(RuntimeError, match="denied"):
            monitor.reopen_issue(7, "body")


class TestScannedSurfaces:
    def test_includes_the_dependency_surface(self, monkeypatch):
        """The monitor's job is completeness; a surface it forgets is unwatched."""
        monkeypatch.setattr(monitor, "scan_image", lambda ref, first_party, cache, severities=None: ([], None))
        monkeypatch.setattr(
            monitor,
            "run_pip_audit",
            lambda: [{"name": "urllib3", "version": "1", "vulns": [{"id": "CVE-1", "fix_versions": ["2"]}]}],
        )

        current, medium, failures = monitor.scan_surfaces(["redis:7"], "/tmp/cache")

        assert failures == []
        assert "image:redis" in current
        assert current["pypi"]["findings"]["CVE-1"]["package"] == "urllib3"

    def test_a_failed_dependency_audit_is_a_failure_not_a_pass(self, monkeypatch):
        monkeypatch.setattr(monitor, "scan_image", lambda ref, first_party, cache, severities=None: ([], None))

        def unreachable():
            raise RuntimeError("OSV unreachable")

        monkeypatch.setattr(monitor, "run_pip_audit", unreachable)

        current, medium, failures = monitor.scan_surfaces(["redis:7"], "/tmp/cache")

        assert "pypi" not in current, "a failed audit must not read as 'nothing found'"
        assert failures and "OSV unreachable" in failures[0]


class TestApply:
    def _wire(self, monkeypatch, issues):
        monkeypatch.setattr(monitor, "third_party_image_refs", lambda paths: [])
        monkeypatch.setattr(monitor, "scan_gate_compose_paths", lambda: [])
        monkeypatch.setattr(
            monitor, "scan_surfaces", lambda refs, cache: ({"image:redis": _entry("CVE-1")}, {}, [])
        )
        monkeypatch.setattr(monitor, "load_baseline", lambda path=None: _baseline())
        monkeypatch.setattr(monitor, "issues_by_title", lambda: issues)
        created: list[str] = []
        reopened: list[int] = []
        monkeypatch.setattr(monitor, "create_issue", lambda t, b: (created.append(t), "url")[1])
        monkeypatch.setattr(monitor, "reopen_issue", lambda n, b: (reopened.append(n), "url")[1])
        return created, reopened

    def test_creates_when_there_is_no_issue(self, monkeypatch, capsys):
        created, reopened = self._wire(monkeypatch, {})

        assert monitor.main(["--apply"]) == 0

        assert len(created) == 1
        assert reopened == []

    def test_reopens_a_closed_issue_instead_of_creating_a_twin(self, monkeypatch, capsys):
        title = monitor.issue_title("image:redis", "CVE-1")
        created, reopened = self._wire(monkeypatch, {title: {"number": 4, "state": "CLOSED"}})

        assert monitor.main(["--apply"]) == 0

        assert created == []
        assert reopened == [4]

    def test_skips_an_open_issue(self, monkeypatch, capsys):
        title = monitor.issue_title("image:redis", "CVE-1")
        created, reopened = self._wire(monkeypatch, {title: {"number": 4, "state": "OPEN"}})

        assert monitor.main(["--apply"]) == 0

        assert created == []
        assert reopened == []

    def test_dry_run_files_nothing_but_says_what_it_would(self, monkeypatch, capsys):
        created, reopened = self._wire(monkeypatch, {})

        assert monitor.main([]) == 0

        assert created == [] and reopened == []
        assert "would be filed" in capsys.readouterr().out

    def test_a_partial_scan_failure_exits_non_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(monitor, "third_party_image_refs", lambda paths: [])
        monkeypatch.setattr(monitor, "scan_gate_compose_paths", lambda: [])
        monkeypatch.setattr(monitor, "scan_surfaces", lambda refs, cache: ({}, {}, ["redis: timed out"]))
        monkeypatch.setattr(monitor, "load_baseline", lambda path=None: _baseline())

        assert monitor.main([]) == 1

        assert "could not be scanned" in capsys.readouterr().err

    def test_a_missing_baseline_still_reports_findings(self, monkeypatch, capsys):
        """Degrade the drift comparison, never the finding itself."""
        created, _ = self._wire(monkeypatch, {})
        monkeypatch.setattr(
            monitor, "load_baseline", lambda path=None: (_ for _ in ()).throw(monitor.BaselineError("gone"))
        )

        assert monitor.main(["--apply"]) == 0

        assert len(created) == 1
        assert "without a drift comparison" in capsys.readouterr().err


class TestStateOut:
    """Phase 847d: the fix-forward bot consumes the monitor's findings.

    The state file is the hand-off between two steps of the same workflow, so
    the contract is exactly: `current` (what was measured) plus the drift and
    the fixable queue. It is written in REPORT-ONLY mode too, because the bot
    runs before any issue is filed.
    """

    def _wire(self, monkeypatch):
        monkeypatch.setattr(monitor, "third_party_image_refs", lambda paths: [])
        monkeypatch.setattr(monitor, "scan_gate_compose_paths", lambda: [])
        monkeypatch.setattr(
            monitor,
            "scan_surfaces",
            lambda refs, cache: ({"image:redis": _entry("CVE-1", fix="2.0")}, {}, []),
        )
        monkeypatch.setattr(monitor, "load_baseline", lambda path=None: _baseline())

    def test_writes_the_state_in_report_only_mode(self, monkeypatch, tmp_path):
        self._wire(monkeypatch)
        out = tmp_path / "state.json"

        assert monitor.main(["--state-out", str(out)]) == 0

        state = json.loads(out.read_text(encoding="utf-8"))
        assert "current" in state
        assert state["current"]["image:redis"]["findings"]["CVE-1"]["fixed"] == "2.0"
        assert "generated_at" in state
        assert "drift" in state

    def test_the_state_carries_the_fixable_queue(self, monkeypatch, tmp_path):
        self._wire(monkeypatch)
        out = tmp_path / "state.json"

        monitor.main(["--state-out", str(out)])

        state = json.loads(out.read_text(encoding="utf-8"))
        assert [entry["cve"] for entry in state["fixable"]] == ["CVE-1"]

    def test_a_partial_scan_writes_no_state(self, monkeypatch, tmp_path):
        """A state file from a partial scan would let the bot act on a picture
        that is missing surfaces — the exact 'clean bill of health from a
        partial scan' failure the monitor already refuses to report."""
        monkeypatch.setattr(monitor, "third_party_image_refs", lambda paths: [])
        monkeypatch.setattr(monitor, "scan_gate_compose_paths", lambda: [])
        monkeypatch.setattr(monitor, "scan_surfaces", lambda refs, cache: ({}, {}, ["redis: timed out"]))
        monkeypatch.setattr(monitor, "load_baseline", lambda path=None: _baseline())
        out = tmp_path / "state.json"

        assert monitor.main(["--state-out", str(out)]) == 1

        assert not out.exists()

    def test_the_state_is_consumable_by_fix_forward(self, monkeypatch, tmp_path):
        """The two scripts must agree on the contract, not just on this repo."""
        from scripts import fix_forward as ff

        self._wire(monkeypatch)
        out = tmp_path / "state.json"
        monitor.main(["--state-out", str(out)])

        state = json.loads(out.read_text(encoding="utf-8"))

        # fix_forward reads `state["current"]` and iterates its surfaces.
        current = state.get("current") or {}
        assert current
        for surface, entry in current.items():
            assert isinstance(surface, str)
            assert "findings" in entry


class TestMediumBand:
    """The MEDIUM band in the monitor — Phase 847e.

    The monitor measures the MEDIUM band in the same scan pass as the
    HIGH/CRITICAL one and reports it against the committed record, so the
    backlog is visible without ever becoming a gate.
    """

    def _rows(self, *rows):
        return list(rows), "sha256:x"

    def _row(self, cve, severity, fix=""):
        return type(
            "R",
            (),
            {"cve": cve, "severity": severity, "package": "pkg", "installed": "1.0", "fixed": fix},
        )()

    def test_the_two_bands_are_partitioned_not_mixed(self, monkeypatch):
        monkeypatch.setattr(
            monitor,
            "scan_image",
            lambda ref, first_party, cache, severities=None: self._rows(
                self._row("CVE-H", "HIGH"),
                self._row("CVE-M", "MEDIUM"),
                self._row("CVE-L", "LOW"),
            ),
        )
        monkeypatch.setattr(monitor, "run_pip_audit", lambda: [])

        current, medium, failures = monitor.scan_surfaces(["redis:7"], "/tmp/cache")

        assert failures == []
        assert set(current["image:redis"]["findings"]) == {"CVE-H"}
        assert set(medium["image:redis"]["findings"]) == {"CVE-M"}

    def test_the_scan_asks_for_both_bands_in_one_pass(self, monkeypatch):
        seen = []

        def fake_scan(ref, first_party, cache, severities=None):
            seen.append(severities)
            return [], "sha256:x"

        monkeypatch.setattr(monitor, "scan_image", fake_scan)
        monkeypatch.setattr(monitor, "run_pip_audit", lambda: [])

        monitor.scan_surfaces(["redis:7"], "/tmp/cache")

        assert seen == ["MEDIUM,HIGH,CRITICAL"]

    def test_the_python_surface_has_no_medium_band(self, monkeypatch):
        """pip-audit reports no severity, so there is nothing to partition."""
        monkeypatch.setattr(monitor, "scan_image", lambda ref, first_party, cache, severities=None: ([], None))
        monkeypatch.setattr(
            monitor,
            "run_pip_audit",
            lambda: [{"name": "urllib3", "version": "1", "vulns": [{"id": "CVE-1", "fix_versions": ["2"]}]}],
        )

        current, medium, failures = monitor.scan_surfaces(["redis:7"], "/tmp/cache")

        assert "pypi" in current
        assert "pypi" not in medium


class TestMediumState:
    """`medium_state` — the live count against the committed record."""

    def _medium(self, count):
        return {
            "image:redis": {
                "findings": {f"CVE-{i}": {"severity": "MEDIUM"} for i in range(count)},
            }
        }

    def _record(self, count, ceiling):
        return {
            "version": 1,
            "ceiling": ceiling,
            "surfaces": {
                "image:redis": {
                    "findings": {f"CVE-{i}": {"severity": "MEDIUM"} for i in range(count)},
                }
            },
        }

    def test_the_live_count_is_compared_with_the_record_and_the_ceiling(self):
        state = monitor.medium_state(self._medium(5), self._record(4, 4))
        assert state["live"] == 5
        assert state["recorded"] == 4
        assert state["ceiling"] == 4
        assert state["over_ceiling"] is True

    def test_a_shrinking_backlog_is_not_flagged(self):
        state = monitor.medium_state(self._medium(2), self._record(4, 4))
        assert state["live"] == 2
        assert state["over_ceiling"] is False

    def test_a_missing_record_degrades_to_the_live_count(self):
        """No record means nothing to compare against — not a crash, not a pass."""
        state = monitor.medium_state(self._medium(3), None)
        assert state["live"] == 3
        assert state["recorded"] == 0
        assert state["ceiling"] == 0

    def test_the_report_shows_the_medium_state(self):
        report = monitor.render_report(
            {"image:redis": _entry()},
            {"appeared": {}, "cleared": {}, "retagged": {}},
            [],
            [],
            monitor.medium_state(self._medium(5), self._record(4, 4)),
        )
        assert "MEDIUM band" in report
        assert "**5**" in report
        assert "above the ceiling" in report
