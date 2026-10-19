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

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import scan_baseline_monitor as monitor  # noqa: E402


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
    def test_existing_title_is_not_refiled(self):
        current = {"image:redis": _entry("CVE-1")}
        existing = {monitor.issue_title("image:redis", "CVE-1")}
        assert monitor.plan_issues(current, existing) == []

    def test_missing_title_is_planned(self):
        current = {"image:redis": _entry("CVE-1")}
        planned = monitor.plan_issues(current, set())
        assert [p["cve"] for p in planned] == ["CVE-1"]

    def test_critical_sorts_before_high(self):
        current = {
            "image:a": {
                "findings": {
                    "CVE-HIGH": {"severity": "HIGH", "package": "p", "installed": "1", "fixed": ""},
                    "CVE-CRIT": {"severity": "CRITICAL", "package": "p", "installed": "1", "fixed": ""},
                }
            }
        }
        assert [p["cve"] for p in monitor.plan_issues(current, set())] == ["CVE-CRIT", "CVE-HIGH"]

    def test_planning_is_deterministic(self):
        current = {"image:b": _entry("CVE-2"), "image:a": _entry("CVE-1")}
        assert monitor.plan_issues(current, set()) == monitor.plan_issues(current, set())


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
