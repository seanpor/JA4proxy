"""
tests/unit/test_medium_ratchet.py

The MEDIUM band's ratchet — Phase 847e.

The MEDIUM surface is a backlog this repository has committed to shrinking.
Two properties make that commitment real, and this file pins both:

    * the recorded MEDIUM count never exceeds the recorded ceiling;
    * the ceiling never exceeds the value Phase 847e committed.

Both are measured against the **committed record**, never against a live scan.
The Trivy database churns daily, so a ratchet measured against a live scan
would be a coin-flip — and a coin-flip is not a ratchet. The record is the
thing a reviewer can argue with.

The ceiling's maximum is written *here* rather than in the record, on purpose:
a record that could raise its own ceiling would be a record that can grow
without anybody deciding that it may. Raising it means editing this line, which
is a reviewed diff — exactly the "lowering is explicit and reviewed" property
the phase requires.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "scripts"))

import medium_inventory as inv  # noqa: E402
from scan_baseline import MEDIUM_BASELINE_PATH, BaselineError, load_baseline  # noqa: E402

# The MEDIUM surface as measured on 2026-10-21 (Phase 847e): 152. It may only
# go DOWN. Lowering it is a reviewed edit to this file — that is the point.
#
# 2026-10-23 (Phase 847g): re-measured at **79**. The CVE-2026-111943 image
# bumps did most of it — every replacement tag was measured for MEDIUM as well
# as HIGH, and three of the four came back with none: loki 14 -> 0,
# prometheus 9 -> 0, redis_exporter 9 -> 0, alloy 59 -> 16 (two minors forward,
# newer base). grafana 30 -> 31 and ja4proxy-test 1 -> 2 are the only growth,
# and both are recorded in `security/baseline-medium.json`. Lowering the ceiling
# to the new measurement is what keeps this a ratchet instead of a rubber stamp:
# leaving it at 152 would let a later re-measure silently re-accrete 73 findings.
MEDIUM_CEILING_MAX = 79


def _record() -> dict:
    """The committed MEDIUM record, loaded through the shared loader."""
    return load_baseline(MEDIUM_BASELINE_PATH)


class TestTheRatchetHolds:
    def test_the_recorded_count_never_exceeds_the_ceiling(self):
        state = inv.ratchet(_record())
        assert state["holds"], (
            f"the MEDIUM record holds {state['recorded']} finding(s) against a "
            f"ceiling of {state['ceiling']} — the record may only shrink"
        )

    def test_the_ceiling_never_exceeds_the_committed_maximum(self):
        state = inv.ratchet(_record())
        assert state["ceiling"] <= MEDIUM_CEILING_MAX, (
            f"the MEDIUM ceiling is {state['ceiling']}, above the {MEDIUM_CEILING_MAX} "
            f"committed by Phase 847e — raising it means editing this test"
        )

    def test_the_record_is_not_empty(self):
        """A record with nothing in it would make the ratchet vacuous.

        The whole point of the ceiling is to bound a *real* surface. If the
        record emptied out, the ceiling would have to drop with it, and the
        test would pass without proving anything.
        """
        state = inv.ratchet(_record())
        assert state["recorded"] > 0

    def test_the_record_loads_through_the_shared_loader(self):
        """The gate loads this file with the same loader, so it must be valid."""
        baseline = load_baseline(MEDIUM_BASELINE_PATH)
        assert baseline["version"] == 1
        assert isinstance(baseline["surfaces"], dict)


class TestTheBandsDoNotBleed:
    def test_the_medium_record_holds_only_medium_findings(self):
        """A HIGH finding in the MEDIUM record would be judged twice.

        The HIGH/CRITICAL band is judged against `security/baseline.json` and
        the MEDIUM band against `security/baseline-medium.json`. A finding
        recorded in both would be counted twice, and a HIGH finding recorded
        only in the MEDIUM file would be invisible to the band that is
        supposed to gate it.
        """
        for surface, entry in _record()["surfaces"].items():
            for cve, finding in entry["findings"].items():
                assert finding.get("severity") == "MEDIUM", (
                    f"{surface}/{cve} is recorded in the MEDIUM record at severity "
                    f"{finding.get('severity')!r}"
                )

    def test_the_python_surface_is_not_in_the_medium_record(self):
        """pip-audit reports no severity, so it has no MEDIUM band.

        Recording its findings here would silently claim a severity the tool
        does not report — the same invention this phase refused to make in the
        inventory itself.
        """
        assert "pypi" not in _record()["surfaces"]

    def test_a_high_finding_in_the_medium_record_is_rejected(self):
        """The check is not vacuous: a HIGH finding really is caught."""
        baseline = _record()
        surface = sorted(baseline["surfaces"])[0]
        baseline["surfaces"][surface]["findings"]["CVE-9999-1"] = {
            "severity": "HIGH",
            "package": "p",
            "installed": "1",
            "fixed": "",
        }
        offenders = [
            f"{surface}/{cve}"
            for surface, entry in baseline["surfaces"].items()
            for cve, finding in entry["findings"].items()
            if finding.get("severity") != "MEDIUM"
        ]
        assert offenders == [f"{surface}/CVE-9999-1"]


class TestTheRatchetLogic:
    """The ratchet must actually reject a grown record, not just describe one."""

    def test_a_grown_record_does_not_hold(self):
        baseline = {
            "version": 1,
            "ceiling": 2,
            "surfaces": {
                "image:x": {
                    "findings": {
                        f"CVE-{i}": {"severity": "MEDIUM"} for i in range(3)
                    }
                }
            },
        }
        state = inv.ratchet(baseline)
        assert state["recorded"] == 3
        assert state["ceiling"] == 2
        assert state["holds"] is False

    def test_a_shrunken_record_holds(self):
        baseline = {
            "version": 1,
            "ceiling": 5,
            "surfaces": {"image:x": {"findings": {"CVE-1": {"severity": "MEDIUM"}}}},
        }
        state = inv.ratchet(baseline)
        assert state["holds"] is True

    def test_a_missing_ceiling_is_treated_as_zero(self):
        """A record with no ceiling is a record that may hold nothing.

        Treating "no ceiling" as "no limit" would let a record with findings
        in it pass by accident — the silent-growth path this exists to close.
        """
        baseline = {
            "version": 1,
            "surfaces": {"image:x": {"findings": {"CVE-1": {"severity": "MEDIUM"}}}},
        }
        assert inv.ratchet(baseline)["holds"] is False

    def test_the_loader_rejects_a_malformed_record(self):
        """The gate reads this file too, so its shape must be enforced."""
        broken = _ROOT / "security" / "baseline-medium.json"
        original = broken.read_text(encoding="utf-8")
        try:
            broken.write_text(json.dumps({"version": 1, "surfaces": []}), encoding="utf-8")
            with pytest.raises(BaselineError):
                load_baseline(broken)
        finally:
            broken.write_text(original, encoding="utf-8")
