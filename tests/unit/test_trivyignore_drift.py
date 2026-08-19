"""Phase 829a, outcomes O1/O2/O4 — the ignorefile must be measured, not assumed.

WHY THIS EXISTS
---------------
On 2026-08-19 ``make scan-images`` was failing on ``grafana/alloy:v1.18.1`` with
two unwaived HIGHs. Nobody had changed that image — the CVEs entered the
vulnerability database after the previous day's renewal review, and the
ignorefile went stale underneath a deployment that had not moved.

Nothing detected it, because the weekly workflow only re-dates entries it
already knows about. A date-only renewal structurally cannot see a CVE that did
not exist last week.

``test_date_only_renewal_does_not_hide_a_new_cve`` is the direct regression test
for that incident.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_trivyignore_drift import (
    drift,
    findings_from_scan,
    main,
    scan_dir_findings,
    waived_ids,
)


def _report(tmp: Path, image: str, vulns: list[tuple[str, str]]) -> Path:
    """Write a minimal Trivy JSON report for `image`."""
    doc = {
        "Results": [
            {
                "Target": image,
                "Vulnerabilities": [
                    {"VulnerabilityID": cve, "Severity": sev} for cve, sev in vulns
                ],
            }
        ]
    }
    p = tmp / f"{image}.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _ignorefile(tmp: Path, ids: list[str]) -> Path:
    body = ["# header, not an entry", "# CVE-2000-0000 mentioned in prose only", ""]
    for i in ids:
        body += [f"# why no fix for {i}", f"{i} exp:2026-08-26", ""]
    p = tmp / ".trivyignore.third-party"
    p.write_text("\n".join(body), encoding="utf-8")
    return p


# ── O1: gaps ──────────────────────────────────────────────────────────────────


def test_unwaived_cve_is_reported_as_a_gap(tmp_path: Path, capsys) -> None:
    scans = tmp_path / "scans"
    scans.mkdir()
    _report(scans, "alloy", [("CVE-2026-56864", "HIGH"), ("CVE-2026-1111", "HIGH")])
    ign = _ignorefile(tmp_path, ["CVE-2026-1111"])

    rc = main(["--scan-dir", str(scans), "--ignorefile", str(ign)])
    out = capsys.readouterr().out

    assert rc == 1, "an unwaived finding must fail — it breaks make scan-images"
    assert "CVE-2026-56864" in out
    assert "alloy" in out, "a gap is only actionable if it names the carrier"


def test_gap_names_every_carrier(tmp_path: Path, capsys) -> None:
    """Two images carrying one CVE must both be listed.

    Bumping only one of them leaves the entry live, which is exactly the
    misunderstanding that makes bumps look useless.
    """
    scans = tmp_path / "scans"
    scans.mkdir()
    _report(scans, "alloy", [("CVE-2026-56864", "HIGH")])
    _report(scans, "alertmanager", [("CVE-2026-56864", "HIGH")])
    ign = _ignorefile(tmp_path, [])

    main(["--scan-dir", str(scans), "--ignorefile", str(ign)])
    out = capsys.readouterr().out

    assert "alloy" in out and "alertmanager" in out


def test_critical_wins_over_high_for_the_same_id(tmp_path: Path) -> None:
    """Trivy can report one id at different severities across packages.

    Reporting the lower one would understate the finding.
    """
    scans = tmp_path / "scans"
    scans.mkdir()
    _report(scans, "img", [("CVE-1", "HIGH")])
    _report(scans, "img2", [("CVE-1", "CRITICAL")])

    severity, _ = scan_dir_findings(scans)

    assert severity["CVE-1"] == "CRITICAL"


# ── O2: dead entries ──────────────────────────────────────────────────────────


def test_waived_but_uncarried_cve_is_reported_dead(tmp_path: Path, capsys) -> None:
    scans = tmp_path / "scans"
    scans.mkdir()
    _report(scans, "img", [("CVE-2026-1111", "HIGH")])
    ign = _ignorefile(tmp_path, ["CVE-2026-1111", "CVE-2020-11111"])

    rc = main(["--scan-dir", str(scans), "--ignorefile", str(ign)])
    out = capsys.readouterr().out

    assert "CVE-2020-11111" in out
    assert rc == 0, "a dead entry is tidy-up, not a broken gate"


def test_dead_entries_can_be_made_fatal(tmp_path: Path) -> None:
    scans = tmp_path / "scans"
    scans.mkdir()
    _report(scans, "img", [])
    ign = _ignorefile(tmp_path, ["CVE-2020-11111"])

    assert main(["--scan-dir", str(scans), "--ignorefile", str(ign), "--fail-on-dead"]) == 1


# ── O4: the 2026-08-19 regression ─────────────────────────────────────────────


def test_date_only_renewal_does_not_hide_a_new_cve(tmp_path: Path, capsys) -> None:
    """The incident this phase exists for.

    Simulates the real sequence: the ignorefile is complete and every entry has
    a fresh expiry date — exactly the state a date-only renewal leaves behind —
    and then the vulnerability database learns about one more CVE in an image
    nobody touched.

    A checker that only looked at expiry dates would report everything healthy.
    """
    scans = tmp_path / "scans"
    scans.mkdir()
    # Yesterday's known set, all freshly renewed...
    known = [("CVE-2026-1111", "HIGH"), ("CVE-2026-2222", "HIGH")]
    # ...plus what the DB learned overnight.
    _report(scans, "alloy", known + [("CVE-2026-56864", "HIGH")])
    ign = _ignorefile(tmp_path, ["CVE-2026-1111", "CVE-2026-2222"])

    rc = main(["--scan-dir", str(scans), "--ignorefile", str(ign)])
    out = capsys.readouterr().out

    assert rc == 1, (
        "a freshly-renewed ignorefile with a new upstream CVE must FAIL — "
        "this is the exact state that broke make scan-images on 2026-08-19"
    )
    assert "CVE-2026-56864" in out


# ── vacuity guard ─────────────────────────────────────────────────────────────


def test_clean_state_is_silent_and_passes(tmp_path: Path, capsys) -> None:
    """A correct file must produce no gaps and no dead entries.

    Without this, a checker that reported everything as a gap would pass every
    test above while being useless.
    """
    scans = tmp_path / "scans"
    scans.mkdir()
    _report(scans, "img", [("CVE-2026-1111", "HIGH"), ("CVE-2026-2222", "CRITICAL")])
    ign = _ignorefile(tmp_path, ["CVE-2026-1111", "CVE-2026-2222"])

    rc = main(["--scan-dir", str(scans), "--ignorefile", str(ign)])
    out = capsys.readouterr().out

    assert rc == 0
    assert "no gaps, no dead entries" in out
    assert "GAPS" not in out and "DEAD" not in out


# ── parsing robustness ────────────────────────────────────────────────────────


def test_prose_mentions_are_not_treated_as_entries(tmp_path: Path) -> None:
    """A CVE named inside a comment is not a waiver.

    Counting those would silently widen the waived set and hide real gaps —
    the opposite of what this script is for.
    """
    ign = tmp_path / "ig"
    ign.write_text(
        "# CVE-2026-9999 is discussed here but NOT waived\n"
        "#   see also CVE-2026-8888\n"
        "CVE-2026-1111 exp:2026-08-26\n",
        encoding="utf-8",
    )

    assert waived_ids(ign) == {"CVE-2026-1111"}


def test_ghsa_ids_are_recognised(tmp_path: Path) -> None:
    ign = tmp_path / "ig"
    ign.write_text("GHSA-r277-6w6q-xmqw exp:2026-08-26\n", encoding="utf-8")
    assert waived_ids(ign) == {"GHSA-r277-6w6q-xmqw"}


def test_low_and_medium_findings_are_ignored(tmp_path: Path) -> None:
    """The gate is HIGH/CRITICAL only; counting others would invent gaps."""
    scans = tmp_path / "s"
    scans.mkdir()
    _report(scans, "img", [("CVE-LOW", "LOW"), ("CVE-MED", "MEDIUM"), ("CVE-H", "HIGH")])
    severity, _ = scan_dir_findings(scans)
    assert set(severity) == {"CVE-H"}


def test_empty_scan_dir_is_an_error_not_a_pass(tmp_path: Path) -> None:
    """No reports means the scan did not run.

    Reporting "no gaps" there would turn a broken pipeline into a green check —
    which is the failure mode this whole phase exists to remove.
    """
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["--scan-dir", str(empty)]) == 2


def test_unreadable_report_raises_rather_than_silently_skipping(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        findings_from_scan(bad)


def test_drift_is_deterministic() -> None:
    """Stable ordering: the workflow diffs this output between runs."""
    waived = {"B", "A", "C"}
    measured = {"C": "HIGH", "D": "HIGH"}
    gaps, dead = drift(waived, measured)
    assert gaps == ["D"]
    assert dead == ["A", "B"]


def test_malformed_entry_is_not_silently_registered(tmp_path: Path) -> None:
    """A partial match would be worse than no match.

    A looser id pattern turned "CVE-2020-DEAD" into the id "CVE-2020-",
    registering a waiver for something that does not exist while the real line
    went unrecognised. A malformed line must fail to match entirely, so it shows
    up as an unwaived gap — loud — rather than as a corrupted waiver.
    """
    ign = tmp_path / "ig"
    ign.write_text(
        "CVE-2020-DEAD exp:2026-08-26\n"
        "CVE-2026-1111 exp:2026-08-26\n",
        encoding="utf-8",
    )

    ids = waived_ids(ign)

    assert ids == {"CVE-2026-1111"}
    assert not any(i.endswith("-") for i in ids), f"truncated id registered: {ids}"
