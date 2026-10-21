"""
tests/unit/test_renew_trivyignore.py

Unit tests for scripts/renew_trivyignore.py.

Phase 812 (812-B) origin; reworked for Phase 847a when the ignorefiles became
generated from security/waivers.yaml, and again for Phase 847d, which removed
the auto-renew: an expiring waiver is now classified dead / fixable / escalate,
and there is **no path that extends an expiry**. These tests exist mainly to
hold that line — the old behaviour was a silent no-op with respect to truth.
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import render_waivers  # noqa: E402
import renew_trivyignore  # noqa: E402

TODAY = date(2026, 8, 4)


def _registry(*entries):
    return {"version": 1, "policy": {"max_window_days": 90}, "waivers": list(entries)}


def _entry(cve, expires, source="trivy", carriers=("grafana/grafana:13.2.4",)):
    created = (date.fromisoformat(expires) - timedelta(days=30)).isoformat()
    return {
        "id": cve,
        "scope": "third-party",
        "severity": "HIGH",
        "source": source,
        "carriers": list(carriers),
        "rationale": "test",
        "created": created,
        "expires": expires,
    }


def _write_registry(path: Path, *entries) -> Path:
    """Write a registry in the same *text* shape the real file uses.

    `yaml.safe_dump` nests sequences differently from hand-authored
    `security/waivers.yaml`, and both `_splice_entry_block` and `remove_entries`
    operate on that authored text — so fixtures must be authored, not dumped.
    """
    lines = [
        "version: 1\n",
        "policy:\n",
        "  max_window_days: 90\n",
        "  default_owner: security-oncall\n",
        "waivers:\n",
    ]
    for e in entries:
        lines += [
            f"  - id: {e['id']}\n",
            f"    scope: {e['scope']}\n",
            f"    severity: {e['severity']}\n",
            f"    source: {e['source']}\n",
            "    carriers: [" + ", ".join(f'"{c}"' for c in e["carriers"]) + "]\n",
            f"    rationale: {e['rationale']}\n",
            f"    created: {e['created']}\n",
            f"    expires: {e['expires']}\n",
        ]
    path.write_text("".join(lines), encoding="utf-8")
    return path


def _scan_dir(tmp_path: Path, findings: dict) -> Path:
    """One Trivy JSON report per image: `{"image: ref": {cve: severity}}`."""
    out = tmp_path / "scan"
    out.mkdir(exist_ok=True)
    for ref, cves in findings.items():
        doc = {
            "ArtifactName": ref,
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": cve, "Severity": sev, "PkgName": "p"}
                        for cve, sev in cves.items()
                    ]
                }
            ],
        }
        (out / f"{ref.replace('/', '_').replace(':', '_')}.json").write_text(
            json.dumps(doc), encoding="utf-8"
        )
    return out


# ── selection ───────────────────────────────────────────────────────────────

def test_selects_only_trivy_entries_inside_the_window() -> None:
    reg = _registry(
        _entry("CVE-2099-00001", "2027-01-01"),  # outside the window (and inside policy)
        _entry("CVE-2026-00002", "2026-08-09"),  # inside the window
        _entry("CVE-2026-99999", "2026-08-02", source="pip-audit"),  # wrong source
    )
    got = renew_trivyignore.expiring_entries(reg, 5, TODAY)
    assert [e["id"] for e in got] == ["CVE-2026-00002"]


def test_selection_sorts_oldest_expiry_first() -> None:
    reg = _registry(
        _entry("CVE-2026-00003", "2026-08-02"),
        _entry("CVE-2026-00001", "2026-06-01"),
    )
    assert [e["id"] for e in renew_trivyignore.expiring_entries(reg, 5, TODAY)] == [
        "CVE-2026-00001",
        "CVE-2026-00003",
    ]


def test_unparseable_expiry_is_skipped_not_crashed() -> None:
    entry = _entry("CVE-2026-00001", "2026-08-06")
    entry["expires"] = "not-a-date"  # built by hand: _entry derives created from it
    assert renew_trivyignore.expiring_entries(_registry(entry), 5, TODAY) == []


# ── classification ──────────────────────────────────────────────────────────

def test_classify_dead_when_every_declared_carrier_was_scanned_clean() -> None:
    entry = _entry("CVE-2026-00001", "2026-08-06")  # carriers: grafana/grafana:13.2.4
    scanned = {"grafana/grafana:13.2.4"}
    assert renew_trivyignore.classify(entry, {}, scanned) == "dead"
    assert (
        renew_trivyignore.classify(entry, {"CVE-2026-00001": ["img:1"]}, scanned) == "present"
    )


def test_classify_unmeasured_when_a_declared_carrier_has_no_report() -> None:
    """The load-bearing guard: a CVE missing from the results is only *dead* if
    the images it was pinned to were actually scanned. A failed Trivy run writes
    no report, and treating that as 'gone' would delete a live waiver."""
    entry = _entry("CVE-2026-00001", "2026-08-06")
    # The scan covered a different image entirely — ours is unmeasured, NOT dead.
    assert (
        renew_trivyignore.classify(entry, {}, {"some/other:1.0"}) == "unmeasured"
    )
    # With no scan at all (empty dir never gets here, but defensively): unmeasured.
    assert renew_trivyignore.classify(entry, {}, set()) == "unmeasured"


def test_classify_handles_entry_with_no_declared_carriers() -> None:
    entry = _entry("CVE-2026-00001", "2026-08-06", carriers=())
    assert renew_trivyignore.classify(entry, {}, set()) == "dead"


def test_measure_carriers_reports_images_that_carried_nothing() -> None:
    """An image with zero findings contributes no carrier entries, so the scanned
    set must be recovered from the report's ArtifactName — otherwise a clean
    image looks exactly like an unscanned one."""
    tmp = Path(tempfile.mkdtemp())
    scan = tmp / "scan"
    scan.mkdir()
    (scan / "clean.json").write_text(
        json.dumps({"ArtifactName": "grafana/grafana:13.2.4", "Results": []}),
        encoding="utf-8",
    )
    carriers, scanned = renew_trivyignore.measure_carriers(scan)
    assert carriers == {}
    assert scanned == {"grafana/grafana:13.2.4"}


# ── the cardinal rule: nothing extends an expiry ────────────────────────────

def test_no_autorenew_helper_exists_any_more() -> None:
    """Phase 847d deleted the renewal primitive outright. If someone
    reintroduces it, this fails and forces the conversation."""
    assert not hasattr(render_waivers, "renew_expiring")


def test_main_never_extends_dates_for_a_live_finding(tmp_path, monkeypatch, capsys) -> None:
    """A CVE still present in a scan with no clearing tag: escalate, dates intact.

    This is the exact case the old script silently renewed for 90 days.
    """
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00001", "2026-08-06"))
    scan = _scan_dir(tmp_path, {"grafana/grafana:13.2.4": {"CVE-2026-00001": "HIGH"}})
    # No clearing tag exists upstream: every candidate still carries the CVE.
    monkeypatch.setattr(
        renew_trivyignore,
        "fix_proposal",
        lambda entry, carriers, registry, today: None,
    )

    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5",
         "--registry", str(reg_path), "--scan-dir", str(scan)]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "needs a human decision (dates unchanged)" in out
    assert "No expiry was extended" in out
    reloaded = render_waivers.load_registry(reg_path)
    assert reloaded["waivers"][0]["expires"] == "2026-08-06"  # UNTOUCHED
    assert reloaded["waivers"][0]["created"] == _entry("CVE-2026-00001", "2026-08-06")["created"]


def test_main_removes_a_dead_waiver_and_rerenders(tmp_path, monkeypatch, capsys) -> None:
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00001", "2026-08-06"))
    # The scan sees a *different* CVE: ours is gone.
    scan = _scan_dir(tmp_path, {"grafana/grafana:13.2.4": {"CVE-2026-deadbeef": "LOW"}})
    third = tmp_path / ".trivyignore.third-party"
    rw = renew_trivyignore.render_waivers
    monkeypatch.setattr(rw, "THIRD_PARTY_IGNORE", third)
    monkeypatch.setattr(rw, "FIRST_PARTY_IGNORE", tmp_path / ".trivyignore.first-party")
    monkeypatch.setattr(rw, "PIP_AUDIT_IGNORES", tmp_path / ".pip-audit-ignores")

    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5",
         "--registry", str(reg_path), "--scan-dir", str(scan)]
    )
    out = capsys.readouterr().out
    assert rc == 1  # something changed: a human should see it
    assert "dead: CVE-2026-00001 no longer appears in any scan" in out
    assert "CVE-2026-00001" not in third.read_text(encoding="utf-8")
    # Deleting the last waiver is the intended end state of the "zero CVEs"
    # programme, so the registry must still validate as empty, not fail.
    assert render_waivers.load_registry(reg_path)["waivers"] == []
    assert render_waivers.validate(render_waivers.load_registry(reg_path)) == []


def test_main_does_not_delete_when_the_scan_missed_the_carrier(tmp_path, capsys) -> None:
    """The end-to-end form of the guard: a partial scan dir must never delete.

    The entry declares grafana/grafana:13.2.4, but the scan dir only has a report
    for an unrelated image (e.g. Grafana's Trivy run failed and wrote nothing).
    The old code would have called this DEAD and removed the waiver.
    """
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00001", "2026-08-06"))
    original = reg_path.read_text(encoding="utf-8")
    scan = _scan_dir(tmp_path, {"unrelated/image:1.0": {"CVE-2026-other": "LOW"}})

    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5",
         "--registry", str(reg_path), "--scan-dir", str(scan)]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "carrier(s) missing from --scan-dir" in out
    assert reg_path.read_text(encoding="utf-8") == original  # UNTOUCHED


def test_main_reports_fixable_without_touching_dates(tmp_path, monkeypatch, capsys) -> None:
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00001", "2026-08-06"))
    scan = _scan_dir(tmp_path, {"grafana/grafana:13.2.4": {"CVE-2026-00001": "HIGH"}})
    monkeypatch.setattr(
        renew_trivyignore,
        "fix_proposal",
        lambda entry, carriers, registry, today: {"bump": {"to": "13.3.1"}},
    )
    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5",
         "--registry", str(reg_path), "--scan-dir", str(scan)]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "is cleared by 13.3.1" in out
    assert "fix_forward.py" in out
    assert render_waivers.load_registry(reg_path)["waivers"][0]["expires"] == "2026-08-06"


def test_main_requires_a_scan_to_decide(tmp_path, capsys) -> None:
    """Without --scan-dir nothing can be classified, so nothing may change."""
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00001", "2026-08-06"))
    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5", "--registry", str(reg_path)]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "needs a scan to decide" in out
    assert render_waivers.load_registry(reg_path)["waivers"][0]["expires"] == "2026-08-06"


def test_main_nothing_in_window_is_a_clean_zero(tmp_path, capsys) -> None:
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00005", "2026-12-01"))
    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5", "--registry", str(reg_path)]
    )
    assert rc == 0
    assert "nothing to re-affirm" in capsys.readouterr().out


def test_check_mode_writes_nothing(tmp_path, monkeypatch, capsys) -> None:
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00001", "2026-08-06"))
    original = reg_path.read_text(encoding="utf-8")
    scan = _scan_dir(tmp_path, {"grafana/grafana:13.2.4": {"CVE-2026-deadbeef": "LOW"}})
    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5",
         "--registry", str(reg_path), "--scan-dir", str(scan), "--check"]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "[check]" in out
    assert "nothing written" in out
    assert reg_path.read_text(encoding="utf-8") == original  # byte-identical


def test_scan_dir_without_reports_is_an_error(tmp_path, capsys) -> None:
    reg_path = _write_registry(tmp_path / "waivers.yaml", _entry("CVE-2026-00001", "2026-08-06"))
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--registry", str(reg_path), "--scan-dir", str(empty)]
    )
    assert rc == 2
    assert "no Trivy JSON reports" in capsys.readouterr().err


# ── fix_proposal wiring ─────────────────────────────────────────────────────

def test_fix_proposal_returns_none_when_no_carrier_sees_the_cve() -> None:
    assert (
        renew_trivyignore.fix_proposal(
            _entry("CVE-2026-00001", "2026-08-06"), {}, _registry(), TODAY
        )
        is None
    )


def test_fix_proposal_delegates_to_the_engine(monkeypatch) -> None:
    """The proposal must come from fix_forward's real image check, not a guess."""
    from scripts import fix_forward as ff

    seen: dict = {}

    def fake_check_image_fix(ref, surface, cves, current, **kw):
        seen.update(ref=ref, surface=surface, cves=cves, current=current)
        return [
            {
                "surface": surface,
                "cve": sorted(cves)[0],
                "decision": "fixable",
                "evidence": "checked",
                "recheck": "",
                "bump": {"kind": "image", "to": "13.3.1"},
                "table": [],
            }
        ]

    monkeypatch.setattr(ff, "check_image_fix", fake_check_image_fix)
    monkeypatch.setattr(ff, "default_scanner", lambda: (lambda ref: {}))
    got = renew_trivyignore.fix_proposal(
        _entry("CVE-2026-00001", "2026-08-06"),
        {"CVE-2026-00001": ["grafana/grafana:13.2.4"]},
        _registry(),
        TODAY,
    )
    assert got is not None and got["bump"]["to"] == "13.3.1"
    assert seen["ref"] == "grafana/grafana:13.2.4"
    assert seen["surface"] == "image:grafana/grafana"
    assert seen["cves"] == {"CVE-2026-00001"}


def test_fix_proposal_returns_none_for_a_multi_carrier_entry(monkeypatch) -> None:
    """A bump to one image says nothing about the other, so it must not be
    reported as fixable — that would overclaim."""
    from scripts import fix_forward as ff

    monkeypatch.setattr(
        ff,
        "check_image_fix",
        lambda *a, **kw: pytest.fail("must not even be called for multi-carrier"),
    )
    assert (
        renew_trivyignore.fix_proposal(
            _entry("CVE-2026-00001", "2026-08-06"),
            {"CVE-2026-00001": ["grafana/grafana:13.2.4", "grafana/alloy:1.18.1"]},
            _registry(),
            TODAY,
        )
        is None
    )


def test_main_escalates_a_multi_carrier_entry_as_multi(tmp_path, capsys) -> None:
    """A CVE carried by two images where both are still reported: neither dead
    nor fixable, so it escalates with the multi-carrier next step."""
    reg_path = _write_registry(
        tmp_path / "waivers.yaml",
        _entry("CVE-2026-00001", "2026-08-06",
               carriers=("grafana/grafana:13.2.4", "grafana/alloy:1.18.1")),
    )
    scan = _scan_dir(
        tmp_path,
        {
            "grafana/grafana:13.2.4": {"CVE-2026-00001": "HIGH"},
            "grafana/alloy:1.18.1": {"CVE-2026-00001": "HIGH"},
        },
    )
    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5",
         "--registry", str(reg_path), "--scan-dir", str(scan)]
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "carried by 2 images" in out
    assert render_waivers.load_registry(reg_path)["waivers"][0]["expires"] == "2026-08-06"


def test_fix_proposal_returns_none_when_verdict_is_not_fixable(monkeypatch) -> None:
    from scripts import fix_forward as ff

    monkeypatch.setattr(
        ff,
        "check_image_fix",
        lambda *a, **kw: [
            {"surface": "s", "cve": "c", "decision": "blocked", "bump": None, "table": None}
        ],
    )
    monkeypatch.setattr(ff, "default_scanner", lambda: (lambda ref: {}))
    assert (
        renew_trivyignore.fix_proposal(
            _entry("CVE-2026-00001", "2026-08-06"),
            {"CVE-2026-00001": ["grafana/grafana:13.2.4"]},
            _registry(),
            TODAY,
        )
        is None
    )


# ── remove_entries (the deletion path) ──────────────────────────────────────

def test_remove_entries_trims_only_the_named_block(tmp_path, monkeypatch) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text(
        "version: 1\n"
        "policy:\n"
        "  max_window_days: 90\n"
        "  default_owner: security-oncall\n"
        "waivers:\n"
        "  # --- third-party ---\n"
        "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img-a:1.0"]\n'
        "    rationale: goes away\n"
        "    created: 2026-01-01\n"
        "    expires: 2026-08-05\n"
        "  - id: CVE-2026-00002\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img-b:1.0"]\n'
        "    rationale: stays\n"
        "    created: 2026-01-01\n"
        "    expires: 2026-08-05\n",
        encoding="utf-8",
    )
    registry = render_waivers.load_registry(path)
    removed = render_waivers.remove_entries(registry, ["CVE-2026-00001"], path)
    assert removed == ["CVE-2026-00001"]
    text = path.read_text(encoding="utf-8")
    assert "CVE-2026-00001" not in text
    assert "CVE-2026-00002" in text
    assert "# --- third-party ---" in text  # comments survive
    assert "img-b:1.0" in text and "img-a:1.0" not in text
    assert [w["id"] for w in render_waivers.load_registry(path)["waivers"]] == ["CVE-2026-00002"]


def test_remove_entries_refuses_unknown_id_without_writing(tmp_path, monkeypatch) -> None:
    path = tmp_path / "waivers.yaml"
    original = (
        "version: 1\npolicy:\n  max_window_days: 90\n  default_owner: security-oncall\n"
        "waivers:\n"
        "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img-a:1.0"]\n'
        "    rationale: r\n"
        "    created: 2026-01-01\n"
        "    expires: 2026-08-05\n"
    )
    path.write_text(original, encoding="utf-8")
    registry = render_waivers.load_registry(path)
    with pytest.raises(ValueError, match="no registry entry"):
        render_waivers.remove_entries(registry, ["CVE-2099-99999"], path)
    assert path.read_text(encoding="utf-8") == original


def test_remove_entries_refuses_to_drop_a_shared_carrier(tmp_path, monkeypatch) -> None:
    """Deleting this entry would narrow a surviving waiver's carrier list."""
    path = tmp_path / "waivers.yaml"
    path.write_text(
        "version: 1\npolicy:\n  max_window_days: 90\n  default_owner: security-oncall\n"
        "waivers:\n"
        "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["shared:1.0"]\n'
        "    rationale: r\n"
        "    created: 2026-01-01\n"
        "    expires: 2026-08-05\n"
        "  - id: CVE-2026-00002\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["shared:1.0"]\n'
        "    rationale: r\n"
        "    created: 2026-01-01\n"
        "    expires: 2026-08-05\n",
        encoding="utf-8",
    )
    registry = render_waivers.load_registry(path)
    with pytest.raises(ValueError, match="still"):
        render_waivers.remove_entries(registry, ["CVE-2026-00001"], path)
    assert "CVE-2026-00001" in path.read_text(encoding="utf-8")


def test_remove_entries_with_no_ids_is_a_noop(tmp_path, monkeypatch) -> None:
    path = tmp_path / "waivers.yaml"
    path.write_text("# untouched\n", encoding="utf-8")
    assert render_waivers.remove_entries({"waivers": []}, [], path) == []
    assert path.read_text(encoding="utf-8") == "# untouched\n"
