"""
tests/unit/test_renew_trivyignore.py

Unit tests for scripts/renew_trivyignore.py.

Phase 812 (812-B) origin; reworked for Phase 847a when the ignorefiles became
generated from security/waivers.yaml — the renewal now mutates the registry and
re-renders, rather than rewriting the .trivyignore.* files in place.
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import render_waivers  # noqa: E402
import renew_trivyignore  # noqa: E402


def _registry(*entries):
    return {"version": 1, "policy": {"max_window_days": 90}, "waivers": list(entries)}


def _entry(cve, expires, source="trivy"):
    return {
        "id": cve,
        "scope": "third-party",
        "severity": "HIGH",
        "source": source,
        "carriers": ["example:1.0"],
        "rationale": "test",
        "created": "2026-01-01",
        "expires": expires,
    }


def test_renews_only_entries_within_window():
    reg = _registry(
        _entry("CVE-2099-00001", "2099-01-01"),
        _entry("CVE-2026-00002", "2026-08-09"),
    )
    n = render_waivers.renew_expiring(reg, within_days=5, days=7, today=date(2026, 8, 4))
    assert n == 1
    by_id = {w["id"]: w for w in reg["waivers"]}
    assert by_id["CVE-2099-00001"]["expires"] == "2099-01-01"  # untouched
    assert by_id["CVE-2026-00002"]["expires"] == "2026-08-11"  # today + 7d
    assert by_id["CVE-2026-00002"]["created"] == "2026-08-04"  # window start moved


def test_renewal_date_is_today_plus_n_not_old_exp_plus_n():
    """The whole point: renewing a long-overdue entry must not compound its
    already-passed old expiry — it is always today + renew_days.
    """
    reg = _registry(_entry("CVE-2026-00001", "2020-01-01"))
    render_waivers.renew_expiring(reg, within_days=5, days=7, today=date(2026, 8, 4))
    w = reg["waivers"][0]
    assert w["expires"] == "2026-08-11"  # today + 7d, not 2020-01-08


def test_pip_audit_entries_are_not_touched():
    """pip-audit ignores are rendered without an expiry; renewal must skip them."""
    reg = _registry(_entry("CVE-2026-99999", "2020-01-01", source="pip-audit"))
    n = render_waivers.renew_expiring(reg, within_days=5, days=7, today=date(2026, 8, 4))
    assert n == 0
    assert reg["waivers"][0]["expires"] == "2020-01-01"


def test_idempotent_when_nothing_in_window():
    reg = _registry(_entry("CVE-2026-00001", "2099-01-01"))
    n = render_waivers.renew_expiring(reg, within_days=5, days=7, today=date(2026, 8, 4))
    assert n == 0


def test_main_reports_nothing_to_renew(tmp_path, capsys):
    reg_path = tmp_path / "waivers.yaml"
    import yaml

    reg_path.write_text(
        yaml.safe_dump(
            _registry(_entry("CVE-2026-00001", "2099-01-01")), sort_keys=False
        ),
        encoding="utf-8",
    )
    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5", "--registry", str(reg_path)]
    )
    assert rc == 0
    assert "nothing to renew" in capsys.readouterr().out


def test_main_renews_within_window(tmp_path, monkeypatch, capsys):
    """End-to-end: a near-expiry entry is bumped in the registry AND the derived
    files are re-rendered from it.
    """
    import yaml

    reg_path = tmp_path / "waivers.yaml"
    reg_path.write_text(
        yaml.safe_dump(
            _registry(_entry("CVE-2026-00001", "2026-08-09")), sort_keys=False
        ),
        encoding="utf-8",
    )
    third = tmp_path / ".trivyignore.third-party"
    first = tmp_path / ".trivyignore.first-party"
    pip = tmp_path / ".pip-audit-ignores"
    # Patch the module object renew_trivyignore actually resolves (it may be
    # scripts.render_waivers, not a top-level render_waivers import — patching
    # the wrong module object would silently not take effect).
    rw = renew_trivyignore.render_waivers
    monkeypatch.setattr(rw, "THIRD_PARTY_IGNORE", third)
    monkeypatch.setattr(rw, "FIRST_PARTY_IGNORE", first)
    monkeypatch.setattr(rw, "PIP_AUDIT_IGNORES", pip)

    rc = renew_trivyignore.main(
        ["--today", "2026-08-04", "--within-days", "5", "--days", "7",
         "--registry", str(reg_path)]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Renewed 1 exception(s)" in out
    assert "REVIEWER:" in out
    assert "2026-08-09 -> 2026-08-11" in out
    reloaded = render_waivers.load_registry(reg_path)
    assert reloaded["waivers"][0]["expires"] == "2026-08-11"
    assert "CVE-2026-00001 exp:2026-08-11" in third.read_text(encoding="utf-8")
