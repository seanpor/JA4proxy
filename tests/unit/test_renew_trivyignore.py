"""
tests/unit/test_renew_trivyignore.py

Unit tests for scripts/renew_trivyignore.py -- Phase 812 (812-B).
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import renew_trivyignore  # noqa: E402


def test_renews_only_entries_within_window():
    text = (
        "# far away\n"
        "CVE-2099-00001 exp:2099-01-01\n"
        "\n"
        "# soon\n"
        "CVE-2026-00002 exp:2026-08-09\n"
    )
    new_text, renewed = renew_trivyignore.renew(text, date(2026, 8, 4), within_days=5)
    assert renewed == ["CVE-2026-00002"]
    assert "CVE-2099-00001 exp:2099-01-01" in new_text  # untouched
    assert "CVE-2026-00002 exp:2026-08-11" in new_text  # today (08-04) + 7d


def test_renewal_date_is_today_plus_7_not_old_exp_plus_7():
    """The whole point of this script: renewing a long-overdue entry must
    not compound its already-passed old exp: date -- it's always today+7d.
    """
    text = "CVE-2026-00001 exp:2020-01-01\n"  # wildly expired
    new_text, renewed = renew_trivyignore.renew(text, date(2026, 8, 4), within_days=5)
    assert renewed == ["CVE-2026-00001"]
    assert "exp:2026-08-11" in new_text  # today+7d, not 2020-01-08
    assert "2020" not in new_text


def test_no_exp_entries_are_never_touched():
    """NO-EXP entries are a policy violation to fix by hand (add a real
    exp: date and justification), not something this script should
    silently paper over by inventing one.
    """
    text = "CVE-2026-00001\n"
    new_text, renewed = renew_trivyignore.renew(text, date(2026, 8, 4), within_days=5)
    assert renewed == []
    assert new_text == text


def test_comments_and_blank_lines_are_preserved_verbatim():
    text = (
        "# Justification block\n"
        "# spanning multiple lines\n"
        "CVE-2026-00001 exp:2026-08-09\n"
        "\n"
        "# Another one\n"
        "CVE-2026-00002 exp:2099-01-01\n"
    )
    new_text, renewed = renew_trivyignore.renew(text, date(2026, 8, 4), within_days=5)
    assert renewed == ["CVE-2026-00001"]
    assert "# Justification block\n# spanning multiple lines\n" in new_text
    assert "# Another one\n" in new_text
    assert "CVE-2026-00002 exp:2099-01-01" in new_text


def test_idempotent_when_nothing_in_window():
    text = "CVE-2026-00001 exp:2099-01-01\n"
    new_text, renewed = renew_trivyignore.renew(text, date(2026, 8, 4), within_days=5)
    assert renewed == []
    assert new_text == text


def test_main_writes_file_and_reports_summary(tmp_path, monkeypatch, capsys):
    ignore = tmp_path / ".trivyignore"
    ignore.write_text("CVE-2026-00001 exp:2026-08-09\n", encoding="utf-8")
    monkeypatch.setattr(renew_trivyignore, "IGNORE_FILES", (ignore,))
    rc = renew_trivyignore.main(["--today", "2026-08-04", "--within-days", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Renewed 1 exception(s)" in out
    assert "REVIEWER:" in out
    assert "exp:2026-08-11" in ignore.read_text(encoding="utf-8")


def test_main_no_changes_when_nothing_in_window(tmp_path, monkeypatch, capsys):
    ignore = tmp_path / ".trivyignore"
    original = "CVE-2026-00001 exp:2099-01-01\n"
    ignore.write_text(original, encoding="utf-8")
    monkeypatch.setattr(renew_trivyignore, "IGNORE_FILES", (ignore,))
    rc = renew_trivyignore.main(["--today", "2026-08-04", "--within-days", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "nothing to renew" in out
    assert ignore.read_text(encoding="utf-8") == original
