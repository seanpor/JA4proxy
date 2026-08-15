"""
tests/unit/test_scan_exceptions.py

Unit tests for scripts/scan_exceptions.py -- Phase 812 (812-B).

Covers the --within-days flag added for the proactive .trivyignore renewal
workflow (trivyignore-renewal.yml): it must list entries expiring within N
days from --today (never from the entry's own old expiry, which is exactly
the drift bug the phase exists to avoid), and must always surface NO-EXP /
EXPIRED entries regardless of the window asked for.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add scripts/ to path so we can import the module directly
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import scan_exceptions  # noqa: E402


def _write_ignore(tmp_path: Path, content: str) -> Path:
    p = tmp_path / ".trivyignore"
    p.write_text(content, encoding="utf-8")
    return p


def test_within_days_excludes_far_future_entries(tmp_path, monkeypatch, capsys):
    ignore = _write_ignore(
        tmp_path,
        """\
# far away
CVE-2099-00001 exp:2099-01-01

# soon -- 5 days from 2026-08-04
CVE-2026-00002 exp:2026-08-09
""",
    )
    monkeypatch.setattr(scan_exceptions, "IGNORE_FILES", (("third-party", ignore),))
    rc = scan_exceptions.main(["--today", "2026-08-04", "--within-days", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE-2026-00002" in out
    assert "CVE-2099-00001" not in out


def test_within_days_always_includes_expired_and_no_exp(tmp_path, monkeypatch, capsys):
    ignore = _write_ignore(
        tmp_path,
        """\
# already expired, well outside any reasonable window
CVE-2026-00001 exp:2020-01-01

# no exp at all -- always a violation regardless of window
CVE-2026-00002
""",
    )
    monkeypatch.setattr(scan_exceptions, "IGNORE_FILES", (("third-party", ignore),))
    rc = scan_exceptions.main(["--today", "2026-08-04", "--within-days", "1"])
    out = capsys.readouterr().out
    assert rc == 1  # violations still fail the gate even in listing mode
    assert "CVE-2026-00001" in out
    assert "CVE-2026-00002" in out
    assert "EXPIRED" in out
    assert "NO-EXP" in out


def test_within_days_date_arithmetic_is_today_relative(tmp_path, monkeypatch, capsys):
    """The whole point of 812-B: renewal must compute from *today*, not the
    entry's own (soon-to-be-stale) exp: date. This test only asserts the
    reading side (--within-days correctly measures from --today); the
    renewal workflow itself is responsible for writing new exp: dates as
    today + 7d when it acts on this listing.
    """
    ignore = _write_ignore(
        tmp_path,
        """\
# exactly at the boundary of a 5-day window from 2026-08-04
CVE-2026-00003 exp:2026-08-09
""",
    )
    monkeypatch.setattr(scan_exceptions, "IGNORE_FILES", (("third-party", ignore),))

    # 5 days from 2026-08-04 to 2026-08-09 inclusive -> included
    rc = scan_exceptions.main(["--today", "2026-08-04", "--within-days", "5"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE-2026-00003" in out

    # 4 days from 2026-08-04 doesn't reach 2026-08-09 -> excluded
    rc = scan_exceptions.main(["--today", "2026-08-04", "--within-days", "4"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE-2026-00003" not in out


def test_without_within_days_preserves_existing_behavior(tmp_path, monkeypatch, capsys):
    ignore = _write_ignore(
        tmp_path,
        """\
# still valid
CVE-2026-00001 exp:2099-01-01
""",
    )
    monkeypatch.setattr(scan_exceptions, "IGNORE_FILES", (("third-party", ignore),))
    rc = scan_exceptions.main(["--today", "2026-08-04"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE-2026-00001" in out
    assert "all within their time window" in out


# ── expiry boundary: must match Trivy's semantics exactly ────────────────────
#
# Trivy suppresses a finding only while `today < exp`. An entry whose exp: IS
# today is ALREADY expired — trivy reports it and `make scan` fails.
# Verified empirically against aquasec/trivy:0.71.0 on 2026-08-10:
#     exp:2026-08-09 (yesterday) -> reported
#     exp:2026-08-10 (today)     -> reported      <-- the boundary
#     exp:2026-08-11 (tomorrow)  -> suppressed
#
# This script previously treated d == 0 as still-valid, so it exited 0 and
# printed "all within their time window" while `make scan` was red. That is how
# the 2026-08-10 cliff (~40 entries) reached a release run with no warning.


def test_entry_expiring_today_is_expired_not_soon(tmp_path, monkeypatch, capsys):
    """exp: == today must report EXPIRED and exit non-zero — trivy already fails it."""
    ignore = _write_ignore(
        tmp_path,
        """\
# expires today -- trivy stops ignoring this at 00:00
CVE-2026-00002 exp:2026-08-10
""",
    )
    monkeypatch.setattr(scan_exceptions, "IGNORE_FILES", (("third-party", ignore),))
    rc = scan_exceptions.main(["--today", "2026-08-10"])
    out = capsys.readouterr().out

    assert "EXPIRED" in out, "an entry expiring today must be flagged EXPIRED"
    assert "SOON" not in out, "d == 0 must not be reported as merely SOON"
    assert rc != 0, (
        "exit code must be non-zero so CI fails on the same day trivy does; "
        "exiting 0 here is what let the expiry cliff pass unnoticed"
    )


def test_entry_expiring_tomorrow_is_still_valid(tmp_path, monkeypatch, capsys):
    """exp: == today+1 is the last still-suppressed day — must not be EXPIRED."""
    ignore = _write_ignore(
        tmp_path,
        """\
# expires tomorrow -- trivy still ignores this today
CVE-2026-00003 exp:2026-08-11
""",
    )
    monkeypatch.setattr(scan_exceptions, "IGNORE_FILES", (("third-party", ignore),))
    rc = scan_exceptions.main(["--today", "2026-08-10"])
    out = capsys.readouterr().out

    assert "EXPIRED" not in out
    assert rc == 0
