#!/usr/bin/env python3
"""Renew soon-to-expire .trivyignore exceptions (Phase 812, 812-B).

Mechanically bumps the `exp:` date of every entry expiring within
--within-days (default 5) to `today + 7 days` -- computed from *today*,
never from the entry's own (soon-to-be-stale) old expiry, which is exactly
the drift that would let the Phase 226 7-day maximum window creep longer
through repeated renewals.

Deliberately does NOT attempt to decide whether a newer upstream image tag
exists and clears the CVE -- that judgment call (comparing total CVE counts,
checking for regressions, the same process used manually every time this
came up) stays with the human reviewing the PR this script's output feeds
into. Automating tag discovery across Docker Hub, GCR, and whatever
registries future images use is real, ongoing maintenance surface for a
question a human can answer in the same PR review anyway; not worth it for
a first version. See docs/phases/PHASE_812.md's 812-B section.

Prints a summary of what changed (for the calling workflow's PR body) and
exits 0 if nothing needed renewal, 1 on error. Idempotent: re-running with
nothing newly in the window is a no-op.
"""
from __future__ import annotations

import re
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

IGNORE = Path(__file__).resolve().parents[1] / ".trivyignore"
ENTRY_LINE = re.compile(
    r"^(?P<id>CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})"
    r"\s+exp:(?P<exp>\d{4}-\d{2}-\d{2})\s*$"
)


def renew(text: str, today: date, within_days: int) -> tuple[str, list[str]]:
    """Return (new_text, renewed_ids). Only rewrites the exp: date on
    matching lines; every other line (including comments, blank lines,
    NO-EXP entries which are policy violations to fix by hand, not renew)
    is left byte-for-byte untouched.
    """
    new_exp = (today + timedelta(days=7)).isoformat()
    renewed: list[str] = []
    out_lines = []
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        m = ENTRY_LINE.match(stripped)
        if m:
            days = (datetime.strptime(m.group("exp"), "%Y-%m-%d").date() - today).days
            if days <= within_days:
                out_lines.append(f"{m.group('id')} exp:{new_exp}\n")
                renewed.append(m.group("id"))
                continue
        out_lines.append(line)
    return "".join(out_lines), renewed


def main(argv: list[str]) -> int:
    today = date.today()
    if "--today" in argv:
        today = datetime.strptime(argv[argv.index("--today") + 1], "%Y-%m-%d").date()
    within_days = 5
    if "--within-days" in argv:
        within_days = int(argv[argv.index("--within-days") + 1])

    if not IGNORE.exists():
        print("No .trivyignore file — nothing to renew.")
        return 0

    text = IGNORE.read_text(encoding="utf-8")
    new_text, renewed = renew(text, today, within_days)

    if not renewed:
        print(f"No exceptions expiring within {within_days} day(s) — nothing to renew.")
        return 0

    IGNORE.write_text(new_text, encoding="utf-8")
    new_exp = (today + timedelta(days=7)).isoformat()
    print(f"Renewed {len(renewed)} exception(s) to exp:{new_exp}:")
    for cve in renewed:
        print(f"  - {cve}")
    print(
        "\nREVIEWER: verify no newer upstream image tag clears each CVE above "
        "before merging (compare total CVE counts the same way past renewals "
        "have — see docs/runbooks/security_scan_exceptions.md). This script "
        "only renews the time window; it does not check for a real fix."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
