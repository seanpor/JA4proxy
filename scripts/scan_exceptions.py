#!/usr/bin/env python3
"""List Trivy scan exceptions (.trivyignore) with days-to-expiry.

Operator helper (Phase 226). Shows every justified, time-windowed exception,
its expiry, days remaining, and the justification comment; flags entries that
are EXPIRED or that have no `exp:` date (both policy violations) and exits
non-zero so they cannot be quietly forgotten.

Dependency-free (stdlib only), like the other Makefile guards.
Optional `--today YYYY-MM-DD` for deterministic testing.

Phase 812 (812-B): `--within-days N` filters the listing to entries expiring
within N days from today (inclusive; already-expired entries, negative days,
are always included too) instead of every entry. Used by
.github/workflows/trivyignore-renewal.yml to find exceptions worth renewing
*before* they expire, rather than reacting the same day a same-batch cliff
takes out Security Scan on every open PR. Renewal dates computed from this
listing must always be `today + 7d`, never `old_exp + 7d` -- see that
workflow and PHASE_812.md for why (repeated mechanical renewal must not let
the Phase 226 7-day maximum silently drift longer).
"""
from __future__ import annotations

import re
import sys
from datetime import date, datetime
from pathlib import Path

IGNORE = Path(__file__).resolve().parents[1] / ".trivyignore"
ENTRY = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})(?:\s+exp:(\d{4}-\d{2}-\d{2}))?\s*$")


def parse(text: str):
    entries, comment = [], []
    for ln in text.splitlines():
        s = ln.strip()
        if not s:
            comment = []  # blank line ends a comment block
        elif s.startswith("#"):
            comment.append(s.lstrip("#").strip())
        else:
            m = ENTRY.match(s)
            if m:
                just = " ".join(c for c in comment if c)
                entries.append((m.group(1), m.group(2), just))
            else:
                comment = []
    return entries


def main(argv: list[str]) -> int:
    today = date.today()
    if "--today" in argv:
        today = datetime.strptime(argv[argv.index("--today") + 1], "%Y-%m-%d").date()
    within_days: int | None = None
    if "--within-days" in argv:
        within_days = int(argv[argv.index("--within-days") + 1])
    if not IGNORE.exists():
        print("No .trivyignore file — no scan exceptions.")
        return 0
    entries = parse(IGNORE.read_text(encoding="utf-8"))
    if not entries:
        print("No scan exceptions defined in .trivyignore.")
        return 0

    print(f"{'CVE':<18} {'EXPIRES':<12} {'DAYS':>5}  {'STATUS':<8} JUSTIFICATION")
    print("-" * 78)
    violations = 0
    shown = 0
    for cve, exp, just in entries:
        if not exp:
            status, days, d = "NO-EXP", "  -", None
        else:
            d = (datetime.strptime(exp, "%Y-%m-%d").date() - today).days
            days = str(d)
            if d < 0:
                status = "EXPIRED"
            elif d <= 3:
                status = "SOON"
            else:
                status = "ok"

        # --within-days N: only show entries expiring within N days from
        # today (always includes NO-EXP/EXPIRED, since those need action
        # regardless of the window asked for).
        if within_days is not None and d is not None and d > within_days:
            continue

        if status in ("NO-EXP", "EXPIRED"):
            violations += 1
        shown += 1
        print(f"{cve:<18} {exp or '(none)':<12} {days:>5}  {status:<8} {just[:90]}")

    print("-" * 78)
    if violations:
        print(
            f"\n✗ {violations} exception(s) EXPIRED or missing exp: date. "
            "Re-justify (extend exp:, max +7d) or remove (prefer a real fix)."
        )
        return 1
    if within_days is not None:
        print(f"\n✓ {shown} exception(s) expiring within {within_days} day(s).")
        return 0
    print(f"\n✓ {len(entries)} exception(s), all within their time window.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
