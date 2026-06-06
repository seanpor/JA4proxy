#!/usr/bin/env python3
"""List Trivy scan exceptions (.trivyignore) with days-to-expiry.

Operator helper (Phase 226). Shows every justified, time-windowed exception,
its expiry, days remaining, and the justification comment; flags entries that
are EXPIRED or that have no `exp:` date (both policy violations) and exits
non-zero so they cannot be quietly forgotten.

Dependency-free (stdlib only), like the other Makefile guards.
Optional `--today YYYY-MM-DD` for deterministic testing.
"""
from __future__ import annotations

import re
import sys
from datetime import date, datetime
from pathlib import Path

IGNORE = Path(__file__).resolve().parents[1] / ".trivyignore"
ENTRY = re.compile(r"^(CVE-\d{4}-\d+)(?:\s+exp:(\d{4}-\d{2}-\d{2}))?\s*$")


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
    for cve, exp, just in entries:
        if not exp:
            status, days = "NO-EXP", "  -"
            violations += 1
        else:
            d = (datetime.strptime(exp, "%Y-%m-%d").date() - today).days
            days = str(d)
            if d < 0:
                status = "EXPIRED"
                violations += 1
            elif d <= 3:
                status = "SOON"
            else:
                status = "ok"
        print(f"{cve:<18} {exp or '(none)':<12} {days:>5}  {status:<8} {just[:90]}")

    print("-" * 78)
    if violations:
        print(
            f"\n✗ {violations} exception(s) EXPIRED or missing exp: date. "
            "Re-justify (extend exp:, max +14d) or remove (prefer a real fix)."
        )
        return 1
    print(f"\n✓ {len(entries)} exception(s), all within their time window.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
