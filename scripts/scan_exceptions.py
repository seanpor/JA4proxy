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

_ROOT = Path(__file__).resolve().parents[1]

# phase-822: `.trivyignore` was split so a waiver for a third-party sidecar can
# never silently cover a finding in an image we build. Both files are reported
# here, tagged, because a single combined count hid exactly that confusion.
IGNORE_FILES = (
    ("first-party", _ROOT / ".trivyignore.first-party"),
    ("third-party", _ROOT / ".trivyignore.third-party"),
)
# Retained so a stale checkout with the old single file still reports rather
# than silently claiming zero exceptions.
LEGACY_IGNORE = _ROOT / ".trivyignore"

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
    sources = [(scope, p) for scope, p in IGNORE_FILES if p.exists()]
    if not sources and LEGACY_IGNORE.exists():
        sources = [("legacy", LEGACY_IGNORE)]
    if not sources:
        print("No .trivyignore.{first,third}-party file — no scan exceptions.")
        return 0

    entries = []
    per_scope: dict[str, int] = {}
    for scope, path in sources:
        found = parse(path.read_text(encoding="utf-8"))
        per_scope[scope] = len(found)
        entries.extend((cve, exp, just, scope) for cve, exp, just in found)
    if not entries:
        print("No scan exceptions defined.")
        return 0

    print(f"{'CVE':<18} {'SCOPE':<12} {'EXPIRES':<12} {'DAYS':>5}  {'STATUS':<8} JUSTIFICATION")
    print("-" * 92)
    violations = 0
    shown = 0
    for cve, exp, just, scope in entries:
        if not exp:
            status, days, d = "NO-EXP", "  -", None
        else:
            d = (datetime.strptime(exp, "%Y-%m-%d").date() - today).days
            days = str(d)
            # Trivy ignores a finding only while `today < exp`, so an entry
            # whose exp: IS today (d == 0) is ALREADY expired — trivy reports
            # it and `make scan` fails. Verified against aquasec/trivy:0.71.0:
            # exp:today -> reported, exp:tomorrow -> suppressed.
            # Treating d == 0 as still-valid (the pre-2026-08-10 behaviour) made
            # this script exit 0 while `make scan` was red, which is how the
            # 2026-08-10 expiry cliff reached a release run unannounced.
            if d <= 0:
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
        print(f"{cve:<18} {scope:<12} {exp or '(none)':<12} {days:>5}  {status:<8} {just[:78]}")

    print("-" * 92)
    breakdown = ", ".join(f"{n} {scope}" for scope, n in sorted(per_scope.items()))
    if violations:
        print(
            f"\n✗ {violations} exception(s) EXPIRED or missing exp: date. "
            "Re-justify (extend exp:, max +7d) or remove (prefer a real fix)."
        )
        return 1
    if within_days is not None:
        print(f"\n✓ {shown} exception(s) expiring within {within_days} day(s).")
        return 0
    print(f"\n✓ {len(entries)} exception(s) ({breakdown}), all within their time window.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
