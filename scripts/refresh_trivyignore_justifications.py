#!/usr/bin/env python3
"""Regenerate the "carried by" line on each .trivyignore entry from scan data.

Phase 829b.

WHY THIS EXISTS
---------------
18 of the 56 third-party exceptions claimed to cover `promtail:3.6.11` (removed
in phase-825), `grafana:13.0.4-ubuntu` (now 13.0.6) and
`prom/haproxy-exporter:v0.15.0` (retired in phase-820) — images not present in
the deployment at all. Several read "both already on newest stable tag" about
two images that were not deployed.

The waivers themselves were correct: the CVEs are genuinely present. What had
rotted was the stated REASON, which is the entire point of a *justified*
exception. A reviewer trusting that text was being told the waiver covered
something it did not.

They were rewritten by hand on 2026-08-19 (#459). Nothing stopped them rotting
again, because the claim is prose about image versions and image versions move.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It rewrites the CARRIER CLAIM only — the machine-checkable half.

The "why not exploitable here" reasoning underneath is a human judgement about
OUR deployment ("cadvisor is an internal-only metrics sidecar with no host port
published"), and no scanner knows that. Generating it would produce confident
text nobody had thought about, which is worse than stale text someone once did.

The file's dated history sections are also left alone. They record what was true
at the time; regenerating them would falsify the record.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List, Sequence

# Imported as a package member so this works both as `python3 scripts/x.py`
# and as `from scripts.x import ...` in tests.
try:
    from scripts.check_trivyignore_drift import _ENTRY, scan_dir_findings
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_trivyignore_drift import _ENTRY, scan_dir_findings

_ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY_IGNORE = _ROOT / ".trivyignore.third-party"

# The generated block. Recognised by this marker on re-runs so the script is
# idempotent instead of stacking a new claim on every invocation.
MARKER = "# Carriers (generated"

# Lines that begin the human reasoning. The generator stops at the first of
# these and never touches anything from there down.
HUMAN_SECTIONS = (
    "# Why not exploitable",
    "# Why not applicable",
    "# Re-review",
    "# ⚠",
    "# Note:",
)

# A claim line the generator owns and may replace.
OWNED_PREFIXES = ("# Why no fix:", MARKER)


def build_claim(cve: str, carriers: Sequence[str], date: str) -> List[str]:
    """The generated carrier block for one entry."""
    if carriers:
        who = ", ".join(sorted(carriers))
        # Measure the WHOLE line, not just the carrier list. Comparing `who`
        # alone ignored the ~30-character marker prefix and emitted a
        # 103-column line.
        single = f"{MARKER} {date}): {who}."
        lines = [single] if len(single) <= 79 else [f"{MARKER} {date}):"]
        if len(single) > 79:
            # Wrap long carrier lists rather than emitting a 200-column line.
            current = "#   "
            for name in sorted(carriers):
                piece = name + ", "
                if len(current) + len(piece) > 76:
                    lines.append(current.rstrip())
                    current = "#   "
                current += piece
            lines.append(current.rstrip().rstrip(","))
        lines.append(
            "# Each is a pinned third-party image we cannot rebuild, so the fix"
        )
        lines.append(
            "# only reaches us when the publisher ships a new tag."
        )
        return lines
    return [
        f"{MARKER} {date}): NO deployed image carries this any more.",
        "# This entry is DEAD and can be deleted — see check_trivyignore_drift.py.",
    ]


def refresh(text: str, carriers_by_cve: Dict[str, List[str]], date: str) -> str:
    """Rewrite the carrier claim above every entry line.

    Walks the file, and for each entry line rewrites the owned lines in the
    comment block directly above it, leaving everything else byte-identical.
    """
    lines = text.split("\n")
    out: List[str] = []

    for line in lines:
        m = _ENTRY.match(line.strip())
        if not m:
            out.append(line)
            continue

        cve = m.group("id")

        # Find this entry's comment block: contiguous '#' lines directly above.
        start = len(out)
        while start > 0 and out[start - 1].startswith("#"):
            start -= 1
        block = out[start:]

        # Split into the part the generator owns and the human part.
        #
        # `in_owned` is explicit state, not a look-back at the last KEPT line.
        # Peeking at kept[-1] cannot work: once an owned line is skipped it is
        # never in `kept`, so the continuation lines beneath it looked
        # unowned, survived, and a fresh claim was appended above them — the
        # file grew by two lines per entry per run. Caught by the idempotency
        # test, which is exactly what that test is for.
        kept: List[str] = []
        i = 0
        in_owned = False
        while i < len(block):
            b = block[i]
            if b.startswith(HUMAN_SECTIONS):
                break
            if b.startswith(OWNED_PREFIXES):
                in_owned = True
                i += 1
                continue
            if in_owned and b.startswith("#"):
                i += 1
                continue
            in_owned = False
            kept.append(b)
            i += 1
        human = block[i:]

        rebuilt = kept + build_claim(cve, carriers_by_cve.get(cve, []), date) + human
        out[start:] = rebuilt
        out.append(line)

    return "\n".join(out)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", type=Path, required=True)
    parser.add_argument("--ignorefile", type=Path, default=THIRD_PARTY_IGNORE)
    parser.add_argument("--date", default="", help="stamp (default: today)")
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the file would change, without writing",
    )
    args = parser.parse_args(argv)

    if not args.date:
        from datetime import date as _date

        args.date = _date.today().isoformat()

    try:
        _severity, carriers = scan_dir_findings(args.scan_dir)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    original = args.ignorefile.read_text(encoding="utf-8")
    updated = refresh(original, carriers, args.date)

    if updated == original:
        print("Carrier claims already match the scan data.")
        return 0

    if args.check:
        print("✗ carrier claims are stale — run without --check to regenerate.")
        return 1

    args.ignorefile.write_text(updated, encoding="utf-8")
    print(f"Regenerated carrier claims in {args.ignorefile.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
