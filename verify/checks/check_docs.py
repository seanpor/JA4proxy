#!/usr/bin/env python3
"""check_docs.py — document-integrity checks for the llm-reframing series.

Runs as golden-battery fixtures so the docs' own consistency is enforced
by the correctness gates:

  --mode index   series file set is complete (00-README + 01..17 + SUMMARY +
                 PRACTICAL-GUIDE) and the README table lists every file
  --mode links   every internal markdown link resolves to an existing file
  --mode next    the 01 -> ... -> 17 reading chain is unbroken
  --mode all     run all modes (default)

Exit 0 = pass, 1 = fail (prints the defects).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERIES = ROOT / "llm-reframing"

NUMERIC_RE = re.compile(r"^(\d{2})-.*\.md$")
LINK_RE = re.compile(r"\]\(([^)#]+?\.md)(?:#[^)]*)?\)")

EXTRA_FILES = ("SUMMARY.md", "PRACTICAL-GUIDE.md")


def numeric_files() -> dict[int, Path]:
    out: dict[int, Path] = {}
    for p in SERIES.glob("*.md"):
        m = NUMERIC_RE.match(p.name)
        if m:
            out[int(m.group(1))] = p
    return out


def mode_index() -> list[str]:
    defects: list[str] = []
    nums = numeric_files()
    want = set(range(0, 18))
    have = set(nums)
    if have != want:
        defects.append(f"series numbering incomplete: missing {sorted(want - have)}, "
                       f"unexpected {sorted(have - want)}")
    for extra in EXTRA_FILES:
        if not (SERIES / extra).is_file():
            defects.append(f"expected file missing: llm-reframing/{extra}")
    readme = (SERIES / "00-README.md")
    if not readme.is_file():
        defects.append("missing 00-README.md (series index)")
        return defects
    body = readme.read_text(encoding="utf-8")
    listed = set(re.findall(r"\]\(([^)#]+?\.md)", body))
    for p in SERIES.glob("*.md"):
        if p.name != readme.name and p.name not in listed:
            defects.append(f"00-README.md table does not reference {p.name}")
    return defects


def mode_links() -> list[str]:
    defects: list[str] = []
    for p in sorted(SERIES.glob("*.md")):
        for target in LINK_RE.findall(p.read_text(encoding="utf-8")):
            if target.startswith("http"):
                continue
            resolved = (p.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                defects.append(f"{p.name}: link escapes repo: {target}")
                continue
            if not resolved.is_file():
                defects.append(f"{p.name}: broken link -> {target}")
    return defects


def mode_next() -> list[str]:
    defects: list[str] = []
    nums = numeric_files()
    for n in range(1, 17):
        cur = nums.get(n)
        nxt = nums.get(n + 1)
        if cur is None or nxt is None:
            continue
        if f"]({nxt.name})" not in cur.read_text(encoding="utf-8"):
            defects.append(f"{cur.name}: missing Next link to {nxt.name}")
    end = nums.get(17)
    if end is not None and "End of series" not in end.read_text(encoding="utf-8"):
        defects.append(f"{end.name}: missing 'End of series' marker")
    return defects


MODES = {"index": mode_index, "links": mode_links, "next": mode_next}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", default="all", help="one of: all, index, links, next")
    args = ap.parse_args()
    chosen = [args.mode] if args.mode != "all" else list(MODES)
    defects: list[str] = []
    for mode in chosen:
        defects.extend(MODES[mode]())
    if defects:
        print(f"check_docs ({', '.join(chosen)}): {len(defects)} defect(s):")
        for d in defects:
            print(f"  - {d}")
        return 1
    print(f"check_docs ({', '.join(chosen)}): OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
