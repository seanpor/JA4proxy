#!/usr/bin/env python3
"""Diff `docs/phases/manifest.yaml` between two revisions, at the YAML level.

Written to test one specific hypothesis from the interim review of Phase 867: that
the 867 merge had destroyed a pre-existing sub-phase entry (`245.1`) because the
unquoted key `245.10` parses as the float `245.1`. That hypothesis is FALSE, and
this script is the evidence: the merge adds exactly one key and changes nothing else.

It also dumps the manifest's numeric-looking keys, because the *latent* hazard is
real even though it has not fired: an unquoted `245.1` and `245.10` collide.

Usage:
    python3 manifest_diff.py [BEFORE_REV] [AFTER_REV]
        defaults: origin/main~1  origin/main
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

MANIFEST = "docs/phases/manifest.yaml"


def show(rev: str) -> str:
    proc = subprocess.run(
        ["git", "show", f"{rev}:{MANIFEST}"], capture_output=True, text=True, check=True
    )
    return proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("before", nargs="?", default="origin/main~1")
    ap.add_argument("after", nargs="?", default="origin/main")
    args = ap.parse_args()

    before = yaml.safe_load(show(args.before))["phases"]
    after = yaml.safe_load(show(args.after))["phases"]

    print(f"BEFORE {args.before}: {len(before)} phase keys")
    print(f"AFTER  {args.after}: {len(after)} phase keys")
    print("ADDED  :", sorted(k for k in after if k not in before))
    print("REMOVED:", sorted(k for k in before if k not in after))
    changed = [k for k in before if k in after and before[k] != after[k]]
    print("CHANGED:", changed)
    for k in changed:
        fields = sorted(set(before[k]) | set(after[k]))
        for f in fields:
            if before[k].get(f) != after[k].get(f):
                print(f"  {k}.{f}")
                print(f"    before: {str(before[k].get(f))[:160]}")
                print(f"    after : {str(after[k].get(f))[:160]}")

    # The unquoted-decimal-key hazard, demonstrated on the live file.
    numeric = [k for k in after if isinstance(k, float)]
    print(f"\nUnquoted float-valued phase keys in {MANIFEST}: "
          f"{sorted(numeric, key=float)}")
    demo = yaml.safe_load("phases:\n  245.1: {name: step eleven}\n"
                          "  245.10: {name: step twelve}\n")["phases"]
    print("Demonstration of the collision (`245.1` + `245.10` in one mapping):")
    print("  yaml.safe_load(...)", "->", demo)
    print("  -> two entries become one; the first value is silently discarded.")

    # Duplicate raw keys anywhere under `phases:` (PyYAML also silently keeps last).
    text = show(args.after)
    try:
        tree = yaml.compose(text)  # node-level view: duplicates are still visible
    except yaml.YAMLError as exc:  # pragma: no cover
        print(f"yaml.compose failed: {exc}")
        return 1

    dupes: list[str] = []

    def walk(node) -> None:
        if isinstance(node, yaml.MappingNode):
            seen: dict[str, int] = {}
            for key, _value in node.value:
                k = key.value if isinstance(key, yaml.ScalarNode) else "?"
                seen[k] = seen.get(k, 0) + 1
            for k, n in seen.items():
                if n > 1:
                    dupes.append(f"{k} (x{n})")
            for _k, val in node.value:
                walk(val)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                walk(item)

    walk(tree)
    print("\nDuplicate mapping keys visible at the node level:", dupes or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
