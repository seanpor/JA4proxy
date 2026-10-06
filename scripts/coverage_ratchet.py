#!/usr/bin/env python3
"""
coverage_ratchet.py — Enforce monotonic coverage ratchet for Go and Python packages.

Usage:
  python3 scripts/coverage_ratchet.py check --lang (go|python) --profile <path> --baseline <path>
  python3 scripts/coverage_ratchet.py update --lang (go|python) --profile <path> --baseline <path>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Tuple

MODULE_PREFIX = "github.com/seanpor/ja4proxy/"
TOLERANCE_PP = 0.1  # Allow up to 0.1 percentage point drop for atomic jitter


def parse_go_coverage(profile_path: Path) -> Dict[str, float]:
    """Parse Go coverage profile (coverage.txt) and return per-package statement coverage percentages.

    De-duplicates blocks by (file, block_spec) taking maximum count.
    """
    # Key: (file_path, block_spec) -> (num_statements, max_count)
    blocks: Dict[Tuple[str, str], Tuple[int, int]] = {}

    with profile_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("mode:"):
                continue

            parts = line.split()
            if len(parts) != 3:
                continue

            block_ref, stmts_str, count_str = parts[0], parts[1], parts[2]
            try:
                num_stmts = int(stmts_str)
                count = int(count_str)
            except ValueError:
                continue

            if ":" in block_ref:
                file_path, block_spec = block_ref.split(":", 1)
            else:
                file_path, block_spec = block_ref, ""

            if file_path.startswith(MODULE_PREFIX):
                file_path = file_path[len(MODULE_PREFIX):]

            key = (file_path, block_spec)
            if key in blocks:
                existing_stmts, existing_count = blocks[key]
                blocks[key] = (existing_stmts, max(existing_count, count))
            else:
                blocks[key] = (num_stmts, count)

    # Aggregate by package directory (e.g. internal/tls, cmd/ja4pd)
    pkg_totals: Dict[str, int] = {}
    pkg_covered: Dict[str, int] = {}

    for (file_path, _), (num_stmts, count) in blocks.items():
        pkg_dir = str(Path(file_path).parent)
        pkg_totals[pkg_dir] = pkg_totals.get(pkg_dir, 0) + num_stmts
        if count > 0:
            pkg_covered[pkg_dir] = pkg_covered.get(pkg_dir, 0) + num_stmts

    results: Dict[str, float] = {}
    for pkg, total in pkg_totals.items():
        if total > 0:
            cov = (pkg_covered.get(pkg, 0) / total) * 100.0
            results[pkg] = round(cov, 2)

    return results


def parse_python_coverage(profile_path: Path) -> Dict[str, float]:
    """Parse Python coverage JSON report (coverage-python.json) and return per-package directory coverage percentages."""
    with profile_path.open(encoding="utf-8") as f:
        data = json.load(f)

    files_data = data.get("files", {})
    pkg_totals: Dict[str, int] = {}
    pkg_covered: Dict[str, int] = {}

    for file_path, f_info in files_data.items():
        summary = f_info.get("summary", {})
        num_stmts = summary.get("num_statements", 0)
        covered = summary.get("covered_lines", 0)

        # Aggregate by top two directory levels, e.g. management/api or src/analytics
        path_parts = Path(file_path).parts
        if len(path_parts) >= 2:
            pkg_dir = f"{path_parts[0]}/{path_parts[1]}"
        elif len(path_parts) == 1:
            pkg_dir = path_parts[0]
        else:
            continue

        pkg_totals[pkg_dir] = pkg_totals.get(pkg_dir, 0) + num_stmts
        pkg_covered[pkg_dir] = pkg_covered.get(pkg_dir, 0) + covered

    results: Dict[str, float] = {}
    for pkg, total in pkg_totals.items():
        if total > 0:
            cov = (pkg_covered.get(pkg, 0) / total) * 100.0
            results[pkg] = round(cov, 2)

    return results


def load_baseline(baseline_path: Path) -> dict:
    if not baseline_path.exists():
        return {"go": {}, "python": {}, "targets": {"internal/*": 95.0, "cmd/*": 85.0, "management/*": 90.0}}
    with baseline_path.open(encoding="utf-8") as f:
        return json.load(f)


def save_baseline(baseline_path: Path, data: dict) -> None:
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    with baseline_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def check_coverage(lang: str, current: Dict[str, float], baseline: dict) -> int:
    base_lang = baseline.get(lang, {})
    failures: list[str] = []

    for pkg, base_cov in sorted(base_lang.items()):
        if pkg not in current:
            print(f"  [WARN] Package '{pkg}' is in baseline ({base_cov:.1f}%) but missing from current profile.")
            continue

        curr_cov = current[pkg]
        if curr_cov < base_cov - TOLERANCE_PP:
            failures.append(
                f"  ✗ Package '{pkg}': current coverage {curr_cov:.2f}% dropped below baseline {base_cov:.2f}% (tolerance {TOLERANCE_PP} pp)"
            )

    if failures:
        print(f"Coverage ratchet CHECK FAILED for language '{lang}':\n", file=sys.stderr)
        for f in failures:
            print(f, file=sys.stderr)
        print("\nTo update baseline after intentional changes, run: make cover-update", file=sys.stderr)
        return 1

    print(f"Coverage ratchet OK for language '{lang}' ({len(current)} packages checked).")
    return 0


def update_baseline(lang: str, current: Dict[str, float], baseline: dict, baseline_path: Path) -> int:
    if lang not in baseline:
        baseline[lang] = {}

    base_lang = baseline[lang]
    updated_count = 0

    for pkg, curr_cov in sorted(current.items()):
        prev_cov = base_lang.get(pkg, 0.0)
        new_cov = max(prev_cov, curr_cov)
        if new_cov != prev_cov:
            updated_count += 1
        base_lang[pkg] = round(new_cov, 2)

    save_baseline(baseline_path, baseline)
    print(f"Coverage baseline updated for '{lang}': {updated_count} packages updated/added.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce coverage ratchet for Go and Python packages.")
    parser.add_argument("command", choices=["check", "update"], help="Action to perform")
    parser.add_argument("--lang", choices=["go", "python"], required=True, help="Language to evaluate")
    parser.add_argument("--profile", type=Path, required=True, help="Coverage profile path")
    parser.add_argument("--baseline", type=Path, required=True, help="Baseline JSON path")

    args = parser.parse_args()

    if not args.profile.exists():
        print(f"ERROR: profile file not found: {args.profile}", file=sys.stderr)
        return 1

    baseline = load_baseline(args.baseline)

    if args.lang == "go":
        current = parse_go_coverage(args.profile)
    else:
        current = parse_python_coverage(args.profile)

    if args.command == "check":
        return check_coverage(args.lang, current, baseline)
    else:
        return update_baseline(args.lang, current, baseline, args.baseline)


if __name__ == "__main__":
    sys.exit(main())
