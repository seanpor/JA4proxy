#!/usr/bin/env python3
"""Extract and run the GATE verification commands from the Phase 867 phase doc.

Mechanical extraction beats hand-transcription: the transcript this produces runs
byte-identical commands to the ones committed in `docs/phases/complete/PHASE_867.md`
(which is checked out alongside this file as `source_Phase_867_phase_doc.md`).

This is the re-audit's GATE-1..GATE-9 evidence. GATE-10 (`make preflight`) is not
re-run here; its transcript is in `preflight_main.transcript.txt` and is far more
expensive to reproduce.

Usage:
    python3 extract_and_run_gates.py            # run GATE-1..GATE-9
    python3 extract_and_run_gates.py --list     # print commands, run nothing
    python3 extract_and_run_gates.py --only 1 4 # run selected gates

Exit code: 0 if every executed gate exits 0, else 1.
"""

from __future__ import annotations

import argparse
import datetime
import platform
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOC = HERE / "source_Phase_867_phase_doc.md"

REPORT_REL = "docs/reports/PERFORMANCE_HARNESS_REVIEW.md"


def split_cells(row: str) -> list[str]:
    """Split a markdown table row on `|` outside code spans and outside escapes.

    GATE-1's command contains literal `\\|` inside a backtick code span, so a naive
    `row.split("|")` shreds that row and the gate silently disappears from the
    transcript. Scanning with code-span state is the only safe way.
    """
    cells: list[str] = []
    buf: list[str] = []
    in_code = False
    prev_backslash = False
    for ch in row.strip().strip("|"):
        if ch == "`" and not prev_backslash:
            in_code = not in_code
        if ch == "|" and not in_code and not prev_backslash:
            cells.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        prev_backslash = ch == "\\" and not prev_backslash
    cells.append("".join(buf).strip())
    return cells


def extract() -> list[dict[str, object]]:
    """Parse the acceptance table into {number, command, expectation}.

    The verification command is always the second-to-last cell. A `.*?` between
    pipes over-captures, because criterion cells also contain inline code spans
    (GATE-2's criterion names `GoodBlocked` and HTTP 403).
    """
    if not DOC.exists():
        raise SystemExit(f"ERROR: {DOC} not found")
    gates: list[dict[str, object]] = []
    for line in DOC.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| **GATE-"):
            continue
        cells = split_cells(line)
        if len(cells) < 5:
            continue
        num = re.match(r"\*\*GATE-(\d+)\*\*", cells[0])
        if not num:
            continue
        cmd_cell = cells[-2]
        if not (cmd_cell.startswith("`") and cmd_cell.endswith("`")):
            continue
        gates.append(
            {
                "n": int(num.group(1)),
                "cmd": cmd_cell[1:-1],
                "expect": cells[-1].strip(),
            }
        )
    if not gates:
        raise SystemExit("ERROR: no GATE rows matched — the doc table format changed")
    return gates


def git(args: list[str]) -> str:
    try:
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, cwd=HERE, check=False
        ).stdout.strip()
    except OSError:
        return "unavailable"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print commands without running")
    ap.add_argument("--only", nargs="*", type=int, help="gate numbers to run")
    ap.add_argument("--timeout", type=int, default=1200, help="per-gate timeout seconds")
    ap.add_argument(
        "--repo-root",
        type=Path,
        default=HERE.parents[2],
        help="checkout containing the Phase 867 deliverables (default: this repo)",
    )
    args = ap.parse_args()

    repo_root = args.repo_root.resolve()
    if not (repo_root / REPORT_REL).exists():
        raise SystemExit(
            f"ERROR: {REPORT_REL} is not present in {repo_root}.\n"
            "The gates read that file, so they must run from a checkout of origin/main "
            "@ fba6f574 or later. Create one without disturbing the current tree:\n"
            "    git worktree add ../phase867-main origin/main\n"
            "then re-run with --repo-root ../phase867-main"
        )

    gates = extract()
    if args.only:
        gates = [g for g in gates if g["n"] in set(args.only)]

    print("# Phase 867 GATE transcript (GATE-1..GATE-9)")
    print(f"# generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print(f"# run from: {repo_root}")
    print(f"# checkout HEAD: {git(['rev-parse', '--short=10', 'HEAD'])} "
          f"{git(['rev-parse', '--abbrev-ref', 'HEAD'])}")
    print(f"# audited commit: origin/main @ fba6f574 (PR #719, Phase 867 merge)")
    print(f"# host: {platform.platform()}")
    print(f"# python: {sys.version.split()[0]}")
    print("# GATE-10 (make preflight) is not re-run here; "
          "see preflight_main.transcript.txt\n")

    failed: list[int] = []
    for g in gates:
        print(f"=== GATE-{g['n']} ===")
        print(f"$ {g['cmd']}")
        if args.list:
            print("(not run)\n")
            continue
        try:
            # `shell=True` is deliberate: the point of this runner is to execute the
            # gate commands **exactly as the phase doc commits them**, including their
            # shell env prefixes (`GOROOT=… go test …`) and `$PWD` uses. The input is a
            # file checked into this bundle (`source_Phase_867_phase_doc.md`), never
            # user input — same justification and suppression as
            # `scripts/benchmark_comparison.py:566`.
            proc = subprocess.run(
                str(g["cmd"]),
                shell=True,  # noqa: S602 — non-user input  # nosemgrep: subprocess-shell-true
                capture_output=True,
                text=True,
                cwd=repo_root,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"EXIT=TIMEOUT after {args.timeout}s (not counted as a gate failure)")
            print()
            continue
        out = (proc.stdout + proc.stderr).strip()
        if out:
            print(out)
        print(f"EXIT={proc.returncode}")
        print(f"doc expects: {g['expect']}")
        if proc.returncode != 0:
            failed.append(int(g["n"]))
        print()

    if not args.list:
        print(f"SUMMARY: {len(gates)} gate(s) executed, failing: "
              f"{failed if failed else 'none'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
