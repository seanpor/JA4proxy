#!/usr/bin/env python3
"""Compare the Phase 867 report's §4 micro-benchmark table against re-runs.

Three questions, all answerable mechanically:

1. Coverage — how many `func Benchmark*` exist in the nine GATE-4 packages, how many
   rows does the report's §4 table have, and which functions are missing from it?
2. Reproducibility — for functions present in both, how far do `ns/op`, `B/op` and
   `allocs/op` move between the report's published numbers and a re-run on this host?
3. Allocation stability — are `B/op` and `allocs/op` identical while `ns/op` is not?
   That pattern distinguishes "different machine" from "different code".

Inputs (all in this directory):
  source_Performance_Harness_Review_report.md   the audited report (snapshot of origin/main)
  bench_count1.log, bench_count3.log            re-run transcripts (see README.md)

`go test` writes logrus `level=warning` lines into the benchmark stream on this repo,
so the parser is noise-tolerant by construction (see parse_log's docstring).

No `benchstat` is installed on this host, so run-to-run noise is reported as
min/median/max over the `-count=3` samples rather than as a confidence interval.

Usage: python3 bench_compare.py [--counts bench_count3.log ...]
"""

from __future__ import annotations

import argparse
import re
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORT = HERE / "source_Performance_Harness_Review_report.md"

# The tool reads `origin/main` from the repository, so pin the git cwd to the repo root
# regardless of where the script is invoked from. `cwd=HERE` matters: the bundle lives
# inside the repo, so it resolves even when the caller's own directory is not a repo.
_git = subprocess.run(
    ["git", "rev-parse", "--show-toplevel"],
    capture_output=True,
    text=True,
    cwd=HERE,
)
ROOT = _git.stdout.strip() if _git.returncode == 0 else None

# The nine packages GATE-4 names; kept here so the coverage claim is checkable.
GATE4_PACKAGES = [
    "cmd/ja4pd",
    "internal/tls",
    "internal/quic",
    "internal/server",
    "internal/security",
    "internal/cache",
    "internal/tap",
    "internal/webhook",
    "internal/redis",
]

# e.g. "BenchmarkClientHelloParse-16   3779989  303.7 ns/op  456 B/op  8 allocs/op"
# Names exclude "/" on purpose: `b.Run` leaf rows are counted separately (LEAF_LINE),
# so the table-vs-function comparison stays apples to apples.
BENCH_LINE = re.compile(
    r"^(?P<name>Benchmark[A-Za-z0-9_]+?)(?:-\d+)?\s+"
    r"(?P<iters>[\d,]+)\s+(?P<ns>[\d,.]+)\s+ns/op\s+"
    r"(?P<b>[\d,.]+)\s+B/op\s+(?P<allocs>\d+)\s+allocs/op"
)
# name printed on its own line (numbers landed elsewhere because of interleaved output)
BENCH_HEAD = re.compile(r"^(?P<name>Benchmark[A-Za-z0-9_]+?)(?:-\d+)?\s*\t")
# numbers with no name in front of them
ORPHAN_TAIL = re.compile(
    r"^\s*(?P<iters>[\d,]+)\s+(?P<ns>[\d,.]+)\s+ns/op\s+"
    r"(?P<b>[\d,.]+)\s+B/op\s+(?P<allocs>\d+)\s+allocs/op"
)
# `b.Run` leaves, e.g. "BenchmarkReadVarint/1-Byte-16   542685879   2.178 ns/op ..."
LEAF_LINE = re.compile(
    r"^(?P<name>Benchmark[A-Za-z0-9_]+/[A-Za-z0-9_\-]+?)(?:-\d+)?\s+"
    r"(?P<iters>[\d,]+)\s+(?P<ns>[\d,.]+)\s+ns/op\s+"
    r"(?P<b>[\d,.]+)\s+B/op\s+(?P<allocs>\d+)\s+allocs/op"
)
# report table row, 7 columns with units baked into the cells:
# | `cmd/ja4pd` | `BenchmarkPipeline_Allow` | 1,481,631 | 889.9 ns | 184 B | 3 | prose |
REPORT_ROW = re.compile(
    r"^\|\s*`[^`]+`\s*\|\s*`(?P<name>Benchmark[A-Za-z0-9_]+)`\s*\|\s*(?P<iters>[\d,]+)\s*\|\s*"
    r"(?P<ns>[\d,.]+)\s*ns\s*\|\s*(?P<b>[\d,.]+)\s*B\s*\|\s*(?P<allocs>\d+)\s*\|"
)


def parse_log(path: Path) -> tuple[dict[str, list[tuple[float, float, int]]], set[str]]:
    """Parse `go test -bench=… -benchmem` output into name -> [runs], plus leaf names.

    Two real-world wrinkles in this repo's output, both observed in the bundled logs:

    * `cmd/ja4pd`'s benchmarks emit logrus warnings on stdout. Go prints the benchmark
      name, a tab, and then the program's interleaved log text, so the numeric result
      lands on an orphan continuation line with no name at all.
      `BenchmarkPipeline_Allow` / `BenchmarkPipeline_Score` are only recoverable by
      attributing a numbers-only line to the last-seen name. This is direct evidence
      for F-06: a line-oriented gate parser cannot see those two rows at all.
    * Benchmarks that call `b.Run(…)` print only leaf rows
      (e.g. `BenchmarkReadVarint/1-Byte-16`); the parent row has no numbers.
    """
    runs: dict[str, list[tuple[float, float, int]]] = defaultdict(list)
    leaves: set[str] = set()
    pending: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if LEAF_LINE.match(stripped):
            leaves.add(stripped.split(None, 1)[0])
            pending = None
            continue
        m = BENCH_LINE.match(stripped)
        if m:
            runs[m.group("name")].append(
                (float(m.group("ns")), float(m.group("b")), int(m.group("allocs")))
            )
            pending = None
            continue
        head = BENCH_HEAD.match(stripped)
        if head and not ORPHAN_TAIL.match(stripped[head.end() :]):
            # name printed, numbers pushed onto a following line by interleaved output
            pending = head.group("name")
            continue
        if pending:
            o = ORPHAN_TAIL.match(stripped)
            if o:
                runs[pending].append(
                    (float(o.group("ns")), float(o.group("b")), int(o.group("allocs")))
                )
                pending = None
    return runs, leaves


def parse_report() -> dict[str, tuple[float, float, int]]:
    """The report's §4 table, as published: name -> (ns/op, B/op, allocs/op)."""
    text = REPORT.read_text(encoding="utf-8")
    section = text.split("## 4.")[1].split("## 5.")[0]
    out: dict[str, tuple[float, float, int]] = {}
    for line in section.splitlines():
        m = REPORT_ROW.match(line.strip())
        if m:
            out[m.group("name")] = (
                float(m.group("ns").replace(",", "")),
                float(m.group("b").replace(",", "")),
                int(m.group("allocs")),
            )
    return out


def declared_benchmarks() -> dict[str, list[str]]:
    """`func Benchmark*` per file, read from the source tree at `origin/main`."""
    if ROOT is None:
        return {}
    blobs = subprocess.run(
        ["git", "grep", "-l", "^func Benchmark", "origin/main", "--", *GATE4_PACKAGES],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    ).stdout.split()
    per_file: dict[str, list[str]] = {}
    for blob_id in blobs:
        blob = subprocess.run(
            ["git", "show", blob_id], capture_output=True, text=True, check=True, cwd=ROOT
        ).stdout
        names = re.findall(r"^func (Benchmark[A-Za-z0-9_]+)", blob, re.MULTILINE)
        if names:
            per_file[blob_id.split(":", 1)[1]] = names
    return per_file


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", nargs="*", default=["bench_count3.log", "bench_count1.log"])
    args = ap.parse_args()

    report = parse_report()
    measured: dict[str, list[tuple[float, float, int]]] = defaultdict(list)
    all_leaves: set[str] = set()
    for log in args.counts:
        p = HERE / log
        if not p.exists():
            print(f"missing re-run log: {p}")
            continue
        runs, leaves = parse_log(p)
        all_leaves |= leaves
        for name, rs in runs.items():
            measured[name].extend(rs)

    print("=== 1. Coverage ===")
    per_file = declared_benchmarks()
    if not per_file:
        print("note: not inside a git repository from this cwd, so the declared-function")
        print("      census is skipped; run from any checkout of this repo to get it.")
    declared = sorted(n for names in per_file.values() for n in names)
    print(f"benchmark functions declared in the 9 GATE-4 packages: {len(declared)}")
    print(f"rows in the report's §4 table:                        {len(report)}")
    print(f"functions observed in re-runs:                        {len(measured)}")
    print(f"`b.Run` leaf rows seen in re-runs:                    {len(all_leaves)} "
          f"({sorted(all_leaves)})")
    missing = sorted(set(declared) - set(report))
    print(f"\ndeclared in-scope but absent from the §4 table ({len(missing)}):")
    for n in missing:
        print(f"  - {n}")
    extra = sorted(set(report) - set(declared))
    print(f"table rows not declared in the GATE-4 packages ({len(extra)}): {extra}")
    not_run = sorted(set(declared) - set(measured))
    print(f"declared in-scope but not observed in re-runs ({len(not_run)}): {not_run}")
    print("\nper-file declaration counts:")
    for f, names in sorted(per_file.items()):
        print(f"  {len(names):2}  {f}")

    print("\n=== 2. Report vs re-run (ns/op; median over N observed runs) ===")
    deltas: list[tuple[float, str, float, float, int]] = []
    mismatches: list[str] = []
    alloc_same = 0
    allocs_only_same = 0
    bytes_only_same = 0
    for name, (r_ns, r_b, r_allocs) in sorted(report.items()):
        runs = measured.get(name)
        if not runs:
            mismatches.append(f"  no re-run row for {name}")
            continue
        ns_vals = [r[0] for r in runs]
        b_vals = {r[1] for r in runs}
        a_vals = {r[2] for r in runs}
        med = statistics.median(ns_vals)
        delta = (med - r_ns) / r_ns * 100.0
        deltas.append((delta, name, r_ns, med, len(runs)))
        if r_allocs in a_vals:
            allocs_only_same += 1
        if r_b in b_vals:
            bytes_only_same += 1
        if r_b in b_vals and r_allocs in a_vals:
            alloc_same += 1
        else:
            mismatches.append(
                f"  ALLOCATION MISMATCH {name}: report {r_b:g} B / {r_allocs} allocs; "
                f"measured {sorted(b_vals)} B / {sorted(a_vals)} allocs"
            )
    print(f"{'benchmark':42} {'report':>10} {'n':>3} {'min':>10} {'median':>10} "
          f"{'max':>10} {'delta%':>8}")
    for delta, name, r_ns, med, n in sorted(deltas):
        runs = measured[name]
        ns_vals = [r[0] for r in runs]
        print(f"{name:42} {r_ns:10.4g} {n:3} {min(ns_vals):10.4g} {med:10.4g} "
              f"{max(ns_vals):10.4g} {delta:+8.1f}")
    for m in mismatches:
        print(m)

    print("\n=== 3. Allocation stability vs timing noise ===")
    print(f"allocs/op identical to the report: {allocs_only_same} of {len(deltas)}")
    print(f"B/op identical to the report:      {bytes_only_same} of {len(deltas)}")
    print(f"both identical:                    {alloc_same} of {len(deltas)}")

    # Run-to-run noise for the SAME binary across the samples supplied on the command
    # line. Pass one log (e.g. -count=3) to measure noise *within* a single invocation;
    # pass several logs to measure noise across invocations minutes apart. This is the
    # yardstick: a drift gate tighter than this cannot detect code changes.
    spreads = {
        name: (max(r[0] for r in runs) - min(r[0] for r in runs)) / min(r[0] for r in runs) * 100.0
        for name, runs in measured.items()
        if len(runs) >= 2
    }
    if spreads:
        vals = sorted(spreads.values())
        print(f"same-binary run-to-run ns/op spread over {len(args.counts)} log(s) "
              f"({len(vals)} functions): {vals[0]:.1f}% .. {vals[-1]:.1f}%, "
              f"median {statistics.median(vals):.1f}%")

    ns_deltas = [d[0] for d in deltas]
    if ns_deltas:
        print(f"report-vs-rerun ns/op delta range: {min(ns_deltas):+.1f}% .. "
              f"{max(ns_deltas):+.1f}%")
        # Per-function comparison: how far did the number move, against how far the same
        # binary moves between its own runs?
        per_fn = [
            (name, delta, spreads[name])
            for delta, name, _, _, _ in deltas
            if name in spreads
        ]
        worse = [(n, d, s) for n, d, s in per_fn if abs(d) > s]
        print(f"functions whose report-vs-rerun delta is larger than their own "
              f"same-binary spread: {len(worse)} of {len(per_fn)}")
        for n, d, s in sorted(worse, key=lambda x: -abs(x[1]))[:8]:
            print(f"  {n:42} delta {d:+7.1f}%  own spread {s:5.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
