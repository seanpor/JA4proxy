#!/usr/bin/env python3
"""scripts/scan_summary.py — human-readable rollup of Trivy image scans (Phase 228).

`make scan` prints the full Trivy tables, which scroll past as a blur. This tool
runs Trivy in JSON mode (via the pinned aquasec/trivy container, reusing the
Phase 227 TRIVY_CACHE) for each image given on argv and prints ONE compact row
per image — CRITICAL / HIGH / MEDIUM counts and a verdict — plus a rollup.

It is a *reporting* tool, not a gate: `make scan` remains the authoritative
pass/fail. This script exits 0 even when CVEs are present; it exits non-zero only
if Trivy could not be run at all (so CI/operators notice a broken summary).

Usage:
    python3 scripts/scan_summary.py [IMAGE ...]
    make scan-summary
"""
from __future__ import annotations

import json
import os
import subprocess  # nosec B404 -- invokes the pinned trivy container by fixed argv
import sys

TRIVY_IMAGE = "aquasec/trivy:0.71.0"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")


def count_severities(trivy_json: dict) -> dict[str, int]:
    """Tally vulnerabilities by severity from a parsed Trivy JSON document.

    Pure function (no I/O) so it is unit-testable against fixture JSON.
    """
    counts = {sev: 0 for sev in SEVERITIES}
    for result in trivy_json.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            sev = (vuln.get("Severity") or "").upper()
            if sev in counts:
                counts[sev] += 1
    return counts


def verdict(counts: dict[str, int]) -> str:
    """A CRITICAL is a FAIL; HIGH-only is WARN; otherwise OK. (Matches the
    `make scan` gate, which fails on CRITICAL and treats HIGH as advisory.)"""
    if counts.get("CRITICAL", 0) > 0:
        return "FAIL"
    if counts.get("HIGH", 0) > 0:
        return "WARN"
    return "OK"


def format_table(rows: list[tuple[str, dict[str, int]]]) -> str:
    """Render rows of (image, counts) as a fixed-width table with a totals line.

    Pure function (no I/O) so it is unit-testable.
    """
    name_w = max([len("IMAGE")] + [len(img) for img, _ in rows]) if rows else len("IMAGE")
    header = f"{'IMAGE':<{name_w}}  {'CRIT':>4}  {'HIGH':>4}  {'MED':>4}  VERDICT"
    sep = "-" * len(header)
    lines = [header, sep]
    totals = {sev: 0 for sev in SEVERITIES}
    for img, counts in rows:
        for sev in SEVERITIES:
            totals[sev] += counts.get(sev, 0)
        lines.append(
            f"{img:<{name_w}}  {counts.get('CRITICAL', 0):>4}  "
            f"{counts.get('HIGH', 0):>4}  {counts.get('MEDIUM', 0):>4}  {verdict(counts)}"
        )
    lines.append(sep)
    lines.append(
        f"{'TOTAL':<{name_w}}  {totals['CRITICAL']:>4}  {totals['HIGH']:>4}  "
        f"{totals['MEDIUM']:>4}  {verdict(totals)}"
    )
    return "\n".join(lines)


def scan_image(image: str) -> dict[str, int]:
    """Run Trivy (containerised) against one image and return severity counts."""
    cache = os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))
    os.makedirs(cache, exist_ok=True)
    cwd = os.getcwd()
    cmd = [
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{cwd}:/scan:ro",
        "-v", f"{cache}:/root/.cache/trivy",
        TRIVY_IMAGE, "image",
        "--severity", "CRITICAL,HIGH,MEDIUM",
        "--scanners", "vuln", "--no-progress",
        "--ignorefile", "/scan/.trivyignore",
        "--format", "json", image,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603 -- fixed argv, no shell
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"trivy failed for {image}: {proc.stderr.strip()[:300]}")
    return count_severities(json.loads(proc.stdout))


def main(argv: list[str]) -> int:
    images = argv[1:]
    if not images:
        print("usage: scan_summary.py IMAGE [IMAGE ...]", file=sys.stderr)
        return 2
    rows: list[tuple[str, dict[str, int]]] = []
    failed_to_run = False
    for img in images:
        try:
            rows.append((img, scan_image(img)))
        except Exception as exc:  # pragma: no cover - exercised via integration, not unit
            print(f"  ! could not scan {img}: {exc}", file=sys.stderr)
            failed_to_run = True
    print("\n=== Trivy scan summary (reporting only — `make scan` is the gate) ===")
    print(format_table(rows))
    return 1 if failed_to_run else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
