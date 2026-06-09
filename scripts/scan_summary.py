#!/usr/bin/env python3
"""scripts/scan_summary.py — human-readable rollup of the security scans (Phase 228).

`make scan` prints full Trivy tables + Dockerfile misconfig tables + gosec output,
which scroll past as a blur. This tool turns each machine-readable scanner output
into a compact table so a person can see at a glance what passed and what didn't.

Modes:
    scan_summary.py IMAGE [IMAGE ...]   # run Trivy (vuln) per image, summarise
    scan_summary.py misconfig           # read Trivy `config` JSON on stdin
    scan_summary.py gosec               # read gosec `-fmt json` JSON on stdin

It is a *reporting* tool, not a gate: `make scan` remains the authoritative
pass/fail. It exits 0 even when findings exist; non-zero only if a scanner could
not be run at all (so a broken summary is noticed).

`make scan-summary` runs the image + gosec rollups (both scoped to match the
gate). The `misconfig` mode is provided for manual use, e.g.:
    docker run ... aquasec/trivy config --format json /scan/deploy/docker \\
        | python3 scripts/scan_summary.py misconfig
It is intentionally NOT auto-run, because a whole-directory misconfig scan is
broader than `scan-dockerfiles` (which gates a specific file list) and would
otherwise report findings the gate does not check.
"""
from __future__ import annotations

import json
import os
import subprocess  # nosec B404 -- invokes the pinned trivy container by fixed argv
import sys

TRIVY_IMAGE = "aquasec/trivy:0.71.0"
VULN_SEVS = ("CRITICAL", "HIGH", "MEDIUM")     # Trivy image/vuln + misconfig
GOSEC_SEVS = ("HIGH", "MEDIUM", "LOW")         # gosec issue severities
_ABBREV = {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}


# --- pure tally / verdict / table helpers (unit-tested) ----------------------

def _tally(raw_severities, tracked) -> dict[str, int]:
    counts = {s: 0 for s in tracked}
    for rs in raw_severities:
        s = (rs or "").upper()
        if s in counts:
            counts[s] += 1
    return counts


def count_severities(trivy_json: dict) -> dict[str, int]:
    """Tally Trivy *vulnerabilities* by severity (CRITICAL/HIGH/MEDIUM)."""
    raw = (
        v.get("Severity")
        for r in (trivy_json.get("Results") or [])
        for v in (r.get("Vulnerabilities") or [])
    )
    return _tally(raw, VULN_SEVS)


def count_misconfig(trivy_json: dict) -> dict[str, int]:
    """Tally Trivy *misconfigurations* (Dockerfile/compose) by severity."""
    raw = (
        m.get("Severity")
        for r in (trivy_json.get("Results") or [])
        for m in (r.get("Misconfigurations") or [])
    )
    return _tally(raw, VULN_SEVS)


def count_gosec(gosec_json: dict) -> dict[str, int]:
    """Tally gosec issues by severity (HIGH/MEDIUM/LOW)."""
    raw = (i.get("severity") for i in (gosec_json.get("Issues") or []))
    return _tally(raw, GOSEC_SEVS)


def verdict(counts: dict[str, int], fail=("CRITICAL",), warn=("HIGH",)) -> str:
    """FAIL if any `fail` severity is present; WARN if any `warn` severity is;
    else OK. Defaults match the image gate (CRITICAL fails, HIGH is advisory)."""
    if any(counts.get(s, 0) > 0 for s in fail):
        return "FAIL"
    if any(counts.get(s, 0) > 0 for s in warn):
        return "WARN"
    return "OK"


def format_table(rows, severities=VULN_SEVS, verdict_fn=verdict, name_header="IMAGE") -> str:
    """Render rows of (name, counts) as a fixed-width table with a totals line.

    Pure (no I/O). `severities` sets the columns; `verdict_fn(counts)` the verdict.
    """
    name_w = max([len(name_header)] + [len(n) for n, _ in rows]) if rows else len(name_header)
    cols = "  ".join(f"{_ABBREV[s]:>4}" for s in severities)
    header = f"{name_header:<{name_w}}  {cols}  VERDICT"
    sep = "-" * len(header)
    lines = [header, sep]
    totals = {s: 0 for s in severities}
    for name, counts in rows:
        for s in severities:
            totals[s] += counts.get(s, 0)
        cells = "  ".join(f"{counts.get(s, 0):>4}" for s in severities)
        lines.append(f"{name:<{name_w}}  {cells}  {verdict_fn(counts)}")
    lines.append(sep)
    tcells = "  ".join(f"{totals[s]:>4}" for s in severities)
    lines.append(f"{'TOTAL':<{name_w}}  {tcells}  {verdict_fn(totals)}")
    return "\n".join(lines)


# --- scanner invocation (I/O) ------------------------------------------------

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


# --- mode dispatch -----------------------------------------------------------

def _summarise_images(images: list[str]) -> int:
    rows, failed = [], False
    for img in images:
        try:
            rows.append((img, scan_image(img)))
        except Exception as exc:  # pragma: no cover - integration path
            print(f"  ! could not scan {img}: {exc}", file=sys.stderr)
            failed = True
    print("\n=== Image CVE summary (Trivy) — reporting only; `make scan` is the gate ===")
    print(format_table(rows))
    return 1 if failed else 0


def _summarise_stdin(kind: str) -> int:
    raw = sys.stdin.read()
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - integration path
        print(f"  ! could not parse {kind} JSON: {exc}", file=sys.stderr)
        return 1
    if kind == "gosec":
        counts = count_gosec(doc)
        v = lambda c: verdict(c, fail=("HIGH",), warn=("MEDIUM",))  # noqa: E731
        print("\n=== gosec summary (Go SAST) — reporting only; `make scan` is the gate ===")
        print(format_table([("gosec", counts)], GOSEC_SEVS, v, name_header="SCAN"))
    else:  # misconfig
        counts = count_misconfig(doc)
        v = lambda c: verdict(c, fail=("CRITICAL", "HIGH"), warn=("MEDIUM",))  # noqa: E731
        print("\n=== Dockerfile/compose misconfig summary (Trivy) — reporting only ===")
        print(format_table([("dockerfiles", counts)], VULN_SEVS, v, name_header="SCAN"))
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: scan_summary.py {IMAGE...|gosec|misconfig}", file=sys.stderr)
        return 2
    if argv[1] in ("gosec", "misconfig"):
        return _summarise_stdin(argv[1])
    return _summarise_images(argv[1:])


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
