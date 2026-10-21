#!/usr/bin/env python3
"""Diff what the deployed images actually carry against what the ignorefile waives.

Phase 829a.

WHY THIS EXISTS
---------------
On 2026-08-19 `make scan-images` was FAILING on `grafana/alloy:v1.18.1` with two
unwaived HIGHs (CVE-2026-56864, CVE-2026-56865). Nobody had changed that image.
The CVEs had simply entered the vulnerability database after the previous day's
renewal review, and the ignorefile went stale underneath a deployment that had
not moved.

Nothing detected it, because the weekly renewal workflow runs
`scan_exceptions.py` (a listing) and `renew_trivyignore.py` (a date rewrite) and
never invokes Trivy at all. A workflow that only re-dates entries it already
knows about structurally cannot see a CVE that did not exist last week.

This closes that hole by measuring, in BOTH directions:

  GAP   — carried by a deployed image, not waived. This BREAKS `make
          scan-images`. Exits non-zero: a report nobody reads is what let the
          2026-08-19 failure through.

  DEAD  — waived, but carried by no deployed image any more. Informational, but
          it is the ONLY category that can ever shrink the file, and today
          nothing tells anyone these exist. They accumulate silently: entries
          are added when a scan fails and removed only if a human happens to
          notice.

Reads Trivy JSON produced by the caller (`--scan-dir`) rather than shelling out,
so it stays dependency-free and unit-testable without Docker.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, NamedTuple, Set, Tuple

_ROOT = Path(__file__).resolve().parents[1]

THIRD_PARTY_IGNORE = _ROOT / ".trivyignore.third-party"

# Matches an entry line: the CVE/GHSA id at the start, optional `exp:` after.
#
# Anchored on a whole token. A looser `CVE-[\d-]+` PARTIALLY matches a malformed
# line — "CVE-2020-DEAD" silently became the id "CVE-2020-", registering a waiver
# for something that does not exist while the real line went unrecognised. A
# malformed entry must fail to match entirely, so it surfaces as an unwaived gap
# (loud) rather than as a corrupted waiver (silent).
_ENTRY = re.compile(r"^(?P<id>CVE-\d{4}-\d+|GHSA-[\w-]{4,})(?=\s|$)")

SEVERITIES = ("HIGH", "CRITICAL")

# Severity order, most severe first. Used to pick the *highest* severity seen
# for one CVE id within a report: Trivy can report the same id at different
# severities across packages within one image, and reporting the lower one
# would understate the finding.
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def waived_ids(ignorefile: Path) -> Set[str]:
    """Every CVE/GHSA id the ignorefile waives."""
    if not ignorefile.exists():
        return set()
    out = set()
    for line in ignorefile.read_text(encoding="utf-8").splitlines():
        m = _ENTRY.match(line.strip())
        if m:
            out.add(m.group("id"))
    return out


class VulnRow(NamedTuple):
    """One HIGH/CRITICAL finding: CVE id, package, installed version, severity.

    `fixed` is the upstream fix version Trivy reports, or "" when none is
    published. Added in Phase 847c as a trailing field with a default, so every
    existing positional construction keeps working: the baseline needs
    fix-availability to decide what it can *act* on (847d's fix-forward queue),
    and getting it from the one shared parser keeps that fact in step with the
    id/severity facts rather than re-deriving it from a second scan.
    """

    cve: str
    package: str
    installed: str
    severity: str
    fixed: str = ""


def load_report(path: Path) -> Dict[str, Any]:
    """Parse one Trivy JSON report, naming the file in the error if it is unusable."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"unreadable Trivy report {path.name}: {exc}") from exc


def vuln_rows(doc: Dict[str, Any], severities: Iterable[str] | None = None) -> List[VulnRow]:
    """Findings in one Trivy image report, deduplicated by CVE id.

    THE single Trivy-JSON parser in this repo. Both `findings_from_scan` (drift
    checking) and `scripts/trivy_image_report.py` (the `make scan-images` gate)
    derive from this function, so the gate cannot fail on a finding the drift
    checker treats as waived — or vice versa. Phase 847b.3.

    Deduplication is by CVE id, not by row: the ignorefile waives ids, and Trivy
    emits one row per (target, package, CVE), so the same CVE under several
    OS layers is a single finding. Counting rows instead would let one waived id
    inflate a count.

    The **highest** severity wins for the same id: Trivy can report an id at
    different severities across packages within one image, and reporting the
    lower one would understate the finding.

    `severities` is the band this caller asked Trivy for. It defaults to
    `SEVERITIES` (HIGH,CRITICAL) — the band the gate has always used — so the
    default behaviour is unchanged. Phase 847e passes the band it actually
    scanned for, which is what lets the same parser serve a MEDIUM
    measurement without becoming a second, divergent parser.

    The band may be given as a list or as the comma-separated string the
    scanner itself takes. The string form is normalised here rather than
    `set()`-ed directly: `set("MEDIUM")` is the *characters* {'M','E','D','I',
    'U'}, which matches nothing and reads as "this image has no findings" —
    the exact silent-wrongness this parser exists to prevent.
    """
    wanted = severity_set(severities)
    best: Dict[str, VulnRow] = {}
    for result in doc.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            sev = vuln.get("Severity")
            if sev not in wanted:
                continue
            cve = vuln.get("VulnerabilityID")
            if not cve:
                continue
            prev = best.get(cve)
            if prev is None:
                best[cve] = VulnRow(
                    cve=cve,
                    package=vuln.get("PkgName") or "?",
                    installed=vuln.get("InstalledVersion") or "?",
                    severity=sev,
                    fixed=vuln.get("FixedVersion") or "",
                )
            elif _severity_rank(sev) < _severity_rank(prev.severity):
                best[cve] = prev._replace(severity=sev)
    return list(best.values())


def _severity_rank(severity: str) -> int:
    """Where a severity sits in the order — lower is more severe."""
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(_SEVERITY_ORDER)


def severity_set(severities: Iterable[str] | str | None) -> set[str]:
    """Normalise a severity band to a set of severity names.

    A comma-separated string is split; anything iterable is taken as a
    collection of names. `None` means the default band.
    """
    if severities is None:
        return set(SEVERITIES)
    if isinstance(severities, str):
        return {part.strip() for part in severities.split(",") if part.strip()}
    return {str(part).strip() for part in severities if str(part).strip()}


def findings_from_scan(path: Path) -> Dict[str, str]:
    """Return {cve_id: severity} for HIGH/CRITICAL in one Trivy JSON report."""
    return {row.cve: row.severity for row in vuln_rows(load_report(path))}


def _artifact_name(path: Path) -> str:
    """The image reference Trivy recorded, falling back to the filename."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return path.stem
    return doc.get("ArtifactName") or path.stem


def scan_dir_findings(scan_dir: Path) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    """Union the findings across every *.json report in `scan_dir`.

    Returns (severity_by_id, carriers_by_id). The carrier map is what makes a
    DEAD entry actionable and a justification honest — "which image is this
    actually for" is the question stale prose kept getting wrong.
    """
    severity: Dict[str, str] = {}
    carriers: Dict[str, List[str]] = {}
    reports = sorted(scan_dir.glob("*.json"))
    if not reports:
        raise ValueError(f"no Trivy JSON reports found in {scan_dir}")

    for report in reports:
        # Trivy records the full image reference it scanned. Use that rather
        # than the filename: the caller flattens `/`, `:` and `@` to `_` to make
        # a safe filename, and that mapping is not reversible — it produced
        # carrier claims reading "gcr.io_cadvisor_cadvisor_v0.52.1".
        image = _artifact_name(report)
        for cve, sev in findings_from_scan(report).items():
            if severity.get(cve) != "CRITICAL":
                severity[cve] = sev
            carriers.setdefault(cve, []).append(image)
    return severity, carriers


def drift(
    waived: Set[str], measured: Dict[str, str]
) -> Tuple[List[str], List[str]]:
    """Return (gaps, dead) — sorted, so output is stable across runs."""
    gaps = sorted(set(measured) - waived)
    dead = sorted(waived - set(measured))
    return gaps, dead


def _render(
    gaps: Iterable[str],
    dead: Iterable[str],
    severity: Dict[str, str],
    carriers: Dict[str, List[str]],
) -> str:
    lines: List[str] = []
    gaps, dead = list(gaps), list(dead)

    if gaps:
        lines.append("GAPS — carried by a deployed image but NOT waived.")
        lines.append("These fail `make scan-images`. Add a justified entry or bump the image.")
        for cve in gaps:
            who = ", ".join(carriers.get(cve, [])) or "unknown"
            lines.append(f"  {cve} [{severity.get(cve, '?')}]  carried by: {who}")
        lines.append("")

    if dead:
        lines.append("DEAD — waived but no longer carried by any deployed image.")
        lines.append("These can be deleted; they are the only entries that ever shrink the file.")
        for cve in dead:
            lines.append(f"  {cve}")
        lines.append("")

    if not gaps and not dead:
        lines.append("Ignorefile matches the deployed images exactly: no gaps, no dead entries.")

    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scan-dir",
        type=Path,
        required=True,
        help="directory of Trivy JSON reports, one per deployed image "
        "(scan with NO ignorefile, --severity HIGH,CRITICAL)",
    )
    parser.add_argument(
        "--ignorefile",
        type=Path,
        default=THIRD_PARTY_IGNORE,
        help="ignorefile to compare against (default: .trivyignore.third-party)",
    )
    parser.add_argument(
        "--fail-on-dead",
        action="store_true",
        help="also exit non-zero for dead entries. Off by default: a dead entry "
        "is tidy-up, not a broken gate, and failing the weekly job on it would "
        "train people to ignore the job.",
    )
    args = parser.parse_args(argv)

    try:
        severity, carriers = scan_dir_findings(args.scan_dir)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    waived = waived_ids(args.ignorefile)
    gaps, dead = drift(waived, severity)

    print(f"waived entries            : {len(waived)}")
    print(f"distinct HIGH/CRIT deployed: {len(severity)}")
    print()
    print(_render(gaps, dead, severity, carriers))

    if gaps:
        print(
            f"\n✗ {len(gaps)} unwaived finding(s) — the image scan gate is broken.",
            file=sys.stderr,
        )
        return 1
    if dead and args.fail_on_dead:
        print(f"\n✗ {len(dead)} dead entry(ies).", file=sys.stderr)
        return 1
    if dead:
        print(f"\n! {len(dead)} dead entry(ies) — removable, not blocking.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
