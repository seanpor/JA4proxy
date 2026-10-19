#!/usr/bin/env python3
"""Regenerate each Trivy waiver's `carriers:` claim from scan data.

Phase 829b; registry-aware since Phase 847a.

WHY THIS EXISTS
---------------
18 of 56 third-party exceptions claimed to cover `promtail:3.6.11` (removed in
phase-825), `grafana:13.0.4-ubuntu` (now 13.0.6) and
`prom/haproxy-exporter:v0.15.0` (retired in phase-820) — images not present in
the deployment at all. The waivers themselves were correct; the stated REASON had
rotted, which is the entire point of a *justified* exception. A reviewer trusting
that text was told the waiver covered something it did not.

They were rewritten by hand once (#459). Nothing stopped them rotting again,
because the claim is prose about image versions and image versions move.

REGISTRY-AWARE (Phase 847a)
---------------------------
Since 847a the `.trivyignore.*` files are GENERATED from
`security/waivers.yaml`. Rewriting the generated file directly is reverted by the
drift test, so this script now rewrites the registry's `carriers:` list and
re-renders. The machine-checkable half of the claim therefore still tracks
reality, and the human half stays put.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It rewrites the CARRIER CLAIM only — the machine-checkable half.

The `rationale` (the "why not exploitable here" judgement about OUR deployment)
is never machine-written: no scanner knows that cAdvisor is an internal-only
sidecar with no published host port. Generating it would produce confident text
nobody had thought about, which is worse than stale text someone once did.

An entry the scan reports NOTHING for is left untouched rather than being blanked
(a registry entry must name at least one carrier). Such entries are surfaced as
DEAD by `scripts/check_trivyignore_drift.py`, which the renewal PR body includes;
847d turns that into a controlled removal.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts import render_waivers
except ImportError:  # invoked directly, scripts/ on sys.path
    import render_waivers

try:
    from scripts.check_trivyignore_drift import scan_dir_findings
except ImportError:  # invoked directly
    from check_trivyignore_drift import scan_dir_findings


def refresh(registry: Dict[str, Any], carriers_by_cve: Dict[str, List[str]]) -> List[str]:
    """Rewrite each trivy waiver's `carriers:` from measured scan data.

    Returns the ids that changed. Entries the scan reported nothing for are left
    as-is (see module docstring).
    """
    changed: List[str] = []
    for w in registry.get("waivers") or []:
        if w.get("source") != "trivy":
            continue
        measured = carriers_by_cve.get(str(w.get("id")))
        if not measured:
            continue
        if sorted(measured) != sorted(w.get("carriers") or []):
            w["carriers"] = sorted(measured)
            changed.append(str(w.get("id")))
    return changed


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", type=Path, required=True)
    parser.add_argument("--registry", type=Path, default=render_waivers.REGISTRY)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the registry would change, without writing",
    )
    args = parser.parse_args(argv)

    try:
        _severity, carriers_by_cve = scan_dir_findings(args.scan_dir)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    try:
        registry = render_waivers.load_registry(args.registry)
    except render_waivers.RegistryError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    changed = refresh(registry, carriers_by_cve)
    if not changed:
        print("Carrier claims already match the scan data.")
        return 0

    if args.check:
        print("✗ carrier claims are stale — run without --check to regenerate.")
        return 1

    render_waivers.save_registry(registry, args.registry)
    render_waivers.write_derived(render_waivers.render_all(registry))
    print(f"Regenerated carrier claims for {len(changed)} entry/entries.")
    for wid in sorted(changed):
        print(f"  - {wid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
