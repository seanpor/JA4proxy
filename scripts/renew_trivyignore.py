#!/usr/bin/env python3
"""Re-affirm soon-to-expire Trivy waivers — never blind-renew them (Phase 847d).

Phase 812's version bumped every window falling inside the notice period. That
made each 90-day renewal a silent no-op with respect to truth: the waiver's date
moved, its *premise* was never re-checked, and a CVE that had been fixable for
months could be renewed indefinitely. Phase 847d removes the auto-renew and
replaces it with an explicit decision per expiring entry:

* **DEAD** — the CVE no longer appears in any scan *that covered the images the
  entry declares*. The waiver is obsolete, so it is *removed* from the registry
  and the derived ignorefiles are re-rendered. A stale waiver is not harmless: it
  is a standing exemption nobody is watching. The coverage qualifier matters: if
  a declared carrier has no report (its Trivy run failed, or only some images
  were scanned), the entry is `unmeasured` and escalated — a missing report is
  not evidence that a vulnerability is gone, and deleting on one would silently
  narrow a live exemption.
* **FIXABLE** — a newer upstream tag clears it (`fix_forward` proves this against
  real registry tags, rejecting candidates that introduce new unwaived
  findings). The window is NOT extended; the fix is proposed as a reviewable
  branch instead (`bot/fix-forward-*`), because a bump is strictly better than
  another 90 days of exposure.
* **BLOCKED / UNKNOWN / NEEDS A SCAN** — no decision can be made for the entry.
  It is escalated with the exact next step, and its dates are left **untouched**.
  Zero change is the correct action: a date this script cannot justify must not
  be written.

`--within-days` therefore selects *which entries get looked at*, not which get
renewed. There is deliberately no longer any code path that extends an expiry
without evidence.

Registry deletions go through `render_waivers.remove_entries`, which trims the
entry's text block rather than re-serialising the document, and `remove_entries`
refuses to delete a carrier another surviving waiver still claims.

Exit codes: 0 = nothing needed attention, 1 = something was changed or escalated
for a human, 2 = error. `--check` reports without writing, for CI.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts import render_waivers
except ImportError:  # invoked directly, scripts/ on sys.path
    import render_waivers  # type: ignore[no-redef]

try:
    from scripts.check_trivyignore_drift import scan_dir_findings
except ImportError:  # pragma: no cover - direct invocation
    from check_trivyignore_drift import scan_dir_findings  # type: ignore[no-redef]


def _as_date(value: str) -> date | None:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def expiring_entries(registry: dict, within_days: int, today: date) -> list[dict]:
    """Trivy entries whose expiry is at or inside the notice window, oldest first."""
    out = []
    for w in registry.get("waivers") or []:
        if w.get("source") != "trivy":
            continue
        expires = _as_date(str(w.get("expires") or ""))
        if expires is None:
            continue
        if (expires - today).days <= within_days:
            out.append(w)
    return sorted(out, key=lambda w: (str(w.get("expires")), str(w.get("id"))))


def covered_images(scan_dir: Path) -> set[str]:
    """Images whose report shows Trivy actually ANALYSED them.

    A report *existing* is not the same as the image having been *scanned*.
    Trivy writes `"Results": null` when it could not analyse the image at all
    (no detectable OS, an unreadable layer) — and that report still names the
    image, so counting it as coverage would let a scan that looked at nothing
    read as "this CVE is gone" and delete a live waiver.

    A report whose `Results` is a LIST is the repo's established "scanned"
    shape, including an empty list: `trivy_image_report.py` treats
    `Results: []` as a genuine clean pass
    (tests/unit/test_scan_tooling.py::test_empty_results_report_is_clean),
    and the two must not disagree about what "scanned" means.

    An unreadable file is skipped here; `scan_dir_findings()` raises on it a
    moment later, so the run fails closed rather than reading it as clean.
    """
    covered: set[str] = set()
    for report in sorted(scan_dir.glob("*.json")):
        try:
            doc = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue  # unreadable — scan_dir_findings() raises on this below
        if not isinstance(doc.get("Results"), list):
            continue  # Trivy analysed nothing: not evidence of absence
        covered.add(doc.get("ArtifactName") or report.stem)
    return covered


def measure_carriers(scan_dir: Path) -> tuple[dict[str, list[str]], set[str]]:
    """`({cve: [image refs]}, {images actually scanned})` from `scan_dir`.

    The second element is what makes DEAD trustworthy. A CVE missing from the
    cve→carriers map means "no report mentioned it", which is only evidence of
    absence if the reports covered the images we care about. The workflow writes
    no report for an image whose Trivy run failed (it warns and continues), so
    without the scanned-image set a partial sweep would read as "this CVE is
    gone" and delete a live waiver — silently narrowing an exemption, which is
    exactly the failure Phase 847d exists to remove.
    """
    _severity, carriers = render_waivers.scan_dir_findings(scan_dir)
    # An image that carried nothing at all contributes no carriers entries, so it
    # is invisible in the map above; `covered_images` recovers it from the
    # report itself.
    scanned = {img for refs in carriers.values() for img in refs} | covered_images(scan_dir)
    return carriers, scanned


def classify(entry: dict, carriers: dict[str, list[str]], scanned: set[str]) -> str:
    """`dead` | `present` | `unmeasured` for this waiver's CVE.

    `dead` is returned ONLY when every image the entry declares was actually
    scanned and none of them carried the CVE. If a declared carrier has no
    report, the honest answer is `unmeasured` — a missing report is not evidence
    a vulnerability is gone.
    """
    cve = str(entry.get("id"))
    if carriers.get(cve):
        return "present"
    declared = {str(c) for c in entry.get("carriers") or []}
    if declared and not declared <= scanned:
        return "unmeasured"
    # No declared carriers, or all of them were scanned clean: the CVE is gone.
    return "dead"


def fix_proposal(entry: dict, carriers: dict[str, list[str]], registry: dict, today: date) -> dict | None:
    """Ask `fix_forward` whether a clearing upstream tag exists for this entry.

    Returns its decision dict when it concludes `fixable` (the caller then
    delegates to a fix-forward proposal and leaves the dates alone), else None.
    A `blocked`/`unknown` verdict is not a renewal and not a deletion — the
    caller escalates it with the verdict's own evidence.

    Only a UNIQUE carrier is proposed. `check_image_fix` bumps one image; if the
    CVE is carried by two, clearing the first says nothing about the second, so
    reporting it as `fixable` would overclaim. The caller escalates multi-carrier
    entries for a human instead.
    """
    from scripts import fix_forward as ff

    cve = str(entry.get("id"))
    refs = carriers.get(cve) or []
    if len(refs) != 1:
        return None
    current_findings = {cve: {"severity": entry.get("severity") or "HIGH", "package": "?"}}
    decisions = ff.check_image_fix(
        refs[0],
        f"image:{ff._ref_name_and_tag(refs[0])[0]}",
        {cve},
        current_findings,
        scanner=ff.default_scanner(),
        today=today.isoformat(),
    )
    return decisions[0] if decisions and decisions[0]["decision"] == "fixable" else None


def _escalation_lines(entry: dict, carriers: dict[str, list[str]], verdict: str) -> list[str]:
    cve = str(entry.get("id"))
    refs = carriers.get(cve) or []
    lines = [
        f"  ! {cve} expires {entry.get('expires')} — needs a human decision (dates unchanged).",
        f"    verdict: {verdict or 'no verdict produced'}",
    ]
    if refs:
        lines.append(f"    carriers: {', '.join(refs)}")
        if len(refs) == 1:
            lines.append(
                "    next: check whether a newer tag clears it, then either propose the bump "
                "(`scripts/fix_forward.py --state …`) or re-affirm this waiver by hand."
            )
        else:
            lines.append(
                f"    next: carried by {len(refs)} images — a bump must clear ALL of them "
                "(`scripts/fix_forward.py --state …`, or re-affirm this waiver by hand)."
            )
    else:
        lines.append(
            "    next: no report saw this CVE. If it is genuinely gone, delete the waiver; "
            "otherwise re-run with --scan-dir covering every carrier so the re-check has evidence."
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--within-days", type=int, default=5)
    parser.add_argument("--today", default="", help="override today (YYYY-MM-DD)")
    parser.add_argument("--registry", type=Path, default=render_waivers.REGISTRY)
    parser.add_argument(
        "--scan-dir",
        type=Path,
        default=None,
        help="directory of Trivy JSON reports holding the current findings",
    )
    parser.add_argument(
        "--check", action="store_true", help="report only; never write the registry"
    )
    args = parser.parse_args(argv)

    today = (
        _as_date(args.today) if args.today else date.today()
    ) or date.today()

    try:
        registry = render_waivers.load_registry(args.registry)
        # `RegistryError` is raised for text that will not parse; an empty
        # `waivers:` list is a legitimate end state (see validate()).
    except (render_waivers.RegistryError, ValueError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2

    errors = render_waivers.validate(registry)
    if errors:
        for e in errors:
            print(f"✗ {e}", file=sys.stderr)
        return 2

    entries = expiring_entries(registry, args.within_days, today)
    if not entries:
        print(f"No trivy waiver expires within {args.within_days} day(s) — nothing to re-affirm.")
        return 0

    carriers: dict[str, list[str]] = {}
    scanned: set[str] = set()
    scan_note = "no --scan-dir: expiry classes are unknown"
    if args.scan_dir is not None:
        try:
            carriers, scanned = measure_carriers(args.scan_dir)
        except ValueError as exc:
            print(f"✗ {exc}", file=sys.stderr)
            return 2
        scan_note = (
            f"{sum(len(v) for v in carriers.values())} finding(s) across "
            f"{len(carriers)} CVE(s), {len(scanned)} image(s) scanned"
        )

    print(f"Re-affirming {len(entries)} trivy waiver(s) expiring within {args.within_days} day(s) ({scan_note}).")

    dead: list[dict] = []
    fixable: list[str] = []
    escalations: list[list[str]] = []

    for entry in entries:
        if args.scan_dir is None:
            escalations.append(_escalation_lines(entry, carriers, "needs a scan to decide"))
            continue
        verdict = classify(entry, carriers, scanned)
        if verdict == "dead":
            dead.append(entry)
            print(f"  ✓ dead: {entry['id']} no longer appears in any scan — removing the waiver.")
            continue
        if verdict == "unmeasured":
            escalations.append(
                _escalation_lines(entry, carriers, "carrier(s) missing from --scan-dir")
            )
            continue
        proposal = fix_proposal(entry, carriers, registry, today)
        if proposal is not None:
            fixable.append(str(entry["id"]))
            print(
                f"  → fixable: {entry['id']} is cleared by {proposal['bump']['to']} — "
                "dates unchanged; a fix-forward proposal will carry the bump."
            )
            continue
        escalations.append(_escalation_lines(entry, carriers, "no clearing tag found"))

    changed = False
    if dead and not args.check:
        removed = render_waivers.remove_entries(
            registry, [str(e["id"]) for e in dead], args.registry
        )
        if removed:
            errors = render_waivers.validate(registry)
            if errors:
                print(f"✗ registry invalid after removal: {errors[0]}", file=sys.stderr)
                return 2
            render_waivers.save_registry(registry, args.registry)
            render_waivers.write_derived(render_waivers.render_all(registry))
            changed = True
            print(f"Removed {len(removed)} dead waiver(s): {', '.join(sorted(removed))}")

    for lines in escalations:
        print("\n".join(lines))

    if args.check:
        print(
            f"\n[check] dead={len(dead)} fixable={len(fixable)} escalations={len(escalations)} — nothing written."
        )
        return 1 if (dead or fixable or escalations) else 0

    if escalations:
        print(
            f"\n{len(escalations)} waiver(s) need a human decision. No expiry was extended: "
            "an unjustifiable date must never be written (Phase 847d)."
        )
    if fixable:
        print(
            f"\n{len(fixable)} waiver(s) have a clearing upstream tag — run "
            "`scripts/fix_forward.py --state <monitor-state> --apply` to author the bump."
        )

    return 1 if (escalations or fixable or changed) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
