#!/usr/bin/env python3
"""scripts/scan_baseline_monitor.py — the scheduled baseline monitor (Phase 847c).

WHY THIS EXISTS
---------------
The PR regression gate (`scripts/scan_regression.py`) answers "did this PR
introduce a finding?" and deliberately says nothing about the other question:

    main's images/dependencies have acquired new unwaived findings —
    because the vulnerability DB learned about them, or because the world moved.

That question still has to be answered, and answered **without** reddening
somebody's unrelated PR. This monitor is the other half of the split:

    PR gate    -> small, fast, required, blocked only by this PR's own changes
    monitor    -> full scan, scheduled, never blocks, surfaces drift as issues

WHAT IT DOES
------------
1. Full scan of every scannable surface (third-party images, optionally the
   first-party images the caller built, and the Python dependency surface).
2. Diff against `security/baseline.json`: findings that appeared, findings that
   went away, and surfaces whose artifact digest changed underneath us.
3. One GitHub issue per unwaived HIGH/CRITICAL finding, deduplicated by title,
   so re-running cannot flood the tracker.
4. A fix queue: which findings already have a published fix version (that is
   what the fix-forward bot in 847d burns down).

Exit status
    0  ran fine — which includes "ran fine, found nothing" (the steady state)
    1  a surface could not be scanned, or the report could not be produced

A monitor that is silent when its scanner failed is worse than no monitor: the
absence of issues would be read as the absence of problems. So scan failures
are loud and non-zero.

This is deliberately **not** a required check. It must be free to fail without
blocking a merge, or it becomes the very friction 847 exists to remove.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404 -- fixed argv, no shell
import sys

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_image_versions import scan_gate_compose_paths, third_party_image_refs
    from scripts.scan_baseline import (
        BASELINE_PATH,
        BaselineError,
        image_name,
        is_first_party,
        load_baseline,
        new_findings,
        scan_image,
        surface_for_image,
    )
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_image_versions import (  # type: ignore[no-redef]
        scan_gate_compose_paths,
        third_party_image_refs,
    )
    from scan_baseline import (  # type: ignore[no-redef]
        BASELINE_PATH,
        BaselineError,
        image_name,
        is_first_party,
        load_baseline,
        new_findings,
        scan_image,
        surface_for_image,
    )

TITLE_PREFIX = "[cve-baseline]"
#: Ceiling per run, so a DB-wide disaster cannot open a hundred issues at once.
MAX_ISSUES_PER_RUN = 25


def issue_title(surface: str, cve: str) -> str:
    """Stable, greppable title. Deduplication keys on this, so it must not drift."""
    return f"{TITLE_PREFIX} {cve} {surface}"


def issue_body(surface: str, cve: str, info: dict) -> str:
    """The issue body: what it is, where it lives, and the two ways out."""
    fix = info.get("fixed") or ""
    fix_line = (
        f"- **Fix available:** `{info.get('package')}` {info.get('installed')} → {fix}"
        if fix
        else "- **Fix available:** none published yet — track upstream"
    )
    return "\n".join(
        [
            f"`{cve}` was found on `{surface}` by the scheduled CVE baseline monitor.",
            "",
            f"- **Severity:** {info.get('severity', '?')}",
            f"- **Package:** {info.get('package', '?')} {info.get('installed', '')}",
            fix_line,
            "",
            "This issue is filed because the finding is **unwaived**: no entry in",
            "`security/waivers.yaml` covers it. Two ways to close it:",
            "",
            "1. **Fix it** — bump the image tag or the dependency (see the fix version above).",
            "2. **Waive it** — add a dated entry to `security/waivers.yaml` with a reachability",
            "   argument, then run `python3 scripts/render_waivers.py`. Waivers expire; an",
            "   expired waiver is re-raised here rather than silently renewed.",
            "",
            f"_Tracking: {issue_title(surface, cve)}_",
        ]
    )


def plan_issues(current: dict[str, dict], existing_titles: set[str]) -> list[dict]:
    """Findings that need an issue and do not have one yet.

    Pure: the GitHub call is the caller's. Sorted by severity then id so a capped
    run spends its budget on CRITICALs first, and deterministic so a re-run after
    a partial failure does not reorder and re-file.
    """
    planned: list[dict] = []
    for surface in sorted(current):
        for cve, info in sorted(current[surface].get("findings", {}).items()):
            title = issue_title(surface, cve)
            if title in existing_titles:
                continue
            planned.append({"surface": surface, "cve": cve, "title": title, "info": info})
    planned.sort(key=lambda item: (item["info"].get("severity") != "CRITICAL", item["cve"]))
    return planned


def fixable_queue(current: dict[str, dict]) -> list[dict]:
    """Unwaived findings with a published fix — the actionable backlog (847d)."""
    queue = [
        {"surface": surface, "cve": cve, "fix": info.get("fixed", "")}
        for surface in sorted(current)
        for cve, info in sorted(current[surface].get("findings", {}).items())
        if info.get("fixed")
    ]
    return queue


def drift(baseline: dict, current: dict[str, dict]) -> dict:
    """What changed since the baseline: appeared, cleared, or retagged.

    Reported, not gated. This is the noise that used to redden every PR; here it
    lands in a scheduled issue instead, where it can be triaged once.
    """
    appeared: dict[str, list[str]] = {}
    cleared: dict[str, list[str]] = {}
    retagged: dict[str, dict] = {}
    for surface, entry in sorted(current.items()):
        findings = set(entry.get("findings", {}))
        fresh = new_findings(baseline, surface, findings)
        if fresh:
            appeared[surface] = sorted(fresh)
        recorded = baseline.get("surfaces", {}).get(surface, {}).get("findings")
        if recorded is not None:
            gone = set(recorded) - findings
            if gone:
                cleared[surface] = sorted(gone)
            old_digest = baseline.get("surfaces", {}).get(surface, {}).get("digest")
            new_digest = entry.get("digest")
            if old_digest and new_digest and old_digest != new_digest:
                retagged[surface] = {"was": old_digest, "now": new_digest}
    return {"appeared": appeared, "cleared": cleared, "retagged": retagged}


def render_report(current: dict[str, dict], drift_report: dict, planned: list[dict], queue: list[dict]) -> str:
    """Markdown summary — what a human reads first."""
    total = sum(len(entry.get("findings", {})) for entry in current.values())
    lines = [
        "# CVE baseline monitor",
        "",
        f"- Surfaces scanned: **{len(current)}**",
        f"- Unwaived HIGH/CRITICAL findings: **{total}**",
        f"- With a published fix (actionable): **{len(queue)}**",
        f"- New issues to file: **{len(planned)}**",
        "",
    ]
    if drift_report["appeared"]:
        lines.append("## Findings that appeared since the baseline")
        for surface, ids in sorted(drift_report["appeared"].items()):
            lines.append(f"- `{surface}`: {', '.join(ids)}")
        lines.append("")
    if drift_report["cleared"]:
        lines.append("## Findings that went away")
        for surface, ids in sorted(drift_report["cleared"].items()):
            lines.append(f"- `{surface}`: {', '.join(ids)}")
        lines.append("")
    if drift_report["retagged"]:
        lines.append("## Artifact digests that moved")
        for surface, change in sorted(drift_report["retagged"].items()):
            lines.append(f"- `{surface}`: {change['was'][:19]}… → {change['now'][:19]}…")
        lines.append("")
    if not total:
        lines.append("No unwaived HIGH/CRITICAL findings — steady state.")
    return "\n".join(lines) + "\n"


def scan_surfaces(refs: list[str], cache: str) -> tuple[dict[str, dict], list[str]]:
    """Scan every ref; return `(current, failures)`.

    Failures are collected rather than raised so one unreachable image cannot
    hide the findings of the other nine — but the caller must still exit non-zero.
    """
    current: dict[str, dict] = {}
    failures: list[str] = []
    for ref in refs:
        try:
            rows, digest = scan_image(ref, first_party=is_first_party(ref), cache=cache)
        except Exception as exc:  # noqa: BLE001 -- reported, then exit non-zero
            failures.append(f"{ref}: {exc}")
            continue
        entry: dict = {"ref": ref, "findings": {}}
        if digest:
            entry["digest"] = digest
        for row in rows:
            entry["findings"][row.cve] = {
                "severity": row.severity,
                "package": row.package,
                "installed": row.installed,
                "fixed": row.fixed,
            }
        current[surface_for_image(image_name(ref))] = entry
    return current, failures


def existing_issue_titles() -> set[str]:
    """Open issue titles, so re-running cannot re-file the same finding."""
    proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
        ["gh", "issue", "list", "--state", "open", "--limit", "1000", "--json", "title", "--jq", ".[].title"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh issue list failed: {proc.stderr.strip()[:300]}")
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def create_issue(title: str, body: str) -> str:
    """File one issue; return its URL."""
    proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
        ["gh", "issue", "create", "--title", title, "--body", body],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh issue create failed for {title!r}: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", default=None, help=f"baseline path (default: {BASELINE_PATH})")
    parser.add_argument("--apply", action="store_true", help="actually file issues (default: report only)")
    parser.add_argument("--json", action="store_true", help="machine-readable summary instead of markdown")
    parser.add_argument("--images", nargs="*", default=[], help="extra image refs to scan (e.g. built first-party)")
    parser.add_argument("--max-issues", type=int, default=MAX_ISSUES_PER_RUN)
    args = parser.parse_args(argv)

    cache = os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))
    # Third-party refs from the compose files; the caller supplies first-party
    # refs (`make scan-monitor` passes $(FIRST_PARTY_IMAGES)) so the Makefile
    # stays the one authority on what this repo builds.
    refs = third_party_image_refs(scan_gate_compose_paths()) + list(args.images)
    refs = list(dict.fromkeys(refs))

    current, failures = scan_surfaces(refs, cache)
    if failures:
        for failure in failures:
            print(f"\u2717 {failure}", file=sys.stderr)
        print(
            f"\u2717 {len(failures)} surface(s) could not be scanned — refusing to report "
            f"a clean bill of health from a partial scan",
            file=sys.stderr,
        )
        return 1

    try:
        baseline = load_baseline(args.baseline)
    except BaselineError as exc:
        # Drift is unknown without a baseline, but the findings themselves are
        # still real and must still be filed: degrade, do not abort.
        print(f"\u26a0 {exc} — reporting findings without a drift comparison", file=sys.stderr)
        baseline = {"version": 1, "surfaces": {}}

    drift_report = drift(baseline, current)
    queue = fixable_queue(current)

    if args.apply:
        try:
            existing = existing_issue_titles()
        except RuntimeError as exc:
            print(f"\u2717 {exc}", file=sys.stderr)
            return 1
    else:
        existing = set()

    planned = plan_issues(current, existing)
    report = render_report(current, drift_report, planned, queue)

    if args.json:
        print(json.dumps(
            {
                "surfaces": len(current),
                "findings": sum(len(e.get("findings", {})) for e in current.values()),
                "fixable": len(queue),
                "drift": drift_report,
                "planned_issues": [p["title"] for p in planned[: args.max_issues]],
            },
            indent=2,
            sort_keys=True,
        ))
    else:
        print(report)

    if not args.apply:
        if planned:
            print(f"\n(dry run) {len(planned)} issue(s) would be filed; pass --apply to file them")
        return 0

    filed = 0
    for item in planned[: args.max_issues]:
        try:
            url = create_issue(item["title"], issue_body(item["surface"], item["cve"], item["info"]))
        except RuntimeError as exc:
            print(f"\u2717 {exc}", file=sys.stderr)
            return 1
        print(f"\u2713 filed {url}")
        filed += 1
    if len(planned) > args.max_issues:
        print(
            f"\u26a0 {len(planned) - args.max_issues} further finding(s) not filed this run "
            f"(cap {args.max_issues}); they will be picked up next run"
        )
    print(f"\u2713 {filed} issue(s) filed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
