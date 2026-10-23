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
   so re-running cannot flood the tracker. A closed issue whose finding comes
   back is *reopened*, never duplicated.
4. A fix queue: which findings already have a published fix version (that is
   what the fix-forward bot in 847d burns down).
5. With `--state-out FILE`, the machine-readable state
   (`generated_at` / `current` / `drift` / `fixable`) that
   `scripts/fix_forward.py` consumes — the hand-off between "what we measured"
   and "what can be fixed" (Phase 847d). It is written in report-only mode
   too, because the fix-forward step runs before any issue is filed, and it is
   never written from a partial scan.

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
from datetime import datetime, timezone
from pathlib import Path

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_image_versions import scan_gate_compose_paths, third_party_image_refs
    from scripts.scan_baseline import (
        BASELINE_PATH,
        GATING_SEVERITIES,
        MEDIUM_BASELINE_PATH,
        PYPI_SURFACE,
        BaselineError,
        image_name,
        is_first_party,
        load_baseline,
        new_findings,
        pypi_alias_map,
        pypi_findings,
        run_pip_audit,
        scan_image,
        split_waived,
        surface_for_image,
        waived_pip_ids,
    )
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_image_versions import (  # type: ignore[no-redef]
        scan_gate_compose_paths,
        third_party_image_refs,
    )
    from scan_baseline import (  # type: ignore[no-redef]
        BASELINE_PATH,
        GATING_SEVERITIES,
        MEDIUM_BASELINE_PATH,
        PYPI_SURFACE,
        BaselineError,
        image_name,
        is_first_party,
        load_baseline,
        new_findings,
        pypi_alias_map,
        pypi_findings,
        run_pip_audit,
        scan_image,
        split_waived,
        surface_for_image,
        waived_pip_ids,
    )

TITLE_PREFIX = "[cve-baseline]"
#: Ceiling per run, so a DB-wide disaster cannot open a hundred issues at once.
MAX_ISSUES_PER_RUN = 25

# The MEDIUM band (Phase 847e).
MEDIUM_SEVERITIES = "MEDIUM"
#: The bands the monitor measures, in one scan pass.
MONITOR_SEVERITIES = f"{MEDIUM_SEVERITIES},{GATING_SEVERITIES}"


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


def plan_issues(current: dict[str, dict], known: dict[str, dict]) -> list[dict]:
    """Findings that need an issue and do not already have an open one.

    Pure: the GitHub call is the caller's. `known` maps every issue title to
    `{"number", "state"}`. An issue that matches but is CLOSED is *reopened*, not
    duplicated — the plan's alert-fatigue rule is one issue per finding, forever,
    so a finding that comes back after its issue was closed (fixed, waived, then
    un-waived or rolled back) must resurface without minting a second issue and
    without going silent.

    Sorted by severity then id so a capped run spends its budget on CRITICALs
    first, and deterministic so a re-run after a partial failure does not reorder
    and re-file.
    """
    planned: list[dict] = []
    for surface in sorted(current):
        for cve, info in sorted(current[surface].get("findings", {}).items()):
            title = issue_title(surface, cve)
            existing = known.get(title)
            if existing and existing.get("state") == "OPEN":
                continue
            item = {"surface": surface, "cve": cve, "title": title, "info": info}
            if existing:
                item["reopen"] = existing.get("number")
            planned.append(item)
    planned.sort(key=lambda item: (item["info"].get("severity") != "CRITICAL", item["cve"]))
    return planned


DEAD_WAIVER_PREFIX = "[cve-waiver]"


def dead_waiver_title(cve: str) -> str:
    """Stable title for a dead-waiver issue. Deduplication keys on it, so it must not drift."""
    return f"{DEAD_WAIVER_PREFIX} {cve}"


def dead_waiver_body(cve: str) -> str:
    """What a dead waiver is, why it matters, and the one command that removes it."""
    return "\n".join(
        [
            f"`{cve}` is waived in `security/waivers.yaml`, but no audit reports it any more.",
            "",
            "That makes the waiver **dead**: it waives nothing today, which would be",
            "harmless if it stayed that way. It does not. The rendered `--ignore-vuln`",
            "outlives the finding, so if a later change regresses the pinned dependency",
            "back into the vulnerable range the audit reports the CVE and the ignore",
            "**suppresses it silently** — the exact failure the CVE process exists to",
            "prevent (Phase 848).",
            "",
            "Remove it through the validated splice, which refuses rather than drops a",
            "carrier another waiver still claims:",
            "",
            "```bash",
            f"python3 scripts/render_waivers.py --drop {cve}",
            "```",
            "",
            "Commit `security/waivers.yaml` with the regenerated derived files. This issue",
            "closes itself on the next monitor run once the waiver is gone.",
            "",
            f"_Tracking: {dead_waiver_title(cve)}_",
        ]
    )


def plan_dead_waiver_issues(dead: list[str], known: dict[str, dict]) -> list[dict]:
    """Dead waivers that need an issue and do not already have an open one (pure).

    Same alert-fatigue rule as :func:`plan_issues`: one issue per waiver id,
    forever — a waiver that dies, is removed, then dies again reopens the same
    issue rather than minting a second one.
    """
    planned: list[dict] = []
    for cve in sorted(dead):
        title = dead_waiver_title(cve)
        existing = known.get(title)
        if existing and existing.get("state") == "OPEN":
            continue
        item = {"cve": cve, "title": title}
        if existing:
            item["reopen"] = existing.get("number")
        planned.append(item)
    return planned


def plan_waiver_closures(dead: list[str], known: dict[str, dict]) -> list[dict]:
    """Open dead-waiver issues whose waiver is no longer dead (pure).

    The other half of the loop: an alert that can only open is a list that grows.
    A waiver removed (or genuinely live again) closes its own issue on the next
    run, so what stays open is exactly what still needs a human.
    """
    live = set(dead)
    closures: list[dict] = []
    prefix = f"{DEAD_WAIVER_PREFIX} "
    for title, meta in sorted(known.items()):
        if not title.startswith(prefix) or meta.get("state") != "OPEN":
            continue
        cve = title[len(prefix) :]
        if cve not in live:
            closures.append({"number": meta["number"], "cve": cve})
    return closures


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


def medium_state(medium: dict[str, dict], medium_baseline: dict | None) -> dict:
    """The MEDIUM band's live state against the committed record (Phase 847e).

    The MEDIUM surface is a backlog this repository has committed to shrinking,
    so the interesting number is not "how many MEDIUM findings exist" but "how
    many exist now, against how many we recorded, against the ceiling we set".
    A live count above the ceiling means the backlog grew, and growth is
    supposed to be visible rather than absorbed.

    The live count is *not* a gate and never blocks: the vulnerability database
    churns daily, and a ratchet measured against a live scan would be a
    coin-flip. The committed record is what the ratchet (and the PR gate)
    judges against; this is the monitor's report of the difference.
    """
    live = sum(len(entry.get("findings", {})) for entry in medium.values())
    recorded = 0
    ceiling = 0
    if medium_baseline:
        recorded = sum(
            len(entry.get("findings", {}))
            for entry in (medium_baseline.get("surfaces") or {}).values()
        )
        ceiling = int(medium_baseline.get("ceiling", 0))
    return {
        "live": live,
        "recorded": recorded,
        "ceiling": ceiling,
        "over_ceiling": live > ceiling,
        "surfaces": {
            surface: len(entry.get("findings", {}))
            for surface, entry in sorted(medium.items())
            if entry.get("findings")
        },
    }


def render_report(
    current: dict[str, dict],
    drift_report: dict,
    planned: list[dict],
    queue: list[dict],
    medium: dict | None = None,
    dead: list[str] | None = None,
) -> str:
    """Markdown summary — what a human reads first."""
    total = sum(len(entry.get("findings", {})) for entry in current.values())
    lines = [
        "# CVE baseline monitor",
        "",
        f"- Surfaces scanned: **{len(current)}**",
        f"- Unwaived HIGH/CRITICAL findings: **{total}**",
        f"- With a published fix (actionable): **{len(queue)}**",
        f"- New issues to file: **{len(planned)}**",
    ]
    if dead is not None:
        lines.append(f"- Dead pip waivers (waiving nothing): **{len(dead)}**")
    lines.append("")
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
    if medium is not None:
        lines.extend(
            [
                "## MEDIUM band (Phase 847e)",
                "",
                f"- Unwaived MEDIUM findings now: **{medium['live']}**",
                f"- Recorded in `security/baseline-medium.json`: **{medium['recorded']}**",
                f"- Ceiling (may only go down): **{medium['ceiling']}**",
                "",
            ]
        )
        if medium["over_ceiling"]:
            lines.extend(
                [
                    f"\u26a0 the live MEDIUM count ({medium['live']}) is above the ceiling "
                    f"({medium['ceiling']}) — the backlog grew. Each new MEDIUM finding has to be "
                    "fixed or waived; it is not absorbed by the record.",
                    "",
                ]
            )
        if medium["surfaces"]:
            lines.append("Per surface:")
            lines.append("")
            for surface, count in sorted(medium["surfaces"].items(), key=lambda kv: -kv[1]):
                lines.append(f"- `{surface}`: {count}")
            lines.append("")
    if dead:
        lines.extend(
            [
                "## Dead pip waivers (Phase 848)",
                "",
                "These ids are waived in `security/waivers.yaml` but reported by no audit.",
                "The ignore is still applied, so a regression into the vulnerable range",
                "would be suppressed silently. Remove each with:",
                "",
                f"    python3 scripts/render_waivers.py --drop {dead[0]}",
                "",
            ]
        )
        for cve in dead:
            lines.append(f"- `{cve}`")
        lines.append("")
    if not total:
        lines.append("No unwaived HIGH/CRITICAL findings — steady state.")
    return "\n".join(lines) + "\n"


def scan_surfaces(
    refs: list[str], cache: str
) -> tuple[dict[str, dict], dict[str, dict], list[str], list[str]]:
    """Scan every ref *and* the dependency surface.

    Returns `(current, medium, failures, dead_waivers)`.

    `current` holds the HIGH/CRITICAL findings, in the same shape it has had
    since Phase 847c — the fix-forward bot (847d) consumes it, so its content
    must not change under it. `medium` holds the MEDIUM findings (Phase 847e's
    band), in the same shape.

    One scan pass, two partitions. Two passes would be easier to write and
    wrong: the vulnerability database moves under us, and the two bands have to
    describe the same moment or their totals cannot be compared with anything.

    The dependency surface is scanned here rather than left to a Makefile target
    because the monitor's job is completeness: it is the only thing watching for
    drift on surfaces nobody touched, so a surface it forgot is a surface nobody
    watches. It is `requirements.txt`, the same file the required
    `dependency-audit-python` job audits, so the two cannot disagree about what
    "the Python dependency surface" means. It has no MEDIUM band — pip-audit
    reports no severity — so it appears in `current` only.

    The dependency audit runs **without** the waiver flags and the registry's
    waivers are subtracted in process (Phase 848). Applying them in pip-audit —
    which is what this did before — filters a waived id out of the output before
    anything can compare it, which is exactly how dead waivers stayed invisible:
    an ignore for a finding that no longer exists looks identical to a live one.
    One audit, both answers. The findings the caller sees are unchanged (same
    primary ids); the difference is that ids nobody reported come back as
    `dead_waivers` instead of silently vanishing.

    Failures are collected rather than raised so one unreachable image cannot
    hide the findings of the other nine — but the caller must still exit non-zero.
    """
    current: dict[str, dict] = {}
    medium: dict[str, dict] = {}
    failures: list[str] = []
    for ref in refs:
        try:
            rows, digest = scan_image(
                ref,
                first_party=is_first_party(ref),
                cache=cache,
                severities=MONITOR_SEVERITIES,
            )
        except Exception as exc:  # noqa: BLE001 -- reported, then exit non-zero
            failures.append(f"{ref}: {exc}")
            continue
        surface = surface_for_image(image_name(ref))
        entry: dict = {"ref": ref, "findings": {}}
        medium_entry: dict = {"ref": ref, "findings": {}}
        if digest:
            entry["digest"] = digest
            medium_entry["digest"] = digest
        for row in rows:
            info = {
                "severity": row.severity,
                "package": row.package,
                "installed": row.installed,
                "fixed": row.fixed,
            }
            if row.severity in GATING_SEVERITIES.split(","):
                entry["findings"][row.cve] = info
            elif row.severity == MEDIUM_SEVERITIES:
                medium_entry["findings"][row.cve] = info
        current[surface] = entry
        medium[surface] = medium_entry
    dead: list[str] = []
    try:
        deps = run_pip_audit(ignorefile=None)
        unwaived, dead = split_waived(
            pypi_findings(deps), waived_pip_ids(), pypi_alias_map(deps)
        )
        current[PYPI_SURFACE] = {"findings": unwaived}
    except Exception as exc:  # noqa: BLE001 -- reported, then exit non-zero
        failures.append(f"{PYPI_SURFACE}: {exc}")
    return current, medium, failures, dead


def issues_by_title() -> dict[str, dict]:
    """Every issue, by title: `{"number": n, "state": "OPEN"|"CLOSED"}`.

    ALL states, deliberately. Filtering to open issues would re-file a finding
    whose issue a human closed (fixed, waived, or consciously accepted) on every
    subsequent run — a daily flood of duplicates, which is the adoption risk the
    plan names. Closed issues are reopened instead (see :func:`plan_issues`).
    """
    proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
        [
            "gh", "issue", "list",
            "--state", "all",
            "--limit", "1000",
            "--json", "number,title,state",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh issue list failed: {proc.stderr.strip()[:300]}")
    return {item["title"]: {"number": item["number"], "state": item["state"]} for item in json.loads(proc.stdout)}


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


def reopen_issue(number: int, body: str) -> str:
    """Reopen a closed issue and comment the fresh evidence. Returns a reference."""
    for argv in (
        ["gh", "issue", "reopen", str(number)],
        ["gh", "issue", "comment", str(number), "--body", body],
    ):
        proc = subprocess.run(argv, capture_output=True, text=True)  # nosec B603, B607
        if proc.returncode != 0:
            raise RuntimeError(f"`{' '.join(argv[:3])}` failed: {proc.stderr.strip()[:300]}")
    return f"#{number} (reopened)"


def close_issue(number: int, body: str) -> str:
    """Comment then close a resolved issue. Returns a reference."""
    for argv in (
        ["gh", "issue", "comment", str(number), "--body", body],
        ["gh", "issue", "close", str(number), "--reason", "completed"],
    ):
        proc = subprocess.run(argv, capture_output=True, text=True)  # nosec B603, B607
        if proc.returncode != 0:
            raise RuntimeError(f"`{' '.join(argv[:3])}` failed: {proc.stderr.strip()[:300]}")
    return f"#{number} (closed)"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", default=None, help=f"baseline path (default: {BASELINE_PATH})")
    parser.add_argument(
        "--medium-baseline",
        default=None,
        help=f"MEDIUM band record (default: {MEDIUM_BASELINE_PATH})",
    )
    parser.add_argument("--apply", action="store_true", help="actually file issues (default: report only)")
    parser.add_argument("--json", action="store_true", help="machine-readable summary instead of markdown")
    parser.add_argument("--images", nargs="*", default=[], help="extra image refs to scan (e.g. built first-party)")
    parser.add_argument("--max-issues", type=int, default=MAX_ISSUES_PER_RUN)
    parser.add_argument(
        "--state-out",
        type=Path,
        default=None,
        help=(
            "write the machine-readable monitor state here for downstream steps "
            "(Phase 847d: scripts/fix_forward.py consumes it). Written in "
            "report-only mode too, since the fix-forward bot runs before any "
            "issue is filed. Never written from a partial scan."
        ),
    )
    args = parser.parse_args(argv)

    cache = os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))
    # Third-party refs from the compose files; the caller supplies first-party
    # refs (`make scan-monitor` passes $(FIRST_PARTY_IMAGES)) so the Makefile
    # stays the one authority on what this repo builds.
    refs = third_party_image_refs(scan_gate_compose_paths()) + list(args.images)
    refs = list(dict.fromkeys(refs))

    current, medium, failures, dead = scan_surfaces(refs, cache)
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

    # The MEDIUM band's own record (Phase 847e). Its absence is not fatal: the
    # HIGH/CRITICAL findings are still real and must still be filed. It only
    # means the MEDIUM counts have nothing to be compared against.
    medium_baseline: dict | None = None
    try:
        medium_baseline = load_baseline(args.medium_baseline or MEDIUM_BASELINE_PATH)
    except BaselineError as exc:
        print(f"\u26a0 {exc} — reporting MEDIUM counts without a record to compare against", file=sys.stderr)
    medium_report = medium_state(medium, medium_baseline)

    drift_report = drift(baseline, current)
    queue = fixable_queue(current)

    if args.state_out is not None:
        # The fix-forward bot (Phase 847d) runs as a LATER step and needs the
        # findings this run measured — but it must never act on a partial
        # picture, which is why this sits after the `failures` early-return
        # above: a surface that could not be scanned aborts before we get here.
        args.state_out.parent.mkdir(parents=True, exist_ok=True)
        args.state_out.write_text(
            json.dumps(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "current": current,
                    "medium": medium_report,
                    "drift": drift_report,
                    "fixable": queue,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    if args.apply:
        try:
            existing = issues_by_title()
        except (RuntimeError, json.JSONDecodeError) as exc:
            print(f"\u2717 {exc}", file=sys.stderr)
            return 1
    else:
        existing = {}

    planned = plan_issues(current, existing)
    dead_planned = plan_dead_waiver_issues(dead, existing)
    closures = plan_waiver_closures(dead, existing)
    report = render_report(current, drift_report, planned, queue, medium_report, dead)

    if args.json:
        print(json.dumps(
            {
                "surfaces": len(current),
                "findings": sum(len(e.get("findings", {})) for e in current.values()),
                "fixable": len(queue),
                "drift": drift_report,
                "medium": medium_report,
                "dead_waivers": dead,
                "planned_issues": [p["title"] for p in planned[: args.max_issues]],
                "planned_dead_waiver_issues": [p["title"] for p in dead_planned],
                "planned_waiver_closures": [c["number"] for c in closures],
            },
            indent=2,
            sort_keys=True,
        ))
    else:
        print(report)

    if not args.apply:
        if planned:
            print(f"\n(dry run) {len(planned)} issue(s) would be filed; pass --apply to file them")
        if dead_planned:
            print(f"(dry run) {len(dead_planned)} dead-waiver issue(s) would be filed")
        if closures:
            print(f"(dry run) {len(closures)} dead-waiver issue(s) would be closed")
        return 0

    filed = 0
    for item in planned[: args.max_issues]:
        body = issue_body(item["surface"], item["cve"], item["info"])
        try:
            if item.get("reopen"):
                url = reopen_issue(item["reopen"], f"Reappeared after this issue was closed.\n\n{body}")
            else:
                url = create_issue(item["title"], body)
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
    for item in dead_planned:
        body = dead_waiver_body(item["cve"])
        try:
            if item.get("reopen"):
                url = reopen_issue(item["reopen"], f"Still dead after this issue was closed.\n\n{body}")
            else:
                url = create_issue(item["title"], body)
        except RuntimeError as exc:
            print(f"\u2717 {exc}", file=sys.stderr)
            return 1
        print(f"\u2713 filed {url} (dead waiver)")
        filed += 1

    for closure in closures:
        try:
            ref = close_issue(
                closure["number"],
                f"`{closure['cve']}` is no longer a dead waiver — it is either removed "
                "from `security/waivers.yaml` or reported again. Closing automatically "
                "(Phase 848); reopen if it dies again.",
            )
        except RuntimeError as exc:
            print(f"\u2717 {exc}", file=sys.stderr)
            return 1
        print(f"\u2713 closed {ref} (dead waiver resolved)")

    print(f"\u2713 {filed} issue(s) filed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
