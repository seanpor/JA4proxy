#!/usr/bin/env python3
"""Canonical findings register CLI for JA4proxy.

Source of truth: docs/security/findings.yaml
Human-readable view: docs/security/FINDINGS_REGISTER.md (generated)

Subcommands:
    validate                  Schema + referential integrity checks. Exit 1 on error.
    list                      Filtered listing. --status, --severity, --lane, --sla-breach, --phase.
    add                       Allocate next canonical ID, append a new finding, and open a GitHub issue.
    dedup-hint                Fuzzy match a title against existing findings.
    render                    Regenerate FINDINGS_REGISTER.md human view.
    promote-verified          Auto-promote VERIFIED → CLOSED after 14 days no regression.
    show                      Print a single finding by ID.
    verify-regression-tests   Run just the regression tests listed in the register.
    sync-issues               Reconcile findings.yaml status with GitHub issue state.
"""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
REGISTER_PATH = REPO_ROOT / "docs" / "security" / "findings.yaml"
MARKDOWN_PATH = REPO_ROOT / "docs" / "security" / "FINDINGS_REGISTER.md"

GITHUB_REPO = "seanpor/JA4proxy"

# Severities → GitHub issue label (labels must already exist in the repo)
SEVERITY_LABELS = {
    "CRITICAL": "severity: critical",
    "HIGH": "severity: high",
    "MEDIUM": "severity: medium",
    "LOW": "severity: low",
}

# Statuses that should result in the GitHub issue being closed
CLOSED_STATUSES = {"CLOSED", "DUPLICATE"}

VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
VALID_STATUSES = ("OPEN", "IN_PROGRESS", "FIXED", "VERIFIED", "CLOSED", "DUPLICATE")
VALID_LANES = ("go-proxy", "python-management", "infrastructure")

SLA_DAYS = {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 60, "LOW": 120}
VERIFIED_TO_CLOSED_DAYS = 14

# Phase 814a: findings discovered on or after this date must record the build
# they were found against (`found_against`). Without it a retest cannot tell
# "we fixed it" from "it no longer reproduces for an unrelated reason" — the
# two look identical in a register. The 94 findings that predate the pentest
# range are grandfathered rather than back-filled with guesses; this is a
# frozen baseline, exactly like check_manifest.py's HISTORICAL_CHANGELOG_GAPS.
# Never move this date forward to dodge the check.
PROVENANCE_REQUIRED_FROM = date(2026, 8, 5)

ID_RE = re.compile(r"^JA4PROXY-(\d{4})-(\d{4})$")
CVSS_RE = re.compile(r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/")


@dataclass
class Register:
    schema_version: int
    last_allocated_id: int
    findings: list[dict[str, Any]]
    _raw: dict[str, Any]

    @classmethod
    def load(cls, path: Path = REGISTER_PATH) -> "Register":
        raw = yaml.safe_load(path.read_text()) or {}
        return cls(
            schema_version=raw.get("schema_version", 1),
            last_allocated_id=raw.get("last_allocated_id", 0),
            findings=raw.get("findings") or [],
            _raw=raw,
        )

    def save(self, path: Path = REGISTER_PATH) -> None:
        self._raw["schema_version"] = self.schema_version
        self._raw["last_allocated_id"] = self.last_allocated_id
        self._raw["findings"] = self.findings
        preamble = _preserve_preamble(path)
        body = yaml.safe_dump(
            {
                "schema_version": self.schema_version,
                "last_allocated_id": self.last_allocated_id,
                "findings": self.findings,
            },
            sort_keys=False,
            default_flow_style=False,
            width=100,
        )
        path.write_text(preamble + body)

    def next_id(self, year: int | None = None) -> str:
        year = year or date.today().year
        self.last_allocated_id += 1
        return f"JA4PROXY-{year}-{self.last_allocated_id:04d}"


def _preserve_preamble(path: Path) -> str:
    """Keep the top-of-file comment block (schema documentation)."""
    if not path.exists():
        return ""
    lines = path.read_text().splitlines(keepends=True)
    kept = []
    for line in lines:
        if line.startswith("#") or line.strip() == "":
            kept.append(line)
        else:
            break
    return "".join(kept)


def _parse_date(s: str | date) -> date:
    if isinstance(s, date):
        return s
    return datetime.strptime(s, "%Y-%m-%d").date()


def _due_for(severity: str, discovered: date) -> date:
    return discovered + timedelta(days=SLA_DAYS[severity])


def _earliest_discovered(finding: dict[str, Any]) -> date | None:
    refs = finding.get("source_refs") or []
    dates = []
    for ref in refs:
        d = ref.get("discovered")
        if d:
            dates.append(_parse_date(d))
    if finding.get("discovered"):
        dates.append(_parse_date(finding["discovered"]))
    return min(dates) if dates else None


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------

REQUIRED_AT_CREATION = {
    "id",
    "title",
    "severity",
    "severity_rationale",
    "source_refs",
    "discovered",
    "due",
    "status",
    "lane",
}


def cmd_validate(args: argparse.Namespace) -> int:
    reg = Register.load()
    errors: list[str] = []
    seen_ids: set[str] = set()
    highest_seen = 0

    for i, f in enumerate(reg.findings):
        where = f"findings[{i}] ({f.get('id', '<no id>')})"

        # Required fields
        missing = REQUIRED_AT_CREATION - set(f.keys())
        if missing:
            errors.append(f"{where}: missing fields {sorted(missing)}")
            continue

        # ID format + uniqueness + monotonic ceiling
        fid = f["id"]
        m = ID_RE.match(fid)
        if not m:
            errors.append(f"{where}: id does not match JA4PROXY-YYYY-NNNN")
        else:
            highest_seen = max(highest_seen, int(m.group(2)))
        if fid in seen_ids:
            errors.append(f"{where}: duplicate id {fid}")
        seen_ids.add(fid)

        # Enums
        if f["severity"] not in VALID_SEVERITIES:
            errors.append(f"{where}: invalid severity {f['severity']!r}")
        if f["status"] not in VALID_STATUSES:
            errors.append(f"{where}: invalid status {f['status']!r}")
        if f["lane"] not in VALID_LANES:
            errors.append(f"{where}: invalid lane {f['lane']!r}")

        # source_refs shape
        refs = f.get("source_refs") or []
        if not isinstance(refs, list) or not refs:
            errors.append(f"{where}: source_refs must be a non-empty list")
        else:
            for j, ref in enumerate(refs):
                if not isinstance(ref, dict):
                    errors.append(f"{where}.source_refs[{j}]: not a mapping")
                    continue
                for k in ("report", "id"):
                    if not ref.get(k):
                        errors.append(f"{where}.source_refs[{j}]: missing {k}")

        # CVSS optional but if present must be well-formed
        cvss = f.get("cvss_v3_1")
        if cvss:
            if not isinstance(cvss, dict):
                errors.append(f"{where}.cvss_v3_1: must be a mapping")
            else:
                if not isinstance(cvss.get("score"), (int, float)):
                    errors.append(f"{where}.cvss_v3_1.score: must be numeric")
                vec = cvss.get("vector", "")
                if vec and not CVSS_RE.match(vec):
                    errors.append(
                        f"{where}.cvss_v3_1.vector: {vec!r} not CVSS:3.1 form"
                    )

        # Dates + SLA consistency
        try:
            discovered = _parse_date(f["discovered"])
            due = _parse_date(f["due"])
            expected_due = _due_for(f["severity"], discovered)
            if due != expected_due:
                errors.append(
                    f"{where}: due={due} does not match severity={f['severity']} "
                    f"SLA from discovered={discovered} (expected {expected_due})"
                )
        except (ValueError, KeyError) as exc:
            errors.append(f"{where}: date parse failure: {exc}")

        # Provenance: what build was this found against? (Phase 814a)
        provenance = f.get("found_against")
        if provenance is not None:
            if not isinstance(provenance, dict):
                errors.append(
                    f"{where}.found_against: must be a mapping "
                    "(git_sha, optional config_sha256 / image_digests)"
                )
            elif not provenance.get("git_sha"):
                errors.append(f"{where}.found_against: git_sha is required")
        else:
            try:
                if _parse_date(f["discovered"]) >= PROVENANCE_REQUIRED_FROM:
                    errors.append(
                        f"{where}: discovered on/after {PROVENANCE_REQUIRED_FROM} "
                        "requires found_against (the build it was found against). "
                        "`make pentest-range` prints the block to paste."
                    )
            except (ValueError, KeyError):
                pass  # date problems are already reported above

        # DUPLICATE must set supersedes
        if f["status"] == "DUPLICATE":
            if not f.get("supersedes"):
                errors.append(
                    f"{where}: status=DUPLICATE requires non-empty supersedes"
                )
            else:
                for sup in f["supersedes"]:
                    if sup not in {g["id"] for g in reg.findings}:
                        errors.append(f"{where}.supersedes: unknown id {sup}")

        # Regression test required once status ≥ FIXED
        if f["status"] in ("FIXED", "VERIFIED", "CLOSED"):
            rt = f.get("regression_test")
            if not rt:
                errors.append(f"{where}: status={f['status']} requires regression_test")
            elif not _regression_test_exists(rt):
                errors.append(
                    f"{where}: regression_test {rt!r} does not resolve to a file"
                )

        # closed_commit required when CLOSED
        if f["status"] == "CLOSED" and not f.get("closed_commit"):
            errors.append(f"{where}: status=CLOSED requires closed_commit")

        # VERIFIED/CLOSED require verified_by + verified_on (closure protocol §FIXED→VERIFIED)
        if f["status"] in ("VERIFIED", "CLOSED"):
            if not f.get("verified_by"):
                errors.append(f"{where}: status={f['status']} requires verified_by")
            if not f.get("verified_on"):
                errors.append(f"{where}: status={f['status']} requires verified_on")
            else:
                try:
                    _parse_date(f["verified_on"])
                except (ValueError, TypeError):
                    errors.append(
                        f"{where}: verified_on must be ISO date (got {f['verified_on']!r})"
                    )

        # remediation_phases referential: only strings accepted, don't hard-check phase existence here
        rps = f.get("remediation_phases") or []
        if not isinstance(rps, list):
            errors.append(f"{where}: remediation_phases must be a list")

    # last_allocated_id must be ≥ highest seen
    if highest_seen > reg.last_allocated_id:
        errors.append(
            f"last_allocated_id={reg.last_allocated_id} < highest id suffix {highest_seen}"
        )

    # Transitive DUPLICATE sanity: supersedes chains must not loop and must end at an OPEN/IN_PROGRESS/… entry
    by_id = {f["id"]: f for f in reg.findings}
    for f in reg.findings:
        if f.get("status") != "DUPLICATE":
            continue
        seen_chain = {f["id"]}
        cur = f
        while cur.get("status") == "DUPLICATE":
            sup = (cur.get("supersedes") or [None])[0]
            if sup is None or sup in seen_chain:
                errors.append(f"{f['id']}: supersedes chain loops or is empty")
                break
            seen_chain.add(sup)
            cur = by_id.get(sup)
            if cur is None:
                errors.append(f"{f['id']}: supersedes target {sup} not found")
                break

    if errors:
        print(f"findings register: {len(errors)} error(s)", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    n = len(reg.findings)
    print(f"findings register OK: {n} finding(s)")
    return 0


def _regression_test_exists(nodeid: str) -> bool:
    """Best-effort resolution. Accepts pytest nodeids (path::func) or plain paths."""
    path_part = nodeid.split("::", 1)[0]
    p = REPO_ROOT / path_part
    return p.exists()


# ---------------------------------------------------------------------------
# GitHub issue helpers
# ---------------------------------------------------------------------------


def _gh_available() -> bool:
    """Return True if `gh` CLI is on PATH and authenticated."""
    try:
        r = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            timeout=10,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _issue_body(finding: dict[str, Any]) -> str:
    lines = [
        f"**Canonical ID:** `{finding['id']}`",
        f"**Severity:** {finding['severity']}",
        f"**Lane:** {finding.get('lane', '')}",
        f"**SLA due:** {finding.get('due', '')}",
        "",
    ]
    cvss = finding.get("cvss_v3_1")
    if cvss:
        lines += [
            f"**CVSS v3.1:** {cvss.get('score', '')} — `{cvss.get('vector', '')}`",
            "",
        ]
    rationale = finding.get("severity_rationale", "")
    if rationale and not rationale.startswith("TODO"):
        lines += [f"**Severity rationale:** {rationale}", ""]
    refs = finding.get("source_refs") or []
    if refs:
        lines.append("**Source references:**")
        for ref in refs:
            lines.append(f"- {ref.get('report','')} / {ref.get('id','')} (discovered {ref.get('discovered','')})")
        lines.append("")
    notes = finding.get("notes", "")
    if notes:
        lines += ["**Notes:**", notes, ""]
    lines += [
        "---",
        "_This issue is mirrored from `docs/security/findings.yaml`. "
        "The YAML file is the authoritative record; update status there, "
        "then run `python3 scripts/findings_register.py sync-issues`._",
    ]
    return "\n".join(lines)


def _gh_create_issue(finding: dict[str, Any]) -> int | None:
    """Create a GitHub issue for a finding. Returns the issue number or None on failure."""
    if not _gh_available():
        print("  gh CLI not available or not authenticated — skipping issue creation", file=sys.stderr)
        return None

    label_name = SEVERITY_LABELS.get(finding["severity"], "")
    cmd = [
        "gh", "issue", "create",
        "--repo", GITHUB_REPO,
        "--title", f"{finding['id']}: {finding['title']}",
        "--body", _issue_body(finding),
        "--label", "security",
    ]
    if label_name:
        cmd += ["--label", label_name]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        print("  gh issue create timed out", file=sys.stderr)
        return None

    if r.returncode != 0:
        # Missing label is the most common transient error — warn but don't abort.
        print(f"  gh issue create failed: {r.stderr.strip()}", file=sys.stderr)
        return None

    # `gh issue create` prints the issue URL as its last line.
    url = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    m = re.search(r"/issues/(\d+)$", url)
    if not m:
        print(f"  could not parse issue number from: {url!r}", file=sys.stderr)
        return None

    number = int(m.group(1))
    print(f"  opened GitHub issue #{number}: {url}")
    return number


def _gh_comment_canonical(number: int, canonical_id: str) -> None:
    """Leave a comment on an existing issue recording the canonical register ID."""
    if not _gh_available():
        return
    body = (
        f"This issue has been triaged and registered in the canonical findings register "
        f"as **`{canonical_id}`**.\n\n"
        f"The authoritative record (CVSS, SLA, status) is maintained in "
        f"`docs/security/findings.yaml`. This issue is the work-surface; "
        f"status updates flow from the YAML via "
        f"`python3 scripts/findings_register.py sync-issues`."
    )
    try:
        subprocess.run(
            ["gh", "issue", "comment", str(number), "--repo", GITHUB_REPO, "--body", body],
            capture_output=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        pass


def _gh_close_issue(number: int, comment: str = "") -> bool:
    """Close a GitHub issue, optionally leaving a comment."""
    if not _gh_available():
        return False
    cmd = ["gh", "issue", "close", str(number), "--repo", GITHUB_REPO]
    if comment:
        cmd += ["--comment", comment]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _gh_reopen_issue(number: int) -> bool:
    """Reopen a GitHub issue (used by sync-issues when status regresses to OPEN)."""
    if not _gh_available():
        return False
    try:
        r = subprocess.run(
            ["gh", "issue", "reopen", str(number), "--repo", GITHUB_REPO],
            capture_output=True, text=True, timeout=30,
        )
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _gh_issue_state(number: int) -> str | None:
    """Return 'OPEN' or 'CLOSED', or None if the issue can't be fetched."""
    if not _gh_available():
        return None
    try:
        r = subprocess.run(
            ["gh", "issue", "view", str(number), "--repo", GITHUB_REPO, "--json", "state", "-q", ".state"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip().upper() or None
    except subprocess.TimeoutExpired:
        return None


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    reg = Register.load()
    today = date.today()
    out = []
    for f in reg.findings:
        if args.status and f.get("status") != args.status:
            continue
        if args.severity and f.get("severity") != args.severity:
            continue
        if args.lane and f.get("lane") != args.lane:
            continue
        if args.phase and args.phase not in (f.get("remediation_phases") or []):
            continue
        if args.sla_breach:
            if f.get("status") in ("CLOSED", "DUPLICATE"):
                continue
            try:
                due = _parse_date(f["due"])
            except (KeyError, ValueError):
                continue
            if due >= today:
                continue
        out.append(f)

    if args.json:
        json.dump(out, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0

    if not out:
        print("(no matches)")
        return 0

    print(f"{'ID':<22} {'SEV':<9} {'STATUS':<12} {'DUE':<12} {'LANE':<20} TITLE")
    for f in out:
        print(
            f"{f.get('id',''):<22} {f.get('severity',''):<9} "
            f"{f.get('status',''):<12} {str(f.get('due','')):<12} "
            f"{f.get('lane',''):<20} {f.get('title','')}"
        )
    return 0


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------


def cmd_add(args: argparse.Namespace) -> int:
    reg = Register.load()
    discovered = _parse_date(args.discovered) if args.discovered else date.today()
    severity = args.severity.upper()
    if severity not in VALID_SEVERITIES:
        print(f"invalid severity {severity!r}", file=sys.stderr)
        return 2
    if args.lane not in VALID_LANES:
        print(f"invalid lane {args.lane!r}", file=sys.stderr)
        return 2

    finding: dict[str, Any] = {
        "id": reg.next_id(),
        "title": args.title,
        "severity": severity,
        "severity_rationale": args.severity_rationale
        or "TODO — populate per SEVERITY_RUBRIC.md",
        "source_refs": [
            {
                "report": args.source,
                "id": args.source_id,
                "discovered": discovered.isoformat(),
            }
        ],
        "remediation_phases": args.remediation_phases or [],
        "owner": args.owner or "",
        "lane": args.lane,
        "discovered": discovered.isoformat(),
        "due": _due_for(severity, discovered).isoformat(),
        "status": "OPEN",
        "supersedes": [],
        "depends_on": [],
        "regression_test": "",
        "closed_commit": "",
    }
    if args.cvss:
        finding["cvss_v3_1"] = {"score": args.cvss_score or 0.0, "vector": args.cvss}
    if args.notes:
        finding["notes"] = args.notes

    reg.findings.append(finding)
    reg.save()
    print(f"added {finding['id']}: {finding['title']}")

    if args.issue:
        # Caller supplied an existing issue number — link it, add a comment to
        # tie the canonical ID back to the issue, but do not create a new one.
        existing = int(args.issue)
        _gh_comment_canonical(existing, finding["id"])
        reg2 = Register.load()
        for f in reg2.findings:
            if f["id"] == finding["id"]:
                f["github_issue"] = existing
                break
        reg2.save()
        print(f"  linked existing GitHub issue #{existing} (github_issue written to findings.yaml)")
    elif not args.no_issue:
        issue_num = _gh_create_issue(finding)
        if issue_num is not None:
            # Reload and patch so we don't clobber the just-written file.
            reg2 = Register.load()
            for f in reg2.findings:
                if f["id"] == finding["id"]:
                    f["github_issue"] = issue_num
                    break
            reg2.save()
            print(f"  github_issue: {issue_num} written to findings.yaml")
    return 0


# ---------------------------------------------------------------------------
# dedup-hint
# ---------------------------------------------------------------------------


def cmd_dedup_hint(args: argparse.Namespace) -> int:
    reg = Register.load()
    query = args.query.lower()
    titles = [(f["id"], f["title"]) for f in reg.findings]
    matches = difflib.get_close_matches(
        query, [t.lower() for _, t in titles], n=args.limit, cutoff=args.cutoff
    )
    if not matches:
        print("(no candidates)")
        return 0
    hits = [(fid, title) for fid, title in titles if title.lower() in matches]
    for fid, title in hits:
        print(f"{fid}  {title}")
    return 0


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


def cmd_render(args: argparse.Namespace) -> int:
    reg = Register.load()
    if not MARKDOWN_PATH.exists():
        print(f"{MARKDOWN_PATH} not found", file=sys.stderr)
        return 1

    today = date.today()
    counts_sev = {s: 0 for s in VALID_SEVERITIES}
    counts_status = {s: 0 for s in VALID_STATUSES}
    breaches: list[dict[str, Any]] = []
    for f in reg.findings:
        if f.get("severity") in counts_sev:
            counts_sev[f["severity"]] += 1
        if f.get("status") in counts_status:
            counts_status[f["status"]] += 1
        if f.get("status") not in ("CLOSED", "DUPLICATE"):
            try:
                if _parse_date(f["due"]) < today:
                    breaches.append(f)
            except (KeyError, ValueError):
                pass

    lines = [
        "",
        f"## Register snapshot ({today.isoformat()})",
        "",
        f"**Total:** {len(reg.findings)} canonical finding(s).",
        "",
        "| Severity | Count | Status | Count |",
        "|----------|-------|--------|-------|",
    ]
    sev_rows = [(s, counts_sev[s]) for s in VALID_SEVERITIES]
    st_rows = [(s, counts_status[s]) for s in VALID_STATUSES]
    rows = max(len(sev_rows), len(st_rows))
    for i in range(rows):
        sev = f"{sev_rows[i][0]} | {sev_rows[i][1]}" if i < len(sev_rows) else " | "
        st = f"{st_rows[i][0]} | {st_rows[i][1]}" if i < len(st_rows) else " | "
        lines.append(f"| {sev} | {st} |")
    lines.append("")

    if breaches:
        lines.append(f"### SLA breaches ({len(breaches)})")
        lines.append("")
        lines.append("| ID | Severity | Due | Title |")
        lines.append("|----|----------|-----|-------|")
        for f in breaches:
            lines.append(f"| {f['id']} | {f['severity']} | {f['due']} | {f['title']} |")
        lines.append("")
    else:
        lines.append("_No SLA breaches._")
        lines.append("")

    if reg.findings:
        lines.append("### All findings")
        lines.append("")
        lines.append("| ID | Severity | Status | Lane | Due | Title |")
        lines.append("|----|----------|--------|------|-----|-------|")
        for f in sorted(reg.findings, key=lambda x: x["id"]):
            lines.append(
                f"| {f['id']} | {f['severity']} | {f['status']} | "
                f"{f.get('lane','')} | {f.get('due','')} | {f['title']} |"
            )
        lines.append("")

    body = "\n".join(lines)
    text = MARKDOWN_PATH.read_text()
    start = "<!-- BEGIN GENERATED: findings_register.py render -->"
    end = "<!-- END GENERATED -->"
    if start not in text or end not in text:
        print("markdown file missing generated markers", file=sys.stderr)
        return 1
    before, rest = text.split(start, 1)
    _, after = rest.split(end, 1)
    new_text = f"{before}{start}\n{body}\n{end}{after}"
    MARKDOWN_PATH.write_text(new_text)
    print(
        f"rendered {len(reg.findings)} finding(s) into {MARKDOWN_PATH.relative_to(REPO_ROOT)}"
    )
    return 0


# ---------------------------------------------------------------------------
# promote-verified
# ---------------------------------------------------------------------------


def cmd_promote_verified(args: argparse.Namespace) -> int:
    reg = Register.load()
    today = date.today()
    promoted = 0
    skipped: list[str] = []
    for f in reg.findings:
        if f.get("status") != "VERIFIED":
            continue
        verified_on = f.get("verified_on")
        verified_by = f.get("verified_by")
        if not verified_on or not verified_by:
            skipped.append(f"{f['id']}: missing verified_by/verified_on")
            continue
        if (today - _parse_date(verified_on)).days < VERIFIED_TO_CLOSED_DAYS:
            continue
        if not f.get("closed_commit"):
            skipped.append(f"{f['id']}: missing closed_commit")
            continue
        f["status"] = "CLOSED"
        promoted += 1
    if promoted:
        reg.save()
    for s in skipped:
        print(f"skip {s}", file=sys.stderr)
    print(f"promoted {promoted} finding(s) VERIFIED → CLOSED")
    return 0


# ---------------------------------------------------------------------------
# verify-regression-tests
# ---------------------------------------------------------------------------


def cmd_verify_regression_tests(args: argparse.Namespace) -> int:
    """Run only the regression tests listed in the register.

    Separates pytest nodeids (tests/*.py::name) from Go nodeids
    (internal/**/*_test.go::TestName). Runs each set once.

    By default, entries with empty regression_test are ignored. With
    --require-all, missing regression_test on any non-OPEN finding is an
    error. With --stub-green, if there are zero populated nodeids the
    command exits 0 with an explanatory message (useful before 121d/h
    land the first regression tests).
    """
    reg = Register.load()
    py_nodes: list[str] = []
    go_nodes: list[str] = []
    missing: list[str] = []

    for f in reg.findings:
        rt = (f.get("regression_test") or "").strip()
        status = f.get("status", "OPEN")
        if not rt:
            if status in ("FIXED", "VERIFIED", "CLOSED"):
                missing.append(f"{f['id']} ({status}): no regression_test")
            continue
        if (
            rt.startswith("tests/")
            or rt.startswith("src/")
            or rt.startswith("management/")
        ):
            py_nodes.append(rt)
        elif (
            rt.startswith("internal/")
            or rt.startswith("cmd/")
            or rt.endswith("_test.go")
            or "::Test" in rt
        ):
            go_nodes.append(rt)
        else:
            # Best-effort default: treat as pytest nodeid
            py_nodes.append(rt)

    if args.require_all and missing:
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        print(f"{len(missing)} finding(s) missing regression_test", file=sys.stderr)
        return 1

    if not py_nodes and not go_nodes:
        msg = "no regression tests currently listed in findings.yaml"
        if args.stub_green:
            print(f"verify-regression-tests: {msg} — exiting 0 (stub-green mode)")
            return 0
        print(f"verify-regression-tests: {msg}", file=sys.stderr)
        print(
            "  Run with --stub-green to allow this, or populate regression_test",
            file=sys.stderr,
        )
        print(
            "  on FIXED/VERIFIED/CLOSED findings per docs/developer/TESTING_STRATEGY.md §6.",
            file=sys.stderr,
        )
        return 1

    failures = 0
    if py_nodes:
        # tests/ and management/tests/ each have __init__.py, so pytest
        # registers both conftest.py files under module name "tests.conftest"
        # and aborts with ImportPathMismatchError when the two trees are
        # collected together. Run each top-level group in its own pytest
        # invocation from the repo root to avoid the collision.
        groups: dict[str, list[str]] = {}
        for n in py_nodes:
            top = "management" if n.startswith("management/") else "."
            groups.setdefault(top, []).append(n)
        print(
            f"verify-regression-tests: running {len(py_nodes)} pytest nodeid(s) "
            f"across {len(groups)} group(s)"
        )
        for _group, nodes in groups.items():
            rc = subprocess.call(
                ["python3", "-m", "pytest", "-q", "--no-header", *nodes],
                cwd=str(REPO_ROOT),
            )
            if rc != 0:
                failures += 1
    if go_nodes:
        # Group by package directory: Go runs one package per invocation.
        pkgs: dict[str, list[str]] = {}
        for n in go_nodes:
            path_part, _, name = n.partition("::")
            pkg_dir = str(Path(path_part).parent)
            pkgs.setdefault(pkg_dir, []).append(name or ".")
        print(
            f"verify-regression-tests: running {len(go_nodes)} go test(s) across {len(pkgs)} package(s)"
        )
        for pkg, names in pkgs.items():
            run_arg = "|".join(n for n in names if n != ".")
            cmd = ["go", "test", "-count=1"]
            if run_arg:
                cmd += ["-run", f"^({run_arg})$"]
            cmd.append(f"./{pkg}")
            rc = subprocess.call(cmd, cwd=str(REPO_ROOT))
            if rc != 0:
                failures += 1

    if failures:
        print(
            f"verify-regression-tests: {failures} test invocation(s) failed",
            file=sys.stderr,
        )
        return 1
    print("verify-regression-tests: all regression tests passed")
    return 0


# ---------------------------------------------------------------------------
# sync-issues
# ---------------------------------------------------------------------------


def cmd_sync_issues(args: argparse.Namespace) -> int:
    """Reconcile findings.yaml status with GitHub issue state.

    For each finding that has a github_issue number:
    - If status is CLOSED or DUPLICATE → close the issue (if open).
    - If status is OPEN/IN_PROGRESS/FIXED/VERIFIED → reopen the issue (if closed).

    Findings without a github_issue are optionally reported with --report-missing.
    With --dry-run, no GitHub mutations are made.
    """
    if not _gh_available():
        print("gh CLI not available or not authenticated", file=sys.stderr)
        return 1

    reg = Register.load()
    closed_count = 0
    reopened_count = 0
    skipped_count = 0
    missing: list[str] = []

    for f in reg.findings:
        fid = f["id"]
        issue_num = f.get("github_issue")
        if not issue_num:
            missing.append(fid)
            continue

        status = f.get("status", "OPEN")
        gh_state = _gh_issue_state(issue_num)
        if gh_state is None:
            print(f"  {fid} #{issue_num}: could not fetch state — skipped", file=sys.stderr)
            skipped_count += 1
            continue

        should_be_closed = status in CLOSED_STATUSES

        if should_be_closed and gh_state == "OPEN":
            comment = f"Auto-closed: findings.yaml status is {status}."
            if not args.dry_run:
                ok = _gh_close_issue(issue_num, comment=comment)
                if ok:
                    print(f"  {fid} #{issue_num}: closed (status={status})")
                    closed_count += 1
                else:
                    print(f"  {fid} #{issue_num}: close failed", file=sys.stderr)
                    skipped_count += 1
            else:
                print(f"  [dry-run] {fid} #{issue_num}: would close (status={status})")
                closed_count += 1

        elif not should_be_closed and gh_state == "CLOSED":
            if not args.dry_run:
                ok = _gh_reopen_issue(issue_num)
                if ok:
                    print(f"  {fid} #{issue_num}: reopened (status={status})")
                    reopened_count += 1
                else:
                    print(f"  {fid} #{issue_num}: reopen failed", file=sys.stderr)
                    skipped_count += 1
            else:
                print(f"  [dry-run] {fid} #{issue_num}: would reopen (status={status})")
                reopened_count += 1
        else:
            # Already in sync.
            pass

    if args.report_missing and missing:
        print(f"\nFindings without a github_issue ({len(missing)}):")
        for fid in missing:
            print(f"  {fid}")

    prefix = "[dry-run] " if args.dry_run else ""
    print(
        f"\n{prefix}sync-issues: {closed_count} closed, {reopened_count} reopened, "
        f"{skipped_count} skipped, {len(missing)} without issue number"
    )
    return 0


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


def cmd_show(args: argparse.Namespace) -> int:
    reg = Register.load()
    for f in reg.findings:
        if f["id"] == args.id:
            yaml.safe_dump(f, sys.stdout, sort_keys=False, default_flow_style=False)
            return 0
    print(f"not found: {args.id}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("validate", help="Schema + referential integrity checks")

    pl = sub.add_parser("list", help="Filtered listing")
    pl.add_argument("--status", choices=VALID_STATUSES)
    pl.add_argument("--severity", choices=VALID_SEVERITIES)
    pl.add_argument("--lane", choices=VALID_LANES)
    pl.add_argument("--phase", help="Filter by remediation phase ID, e.g. 118a")
    pl.add_argument("--sla-breach", action="store_true", help="Only past-due findings")
    pl.add_argument("--json", action="store_true")

    pa = sub.add_parser("add", help="Allocate a new canonical finding and open a GitHub issue")
    pa.add_argument("--title", required=True)
    pa.add_argument("--severity", required=True)
    pa.add_argument("--severity-rationale")
    pa.add_argument("--source", required=True, help="Source report tag, e.g. PHASE_118")
    pa.add_argument(
        "--source-id", required=True, help="Original ID in the source, e.g. 118a-01"
    )
    pa.add_argument("--discovered", help="ISO date (default: today)")
    pa.add_argument("--lane", required=True, choices=VALID_LANES)
    pa.add_argument("--owner", help="GitHub handle, e.g. @seanpor")
    pa.add_argument("--cvss", help="CVSS:3.1 vector string")
    pa.add_argument("--cvss-score", type=float)
    pa.add_argument("--remediation-phases", nargs="*", help="Phase IDs, e.g. 118a 109")
    pa.add_argument("--notes")
    issue_group = pa.add_mutually_exclusive_group()
    issue_group.add_argument(
        "--no-issue",
        action="store_true",
        help="Skip GitHub issue creation (offline / CI use)",
    )
    issue_group.add_argument(
        "--issue",
        type=int,
        metavar="N",
        help="Link an existing GitHub issue number instead of creating a new one",
    )

    pd = sub.add_parser(
        "dedup-hint", help="Fuzzy match a title against existing findings"
    )
    pd.add_argument("query")
    pd.add_argument("--limit", type=int, default=5)
    pd.add_argument("--cutoff", type=float, default=0.55)

    sub.add_parser("render", help="Regenerate FINDINGS_REGISTER.md")
    sub.add_parser("promote-verified", help="VERIFIED → CLOSED after 14 days")

    pv = sub.add_parser(
        "verify-regression-tests",
        help="Run the regression tests listed in the register",
    )
    pv.add_argument(
        "--require-all",
        action="store_true",
        help="Fail if any FIXED/VERIFIED/CLOSED finding lacks a regression_test",
    )
    pv.add_argument(
        "--stub-green",
        action="store_true",
        help="Exit 0 when there are zero regression tests to run (bootstrap mode)",
    )

    ps = sub.add_parser("show", help="Print a single finding by ID")
    ps.add_argument("id")

    psi = sub.add_parser(
        "sync-issues",
        help="Reconcile findings.yaml status with GitHub issue state",
    )
    psi.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without making any GitHub mutations",
    )
    psi.add_argument(
        "--report-missing",
        action="store_true",
        help="List findings that have no github_issue number",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "validate": cmd_validate,
        "list": cmd_list,
        "add": cmd_add,
        "dedup-hint": cmd_dedup_hint,
        "render": cmd_render,
        "promote-verified": cmd_promote_verified,
        "verify-regression-tests": cmd_verify_regression_tests,
        "show": cmd_show,
        "sync-issues": cmd_sync_issues,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
