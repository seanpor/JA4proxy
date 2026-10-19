#!/usr/bin/env python3
"""scripts/scan_baseline.py — record and query the CVE baseline (Phase 847c).

WHY THIS EXISTS
---------------
The required Security Scan conflates two different questions:

    1. did THIS PR introduce a new unwaived finding?      (a regression)
    2. did the upstream vulnerability DB change overnight? (not a regression)

Because it conflated them, a new upstream CVE reddened every open PR at once,
which is what created the pressure to waive rather than fix (Phase 847 root
cause). Phase 847c splits the two:

    PR regression gate  -> scans only the surfaces the PR touches, and fails
                           only on findings absent from the recorded baseline
    baseline monitor    -> full scan on a schedule, surfaces drift as issues

This module is the shared core of both: the baseline file format, its loader,
and the "is this finding new?" diff. It contains no scanner invocation in the
diff path, so the gate's decision logic is unit-testable without docker.

THE MODEL
---------
A **surface** is one thing that can carry findings, keyed by *name* rather than
by tag or digest:

    image:grafana/grafana     a third-party image (all tags collapse to one key)
    image:ja4proxy            a first-party image we build
    pypi                      Python runtime dependencies (requirements.txt)

Baseline entries record the immutable **digest** of the artifact that was
scanned, next to the set of unwaived HIGH/CRITICAL finding ids found on it.
The digest is provenance and staleness evidence; the *diff* is over finding
ids, because "this PR introduced a finding" means "this CVE id was not present
on this surface before", not "the tag changed".

That distinction is deliberate. Keying the diff by digest would fail every
routine image bump, including a bump to an image carrying exactly the CVEs we
already had — a gate that cries wolf gets waived, which is the failure mode
this whole programme exists to remove. Keying it by CVE id keeps the guarantee
that matters: a *new* unwaived finding on a surface the PR touched fails.

FAIL-SAFE, NEVER FAIL-OPEN
--------------------------
A missing, unreadable or malformed baseline raises :class:`BaselineError`. A
surface the baseline has never seen is treated as carrying **only new**
findings, so the PR that introduces it must fix or waive them. Callers must map
these to a failing exit — never to a pass (Phase 847c's headline requirement).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess  # nosec B404 -- invokes fixed argv, no shell
import sys
from pathlib import Path
from typing import Iterable

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_image_versions import (
        FIRST_PARTY_IMAGES,
        scan_gate_compose_paths,
        third_party_image_refs,
    )
    from scripts.check_trivyignore_drift import vuln_rows
    from scripts.trivy_image_report import GATING_SEVERITIES, run_trivy
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_image_versions import (  # type: ignore[no-redef]
        FIRST_PARTY_IMAGES,
        scan_gate_compose_paths,
        third_party_image_refs,
    )
    from check_trivyignore_drift import vuln_rows  # type: ignore[no-redef]
    from trivy_image_report import GATING_SEVERITIES, run_trivy  # type: ignore[no-redef]

BASELINE_PATH = Path("security/baseline.json")
PYPI_SURFACE = "pypi"
TRIVY_IGNOREFILE_THIRD_PARTY = ".trivyignore.third-party"
TRIVY_IGNOREFILE_FIRST_PARTY = ".trivyignore.first-party"
TOOLS_IMAGE = "ja4proxy-tools"


class BaselineError(RuntimeError):
    """The baseline is missing, unreadable or the wrong shape.

    Callers must treat this as a FAILURE. A gate that silently passes when it
    cannot read its own reference data is worse than no gate, because it is
    trusted.
    """


def surface_for_image(image_name: str) -> str:
    """`grafana/grafana` -> `image:grafana/grafana` (tag deliberately dropped)."""
    return f"image:{image_name}"


def image_name(ref: str) -> str:
    """Strip the tag/digest from an image reference, keeping any registry port.

    `grafana/grafana:13.2.4-ubuntu`      -> `grafana/grafana`
    `localhost:5000/x:1`                 -> `localhost:5000/x`
    `x@sha256:abc`                       -> `x`
    `redis:7.4.11-alpine@sha256:abc`     -> `redis`

    The digest is dropped *first*: a digest-pinned ref also carries a tag, and
    handling the `@` case by returning `ref.split("@")[0]` left the tag in the
    key — found live, where the compose-pinned `redis:7.4.11-alpine@sha256:…`
    recorded `image:redis:7.4.11-alpine` instead of `image:redis`. A tag-keyed
    surface breaks the whole design: routine tag bumps would mint a new surface,
    whose findings are all "new" by definition, so the gate would fail exactly
    the bumps it is meant to allow through.
    """
    ref = ref.split("@", 1)[0]
    head, sep, tail = ref.rpartition(":")
    # A colon with no slash after it is a tag; with a slash it is a registry port.
    if sep and "/" not in tail:
        return head
    return ref


def empty_baseline(recorded_at: str) -> dict:
    """A well-formed but empty baseline (all surfaces unknown => all new)."""
    return {"version": 1, "recorded_at": recorded_at, "surfaces": {}}


def load_baseline(path: str | os.PathLike[str] | None = None) -> dict:
    """Read and validate the baseline.

    Raises :class:`BaselineError` for a missing file, invalid JSON, an
    unsupported `version`, or a `surfaces` value that is not an object. Anything
    the diff would otherwise have to guess about is rejected here, where the
    message can name the file.
    """
    p = Path(path) if path is not None else BASELINE_PATH
    if not p.is_file():
        raise BaselineError(
            f"baseline {p} does not exist — record it with `make scan-baseline` "
            f"(or scripts/scan_baseline.py --record)"
        )
    try:
        data = json.loads(p.read_text())
    except ValueError as exc:
        raise BaselineError(f"baseline {p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError(f"baseline {p} must be a JSON object, got {type(data).__name__}")
    if data.get("version") != 1:
        raise BaselineError(f"baseline {p} has unsupported version {data.get('version')!r} (want 1)")
    surfaces = data.get("surfaces")
    if not isinstance(surfaces, dict):
        raise BaselineError(f"baseline {p} must have a 'surfaces' object")
    for name, entry in surfaces.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("findings"), dict):
            raise BaselineError(f"baseline {p}: surface {name!r} must be an object with a 'findings' object")
    return data


def surface_findings(baseline: dict, surface: str) -> dict[str, dict] | None:
    """The recorded findings for *surface*, or None if the baseline never saw it."""
    entry = baseline.get("surfaces", {}).get(surface)
    if entry is None:
        return None
    return entry.get("findings", {})


def new_findings(baseline: dict, surface: str, current_ids: Iterable[str]) -> set[str]:
    """Ids present now but absent from the baseline for *surface*.

    An unrecorded surface is **entirely new**: we have no evidence those
    findings pre-existed, so the safe reading is that they did not. This is the
    fail-safe direction, and it is what makes "a PR that adds a vulnerable
    image fails" fall out without a special case.
    """
    recorded = surface_findings(baseline, surface)
    known = set(recorded) if recorded is not None else set()
    return set(current_ids) - known


def finding_entry(row) -> dict:
    """Serialise one parser row (`VulnRow`) into a baseline finding entry.

    `fixed` is the upstream fix version ("" when none is published) rather than
    a boolean: the fix-forward queue wants to *act* on the value, and a
    yes/no forces a second lookup that can disagree with the record.
    """
    return {
        "severity": row.severity,
        "package": row.package,
        "installed": row.installed,
        "fixed": row.fixed or "",
    }


def record_findings(rows: Iterable, ref: str, digest: str | None) -> dict:
    """Build one surface entry from parsed rows (pure; no scanning).

    Rows are already filtered to `GATING_SEVERITIES` by the scanner. Anything
    else reaching here is a broken filter, and silently recording it would
    widen what a later PR is allowed to introduce — so it raises instead.
    """
    gating = GATING_SEVERITIES.split(",")
    findings = {}
    for row in rows:
        if row.severity not in gating:
            raise ValueError(
                f"{row.cve} has non-gating severity {row.severity!r} — the scanner's "
                f"--severity filter is not being applied"
            )
        findings[row.cve] = finding_entry(row)
    entry: dict = {"findings": findings}
    if ref:
        entry["ref"] = ref
    if digest:
        entry["digest"] = digest
    return entry


def build_baseline(entries: dict[str, dict], recorded_at: str) -> dict:
    """Assemble a baseline document from `{surface: entry}` (pure)."""
    return {
        "version": 1,
        "recorded_at": recorded_at,
        "surfaces": {name: entries[name] for name in sorted(entries)},
    }


def render_baseline(baseline: dict) -> str:
    """Stable JSON: sorted keys, trailing newline, no timestamps beyond recorded_at.

    A baseline that churns on whitespace produces worthless reviews. Sorting and
    a fixed indent keep diffs to actual findings.
    """
    return json.dumps(baseline, indent=2, sort_keys=True) + "\n"


def ignore_vuln_args(ignorefile: str = ".pip-audit-ignores") -> list[str]:
    """Read the generated ignore file into argv (pure; what the shell word-split does).

    The file is emitted by `scripts/render_waivers.py` as one `--ignore-vuln ID`
    pair per line with comment headers, and the Makefile consumes it by
    word-splitting. Parsing it here rather than hard-coding ids keeps Phase
    847a's single-source-of-truth property: a waiver authored once in
    `security/waivers.yaml` reaches the baseline and the regression gate with no
    second list to drift.
    """
    path = Path(ignorefile)
    if not path.is_file():
        raise BaselineError(
            f"{ignorefile} is missing — run `python3 scripts/render_waivers.py` "
            f"(it is generated from security/waivers.yaml)"
        )
    args: list[str] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        args.extend(stripped.split())
    return args


def pip_audit_cmd(requirements: str = "requirements.txt", ignorefile: str = ".pip-audit-ignores") -> list[str]:
    """The exact argv pip-audit receives (pure, so tests can assert the policy).

    Runs inside the pinned tools image for the same reason every other Python
    check does: the host interpreter is not the production target.

    Deliberately *not* `pip-audit-resilient.sh`: that wrapper soft-passes (exit
    0) when both PyPI and OSV are unreachable, which is the right trade for the
    `lint-static` gate — a double outage should not page a maintainer. In a
    **regression** gate the same outage would read as "no findings here", so a
    PR that touched requirements would pass on somebody else's outage. Fail-safe
    means this one exits non-zero and says why.
    """
    return [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}:/src", "-w", "/src",
        TOOLS_IMAGE,
        "pip-audit", "-r", requirements, "-f", "json",
        *ignore_vuln_args(ignorefile),
    ]


def run_pip_audit(requirements: str = "requirements.txt") -> list[dict]:
    """Run pip-audit and return its `dependencies` list.

    Raises RuntimeError when the audit could not be run or parsed — the same
    never-treat-a-failed-scan-as-clean rule as the image gate (Phase 847b).
    """
    proc = subprocess.run(pip_audit_cmd(requirements), capture_output=True, text=True)  # nosec B603 -- fixed argv
    if not proc.stdout.strip():
        raise RuntimeError(f"pip-audit produced no output: {proc.stderr.strip()[:300]}")
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        raise RuntimeError(f"pip-audit output was not JSON ({exc}): {proc.stdout[:200]!r}") from exc
    deps = report.get("dependencies")
    if not isinstance(deps, list):
        raise RuntimeError("pip-audit report has no 'dependencies' list")
    return deps


def pypi_findings(deps: Iterable[dict]) -> dict[str, dict]:
    """Flatten pip-audit dependencies into `{vuln_id: entry}` (pure).

    pip-audit reports one vuln id per entry (`id`, with `aliases`); the primary
    id is the stable key, which is what a baseline diff needs.
    """
    out: dict[str, dict] = {}
    for dep in deps:
        for vuln in dep.get("vulns", []) or []:
            vid = vuln.get("id")
            if not vid:
                continue
            out[vid] = {
                "severity": "HIGH",  # pip-audit carries no severity; treat as gating
                "package": dep.get("name", "?"),
                "installed": dep.get("version", "?"),
                "fixed": ", ".join(vuln.get("fix_versions") or []),
            }
    return out


def image_digest(ref: str) -> str | None:
    """Resolve an image reference to its manifest digest, or None if unavailable.

    Best-effort *provenance only*: the diff never depends on it, so a registry
    that cannot be reached must not make the gate fail. The digest recorded is
    what a future reader needs to answer "was this the artifact we scanned?".
    """
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv
            ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", ref],
            capture_output=True, text=True,
        )
    except OSError:
        return None
    out = proc.stdout.strip()
    if proc.returncode != 0 or "@" not in out:
        return None
    return out.split("@", 1)[1]


def report_digest(report: dict) -> str | None:
    """The digest of what Trivy actually scanned, from its own report.

    Preferred over `docker image inspect`: a registry image is pulled by Trivy
    itself and may never enter the local daemon, so inspect returns nothing for
    exactly the images the gate scans (measured: grafana gave `None`). Trivy
    records the pulled artifact in `Metadata.RepoDigests`, which is the
    provenance the baseline is supposed to hold. First-party images are built
    locally and have no RepoDigests, so :func:`image_digest` stays the fallback.
    """
    for entry in (report.get("Metadata") or {}).get("RepoDigests") or []:
        if "@" in entry:
            return entry.split("@", 1)[1]
    return None


def scan_image(ref: str, first_party: bool, cache: str | None = None) -> tuple[list, str | None]:
    """Scan one image and return (rows, digest).

    `first_party` selects the ignorefile scope and enables the docker socket:
    locally-built images exist only in the local daemon, so Trivy cannot find
    them without it (the Phase 847b defect that made `ja4proxy-tap` silently
    unscannable).
    """
    ignorefile = TRIVY_IGNOREFILE_FIRST_PARTY if first_party else TRIVY_IGNOREFILE_THIRD_PARTY
    cache_dir = cache or os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))
    report = run_trivy(ref, ignorefile, cache_dir, docker_socket=first_party)
    return vuln_rows(report), report_digest(report) or image_digest(ref)


def is_first_party(ref: str) -> bool:
    """True when *ref* names one of the images this repo builds."""
    return image_name(ref) in FIRST_PARTY_IMAGES


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--record", action="store_true", help="scan every surface and write the baseline")
    parser.add_argument("--out", default=str(BASELINE_PATH), help=f"baseline path (default: {BASELINE_PATH})")
    parser.add_argument("--images", nargs="*", default=[], help="extra image refs to record (appended to the compose list)")
    parser.add_argument("--no-third-party", action="store_true", help="skip the compose-derived third-party list")
    parser.add_argument("--no-pypi", action="store_true", help="skip the Python dependency surface")
    parser.add_argument("--summary", action="store_true", help="print the recorded surfaces and exit")
    args = parser.parse_args(argv)

    if args.summary:
        try:
            baseline = load_baseline(args.out)
        except BaselineError as exc:
            print(f"\u2717 {exc}", file=sys.stderr)
            return 2
        for name, entry in baseline.get("surfaces", {}).items():
            print(f"{name}: {len(entry.get('findings', {}))} finding(s)")
        return 0

    if not args.record:
        parser.error("nothing to do: pass --record or --summary")

    # Third-party refs come from the compose files; first-party refs are passed
    # in by the caller (`make scan-baseline` passes $(FIRST_PARTY_IMAGES)), so
    # there is exactly one authority per list rather than a second one here that
    # could disagree with the Makefile about what the repo builds.
    refs: list[str] = []
    if not args.no_third_party:
        refs += third_party_image_refs(scan_gate_compose_paths())
    refs += list(args.images)
    refs = list(dict.fromkeys(refs))  # stable de-dupe; order preserved for readable output
    entries: dict[str, dict] = {}
    failed = 0
    cache = os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))
    for ref in refs:
        try:
            rows, digest = scan_image(ref, is_first_party(ref), cache)
        except Exception as exc:  # noqa: BLE001 -- any scan failure is fatal here
            print(f"\u2717 could not scan {ref}: {exc}", file=sys.stderr)
            failed += 1
            continue
        entries[surface_for_image(image_name(ref))] = record_findings(rows, ref, digest)
        print(f"  {ref}: {len(rows)} HIGH/CRITICAL finding(s)")

    if not args.no_pypi:
        try:
            entries[PYPI_SURFACE] = {"findings": pypi_findings(run_pip_audit())}
        except Exception as exc:  # noqa: BLE001
            print(f"\u2717 could not audit Python dependencies: {exc}", file=sys.stderr)
            failed += 1

    if failed:
        # Never write a partial baseline: a surface missing from the file would
        # read as "nothing known here", turning a scan outage into a failed PR
        # gate later (or, worse, an accepted finding).
        print(f"\u2717 {failed} surface(s) could not be recorded — baseline NOT written", file=sys.stderr)
        return 2

    baseline = build_baseline(
        entries,
        recorded_at=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_baseline(baseline))
    print(f"\u2713 wrote {out} ({len(entries)} surface(s), "
          f"{sum(len(e['findings']) for e in entries.values())} finding(s))")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
