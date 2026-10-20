#!/usr/bin/env python3
"""scripts/scan_regression.py — the PR regression gate (Phase 847c).

THE PROBLEM THIS SOLVES
-----------------------
`make scan` asks every PR two questions at once:

    "did you introduce a vulnerability?"      <- what a PR gate should ask
    "did the upstream vulnerability DB change?"   <- it cannot answer that

so a CVE disclosed on Monday reddened every open PR at once, regardless of
what those PRs touched. That pressure is what produced waivers written to
unblock a merge rather than to document a decision — the Phase 847 root cause.

THE SPLIT
---------
This gate scans **only the surfaces the PR touched**, and fails only on
findings that are not in the baseline recorded on `main`:

    touched surface        scan it, diff against security/baseline.json
    untouched surface      not scanned at all — upstream churn cannot reach it
    nothing touched        pass immediately (the common case, and the big win)

The guarantee that matters survives intact: a PR that bumps an image, adds a
dependency, or edits a Dockerfile gets that surface scanned, and any unwaived
finding it carries that `main` did not already carry **fails the gate**. What
stops failing is a PR that changed nothing security-relevant being reddened by
somebody else's disclosure.

Exit status
    0  pass — no touched surface carries a new unwaived finding
    1  a touched surface carries a finding the baseline does not have
    2  fail-safe: the baseline is unreadable, the diff could not be computed,
       or a surface could not be scanned. NEVER a pass.

Fail-safe, never fail-open: a gate that returns 0 when it cannot read its own
reference data is worse than no gate, because it is trusted.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess  # nosec B404 -- fixed argv, no shell
import sys

try:  # works as `python3 scripts/x.py` and as `from scripts.x import ...`
    from scripts.check_image_versions import (
        FIRST_PARTY_IMAGES,
        SCAN_GATE_COMPOSE_REPOS,
        dockerfile_image_map,
        extract_images_from_text,
    )
    from scripts.scan_baseline import (
        PYPI_SURFACE,
        BaselineError,
        image_name,
        load_baseline,
        new_findings,
        pypi_findings,
        record_findings,
        run_pip_audit,
        scan_image,
        surface_for_image,
    )
except ImportError:  # invoked directly, scripts/ on sys.path
    from check_image_versions import (  # type: ignore[no-redef]
        FIRST_PARTY_IMAGES,
        SCAN_GATE_COMPOSE_REPOS,
        dockerfile_image_map,
        extract_images_from_text,
    )
    from scan_baseline import (  # type: ignore[no-redef]
        PYPI_SURFACE,
        BaselineError,
        image_name,
        load_baseline,
        new_findings,
        pypi_findings,
        record_findings,
        run_pip_audit,
        scan_image,
        surface_for_image,
    )

# Files whose contents define a security surface. Detection follows the same
# file set the scanner uses (SCAN_GATE_COMPOSE_REPOS), so the gate never marks
# a surface that `make scan-images` would not scan — two definitions of "which
# images are in scope" is the divergence this programme exists to remove.
PYPI_FILE_RE = re.compile(
    r"(^|/)(requirements[\w.\-]*\.txt|constraints[\w.\-]*\.txt|pyproject\.toml|Pipfile|Pipfile\.lock)$"
)
# What pip-audit can actually *read* (`-r` wants a requirements-format file). A
# pyproject.toml/Pipfile change still puts the dependency surface in scope, but
# the audit has to run against a requirements file: `pip-audit -r pyproject.toml`
# errors, which would have made a pyproject.toml-only PR exit 2 with "could not
# scan pypi" — a required check failing for a reason unrelated to the change.
AUDITABLE_DEPS_RE = re.compile(r"(^|/)(requirements[\w.\-]*\.txt|constraints[\w.\-]*\.txt)$")
DOCKERFILE_RE = re.compile(r"(^|/)Dockerfile[\w.\-]*$")

# The gate's OWN inputs. `security/waivers.yaml` is the authored registry and
# the three generated files are what Trivy/pip-audit actually apply, so a change
# to any of them changes the verdict for *every* surface — which is the one case
# where scanning only "what this PR touches" would be fail-open: deleting a
# waiver touches no image, so a surface-scoped gate would never look, and the
# finding it un-waives would go unnoticed until the scheduled monitor ran.
WAIVER_INPUTS = (
    "security/waivers.yaml",
    ".trivyignore.third-party",
    ".trivyignore.first-party",
    ".pip-audit-ignores",
)

MAKEFILE = "Makefile"


class DiffError(RuntimeError):
    """The touched-surface diff could not be computed — a failing gate, not a pass."""


def git(*args: str, repo: str = ".") -> str:
    """Run one git command and return stdout; raise DiffError on failure."""
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
            ["git", *args], cwd=repo, capture_output=True, text=True, timeout=120,
        )
    except OSError as exc:
        raise DiffError(f"could not run git {' '.join(args)}: {exc}") from exc
    if proc.returncode != 0:
        raise DiffError(
            f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()[:300]}"
        )
    return proc.stdout


def changed_files(base: str, head: str = "HEAD", repo: str = ".") -> list[str]:
    """Files changed between *base* and *head*, from the merge-base onward.

    Three-dot diff, deliberately: a PR's base may have moved while it was under
    review, and the question is what *this branch* changed — not what main
    changed underneath it.
    """
    out = git("diff", "--name-only", "--diff-filter=d", f"{base}...{head}", repo=repo)
    return [line.strip() for line in out.splitlines() if line.strip()]


def file_at(rev: str, path: str, repo: str = ".") -> str | None:
    """The contents of *path* at *rev*, or None if it did not exist there."""
    try:
        proc = subprocess.run(  # nosec B603 -- fixed argv, no shell
            ["git", "show", f"{rev}:{path}"], cwd=repo, capture_output=True, text=True, timeout=60,
        )
    except OSError as exc:
        raise DiffError(f"could not run git show {rev}:{path}: {exc}") from exc
    if proc.returncode != 0:
        return None
    return proc.stdout


def compose_refs_at(rev: str, repo: str = ".") -> dict[str, frozenset[str]]:
    """`{image name: {versions}}` across the scan-gated compose files at *rev*.

    A *set* of versions per name, not one version: the same image is pinned in
    both the prod and monitoring compose files, so `refs[name] = version` would
    let the last file parsed silently win. That is not hypothetical — bumping
    one file only looks like "no change" under last-wins, which is how this
    gate would have waved through exactly the edit it exists to catch.
    `third_party_image_refs()` treats the same situation as fatal drift; the
    gate does too (a surface with two candidate versions cannot be scanned).
    """
    refs: dict[str, set[str]] = {}
    for compose in SCAN_GATE_COMPOSE_REPOS:
        text = file_at(rev, compose, repo=repo)
        if text is None:
            continue
        for ref in extract_images_from_text(text, source=compose):
            refs.setdefault(ref.name, set()).add(ref.version)
    return {name: frozenset(versions) for name, versions in refs.items()}


def single_ref(name: str, versions: frozenset[str]) -> str:
    """`name:version`, or raise DiffError when the files disagree.

    Fail-safe: an ambiguous image cannot be scanned, and guessing one of the
    versions would scan an artifact the deployment does not run.
    """
    if len(versions) != 1:
        raise DiffError(
            f"{name} resolves to {sorted(versions)} across the gated compose files — "
            f"ambiguous, so there is no single artifact to scan. Fix the drift "
            f"(`python3 scripts/check_image_versions.py --list-third-party` reports it)."
        )
    return f"{name}:{next(iter(versions))}"


def touched_surfaces(
    changed: list[str],
    base_refs: dict[str, frozenset[str]],
    head_refs: dict[str, frozenset[str]],
    dockerfile_images: dict[str, str],
) -> dict[str, dict]:
    """Which surfaces the change touches, and why: `{surface: {ref, reason}}`.

    Pure — the git work is done by the caller, so the decision of *what is in
    scope* is unit-testable without a repository. Raises :class:`DiffError` when
    a touched image has no single version to scan.
    """
    touched: dict[str, dict] = {}

    for name in sorted(head_refs):
        surface = surface_for_image(name)
        head_versions = head_refs[name]
        base_versions = base_refs.get(name)
        if base_versions is None:
            touched[surface] = {
                "ref": single_ref(name, head_versions),
                "reason": "image added",
            }
        elif base_versions != head_versions:
            touched[surface] = {
                "ref": single_ref(name, head_versions),
                "reason": (
                    f"version {', '.join(sorted(base_versions))} -> "
                    f"{', '.join(sorted(head_versions))}"
                ),
            }

    for path in changed:
        if DOCKERFILE_RE.search(path):
            image = dockerfile_images.get(path)
            if image:
                surface = surface_for_image(image_name(image))
                touched.setdefault(surface, {"ref": image, "reason": f"Dockerfile changed ({path})"})
        if PYPI_FILE_RE.search(path):
            touched.setdefault(PYPI_SURFACE, {"ref": requirements_of(changed), "reason": f"deps changed ({path})"})

    return touched


def requirements_of(changed: list[str]) -> str:
    """The requirements-format file to audit, preferring one named in the diff.

    Only files pip-audit can read are candidates. A pyproject.toml change puts
    the dependency surface in scope but still audits `requirements.txt` — the
    file this repo installs from, and the one the recorder and the required
    `dependency-audit-python` job audit — because `-r` on a pyproject.toml fails,
    and a hard failure there would redden a PR for an unrelated reason.
    """
    for path in changed:
        if path.endswith("requirements.txt"):
            return path
    for path in changed:
        if AUDITABLE_DEPS_RE.search(path):
            return path
    return "requirements.txt"


def unscanned_dockerfiles(changed: list[str], dockerfile_images: dict[str, str]) -> list[str]:
    """Changed Dockerfiles that are *not* part of the scanned image set.

    Detection is deliberately limited to what the Makefile builds, because that
    is what `make scan-first-party` scans: marking a surface the scanner does not
    cover would be false coverage, and failing the PR on a dev-tooling Dockerfile
    (`Dockerfile.tools`) would be exactly the unrelated red the split exists to
    remove. It is *reported* rather than ignored — a touched file the gate cannot
    judge must not be silent, which is the programme's "zero silent findings"
    property — and widening the scanned set is 847d/e work, not this gate's.
    """
    return sorted(
        path for path in changed if DOCKERFILE_RE.search(path) and path not in dockerfile_images
    )


def waiver_inputs_changed(changed: list[str]) -> bool:
    """True when the PR edits the waiver registry or the files generated from it."""
    return any(path in WAIVER_INPUTS for path in changed)


def all_surfaces(
    changed: list[str],
    head_refs: dict[str, frozenset[str]],
    dockerfile_images: dict[str, str],
) -> dict[str, dict]:
    """Every surface this repo currently has, for a waiver-input change.

    Compose-derived refs win over Dockerfile-derived ones for the same image, so
    a first-party image pinned in compose is scanned at its deployed tag rather
    than at the Makefile's build tag (they can differ, and the deployed one is
    what the waiver is actually about).
    """
    reason = "waiver set changed"
    everything: dict[str, dict] = {}
    for name in sorted(head_refs):
        everything[surface_for_image(name)] = {"ref": single_ref(name, head_refs[name]), "reason": reason}
    for dockerfile, image in sorted(dockerfile_images.items()):
        everything.setdefault(
            surface_for_image(image_name(image)),
            {"ref": image, "reason": f"{reason} ({dockerfile})"},
        )
    everything.setdefault(PYPI_SURFACE, {"ref": requirements_of(changed), "reason": reason})
    return everything


def scan_surface(surface: str, ref: str, cache: str) -> dict[str, dict]:
    """Scan one surface and return `{finding id: entry}`.

    Raises RuntimeError when the surface could not be scanned — the caller must
    treat that as exit 2, never as "clean" (Phase 847b's lesson, applied here).
    """
    if surface == PYPI_SURFACE:
        return pypi_findings(run_pip_audit(ref))
    rows, digest = scan_image(ref, first_party=image_name(ref) in FIRST_PARTY_IMAGES, cache=cache)
    return record_findings(rows, ref, digest)["findings"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default="origin/main", help="the revision to diff against (default: origin/main)")
    parser.add_argument("--head", default="HEAD", help="the revision under test (default: HEAD)")
    parser.add_argument("--baseline", default=None, help="path to security/baseline.json")
    parser.add_argument("--plan", action="store_true", help="print the touched surfaces as JSON and exit")
    args = parser.parse_args(argv)

    cache = os.environ.get("TRIVY_CACHE", os.path.expanduser("~/.cache/trivy"))

    try:
        changed = changed_files(args.base, args.head)
        base_refs = compose_refs_at(args.base)
        head_refs = compose_refs_at(args.head)
        makefile_text = file_at(args.head, MAKEFILE) or ""
        dockerfiles = dockerfile_image_map(makefile_text)
        if waiver_inputs_changed(changed):
            # The waiver set is an input to the verdict for every surface, so a
            # change to it makes *all* of them "touched". Scanning only the
            # files in the diff would make deleting a waiver a silent no-op.
            touched = all_surfaces(changed, head_refs, dockerfiles)
            # stderr, not stdout: `--plan` writes JSON to stdout and CI parses it.
            print("⚠ a waiver input changed — every surface is in scope for this PR", file=sys.stderr)
        else:
            touched = touched_surfaces(changed, base_refs, head_refs, dockerfiles)
    except DiffError as exc:
        print(f"\u2717 cannot determine what this PR touches: {exc}", file=sys.stderr)
        return 2

    for path in unscanned_dockerfiles(changed, dockerfiles):
        # Visible, not fatal: see the docstring — the scan set is the Makefile's,
        # and a dev-tooling Dockerfile must not block an unrelated PR. Silence
        # here would be the "zero silent findings" property leaking.
        print(
            f"\u26a0 {path} changed but is not built by the Makefile, so it is not in the "
            f"scanned image set — not judged by this gate",
            file=sys.stderr,
        )

    if args.plan:
        print(json.dumps({"base": args.base, "head": args.head, "surfaces": touched}, indent=2, sort_keys=True))
        return 0

    if not touched:
        print(f"\u2713 no security-relevant surface touched ({len(changed)} file(s) changed)")
        print("   nothing to scan — upstream vulnerability-DB churn cannot reach this PR")
        return 0

    print(f"=== Phase 847c regression gate: {len(touched)} surface(s) touched ===")

    try:
        baseline = load_baseline(args.baseline)
    except BaselineError as exc:
        # Fail-safe: without our reference data we cannot say what is new.
        print(f"\u2717 {exc}", file=sys.stderr)
        print("   (refusing to guess — a regression gate with no baseline is a no-op)", file=sys.stderr)
        return 2

    regressions: dict[str, set[str]] = {}
    scan_errors = 0
    for surface, meta in sorted(touched.items()):
        print(f"\n  \u2500\u2500 {surface}  ({meta['reason']})")
        try:
            findings = scan_surface(surface, meta["ref"], cache)
        except (RuntimeError, OSError, ValueError) as exc:
            print(f"    \u2717 could not scan: {exc}", file=sys.stderr)
            scan_errors += 1
            continue
        if not findings:
            print("    \u2713 no HIGH/CRITICAL findings")
            continue
        fresh = new_findings(baseline, surface, findings)
        if not fresh:
            print(f"    \u2713 {len(findings)} finding(s), all already present in the baseline")
            continue
        print(f"    \u2717 {len(fresh)} finding(s) NOT in the baseline:")
        for vid in sorted(fresh):
            entry = findings[vid]
            fix = entry.get("fixed") or ""
            note = f"(fixed in {fix})" if fix else "(no fix published)"
            print(
                f"        {entry['severity']:8s} {vid}  {entry['package']} {entry['installed']}  {note}"
            )
        regressions[surface] = fresh

    if scan_errors:
        print(f"\n\u2717 {scan_errors} surface(s) could not be scanned — failing closed", file=sys.stderr)
        return 2
    if regressions:
        print("\n\u2717 This PR introduces unwaived findings that are not in the baseline.")
        print("   Either fix them (bump the image/dependency) or author a dated waiver in")
        print("   security/waivers.yaml and run `python3 scripts/render_waivers.py` —")
        print("   see docs/runbooks/security_scan_exceptions.md")
        return 1
    print("\n\u2713 no new findings on the surfaces this PR touches")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
