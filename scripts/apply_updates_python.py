#!/usr/bin/env python3
"""
apply_updates_python.py — Python multi-environment parity dependency updater.

Designed to run containerized inside `ja4proxy-tools` (Python 3.15).
Parses requirements.txt, requirements-analytics.txt, and management/requirements.txt,
computes the combined upper-bound constraints for shared packages, queries the PyPI
JSON API for the latest stable compatible release, updates all occurrences in lockstep,
and validates transitive compatibility via scripts/check_deps_resolution.py.

Usage:
    python3 scripts/apply_updates_python.py [--dry-run] [--skip-validate]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIREMENT_FILES: list[Path] = [
    REPO_ROOT / "requirements.txt",
    REPO_ROOT / "requirements-analytics.txt",
    REPO_ROOT / "management" / "requirements.txt",
]

_MAX_PYPI_BYTES = 16 * 1024 * 1024  # 16 MiB bound (boto3 JSON is ~8 MiB)
_PYPI_PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_REQ_LINE_RE = re.compile(
    r"^(?P<indent>\s*)"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?P<extras>\[[^\]]+\])?"
    r"(?P<op>==|>=)"
    r"(?P<ver>[A-Za-z0-9._+-]+)"
    r"(?P<rest>(?:,\s*(?:<=|<|!=|~=)\s*[A-Za-z0-9._*+-]+)*)"
    r"(?P<marker>;[^#]*)?"
    r"(?P<comment>\s*#.*)?$"
)


@dataclass(frozen=True)
class ParsedRequirement:
    """Single parsed requirement line in a requirements file."""

    file_path: Path
    line_index: int
    norm_name: str
    indent: str
    name: str
    extras: str
    op: str
    ver: str
    rest: str
    marker: str
    comment: str

    def render(self, new_ver: str) -> str:
        """Render the requirement line with a new version, preserving formatting."""
        return (
            f"{self.indent}{self.name}{self.extras}{self.op}"
            f"{new_ver}{self.rest}{self.marker}{self.comment}"
        )


def normalize_pkg_name(name: str) -> str:
    """Normalize a Python package name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements_file(file_path: Path) -> tuple[list[str], list[ParsedRequirement]]:
    """Read a requirements file and return (raw_lines, parsed_requirements)."""
    raw_lines = file_path.read_text(encoding="utf-8").splitlines(keepends=False)
    parsed: list[ParsedRequirement] = []

    for idx, line in enumerate(raw_lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = _REQ_LINE_RE.match(line)
        if not match:
            continue
        parsed.append(
            ParsedRequirement(
                file_path=file_path,
                line_index=idx,
                norm_name=normalize_pkg_name(match.group("name")),
                indent=match.group("indent") or "",
                name=match.group("name"),
                extras=match.group("extras") or "",
                op=match.group("op"),
                ver=match.group("ver"),
                rest=match.group("rest") or "",
                marker=match.group("marker") or "",
                comment=match.group("comment") or "",
            )
        )
    return raw_lines, parsed


def fetch_pypi_releases(package: str) -> list[str]:
    """Query PyPI JSON API and return non-yanked release version strings."""
    if not _PYPI_PKG_RE.match(package):
        raise ValueError(f"Invalid PyPI package name: {package!r}")

    url = f"https://pypi.org/pypi/{package}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "ja4proxy-update-engine/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        raw = resp.read(_MAX_PYPI_BYTES)

    data = json.loads(raw.decode("utf-8"))
    releases_dict = data.get("releases", {})
    if not isinstance(releases_dict, dict):
        return []

    versions: list[str] = []
    for ver_str, files in releases_dict.items():
        if not isinstance(files, list) or not files:
            continue
        if all(bool(f.get("yanked", False)) for f in files if isinstance(f, dict)):
            continue
        versions.append(str(ver_str))
    return versions


def select_latest_compatible(
    releases: list[str],
    current_min: str,
    upper_bounds: list[str],
) -> str | None:
    """
    Pick the highest stable release strictly greater than current_min that
    satisfies all combined upper-bound constraints (e.g. [',<2', ',<7']).
    """
    try:
        cur_ver = Version(current_min)
    except InvalidVersion:
        return None

    spec_parts: list[str] = []
    for bound in upper_bounds:
        cleaned = bound.strip().lstrip(",").strip()
        if cleaned:
            spec_parts.append(cleaned)

    try:
        spec_set = SpecifierSet(",".join(spec_parts)) if spec_parts else SpecifierSet()
    except InvalidSpecifier:
        return None

    candidates: list[tuple[Version, str]] = []
    for rel in releases:
        try:
            ver = Version(rel)
        except InvalidVersion:
            continue
        if ver.is_prerelease or ver.is_devrelease:
            continue
        if ver <= cur_ver:
            continue
        if ver not in spec_set:
            continue
        candidates.append((ver, rel))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _run_validation(repo_root: Path) -> bool:
    """Execute scripts/check_deps_resolution.py to verify resolution and parity."""
    script = repo_root / "scripts" / "check_deps_resolution.py"
    if not script.exists():
        print(f"WARNING: validation script not found at {script}", file=sys.stderr)
        return True
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
        return False
    return True


def update_python_requirements(
    req_files: list[Path] | None = None,
    repo_root: Path | None = None,
    dry_run: bool = False,
    validate: bool = True,
) -> int:
    """
    Synchronously upgrade outdated Python dependencies across all requirement files,
    respecting upper-bound constraints and rolling back on validation failure.
    """
    root = repo_root if repo_root is not None else REPO_ROOT
    files = [f for f in (req_files if req_files is not None else REQUIREMENT_FILES) if f.exists()]
    if not files:
        print("No Python requirements files found.")
        return 0

    file_lines: dict[Path, list[str]] = {}
    by_pkg: dict[str, list[ParsedRequirement]] = {}

    for fpath in files:
        lines, parsed = parse_requirements_file(fpath)
        file_lines[fpath] = lines
        for item in parsed:
            by_pkg.setdefault(item.norm_name, []).append(item)

    planned: dict[str, tuple[str, str]] = {}
    for norm_name, occurrences in sorted(by_pkg.items()):
        upper_bounds = [occ.rest for occ in occurrences if occ.rest]
        valid_versions: list[tuple[Version, str]] = []
        for occ in occurrences:
            try:
                valid_versions.append((Version(occ.ver), occ.ver))
            except InvalidVersion:
                continue
        if not valid_versions:
            continue

        valid_versions.sort(key=lambda item: item[0])
        min_ver_str = valid_versions[0][1]
        max_ver_str = valid_versions[-1][1]

        try:
            releases = fetch_pypi_releases(norm_name)
        except (urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            print(f"WARNING: PyPI lookup failed for {norm_name}: {exc}", file=sys.stderr)
            continue

        latest = select_latest_compatible(
            releases=releases,
            current_min=max_ver_str,
            upper_bounds=upper_bounds,
        )
        target_ver = latest if latest is not None else (
            max_ver_str if min_ver_str != max_ver_str else None
        )
        if target_ver is not None:
            planned[norm_name] = (min_ver_str, target_ver)

    if not planned:
        print("All Python requirements are up to date and in parity.")
        return 0

    if dry_run:
        for norm_name, (old_ver, new_ver) in planned.items():
            file_list = ", ".join(
                str(occ.file_path.relative_to(root))
                if occ.file_path.is_relative_to(root)
                else occ.file_path.name
                for occ in by_pkg[norm_name]
            )
            print(f"[dry-run] {norm_name}: {old_ver} -> {new_ver} ({file_list})")
        return 0

    snapshots = {fpath: fpath.read_bytes() for fpath in files}
    modified_files: set[Path] = set()

    for norm_name, (_, target_ver) in planned.items():
        for occ in by_pkg[norm_name]:
            if occ.ver != target_ver:
                file_lines[occ.file_path][occ.line_index] = occ.render(target_ver)
                modified_files.add(occ.file_path)

    try:
        for fpath in modified_files:
            fpath.write_text("\n".join(file_lines[fpath]) + "\n", encoding="utf-8")

        if validate and not _run_validation(root):
            print(
                "ERROR: dependency resolution validation failed — rolling back all requirement files.",
                file=sys.stderr,
            )
            for fpath, raw_bytes in snapshots.items():
                fpath.write_bytes(raw_bytes)
            return 1
    except OSError as exc:
        print(f"ERROR: failed writing requirements files: {exc}", file=sys.stderr)
        for fpath, raw_bytes in snapshots.items():
            fpath.write_bytes(raw_bytes)
        return 1

    for norm_name, (old_ver, new_ver) in planned.items():
        print(f"Updated Python package: {norm_name} {old_ver} -> {new_ver}")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update Python requirements in lockstep across all environments.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned updates without modifying requirement files",
    )
    parser.add_argument(
        "--skip-validate",
        action="store_true",
        help="Skip scripts/check_deps_resolution.py validation",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return update_python_requirements(
        dry_run=args.dry_run,
        validate=not args.skip_validate,
    )


if __name__ == "__main__":
    sys.exit(main())
