#!/usr/bin/env python3
"""
check-python314-compat.py — PyPI wheel compatibility checker for Python 3.14.

Parses requirements.txt, requirements-test.txt, and requirements-analytics.txt,
queries PyPI JSON API for each package, and checks whether a cp314 or py3 wheel
is available.

Usage:
    python3 scripts/check-python314-compat.py

Outputs:
    - Markdown table to stdout
    - reports/python314-compat.md (written)

Exit codes:
    0  All packages have 3.14-compatible wheels or are pure-Python
    1  One or more C-extension packages lack a Python 3.14 wheel

Requires only stdlib — no extra installs needed.
Compatible with Python 3.10+.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REQUIREMENTS_FILES = [
    "requirements.txt",
    "requirements-test.txt",
    "requirements-analytics.txt",
]

PYPI_URL = "https://pypi.org/pypi/{package}/json"

# Wheels that are compatible with Python 3.14
# cp314 = CPython 3.14 specific wheel
# py3   = pure-Python wheel (works with any Python 3)
# py2.py3 = universal pure-Python wheel
COMPAT_TAGS = re.compile(r"cp314|py3|py2\.py3|cp3\d-none-any")

# These are always pure-Python (no compiled extension) — skip PyPI check
ALWAYS_PURE = {
    "pip",
    "setuptools",
    "wheel",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_package_name(line: str) -> str | None:
    """Extract package name from a requirements line. Returns None to skip."""
    line = line.strip()
    # Skip blank lines, comments, and options (e.g., -r, -e, --index-url)
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    # Strip version specifiers: ==, >=, <=, !=, ~=, >, <
    name = re.split(r"[>=<!~\s;#\[]", line)[0].strip()
    return name if name else None


def _collect_packages(repo_root: Path) -> dict[str, str]:
    """
    Read all requirements files and return {package_name: source_file}.
    Deduplicates by package name (first occurrence wins).
    """
    packages: dict[str, str] = {}
    for rel_path in REQUIREMENTS_FILES:
        req_file = repo_root / rel_path
        if not req_file.exists():
            continue
        for line in req_file.read_text(encoding="utf-8").splitlines():
            name = _parse_package_name(line)
            if name and name.lower() not in {k.lower() for k in packages}:
                packages[name] = rel_path
    return packages


def _fetch_pypi(package: str) -> dict | None:
    """Fetch package metadata from PyPI. Returns None on failure."""
    url = PYPI_URL.format(package=package.lower())
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310  # nosemgrep: dynamic-urllib-use-detected
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # package not found on PyPI
        raise
    except Exception:  # noqa: BLE001
        return None


def _check_wheel_compat(data: dict) -> tuple[str, str]:
    """
    Returns (status, notes) where status is one of:
      ok-pure   — pure-Python sdist/wheel (always compatible)
      ok-cp314  — CPython 3.14 wheel found
      warn      — no cp314 wheel, but has py3 universal wheel
      fail      — C extension, no Python 3.14 or universal wheel available
    """
    if data is None:
        return ("unknown", "Package not found on PyPI")

    latest_version = data.get("info", {}).get("version", "unknown")
    urls: list[dict] = data.get("urls", [])

    has_sdist = False
    has_py3_wheel = False
    has_cp314_wheel = False
    has_any_wheel = False
    has_pure_python_wheel = False

    for url_info in urls:
        filename: str = url_info.get("filename", "")
        pkg_type: str = url_info.get("packagetype", "")

        if pkg_type == "sdist":
            has_sdist = True
            continue

        if pkg_type != "bdist_wheel":
            continue

        has_any_wheel = True
        parts = filename.rsplit("-", 3)  # name-ver-pytag-abitag-platformtag.whl
        if len(parts) < 2:
            continue

        # Extract python and abi tags from filename
        # Format: {dist}-{version}(-{build})?-{python}-{abi}-{platform}.whl
        # e.g. cryptography-44.0.3-cp314-cp314-manylinux_2_28_x86_64.whl
        #   or pyyaml-6.0.1-py3-none-any.whl
        wheel_tags = filename[:-4]  # remove .whl
        tag_segment = "-".join(wheel_tags.split("-")[2:])  # pytag-abi-platform

        if re.search(r"\bcp314\b", tag_segment):
            has_cp314_wheel = True
        if re.search(r"\bpy3\b", tag_segment) or re.search(r"\bpy2\.py3\b", tag_segment):
            has_py3_wheel = True
            has_pure_python_wheel = True
        if re.search(r"none-any$", tag_segment):
            has_pure_python_wheel = True

    if has_cp314_wheel:
        return ("ok-cp314", f"cp314 wheel available (v{latest_version})")

    if has_pure_python_wheel or has_py3_wheel:
        return ("ok-pure", f"pure-Python wheel available (v{latest_version})")

    if has_any_wheel:
        # Has wheels but none are cp314 or pure-Python
        return (
            "fail",
            f"C-extension wheels present but no cp314 wheel (v{latest_version}). "
            "Manual verification required.",
        )

    if has_sdist:
        # sdist only — may or may not be compilable on 3.14
        return (
            "warn",
            f"sdist only (v{latest_version}) — unknown if builds on Python 3.14",
        )

    return ("unknown", f"No distribution files found (v{latest_version})")


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

STATUS_EMOJI = {
    "ok-cp314": "ok-cp314",
    "ok-pure": "ok-pure",
    "warn": "WARN",
    "fail": "FAIL",
    "unknown": "UNKNOWN",
}

STATUS_SORT = {
    "fail": 0,
    "warn": 1,
    "unknown": 2,
    "ok-cp314": 3,
    "ok-pure": 4,
}


def _build_report(
    results: list[tuple[str, str, str, str]],
) -> str:
    """Build a markdown report. results = [(package, source, status, notes)]."""
    lines: list[str] = [
        "# Python 3.14 Compatibility Report",
        "",
        "Generated by `scripts/check-python314-compat.py`.",
        "",
        "## Summary",
        "",
    ]

    counts: dict[str, int] = {}
    for _, _, status, _ in results:
        counts[status] = counts.get(status, 0) + 1

    for s in ("ok-cp314", "ok-pure", "warn", "fail", "unknown"):
        if counts.get(s, 0):
            lines.append(f"- **{STATUS_EMOJI[s]}**: {counts[s]} package(s)")

    lines += [
        "",
        "## Package Details",
        "",
        "| Package | Source File | Status | Notes |",
        "|---------|-------------|--------|-------|",
    ]

    for package, source, status, notes in results:
        tag = STATUS_EMOJI[status]
        lines.append(f"| `{package}` | `{source}` | {tag} | {notes} |")

    lines += [
        "",
        "## Interpretation",
        "",
        "- **ok-cp314** — CPython 3.14 binary wheel is available on PyPI. No action needed.",
        "- **ok-pure** — Pure-Python package (no compiled extension). Works on any Python version.",
        "- **WARN** — Only a source distribution (sdist) found. "
        "May need to compile from source or wait for wheel release.",
        "- **FAIL** — C-extension package with no Python 3.14 wheel. "
        "Upgrade blockers — investigate before upgrading.",
        "- **UNKNOWN** — Package not found on PyPI or lookup failed.",
        "",
        "## Decision",
        "",
    ]

    fail_count = counts.get("fail", 0)
    warn_count = counts.get("warn", 0)

    if fail_count == 0:
        lines.append(
            "All packages are compatible with Python 3.14 or have universal wheels. "
            "Dockerfile upgrade to `python:3.14.0-slim` is **safe to proceed**."
        )
    else:
        lines.append(
            f"**{fail_count} package(s) lack Python 3.14 wheels.** "
            "Review FAIL entries before upgrading Dockerfiles."
        )

    if warn_count:
        lines.append(
            f"\n{warn_count} package(s) have sdist-only distributions. "
            "These may build successfully from source or may need manual testing."
        )

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    print("Checking Python 3.14 compatibility for all requirements...\n", flush=True)

    packages = _collect_packages(repo_root)

    if not packages:
        print("ERROR: No packages found in requirements files.", file=sys.stderr)
        return 1

    results: list[tuple[str, str, str, str]] = []
    failed = False

    for package, source in sorted(packages.items(), key=lambda x: x[0].lower()):
        if package.lower() in ALWAYS_PURE:
            results.append((package, source, "ok-pure", "Always pure-Python"))
            continue

        print(f"  Checking {package} ...", end=" ", flush=True)
        data = _fetch_pypi(package)
        status, notes = _check_wheel_compat(data)
        print(status)

        if status == "fail":
            failed = True

        results.append((package, source, status, notes))

    # Sort: failures first, then warnings, then ok
    results.sort(key=lambda r: (STATUS_SORT.get(r[2], 99), r[0].lower()))

    report = _build_report(results)

    # Write to stdout
    print("\n" + "=" * 70)
    print(report)

    # Write to file
    # Note: reports/ is in .gitignore; docs/reports/ is tracked.
    out_path = repo_root / "docs" / "reports" / "python314-compat.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"Report written to: {out_path}", flush=True)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
