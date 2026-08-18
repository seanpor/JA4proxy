"""The requirements files must be mutually installable.

WHY THIS EXISTS
---------------
`make lint` builds a tools image whose Dockerfile does:

    pip install -r requirements.txt -r requirements-test.txt \
                -r requirements-analytics.txt -r requirements-lint-management.txt

All four land in ONE environment. So a package pinned to different versions in
two files is not a difference of opinion between two services — it is an
unresolvable conflict, and the whole image build fails.

That is a slow and confusing way to find out. Raising semgrep to 1.173.0 (to
clear the click and protobuf CVEs) forced `jsonschema~=4.25.1` in
requirements.txt while requirements-analytics.txt still said `==4.26.0`; the
symptom was a Docker build failing several minutes in, on a line that mentions
neither package.

This test finds it in milliseconds instead.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Exactly the set the tools image installs together.
COINSTALLED = [
    "requirements.txt",
    "requirements-test.txt",
    "requirements-analytics.txt",
    "requirements-lint-management.txt",
]

# name, then any specifier(s). Extras and environment markers are stripped.
_REQ = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)"
    r"(?:\[[^\]]*\])?"
    r"(?P<spec>(?:\s*[<>=!~]=?\s*[^,;#\s]+)(?:\s*,\s*[<>=!~]=?\s*[^,;#\s]+)*)?"
)


def parse(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].strip()  # drop environment marker
        m = _REQ.match(line)
        if not m or not m.group("spec"):
            continue
        pins[m.group("name").lower().replace("_", "-")] = re.sub(
            r"\s+", "", m.group("spec")
        )
    return pins


def test_no_package_is_pinned_differently_across_coinstalled_files():
    by_package: dict[str, dict[str, str]] = defaultdict(dict)
    for name in COINSTALLED:
        path = REPO_ROOT / name
        assert path.exists(), f"{name} is installed by the tools image but is missing"
        for pkg, spec in parse(path).items():
            by_package[pkg][name] = spec

    divergent = {
        pkg: files
        for pkg, files in by_package.items()
        if len(files) > 1 and len(set(files.values())) > 1
    }

    assert not divergent, (
        "package(s) pinned inconsistently across files the tools image installs "
        "TOGETHER — pip cannot satisfy both and the image build fails:\n\n"
        + "\n".join(
            f"  {pkg}:\n"
            + "\n".join(f"    {f}: {pkg}{s}" for f, s in sorted(files.items()))
            for pkg, files in sorted(divergent.items())
        )
        + "\n\nPin them to the same specifier, or move one out of the co-installed set."
    )


def test_the_parser_actually_finds_pins():
    """Vacuity guard: a regex that matches nothing would pass the test above."""
    pins = parse(REPO_ROOT / "requirements.txt")
    assert len(pins) > 10, f"only parsed {len(pins)} pins — regex is broken"
    assert "semgrep" in pins, "expected semgrep to be pinned in requirements.txt"


def test_the_coinstalled_list_matches_the_dockerfile():
    """If the Dockerfile installs a file this test does not know about, the gap
    is invisible — that file could diverge freely."""
    # The tools image is built from Dockerfile.tools at the repo root
    # (Makefile: `docker build -f Dockerfile.tools .`). Read that file
    # specifically — an earlier version of this test globbed deploy/docker/ and
    # matched a different image that installs only two of the four, so it
    # "checked" a set that was never co-installed.
    dockerfile = REPO_ROOT / "Dockerfile.tools"
    assert dockerfile.exists(), (
        "Dockerfile.tools not found — the Makefile's tools-image target builds "
        "from it; if it moved, update this test"
    )
    installed = set(
        re.findall(r"-r\s+(requirements[A-Za-z0-9.-]*\.txt)", dockerfile.read_text())
    )
    assert installed, "Dockerfile.tools installs no requirements files — parser broken"
    assert installed == set(COINSTALLED), (
        f"the tools image installs {sorted(installed)} but this test checks "
        f"{sorted(COINSTALLED)} — update COINSTALLED"
    )
