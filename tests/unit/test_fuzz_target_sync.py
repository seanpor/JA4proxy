"""Unit test verifying that every native Go fuzz target in cmd/ and internal/ is

tracked and executed in both Makefile (test-go-fuzz-smoke) and
.github/workflows/fuzzing.yml.
"""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def discover_repo_fuzz_targets() -> dict[str, set[str]]:
    """Scan all Go files under cmd/ and internal/ for func Fuzz*(f *testing.F).

    Returns a dict mapping package path (relative to repo root) to set of target names.
    """
    targets_by_pkg: dict[str, set[str]] = {}
    fuzz_pattern = re.compile(r"^func\s+(Fuzz[A-Za-z0-9_]+)\s*\(\s*\w+\s+\*testing\.F\s*\)", re.MULTILINE)

    for search_dir in ["cmd", "internal"]:
        for go_file in (REPO_ROOT / search_dir).rglob("*.go"):
            try:
                content = go_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            matches = fuzz_pattern.findall(content)
            if matches:
                pkg_path = str(go_file.parent.relative_to(REPO_ROOT))
                targets_by_pkg.setdefault(pkg_path, set()).update(matches)

    return targets_by_pkg


def extract_makefile_fuzz_targets() -> set[str]:
    """Extract all fuzz target names called in Makefile test-go-fuzz-smoke."""
    makefile_path = REPO_ROOT / "Makefile"
    content = makefile_path.read_text(encoding="utf-8")

    # Match lines like: $(GO) test -run='^$$' -fuzz='^FuzzClientHello$$' ...
    pattern = re.compile(r"-fuzz='\^(Fuzz[A-Za-z0-9_]+)\$\$'")
    return set(pattern.findall(content))


def extract_workflow_fuzz_targets() -> set[str]:
    """Extract all fuzz target names declared in .github/workflows/fuzzing.yml."""
    workflow_path = REPO_ROOT / ".github" / "workflows" / "fuzzing.yml"
    data = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))

    targets = set()
    matrix_include = data["jobs"]["fuzz"]["strategy"]["matrix"]["include"]
    for item in matrix_include:
        pkg_targets = item["targets"].split()
        targets.update(pkg_targets)

    return targets


def test_fuzz_targets_registered_in_makefile():
    """Verify that every native Go fuzz target in the repository is wired into

    Makefile's test-go-fuzz-smoke.
    """
    repo_targets_map = discover_repo_fuzz_targets()
    all_repo_targets = {t for targets in repo_targets_map.values() for t in targets}
    makefile_targets = extract_makefile_fuzz_targets()

    missing_in_makefile = all_repo_targets - makefile_targets
    assert not missing_in_makefile, (
        f"The following Go fuzz targets exist in the codebase but are missing from "
        f"Makefile's test-go-fuzz-smoke: {sorted(missing_in_makefile)}"
    )


def test_fuzz_targets_registered_in_fuzzing_workflow():
    """Verify that every native Go fuzz target in the repository is wired into

    .github/workflows/fuzzing.yml.
    """
    repo_targets_map = discover_repo_fuzz_targets()
    all_repo_targets = {t for targets in repo_targets_map.values() for t in targets}
    workflow_targets = extract_workflow_fuzz_targets()

    missing_in_workflow = all_repo_targets - workflow_targets
    assert not missing_in_workflow, (
        f"The following Go fuzz targets exist in the codebase but are missing from "
        f".github/workflows/fuzzing.yml: {sorted(missing_in_workflow)}"
    )


def test_fuzzing_workflow_disables_continue_on_error():
    """Verify that .github/workflows/fuzzing.yml does NOT mask failures with

    continue-on-error.
    """
    workflow_path = REPO_ROOT / ".github" / "workflows" / "fuzzing.yml"
    content = workflow_path.read_text(encoding="utf-8")
    assert "continue-on-error: true" not in content, (
        ".github/workflows/fuzzing.yml must not specify continue-on-error: true; "
        "fuzz regressions must fail the build."
    )
