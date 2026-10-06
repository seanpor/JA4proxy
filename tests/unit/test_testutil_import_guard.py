"""Import guard test asserting internal/testutil is never imported by production Go code."""

from pathlib import Path
import re


def test_testutil_not_imported_in_production_go_code():
    repo_root = Path(__file__).resolve().parents[2]
    production_go_files = []
    
    for path in repo_root.glob("**/*.go"):
        # Ignore files in internal/testutil
        if "internal/testutil" in path.parts:
            continue
        # Ignore test files
        if path.name.endswith("_test.go"):
            continue
        # Ignore vendor directory if present
        if "vendor" in path.parts:
            continue
        production_go_files.append(path)

    assert len(production_go_files) > 0, "Found no production Go files to inspect"

    forbidden_pattern = re.compile(r'github\.com/seanpor/ja4proxy/internal/testutil')
    violations = []

    for path in production_go_files:
        content = path.read_text(encoding="utf-8")
        if forbidden_pattern.search(content):
            violations.append(str(path.relative_to(repo_root)))

    assert not violations, f"Production Go code imports internal/testutil: {violations}"
