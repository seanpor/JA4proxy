"""Invariant registry verification test.

Ensures that every invariant defined in docs/testing/invariants.yaml exists in code,
and that every TestInvariant_* / FuzzInvariant_* / test_invariant_* function in the repo
is registered in invariants.yaml.
"""

from pathlib import Path
import re
import yaml


def test_invariant_registry():
    repo_root = Path(__file__).resolve().parents[2]
    manifest_path = repo_root / "docs" / "phases" / "manifest.yaml"
    registry_path = repo_root / "docs" / "testing" / "invariants.yaml"

    assert manifest_path.exists(), "manifest.yaml does not exist"
    assert registry_path.exists(), "invariants.yaml does not exist"

    manifest_data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    valid_phases = set(manifest_data.get("phases", {}).keys())

    registry_data = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    invariants = registry_data.get("invariants", [])

    id_pattern = re.compile(r"^INV-[A-Z]+-\d{3}$")
    seen_ids = set()
    registered_tests = set()

    for item in invariants:
        inv_id = item.get("id")
        phase = str(item.get("phase"))
        pkg = item.get("package")
        test_name = item.get("test")
        statement = item.get("statement")

        # Validate ID
        assert inv_id, "Invariant entry missing id"
        assert id_pattern.match(inv_id), f"Invalid invariant ID format: {inv_id}"
        assert inv_id not in seen_ids, f"Duplicate invariant ID: {inv_id}"
        seen_ids.add(inv_id)

        # Validate Phase
        assert phase in valid_phases, f"Invariant {inv_id} references unknown phase: {phase}"

        # Validate Statement
        assert statement and len(statement.strip()) > 0, f"Invariant {inv_id} missing statement"

        # Validate Test Existence in Code
        registered_tests.add(test_name)

        if test_name.startswith("TestInvariant_") or test_name.startswith("FuzzInvariant_"):
            pkg_dir = repo_root / pkg
            assert pkg_dir.exists(), f"Package directory does not exist: {pkg}"
            
            found = False
            for test_file in pkg_dir.glob("*_test.go"):
                content = test_file.read_text(encoding="utf-8")
                if f"func {test_name}(" in content:
                    found = True
                    break
            assert found, f"Go test {test_name} for invariant {inv_id} not found in package {pkg}"

        elif test_name.startswith("test_invariant_"):
            # Check Python test locations
            found = False
            for search_dir in [repo_root / "tests" / "unit", repo_root / "management" / "tests"]:
                if not search_dir.exists():
                    continue
                for py_file in search_dir.glob("**/*.py"):
                    content = py_file.read_text(encoding="utf-8")
                    if f"def {test_name}(" in content:
                        found = True
                        break
                if found:
                    break
            assert found, f"Python test {test_name} for invariant {inv_id} not found"

    # Reverse Check: Find all invariant test functions in Go code and verify they are registered
    go_test_func_pattern = re.compile(r"func\s+((?:Test|Fuzz)Invariant_[A-Za-z0-9_]+)\(")
    for go_file in repo_root.glob("**/*_test.go"):
        if "vendor" in go_file.parts:
            continue
        content = go_file.read_text(encoding="utf-8")
        for match in go_test_func_pattern.finditer(content):
            fn_name = match.group(1)
            assert fn_name in registered_tests, f"Unregistered Go invariant test found in code: {fn_name} in {go_file}"

    # Reverse Check: Find all invariant test functions in Python code and verify they are registered
    py_test_func_pattern = re.compile(r"def\s+(test_invariant_[A-Za-z0-9_]+)\(")
    for py_dir in [repo_root / "tests" / "unit", repo_root / "management" / "tests"]:
        if not py_dir.exists():
            continue
        for py_file in py_dir.glob("**/*.py"):
            content = py_file.read_text(encoding="utf-8")
            for match in py_test_func_pattern.finditer(content):
                fn_name = match.group(1)
                if fn_name == "test_invariant_registry":
                    continue
                assert fn_name in registered_tests, f"Unregistered Python invariant test found in code: {fn_name} in {py_file}"
