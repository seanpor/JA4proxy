"""Unit tests verifying zero drift between Go environment variables and docs/reference/ENV_VARS.md (Phase 858)."""

from __future__ import annotations

import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_VARS_MD = REPO_ROOT / "docs" / "reference" / "ENV_VARS.md"

ENV_REGEX = re.compile(r'os\.(?:Getenv|LookupEnv)\("([^"]+)"\)')


def collect_codebase_go_env_vars() -> dict[str, list[str]]:
    """Scan production Go code (cmd/, internal/) for os.Getenv / os.LookupEnv calls.

    Excludes *_test.go and test harnesses / mocks (e.g. internal/test/).
    Returns a dict mapping env var name to list of relative file paths.
    """
    found: dict[str, list[str]] = {}
    search_dirs = [REPO_ROOT / "cmd", REPO_ROOT / "internal"]

    for base_dir in search_dirs:
        for root, _, files in os.walk(base_dir):
            rel_root = Path(root).relative_to(REPO_ROOT)
            # Skip test mock packages or fixtures under internal/test
            if "test" in rel_root.parts:
                continue
            for f in files:
                if f.endswith(".go") and not f.endswith("_test.go"):
                    path = Path(root) / f
                    rel_path = path.relative_to(REPO_ROOT).as_posix()
                    content = path.read_text(encoding="utf-8")
                    for match in ENV_REGEX.finditer(content):
                        var_name = match.group(1)
                        found.setdefault(var_name, []).append(rel_path)
    return found


def parse_documented_go_env_vars() -> dict[str, dict[str, str]]:
    """Parse the Go Proxy table from docs/reference/ENV_VARS.md.

    Returns a dict mapping variable name to metadata dict (source, default, description, security).
    """
    assert ENV_VARS_MD.is_file(), f"Missing doc file: {ENV_VARS_MD}"
    content = ENV_VARS_MD.read_text(encoding="utf-8")

    # Locate Go Proxy section
    lines = content.splitlines()
    in_go_section = False
    in_table = False
    vars_found: dict[str, dict[str, str]] = {}

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## Go Proxy"):
            in_go_section = True
            continue
        elif stripped.startswith("## ") and in_go_section:
            # Reached next section
            break

        if in_go_section:
            if stripped.startswith("| Variable |"):
                in_table = True
                continue
            if in_table:
                if stripped.startswith("|---"):
                    continue
                if stripped.startswith("|"):
                    parts = [p.strip() for p in stripped.split("|")[1:-1]]
                    if len(parts) >= 5:
                        raw_var = parts[0].strip("`")
                        source = parts[1].strip("`")
                        default = parts[2]
                        desc = parts[3]
                        sec = parts[4]
                        vars_found[raw_var] = {
                            "source": source,
                            "default": default,
                            "description": desc,
                            "security": sec,
                        }
                elif not stripped:
                    # Blank line ends table
                    in_table = False

    return vars_found


def test_go_env_vars_and_documentation_in_sync():
    code_vars = collect_codebase_go_env_vars()
    doc_vars = parse_documented_go_env_vars()

    code_set = set(code_vars.keys())
    doc_set = set(doc_vars.keys())

    missing_in_doc = code_set - doc_set
    undocumented_msg = (
        f"Production Go environment variables missing in {ENV_VARS_MD.relative_to(REPO_ROOT)}: "
        f"{sorted(missing_in_doc)}. Add them to the 'Go Proxy' table with descriptions."
    )
    assert not missing_in_doc, undocumented_msg

    extra_in_doc = doc_set - code_set
    stale_msg = (
        f"Documented Go environment variables not found in production Go code: "
        f"{sorted(extra_in_doc)}. Remove or update them in {ENV_VARS_MD.relative_to(REPO_ROOT)}."
    )
    assert not extra_in_doc, stale_msg


def test_documented_source_files_exist():
    code_vars = collect_codebase_go_env_vars()
    doc_vars = parse_documented_go_env_vars()

    for var_name, meta in doc_vars.items():
        source = meta["source"]
        # Source may contain multiple paths or a single path, without line numbers
        src_path = source.split(":")[0].strip()
        full_path = REPO_ROOT / src_path
        assert full_path.is_file(), (
            f"Documented source file for {var_name} does not exist: {src_path}"
        )
        # Verify that the variable is actually referenced in that source file
        assert var_name in code_vars, f"Var {var_name} not found in code"
        assert src_path in code_vars[var_name], (
            f"Documented source {src_path} for {var_name} does not reference {var_name} "
            f"(actual occurrences: {code_vars[var_name]})"
        )
