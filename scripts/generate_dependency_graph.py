#!/usr/bin/env python3
"""
Dependency Graph Generator
Analyzes the codebase to build a dependency graph of Python, Go, and Shell files.
Helps identify unused or obsolete files.

Usage:
    python3 scripts/generate_dependency_graph.py [--output json|dot] [--analyze]
"""

import ast
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

# Directories to exclude
EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    ".claude",
    "reports",
    "geoip",
}


def get_python_imports(file_path):
    imports = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
    except Exception as e:
        print(f"Warning: Failed to parse {file_path}: {e}", file=sys.stderr)
    return imports


def get_shell_dependencies(file_path):
    deps = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            # Match source or direct execution of scripts
            for match in re.finditer(
                r"(?:source|\.)\s+([./a-zA-Z0-9_-]+\.sh)", content
            ):
                deps.append(match.group(1))
            for match in re.finditer(
                r"(?:bash|sh|python3?|go run)\s+([./a-zA-Z0-9_-]+(?:\.sh|\.py|\.go))",
                content,
            ):
                deps.append(match.group(1))
    except Exception:
        pass
    return deps


def main():
    root_dir = Path.cwd()
    graph = defaultdict(list)
    files_found = set()

    for ext in ["*.py", "*.sh", "*.go"]:
        for p in root_dir.rglob(ext):
            if any(part in EXCLUDE_DIRS for part in p.parts):
                continue
            rel_path = p.relative_to(root_dir)
            files_found.add(str(rel_path))

    # Analyze Python
    for f in files_found:
        if f.endswith(".py"):
            imports = get_python_imports(f)
            # Try to map module names to local files
            for imp in imports:
                # Naive mapping: module.sub -> module/sub.py or module/sub/__init__.py
                imp_path = imp.replace(".", "/")
                candidates = [
                    f"{imp_path}.py",
                    f"{imp_path}/__init__.py",
                    f"src/{imp_path}.py",
                    f"scripts/{imp_path}.py",
                    f"internal/{imp_path}.py",
                ]
                for c in candidates:
                    if c in files_found:
                        graph[f].append(c)
        elif f.endswith(".sh"):
            deps = get_shell_dependencies(f)
            for d in deps:
                # Normalize path
                base = os.path.basename(d)
                # Find matching file in files_found
                for known_f in files_found:
                    if known_f.endswith(base):
                        graph[f].append(known_f)
        elif f.endswith(".go"):
            # Simple heuristic for go imports (just within the project)
            try:
                with open(f, "r", encoding="utf-8") as go_file:
                    content = go_file.read()
                    for match in re.finditer(
                        r'"(github\.com/.*?/JA4proxy2/.*?)"', content
                    ):
                        imp = match.group(1)
                        # Naive translation to local path
                        _local_path = imp.split("JA4proxy2/")[-1]
                        # Just link to the directory or try to find a go file
                        # We'll skip deep go parsing for simplicity, relying on go tools if needed
            except Exception:
                pass

    # Find orphans
    incoming_edges = defaultdict(list)
    for src, dsts in graph.items():
        for dst in dsts:
            incoming_edges[dst].append(src)

    orphans = []
    for f in files_found:
        if (
            f not in incoming_edges
            and not f.startswith("tests/")
            and not f.endswith("__init__.py")
        ):
            # It might be an entry point. We should log it.
            orphans.append(f)

    # Save outputs
    out_dir = root_dir / "reports"
    out_dir.mkdir(exist_ok=True)

    with open(out_dir / "dependency_graph.json", "w") as jf:
        json.dump(dict(graph), jf, indent=2)

    with open(out_dir / "dependency_graph.dot", "w") as df:
        df.write("digraph G {\n")
        df.write("  rankdir=LR;\n")
        for src, dsts in graph.items():
            for dst in dsts:
                df.write(f'  "{src}" -> "{dst}";\n')
        df.write("}\n")

    print(
        f"Generated dependency graph with {len(files_found)} nodes and {sum(len(v) for v in graph.values())} edges."
    )
    print("Saved to reports/dependency_graph.json and reports/dependency_graph.dot")

    if "--analyze" in sys.argv:
        print("\nPotential orphans (no internal incoming imports/references):")
        for o in sorted(orphans):
            print(f"  - {o}")


if __name__ == "__main__":
    main()
