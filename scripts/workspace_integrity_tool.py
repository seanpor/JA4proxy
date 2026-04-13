#!/usr/bin/env python3
"""
Workspace Integrity Tool (WIT)
Performs a comprehensive audit of the workspace to identify:
1. Broken References: Files mentioned in code/config that do not exist.
2. Orphans: Files that are not referenced by any other file.

Supports: Python, Go, Bash, Docker, Docker Compose, YAML, Markdown, Ansible, Helm.
"""

import ast
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

# Configuration
EXCLUDE_DIRS = {".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", "node_modules", ".claude", "reports", "geoip", "venv", ".venv"}
SOURCE_EXTS = {".py", ".sh", ".go", ".yml", ".yaml", ".md", ".json", ".txt"}
DOCKER_FILES = {"Dockerfile", "Dockerfile-go", "Dockerfile.test", "Dockerfile.trafficgen", "Dockerfile.mockbackend"}

class WorkspaceIntegrityTool:
    def __init__(self, root_dir):
        self.root_dir = Path(root_dir)
        self.all_files = set()
        self.graph = defaultdict(set)  # src -> {dsts}
        self.incoming = defaultdict(set) # dst -> {srcs}
        self.broken_refs = defaultdict(list) # src -> [broken_path]

    def scan_workspace(self):
        """Build a list of all files in the workspace."""
        for p in self.root_dir.rglob("*"):
            if any(part in EXCLUDE_DIRS for part in p.parts):
                continue
            if p.is_file():
                rel_path = p.relative_to(self.root_dir)
                self.all_files.add(str(rel_path))

    def add_edge(self, src, dst):
        """Add a dependency edge and track incoming references."""
        # Normalize dst path
        dst = dst.strip("./")
        if dst in self.all_files:
            self.graph[src].add(dst)
            self.incoming[dst].add(src)
        else:
            # Check for relative paths if not found as absolute from root
            src_dir = os.path.dirname(src)
            rel_dst = os.path.normpath(os.path.join(src_dir, dst))
            if rel_dst in self.all_files:
                self.graph[src].add(rel_dst)
                self.incoming[rel_dst].add(src)
            else:
                # Potential broken reference or external dependency
                if any(dst.endswith(ext) for ext in SOURCE_EXTS) or "Dockerfile" in dst:
                    self.broken_refs[src].append(dst)

    def parse_python(self, file_path):
        try:
            with open(self.root_dir / file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    # Extract module names
                    modules = []
                    if isinstance(node, ast.Import):
                        modules = [n.name for n in node.names]
                    else:
                        if node.module:
                            modules = [node.module]
                    
                    for mod in modules:
                        mod_path = mod.replace(".", "/")
                        candidates = [f"{mod_path}.py", f"{mod_path}/__init__.py", f"src/{mod_path}.py", f"scripts/{mod_path}.py", f"internal/{mod_path}.py"]
                        for c in candidates:
                            if c in self.all_files:
                                self.add_edge(file_path, c)
                                break
                
                # Look for string literals that look like paths
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if "/" in node.value or "." in node.value:
                        if any(node.value.endswith(ext) for ext in SOURCE_EXTS):
                             self.add_edge(file_path, node.value)

        except Exception:
            pass

    def parse_shell(self, file_path):
        try:
            with open(self.root_dir / file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Matches: source file.sh, . file.sh, bash file.sh, python3 file.py
                matches = re.findall(r'(?:source|\.|bash|sh|python3?|go run)\s+([./a-zA-Z0-9_-]+\.[a-z]+)', content)
                for m in matches:
                    self.add_edge(file_path, m)
                
                # Generic path-like strings in quotes
                matches = re.findall(r'["\']([./a-zA-Z0-9_-]+\.[a-z]+)["\']', content)
                for m in matches:
                    if any(m.endswith(ext) for ext in SOURCE_EXTS):
                        self.add_edge(file_path, m)
        except Exception:
            pass

    def parse_dockerfile(self, file_path):
        try:
            with open(self.root_dir / file_path, "r", encoding="utf-8") as f:
                for line in f:
                    # COPY and ADD
                    match = re.search(r'(?:COPY|ADD)\s+(?:--[a-z]+=\S+\s+)?(\S+)', line)
                    if match:
                        path = match.group(1).strip('"')
                        # Docker COPY can be a dir or file. We check for files.
                        if path in self.all_files:
                            self.add_edge(file_path, path)
                        else:
                            # Try glob-like matching for directories
                            for f_name in self.all_files:
                                if f_name.startswith(path):
                                    self.add_edge(file_path, f_name)
                    
                    # ENTRYPOINT/CMD with scripts
                    match = re.search(r'(?:ENTRYPOINT|CMD)\s+\[?"?([\w./-]+\.sh)"?', line)
                    if match:
                        self.add_edge(file_path, match.group(1))
        except Exception:
            pass

    def parse_yaml(self, file_path):
        try:
            with open(self.root_dir / file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Look for Dockerfiles in compose
                matches = re.findall(r'dockerfile:\s*(\S+)', content)
                for m in matches:
                    self.add_edge(file_path, m)
                
                # Look for env_file
                matches = re.findall(r'env_file:\s*(\S+)', content)
                for m in matches:
                    self.add_edge(file_path, m)

                # Look for volumes (local:remote)
                matches = re.findall(r'-\s*([./\w_-]+):[/\w_-]+', content)
                for m in matches:
                    self.add_edge(file_path, m)
                
                # Generic path-like strings
                matches = re.findall(r'path:\s*(\S+)', content)
                for m in matches:
                    self.add_edge(file_path, m)
                
                # Matches for keys ending in _path or _file
                matches = re.findall(r'[\w_-]+(?:_path|_file):\s*(\S+)', content)
                for m in matches:
                    self.add_edge(file_path, m)

        except Exception:
            pass

    def parse_markdown(self, file_path):
        try:
            with open(self.root_dir / file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Matches [text](path)
                matches = re.findall(r'\[.*?\]\(([./a-zA-Z0-9_-]+\.[a-z]+)\)', content)
                for m in matches:
                    if not m.startswith("http"):
                        self.add_edge(file_path, m)
                
                # Matches `path`
                matches = re.findall(r'`([./a-zA-Z0-9_-]+\.[a-z]+)`', content)
                for m in matches:
                    if any(m.endswith(ext) for ext in SOURCE_EXTS):
                        self.add_edge(file_path, m)
        except Exception:
            pass

    def parse_go(self, file_path):
         try:
            with open(self.root_dir / file_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Matches internal JA4proxy2 imports
                matches = re.findall(r'"github\.com/.*?/JA4proxy2/([\w/_-]+)"', content)
                for m in matches:
                    # m is a package path, look for any .go file in that dir
                    found = False
                    for f_name in self.all_files:
                        if f_name.startswith(m) and f_name.endswith(".go"):
                            self.add_edge(file_path, f_name)
                            found = True
                    if not found:
                         self.broken_refs[file_path].append(m)
         except Exception:
             pass

    def run(self):
        self.scan_workspace()
        
        for f in sorted(self.all_files):
            if f.endswith(".py"):
                self.parse_python(f)
            elif f.endswith(".sh"):
                self.parse_shell(f)
            elif f.endswith(".go"):
                self.parse_go(f)
            elif f.endswith(".md"):
                self.parse_markdown(f)
            elif f.endswith(".yml") or f.endswith(".yaml"):
                self.parse_yaml(f)
            elif os.path.basename(f) in DOCKER_FILES or f.startswith("deploy/docker/"):
                self.parse_dockerfile(f)
            
            # Special case: Makefile
            if f == "Makefile":
                self.parse_shell(f)

        # Categorize
        orphans = []
        for f in sorted(self.all_files):
            # Exclude tests, entrypoints, and standard docs from being orphans
            if f in self.incoming:
                continue
            if f.startswith("tests/"):
                continue
            if f.startswith("docs/phases/"):
                continue  # Phase docs are records
            if f in {
                "README.md", "LICENSE", "CHANGELOG.md", "go.mod", "go.sum",
                "pyproject.toml", "requirements.txt", "Makefile",
                "CONTRIBUTING.md", "SECURITY.md", ".gitignore", "AGENTS.md",
            }:
                continue
            if f.startswith("data/geoip/"):
                continue
            if f.startswith("cmd/"):
                continue  # Entry points
            if f.startswith("scripts/") and f.endswith(".sh"):
                continue  # Many scripts are CLI entry points

            orphans.append(f)

        return orphans, self.broken_refs

def main():
    root = "."
    wit = WorkspaceIntegrityTool(root)
    orphans, broken = wit.run()

    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)

    with open(report_dir / "workspace_audit.json", "w") as jf:
        json.dump({
            "orphans": orphans,
            "broken_references": {k: list(v) for k, v in broken.items() if v}
        }, jf, indent=2)

    print(f"Audit complete. Found {len(orphans)} potential orphans and {len(broken)} files with broken references.")
    print("Full report saved to reports/workspace_audit.json")

    if "--list-orphans" in sys.argv:
        print("\n--- Potential Orphans ---")
        for o in orphans:
            print(o)

    if "--list-broken" in sys.argv:
        print("\n--- Broken References ---")
        for src, refs in broken.items():
            if refs:
                print(f"{src}:")
                for r in refs:
                    print(f"  -> {r}")

if __name__ == "__main__":
    main()
