#!/usr/bin/env python3
"""Count non-blank lines of code by category across the JA4proxy project.

Skips blank lines, .git, build artefacts, and generated output.
Run from the repo root:

    python3 scripts/count_lines.py
    python3 scripts/count_lines.py --root /path/to/repo
"""

import argparse
import os
from collections import defaultdict
from pathlib import Path

# Directories that are never source
EXCLUDE_DIRS = {
    ".git", "__pycache__", "node_modules", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".hypothesis", "test-results",
    "reports", ".local", "bin", ".tox", ".eggs", "htmlcov",
    ".venv", "venv", "env",
}

# File suffixes that are never source
EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".backup", ".bak", ".old", ".swp", ".swo",
                    ".gz", ".tar", ".zip", ".png", ".jpg", ".ico", ".woff",
                    ".db", ".sqlite", ".mmdb", ".bin", ".pfx", ".p12",
                    ".coverage", ".key", ".pem", ".crt", ".cer"}


def count_nonblank(path: Path) -> int:
    try:
        return sum(1 for line in path.open("r", errors="replace") if line.strip())
    except Exception:
        return 0


def classify(path: Path, root: Path) -> str | None:
    rel = path.relative_to(root)
    parts = rel.parts
    name = path.name
    suffix = path.suffix.lower()

    # --- Tests ---
    if "tests" in parts:
        return "Tests (Python)"

    # --- Go ---
    if suffix == ".go":
        if name.endswith("_test.go"):
            return "Tests (Go)"
        return "Go proxy"

    # --- Python ---
    if suffix == ".py":
        if parts[0] == "tests":
            return "Tests (Python)"
        if parts[0] == "scripts":
            return "Scripts (Python)"
        if parts[0] == "analytics":
            return "Analytics (Python)"
        # proxy.py and everything in src/
        return "Python proxy"

    # --- Shell scripts ---
    if suffix == ".sh":
        return "Scripts (Shell)"

    # --- Lua (Redis) ---
    if suffix == ".lua":
        return "Scripts (Lua/Redis)"

    # --- Makefile ---
    if name == "Makefile":
        return "Makefile"

    # --- Dockerfiles ---
    if name.startswith("Dockerfile"):
        return "Infrastructure (Docker)"

    # --- Docker Compose YAML ---
    if name.startswith("docker-compose") and suffix in (".yml", ".yaml"):
        return "Infrastructure (Docker)"

    # --- Proxy / service config YAML ---
    if suffix in (".yml", ".yaml") and parts[0] == "config":
        return "Config (YAML)"

    # --- Monitoring / alerting / grafana YAML ---
    if suffix in (".yml", ".yaml") and parts[0] in ("monitoring", "grafana", "deploy", "docker"):
        return "Infrastructure (YAML)"

    # --- HA-proxy config ---
    if parts[0] in ("ha-config", "backend-config"):
        return "Infrastructure (config)"

    # --- Grafana / dashboard JSON ---
    if suffix == ".json" and parts[0] in ("grafana", "monitoring"):
        return "Infrastructure (JSON)"

    # --- Markdown documentation ---
    if suffix == ".md" and name != "MEMORY.md":
        return "Documentation (Markdown)"

    return None  # skip everything else


ORDER = [
    "Python proxy",
    "Go proxy",
    "Tests (Python)",
    "Tests (Go)",
    "Scripts (Shell)",
    "Scripts (Python)",
    "Scripts (Lua/Redis)",
    "Makefile",
    "Infrastructure (Docker)",
    "Infrastructure (YAML)",
    "Infrastructure (JSON)",
    "Infrastructure (config)",
    "Analytics (Python)",
    "Config (YAML)",
    "Documentation (Markdown)",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repo root (default: .)")
    args = parser.parse_args()
    root = Path(args.root).resolve()

    totals: dict[str, int] = defaultdict(int)
    fcounts: dict[str, int] = defaultdict(int)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in EXCLUDE_SUFFIXES:
                continue
            cat = classify(fpath, root)
            if cat is None:
                continue
            n = count_nonblank(fpath)
            totals[cat] += n
            fcounts[cat] += 1

    print(f"\n{'Category':<30} {'Files':>6}  {'Non-blank lines':>15}")
    print("─" * 56)
    grand_total = 0
    seen = set()
    for cat in ORDER:
        if cat in totals:
            print(f"{cat:<30} {fcounts[cat]:>6}  {totals[cat]:>15,}")
            grand_total += totals[cat]
            seen.add(cat)
    for cat in sorted(totals):
        if cat not in seen:
            print(f"{cat:<30} {fcounts[cat]:>6}  {totals[cat]:>15,}")
            grand_total += totals[cat]
    print("─" * 56)
    print(f"{'TOTAL':<30} {'':>6}  {grand_total:>15,}")
    print()


if __name__ == "__main__":
    main()
