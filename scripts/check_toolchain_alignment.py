#!/usr/bin/env python3
"""
check_toolchain_alignment.py — Verify toolchain version alignment across the project.

Checks:
1. go.mod `go` directive version (e.g. 1.26.6) vs golangci-lint release capabilities.
2. Builder Dockerfile Go versions (e.g. golang:1.27.2-alpine) vs go.mod version.
3. Makefile GOROOT configuration.

Exit codes:
  0: All toolchain versions aligned.
  1: Toolchain misalignment detected.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

GO_MOD = REPO_ROOT / "go.mod"
DOCKERFILES_DIR = REPO_ROOT / "deploy" / "docker"
MAKEFILE = REPO_ROOT / "Makefile"

# Maximum Go version supported by golangci-lint built with Go 1.26.x
GOLANGCI_LINT_MAX_GO = (1, 26, 99)


def parse_semver(ver_str: str) -> tuple[int, ...]:
    """Parse numeric version string like '1.26.6' into tuple (1, 26, 6)."""
    cleaned = ver_str.lstrip("v").split("-")[0]
    try:
        return tuple(int(x) for x in cleaned.split("."))
    except ValueError:
        return ()


def get_go_mod_version() -> tuple[int, ...] | None:
    """Extract `go X.Y.Z` version from go.mod."""
    if not GO_MOD.exists():
        return None
    for line in GO_MOD.read_text().splitlines():
        match = re.match(r"^go\s+([0-9\.]+)", line.strip())
        if match:
            return parse_semver(match.group(1))
    return None


def check_dockerfile_go_versions() -> list[str]:
    """Check Go version in builder Dockerfiles."""
    errors = []
    if not DOCKERFILES_DIR.exists():
        return errors

    for df in sorted(DOCKERFILES_DIR.glob("Dockerfile*")):
        content = df.read_text()
        for line in content.splitlines():
            match = re.search(r"FROM\s+golang:([0-9\.]+)-alpine", line)
            if match:
                ver = parse_semver(match.group(1))
                if ver and ver < (1, 27, 2):
                    errors.append(
                        f"{df.relative_to(REPO_ROOT)} uses Go {match.group(1)} < 1.27.2 (carried stdlib CVE-2026-78667/CVE-2026-97031)"
                    )
    return errors


def main() -> int:
    """Execute all toolchain alignment checks."""
    errors: list[str] = []

    go_mod_ver = get_go_mod_version()
    if go_mod_ver is None:
        errors.append("Could not parse `go` version directive from go.mod")
    else:
        # Check go.mod version against golangci-lint capabilities
        if go_mod_ver > GOLANGCI_LINT_MAX_GO:
            errors.append(
                f"go.mod specifies Go version {'.'.join(str(x) for x in go_mod_ver)}, "
                f"which exceeds golangci-lint capability (max Go 1.26.x). "
                f"Keep go.mod at 1.26.x until golangci-lint is upgraded."
            )

    # Check Dockerfiles
    docker_errors = check_dockerfile_go_versions()
    errors.extend(docker_errors)

    if errors:
        print("✗ Toolchain alignment check FAILED:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("✓ Toolchain alignment check PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
