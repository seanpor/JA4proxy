#!/usr/bin/env python3
"""
check_updates.py — Check all project dependencies for available updates.

Usage:
    python3 scripts/check_updates.py

What it checks:
  1. Docker images — queries Docker Hub / GCR API for newer tags
  2. Go modules  — runs `go list -u -m all` in each Go module
  3. Python packages — runs `pip list --outdated` for each requirements file
  4. Node packages — runs `npm outdated --json`

Each section handles missing tools gracefully (warning, not crash).
No dependencies are installed or modified — this is read-only.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Constants — edit these if images or paths change
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent

MAKEFILE = REPO_ROOT / "Makefile"

# Additional compose-file images NOT in TRIVY_IMAGES but worth checking.
# These are parsed from docker-compose.*.yml by the helper below.
COMPOSE_DIR = REPO_ROOT / "deploy" / "docker"

# Go module directories
GO_MODULES = [
    REPO_ROOT / "cmd" / "proxy",
    REPO_ROOT / "deploy" / "terraform-provider",
]

# Python requirements files to check
PYTHON_REQUIREMENTS = [
    REPO_ROOT / "requirements.txt",
    REPO_ROOT / "requirements-analytics.txt",
    REPO_ROOT / "management" / "requirements.txt",
]

# First-party images built locally — no registry to check.
FIRST_PARTY_IMAGES = frozenset({
    "ja4proxy",
    "ja4proxy-admin-api",
    "ja4proxy-analytics",
    "ja4proxy-management",
    "ja4proxy-mockbackend",
    "ja4proxy-tarpit",
    "ja4proxy-test",
    "ja4proxy-trafficgen",
})

# Images hosted on non-Docker-Hub registries that this script can check.
# Key = image name prefix, Value = "dh" (Docker Hub), "gcr" (Google Container Reg),
# "mcr" (Microsoft Container Reg), or None (skip — no API available).
REGISTRY_MAP: dict[str, str | None] = {
    "gcr.io/": "gcr",
    "mcr.microsoft.com/": None,  # MCR API differs — skip for now
}

# Suffixes to skip when checking for latest tags (unstable/pre-release)
SKIP_SUFFIXES = {"rc", "alpha", "beta", "dev", "nightly", "pre"}

# ANSI color codes for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class Update(NamedTuple):
    """Represents a single dependency with an available update."""

    name: str
    current: str
    available: str
    category: str  # "docker", "go", "python", "node"
    severity: str  # "major", "minor", "patch"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _strip_v(version: str) -> str:
    """
    Remove a leading 'v' from a version string if present.

    'v1.2.3' -> '1.2.3', '10.2.2-alpine' -> '10.2.2-alpine'
    """
    return version.lstrip("v")


def _parse_semver(version: str) -> tuple[int, ...]:
    """
    Parse the numeric part of a version string into a tuple for comparison.

    '2.8.24-alpine' -> (2, 8, 24)
    'v1.55.0' -> (1, 55, 0)
    '10.2.2' -> (10, 2, 2)

    If the version can't be parsed, returns an empty tuple.
    """
    # Strip leading 'v' and take only digits and dots
    cleaned = _strip_v(version).split("-")[0]
    parts = cleaned.split(".")
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, IndexError):
        return ()


def _semver_diff(current: str, available: str) -> str:
    """
    Compare two version strings and return 'major', 'minor', or 'patch'.

    Uses the first three numeric segments:
      (1, 2, 3) -> (2, 0, 0) = major change
      (1, 2, 3) -> (1, 3, 0) = minor change
      (1, 2, 3) -> (1, 2, 4) = patch change
    """
    cur = _parse_semver(current)
    ava = _parse_semver(available)
    if not cur or not ava:
        return "unknown"
    # Pad to at least 3 components
    cur = cur + (0,) * max(0, 3 - len(cur))
    ava = ava + (0,) * max(0, 3 - len(ava))
    if ava[0] > cur[0]:
        return "major"
    if ava[1] > cur[1]:
        return "minor"
    return "patch"


def _color(severity: str) -> str:
    """Return ANSI color code for a given severity level."""
    return {"major": RED, "minor": YELLOW, "patch": YELLOW}.get(severity, RESET)


def _print_section(title: str, updates: list[Update]) -> None:
    """
    Print a color-coded section of the report.

    Each update is printed as:
      package_name    current -> new   (severity)

    Severity determines color:
      major = red, minor/patch = yellow
    """
    print(f"\n  {BOLD}{CYAN}{title}{RESET}")
    if not updates:
        print(f"    {GREEN}up to date{RESET}")
        return
    for u in updates:
        c = _color(u.severity)
        print(f"    {u.name:<45}  {u.current}  {c}→{RESET}  {u.available}  ({c}{u.severity}{RESET})")


def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 30,
         env: dict[str, str] | None = None) -> tuple[str, str, int]:
    """
    Run a shell command and return (stdout, stderr, returncode).

    This is a safe wrapper around subprocess that won't hang.
    If the command is not found, it returns an empty stdout and a
    non-zero return code instead of raising FileNotFoundError.

    Args:
        cmd: Command and arguments as a list
        cwd: Working directory (default: current)
        timeout: Maximum runtime in seconds (default: 30)
        env: Environment variables (default: inherit from parent process)
    """
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", f"command timed out after {timeout}s: {cmd[0]}", 124


# ---------------------------------------------------------------------------
# 1a — Parse images from Makefile and compose files
# ---------------------------------------------------------------------------


def _extract_makefile_images() -> list[str]:
    """
    Read the Makefile and extract all image references from TRIVY_IMAGES.

    TRIVY_IMAGES is defined as a continuation line (backslash-delimited).
    This function parses those lines and returns a list of 'name:tag' strings.
    """
    if not MAKEFILE.exists():
        print(f"  {YELLOW}Makefile not found at {MAKEFILE}{RESET}")
        return []

    text = MAKEFILE.read_text()

    # Find the TRIVY_IMAGES block: starts at the := and ends at a blank line
    # or a line that starts with a non-whitespace character (next target).
    match = re.search(
        r"^TRIVY_IMAGES\s*:=\s*(.+?)(?:\n\S|\Z)",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        print(f"  {YELLOW}TRIVY_IMAGES not found in Makefile{RESET}")
        return []

    block = match.group(1)
    images = []
    for line in block.splitlines():
        # Remove trailing backslash (line continuation)
        line = line.rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        images.append(line)
    return images


def _extract_compose_images() -> list[str]:
    """
    Read docker-compose.*.yml files and extract all image references.

    Returns a list of 'name:tag' strings for images NOT already in TRIVY_IMAGES.
    This catches the monitoring images (cadvisor, socket-proxy, etc.) that
    aren't covered by the Makefile scan list.
    """
    images: list[str] = []
    if not COMPOSE_DIR.exists():
        return images

    # Simple YAML-like grep: look for `image: <name>:<tag>` lines
    for compose_file in sorted(COMPOSE_DIR.glob("docker-compose*.yml")):
        text = compose_file.read_text()
        for match in re.finditer(r'^\s+image:\s+([^\s#]+)', text, re.MULTILINE):
            images.append(match.group(1))
    return sorted(set(images))


# ---------------------------------------------------------------------------
# 1b — Docker image check
# ---------------------------------------------------------------------------


def _docker_hub_tags(image: str) -> list[str]:
    """
    Query Docker Hub API for all tags of a given image.

    Args:
        image: Docker image name, e.g. 'library/haproxy' or 'prom/prometheus'

    Returns:
        Sorted list of tag strings (newest first by semver).
    """
    # Docker Hub API: https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags
    # For official images (library/ prefix), the namespace is 'library'.
    # For user images like 'prom/prometheus', namespace='prom', repo='prometheus'.

    # If the image has no '/', it's an official library image
    if "/" not in image:
        namespace = "library"
        repo = image
    else:
        namespace, repo = image.split("/", 1)

    url = f"https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags?page_size=100"
    tags: list[str] = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ja4proxy-check-updates/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            data = json.loads(resp.read().decode())
            for entry in data.get("results", []):
                name = entry["name"]
                tags.append(name)
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"    {YELLOW}Docker Hub API error for {image}: {e}{RESET}")
        return []

    return tags


def _gcr_tags(image: str) -> list[str]:
    """
    Query Google Container Registry API for all tags of a given image.

    Args:
        image: GCR image name, e.g. 'gcr.io/cadvisor/cadvisor'

    Returns:
        Sorted list of tag strings.
    """
    # GCR API: https://gcr.io/v2/{project}/{image}/tags/list
    # e.g. gcr.io/cadvisor/cadvisor -> project='cadvisor', image='cadvisor'

    # Strip 'gcr.io/' prefix
    path = image.replace("gcr.io/", "", 1)
    url = f"https://gcr.io/v2/{path}/tags/list"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ja4proxy-check-updates/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            data = json.loads(resp.read().decode())
            return data.get("child", []) or data.get("tags", [])
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"    {YELLOW}GCR API error for {image}: {e}{RESET}")
        return []


def _find_newer_tags(current_tag: str, all_tags: list[str]) -> str | None:
    """
    Find the newest tag that is newer than the current tag.

    Only considers tags that share the same version prefix (e.g. '2.8' for
    '2.8.5-alpine') to avoid suggesting unrelated major versions.

    Args:
        current_tag: The current tag, e.g. '2.8.5-alpine'
        all_tags: List of all available tags from the registry

    Returns:
        The newest tag string, or None if no update is available.
    """
    current_ver = _parse_semver(current_tag)
    if not current_ver:
        return None

    # Determine version prefix — use the first two segments (major.minor)
    # to find matching tags (e.g. '2.8.x' for '2.8.5')
    prefix = ".".join(str(p) for p in current_ver[:2])

    candidates: list[tuple[tuple[int, ...], str]] = []
    for tag in all_tags:
        # Skip pre-release tags
        tag_lower = tag.lower()
        if any(suffix in tag_lower for suffix in SKIP_SUFFIXES):
            continue

        # Only consider tags starting with the same major.minor prefix
        if not tag.startswith(prefix) and not tag.startswith("v" + prefix):
            # For grafana-style tags without 'v' prefix
            if not tag.startswith(prefix):
                continue

        ver = _parse_semver(tag)
        if not ver:
            continue

        # Must be strictly newer
        if ver <= current_ver:
            continue

        candidates.append((ver, tag))

    if not candidates:
        return None

    # Return the newest
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def check_docker_images() -> list[Update]:
    """
    Check all Docker images for available updates.

    Queries Docker Hub API (or GCR API) for each image and compares
    the current tag against available tags. Reports any newer tags
    found in the same version family.

    Returns:
        List of Update namedtuples.
    """
    updates: list[Update] = []

    # Collect all unique images from Makefile + compose files
    makefile_images = _extract_makefile_images()
    compose_images = _extract_compose_images()

    # Merge: use Makefile list as primary, add any from compose not duplicated
    seen = set()
    all_images: list[str] = []
    for img in makefile_images + compose_images:
        if img not in seen:
            seen.add(img)
            all_images.append(img)

    for img_ref in sorted(all_images):
        if ":" not in img_ref:
            # Skip images without a tag
            continue

        name, current_tag = img_ref.rsplit(":", 1)

        # Skip first-party images (built locally, no registry)
        if name in FIRST_PARTY_IMAGES:
            continue

        # Determine registry
        registry = "dh"  # default: Docker Hub
        for prefix, reg_type in REGISTRY_MAP.items():
            if name.startswith(prefix):
                registry = reg_type
                break

        if registry is None:
            # Registry not supported by this script (e.g. mcr.microsoft.com)
            continue
        elif registry == "gcr":
            all_tags = _gcr_tags(name)
        else:
            all_tags = _docker_hub_tags(name)

        if not all_tags:
            # Can't check — skip silently (API already warned)
            continue

        newer = _find_newer_tags(current_tag, all_tags)
        if newer:
            severity = _semver_diff(current_tag, newer)
            updates.append(Update(
                name=name,
                current=current_tag,
                available=newer,
                category="docker",
                severity=severity,
            ))

    return updates


# ---------------------------------------------------------------------------
# 2 — Go module check
# ---------------------------------------------------------------------------


def _go_list_updates(module_dir: Path) -> list[Update]:
    """
    Run `go list -u -m all` in a Go module directory and parse updates.

    The `-u` flag tells Go to check upstream registries and annotate
    updatable modules with `[new_version]` in the output.

    Args:
        module_dir: Path to a directory containing go.mod

    Returns:
        List of Update namedtuples for this module.
    """
    updates: list[Update] = []
    go_mod = module_dir / "go.mod"
    if not go_mod.exists():
        return updates

    env = os.environ.copy()
    env["GOROOT"] = "/snap/go/current"

    stdout, _, rc = _run(
        ["go", "list", "-u", "-m", "all"],
        cwd=module_dir,
        env=env,
        timeout=60,
    )
    if rc != 0:
        print(f"    {YELLOW}go list -u failed in {module_dir.relative_to(REPO_ROOT)}{RESET}")
        return updates

    module_label = module_dir.relative_to(REPO_ROOT)
    for line in stdout.splitlines():
        # Look for patterns like:
        #   github.com/redis/go-redis/v9 v9.18.0 [v9.20.0]
        #   golang.org/x/crypto v0.14.0 [v0.31.0]
        match = re.search(r'^(\S+)\s+v?\S+\s+\[v?(\S+)\]', line)
        if match:
            pkg = match.group(1)
            new_ver = match.group(2)
            # Extract current version (between package name and [new])
            cur_match = re.search(r'^(\S+)\s+(v?\S+)\s+\[', line)
            if cur_match:
                cur_ver = cur_match.group(2)
            else:
                cur_ver = "?"

            severity = _semver_diff(cur_ver, new_ver)
            name = f"{pkg} ({module_label})"
            updates.append(Update(
                name=name,
                current=cur_ver,
                available=new_ver,
                category="go",
                severity=severity,
            ))

    return updates


def check_go_modules() -> list[Update]:
    """
    Check all Go modules for available dependency updates.

    Runs `go list -u -m all` in each Go module directory and parses
    the output for lines with [new_version] annotations.

    Returns:
        List of Update namedtuples.
    """
    updates: list[Update] = []

    # Check if Go is available
    _, _, rc = _run(["go", "version"])
    if rc != 0:
        print(f"    {YELLOW}Go not found — skipping Go module checks{RESET}")
        return updates

    for mod_dir in GO_MODULES:
        mod_updates = _go_list_updates(mod_dir)
        updates.extend(mod_updates)

    return updates


# ---------------------------------------------------------------------------
# 3 — Python package check
# ---------------------------------------------------------------------------


def check_python_packages() -> list[Update]:
    """
    Check Python packages for available updates using pip.

    Runs `pip list --outdated --format=json` for each requirements file.
    Skips if pip is not available or no venv is active.

    Returns:
        List of Update namedtuples.
    """
    updates: list[Update] = []

    # Check if pip is available
    stdout, _, rc = _run(["pip", "--version"])
    if rc != 0:
        # Try python3 -m pip
        stdout, _, rc = _run(["python3", "-m", "pip", "--version"])
        pip_cmd = ["python3", "-m", "pip"]
        if rc != 0:
            print(f"    {YELLOW}pip not found — skipping Python checks{RESET}")
            return updates
    else:
        pip_cmd = ["pip"]

    # Check if we're in a virtual environment
    in_venv = sys.prefix != sys.base_prefix
    if not in_venv:
        print(f"    {YELLOW}no virtual environment active — skipping Python checks{RESET}")
        return updates

    stdout, _, rc = _run(pip_cmd + ["list", "--outdated", "--format=json"], timeout=30)
    if rc != 0:
        print(f"    {YELLOW}pip list --outdated failed{RESET}")
        return updates

    try:
        pkgs = json.loads(stdout)
    except json.JSONDecodeError:
        print(f"    {YELLOW}could not parse pip output{RESET}")
        return updates

    for pkg in pkgs:
        cur_ver = pkg.get("version", "?")
        new_ver = pkg.get("latest_version", "?")
        if cur_ver == "?" or new_ver == "?":
            continue

        severity = _semver_diff(cur_ver, new_ver)
        updates.append(Update(
            name=pkg["name"],
            current=cur_ver,
            available=new_ver,
            category="python",
            severity=severity,
        ))

    return updates


# ---------------------------------------------------------------------------
# 4 — Node package check
# ---------------------------------------------------------------------------


def check_node_packages() -> list[Update]:
    """
    Check Node.js packages for available updates using npm.

    Runs `npm outdated --json` in the project root.
    Skips if npm is not installed or package.json has no dependencies.

    Returns:
        List of Update namedtuples.
    """
    updates: list[Update] = []

    package_json = REPO_ROOT / "package.json"
    if not package_json.exists():
        return updates

    # Check if npm is available
    _, _, rc = _run(["npm", "--version"])
    if rc != 0:
        print(f"    {YELLOW}npm not found — skipping Node checks{RESET}")
        return updates

    stdout, _, rc = _run(["npm", "outdated", "--json"], cwd=REPO_ROOT, timeout=30)
    if rc == 127:
        # npm not found
        print(f"    {YELLOW}npm not found — skipping Node checks{RESET}")
        return updates
    if rc != 0 and not stdout.strip():
        # npm outdated returns exit code 1 when outdated packages are found,
        # so we only skip if there's genuinely no output
        print(f"    {YELLOW}npm outdated failed — skipping Node checks{RESET}")
        return updates

    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return updates

    for pkg_name, info in data.items():
        if not isinstance(info, dict):
            continue
        cur_ver = info.get("current", "?")
        new_ver = info.get("latest", "?")
        if cur_ver == "?" or new_ver == "?":
            continue

        severity = _semver_diff(cur_ver, new_ver)
        updates.append(Update(
            name=pkg_name,
            current=str(cur_ver),
            available=str(new_ver),
            category="node",
            severity=severity,
        ))

    return updates


# ---------------------------------------------------------------------------
# Main — run all checks and print report
# ---------------------------------------------------------------------------


def main() -> int:
    """
    Run all four dependency checks and print a color-coded report.

    Returns:
        0 if all checks completed successfully (no errors).
        1 if a tool crashed or encountered an unrecoverable error.
    """
    print(f"{BOLD}{CYAN}=== Dependency Update Checker ==={RESET}")
    print("  Checking Docker, Go, Python, and Node dependencies.")
    print(f"  This is read-only — nothing is installed or modified.{RESET}")
    print()

    all_updates: list[Update] = []

    # --- Docker images ---
    print(f"  {BOLD}--- Docker images ---{RESET}")
    docker = check_docker_images()
    all_updates.extend(docker)
    _print_section("Found updates:", docker)

    # --- Go modules ---
    print(f"\n  {BOLD}--- Go modules ---{RESET}")
    go = check_go_modules()
    all_updates.extend(go)
    _print_section("Found updates:", go)

    # --- Python packages ---
    print(f"\n  {BOLD}--- Python packages ---{RESET}")
    python = check_python_packages()
    all_updates.extend(python)
    _print_section("Found updates:", python)

    # --- Node packages ---
    print(f"\n  {BOLD}--- Node packages ---{RESET}")
    node = check_node_packages()
    all_updates.extend(node)
    _print_section("Found updates:", node)

    # --- Summary ---
    print(f"\n  {BOLD}{'=' * 50}{RESET}")
    major = sum(1 for u in all_updates if u.severity == "major")
    minor = sum(1 for u in all_updates if u.severity == "minor")
    patch = sum(1 for u in all_updates if u.severity == "patch")

    total = len(all_updates)
    if total == 0:
        print(f"  {GREEN}All dependencies up to date!{RESET}")
    else:
        parts = []
        if major:
            parts.append(f"{RED}{major} major{RESET}")
        if minor:
            parts.append(f"{YELLOW}{minor} minor{RESET}")
        if patch:
            parts.append(f"{YELLOW}{patch} patch{RESET}")
        print(f"  {BOLD}Summary:{RESET} {total} update(s) available ({', '.join(parts)})")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
