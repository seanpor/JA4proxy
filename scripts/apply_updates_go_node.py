#!/usr/bin/env python3
"""
apply_updates_go_node.py — Automated dependency upgrade engine for Go modules and Node/sql.js.

Usage:
    python3 scripts/apply_updates_go_node.py --go
    python3 scripts/apply_updates_go_node.py --node [--scan-js]
    python3 scripts/apply_updates_go_node.py --all [--dry-run]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

GO_MODULES: list[Path] = [
    REPO_ROOT,
    REPO_ROOT / "deploy" / "terraform-provider",
]

_SNAP_GOROOT = Path("/snap/go/current")
_MAX_HTTP_BYTES = 256 * 1024  # 256 KiB cap on external registry responses
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_NPM_PKG_RE = re.compile(r"^(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$")
_SPEC_RE = re.compile(r"^([~^]|>=|<=|>|<|=)?\s*(.+)$")


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> tuple[str, str, int]:
    """Run a subprocess safely with timeout and FileNotFoundError handling."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", 127
    except subprocess.TimeoutExpired:
        return "", f"command timed out after {timeout}s: {cmd[0]}", 124


def _go_env_and_bin() -> tuple[str, dict[str, str]]:
    """Resolve the Go binary and environment, preferring /snap/go/current when present."""
    env = os.environ.copy()
    snap_bin = _SNAP_GOROOT / "bin" / "go"
    if _SNAP_GOROOT.is_dir() and snap_bin.is_file():
        env["GOROOT"] = str(_SNAP_GOROOT)
        return str(snap_bin), env
    return "go", env


def _snapshot_files(paths: list[Path]) -> dict[Path, bytes | None]:
    """Capture raw file bytes (or None if absent) for atomic rollback on failure."""
    return {p: (p.read_bytes() if p.exists() else None) for p in paths}


def _restore_files(snapshot: dict[Path, bytes | None]) -> None:
    """Restore files from a snapshot captured by _snapshot_files."""
    for path, content in snapshot.items():
        if content is None:
            if path.exists():
                path.unlink()
        else:
            path.write_bytes(content)


def update_go_modules(
    module_dirs: list[Path] | None = None,
    dry_run: bool = False,
) -> int:
    """
    Upgrade Go dependencies in each module directory via `go get -u ./...`,
    `go mod tidy`, and `go mod verify`.

    Rolls back go.mod and go.sum on any failure.
    """
    dirs = module_dirs if module_dirs is not None else GO_MODULES
    go_bin, env = _go_env_and_bin()

    for mod_dir in dirs:
        go_mod = mod_dir / "go.mod"
        if not go_mod.exists():
            continue

        go_sum = mod_dir / "go.sum"
        label = str(mod_dir)
        commands = [
            [go_bin, "get", "-u", "./..."],
            [go_bin, "mod", "tidy"],
            [go_bin, "mod", "verify"],
        ]

        if dry_run:
            for cmd in commands:
                print(f"[dry-run] ({label}) {' '.join(cmd)}")
            continue

        snapshot = _snapshot_files([go_mod, go_sum])
        for cmd in commands:
            _, stderr, rc = _run(cmd, cwd=mod_dir, env=env, timeout=180)
            if rc != 0:
                print(
                    f"ERROR: {' '.join(cmd)} failed in {label} (rc={rc}): {stderr.strip()}",
                    file=sys.stderr,
                )
                _restore_files(snapshot)
                return 1

        print(f"Updated Go module: {label}")

    return 0


def _parse_version_spec(spec: str) -> tuple[str, str]:
    """Split an npm version range prefix (e.g. '^', '~', '>=') from the version string."""
    match = _SPEC_RE.match(spec.strip())
    if not match:
        return "", spec.strip()
    return (match.group(1) or ""), match.group(2).strip()


def _fetch_npm_latest_version(package: str) -> str:
    """Query the npm registry for the latest stable version of a package."""
    if not _NPM_PKG_RE.match(package):
        raise ValueError(f"Invalid npm package name: {package!r}")

    url = f"https://registry.npmjs.org/{package}/latest"
    req = urllib.request.Request(url, headers={"User-Agent": "ja4proxy-update-engine/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        raw = resp.read(_MAX_HTTP_BYTES)

    data = json.loads(raw.decode("utf-8"))
    version = str(data.get("version", "")).strip()
    if not _SEMVER_RE.match(version):
        raise ValueError(f"Invalid npm version returned for {package}: {version!r}")
    return version


def _sync_vendor_sqljs_if_present(repo_root: Path) -> None:
    """If management/static/vendor/sql.js exists and node_modules has dist assets, sync + hash."""
    vendor_dir = repo_root / "management" / "static" / "vendor" / "sql.js"
    dist_dir = repo_root / "node_modules" / "sql.js" / "dist"
    if not vendor_dir.is_dir() or not dist_dir.is_dir():
        return

    updated_files: list[Path] = []
    for asset in ("sql-wasm.js", "sql-wasm.wasm"):
        src = dist_dir / asset
        if src.is_file():
            dst = vendor_dir / asset
            shutil.copy2(src, dst)
            updated_files.append(dst)

    checksums_file = repo_root / "management" / "static" / "vendor" / "CHECKSUMS.txt"
    if updated_files and checksums_file.is_file():
        lines = checksums_file.read_text().splitlines()
        entries: dict[str, str] = {}
        order: list[str] = []
        for line in lines:
            parts = line.split()
            if len(parts) == 2:
                entries[parts[1]] = parts[0]
                order.append(parts[1])
        for fpath in updated_files:
            rel = str(fpath.relative_to(checksums_file.parent))
            digest = hashlib.sha256(fpath.read_bytes()).hexdigest()
            if rel not in entries:
                order.append(rel)
            entries[rel] = digest
        checksums_file.write_text("\n".join(f"{entries[k]}  {k}" for k in order) + "\n")


def update_node_packages(
    repo_root: Path | None = None,
    dry_run: bool = False,
    run_scan: bool = False,
) -> int:
    """
    Update Node/sql.js dependencies in package.json and regenerate package-lock.json.

    Rolls back package.json and package-lock.json on any failure.
    """
    root = repo_root if repo_root is not None else REPO_ROOT
    pkg_json_path = root / "package.json"
    lock_json_path = root / "package-lock.json"

    if not pkg_json_path.exists():
        print(f"No package.json found in {root} — skipping Node updates.")
        return 0

    try:
        pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: failed to read {pkg_json_path}: {exc}", file=sys.stderr)
        return 1

    deps = pkg_data.get("dependencies", {})
    if not isinstance(deps, dict) or not deps:
        print("No dependencies in package.json — nothing to update.")
        return 0

    changes: list[tuple[str, str, str]] = []
    for pkg_name, current_spec in list(deps.items()):
        prefix, current_ver = _parse_version_spec(str(current_spec))
        try:
            latest = _fetch_npm_latest_version(pkg_name)
        except (urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            print(f"ERROR: npm registry lookup failed for {pkg_name}: {exc}", file=sys.stderr)
            return 1
        new_spec = f"{prefix}{latest}"
        if new_spec != str(current_spec):
            changes.append((pkg_name, str(current_spec), new_spec))
            deps[pkg_name] = new_spec

    if not changes:
        print("Node dependencies are already up to date.")
        return 0

    if dry_run:
        for pkg_name, old_spec, new_spec in changes:
            print(f"[dry-run] {pkg_name}: {old_spec} -> {new_spec}")
        return 0

    snapshot = _snapshot_files([pkg_json_path, lock_json_path])
    try:
        pkg_json_path.write_text(json.dumps(pkg_data, indent=2) + "\n", encoding="utf-8")
        _, stderr, rc = _run(
            ["npm", "install", "--package-lock-only", "--ignore-scripts"],
            cwd=root,
            timeout=120,
        )
        if rc != 0:
            print(f"ERROR: npm lockfile update failed (rc={rc}): {stderr.strip()}", file=sys.stderr)
            _restore_files(snapshot)
            return 1

        _sync_vendor_sqljs_if_present(root)

        if run_scan:
            _, scan_err, scan_rc = _run(
                ["npx", "--yes", "retire@5", "--path", "management/static"],
                cwd=root,
                timeout=120,
            )
            if scan_rc != 0:
                print(
                    f"ERROR: scan-js failed after Node update (rc={scan_rc}): {scan_err.strip()}",
                    file=sys.stderr,
                )
                _restore_files(snapshot)
                return 1
    except OSError as exc:
        print(f"ERROR: Node update failed: {exc}", file=sys.stderr)
        _restore_files(snapshot)
        return 1

    for pkg_name, old_spec, new_spec in changes:
        print(f"Updated Node package: {pkg_name} {old_spec} -> {new_spec}")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated upgrade engine for Go modules and Node/sql.js.",
    )
    parser.add_argument("--go", action="store_true", help="Update Go modules")
    parser.add_argument("--node", action="store_true", help="Update Node / sql.js dependencies")
    parser.add_argument("--all", action="store_true", help="Update both Go and Node (default)")
    parser.add_argument("--dry-run", action="store_true", help="Show planned updates without modifying files")
    parser.add_argument("--scan-js", action="store_true", help="Run retire.js scan after Node update")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    run_go = args.go or args.all or (not args.go and not args.node)
    run_node = args.node or args.all or (not args.go and not args.node)

    rc = 0
    if run_go:
        rc = update_go_modules(dry_run=args.dry_run)
        if rc != 0:
            return rc
    if run_node:
        rc = update_node_packages(dry_run=args.dry_run, run_scan=args.scan_js)
        if rc != 0:
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
