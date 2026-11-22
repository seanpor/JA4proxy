#!/usr/bin/env python3
"""
apply_updates_docker.py — Multi-arch OCI/Docker digest resolver and updater.

Resolves the latest multi-arch manifest digest (`Docker-Content-Digest`) from
Docker Hub (`registry-1.docker.io`) and GCR (`gcr.io`) for digest-pinned base
images in Dockerfiles and `deploy/docker/docker-compose*.yml`, and rewrites
references in-place as `image[:tag]@sha256:<digest>`.

Usage:
    python3 scripts/apply_updates_docker.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_MAX_HTTP_BYTES = 256 * 1024  # 256 KiB cap on auth token responses
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MULTI_ARCH_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.oci.image.manifest.v1+json"
)

# Matches: FROM [--platform=...] <image>[:<tag>]@sha256:<64hex>[ ...]
_DOCKERFILE_FROM_RE = re.compile(
    r"^(?P<prefix>\s*FROM\s+(?:--platform=\S+\s+)?)"
    r"(?P<image>[a-zA-Z0-9][a-zA-Z0-9._/-]*)"
    r"(?::(?P<tag>[a-zA-Z0-9._-]+))?"
    r"@(?P<digest>sha256:[0-9a-f]{64})"
    r"(?P<suffix>.*)$"
)

# Matches:     image: <image>[:<tag>]@sha256:<64hex>[ ...]
_COMPOSE_IMAGE_RE = re.compile(
    r"^(?P<prefix>\s+image:\s+)"
    r"(?P<image>[a-zA-Z0-9][a-zA-Z0-9._/-]*)"
    r"(?::(?P<tag>[a-zA-Z0-9._-]+))?"
    r"@(?P<digest>sha256:[0-9a-f]{64})"
    r"(?P<suffix>.*)$"
)


def _discover_dockerfiles(repo_root: Path) -> list[Path]:
    """Find all Dockerfiles in the repository root and deploy/docker/."""
    found: list[Path] = []
    for path in sorted(repo_root.glob("Dockerfile*")):
        if path.is_file():
            found.append(path)
    docker_dir = repo_root / "deploy" / "docker"
    if docker_dir.is_dir():
        for path in sorted(docker_dir.rglob("Dockerfile*")):
            if path.is_file():
                found.append(path)
    return found


def _discover_compose_files(repo_root: Path) -> list[Path]:
    """Find all docker-compose*.yml files under deploy/docker/."""
    docker_dir = repo_root / "deploy" / "docker"
    if not docker_dir.is_dir():
        return []
    return sorted(p for p in docker_dir.glob("docker-compose*.yml") if p.is_file())


def _validate_digest(digest: str, image: str, tag: str) -> str:
    cleaned = digest.strip()
    if not _DIGEST_RE.match(cleaned):
        raise ValueError(f"Invalid digest returned for {image}:{tag}: {cleaned!r}")
    return cleaned


def _fetch_docker_hub_token(repo: str) -> str:
    """Obtain an anonymous pull bearer token from auth.docker.io."""
    scope = urllib.parse.quote(f"repository:{repo}:pull", safe=":/")
    url = f"https://auth.docker.io/token?service=registry.docker.io&scope={scope}"
    req = urllib.request.Request(url, headers={"User-Agent": "ja4proxy-update-engine/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        data = json.loads(resp.read(_MAX_HTTP_BYTES).decode("utf-8"))
    token = str(data.get("token") or data.get("access_token") or "").strip()
    if not token:
        raise ValueError(f"Empty bearer token returned for {repo}")
    return token


def resolve_digest(image: str, tag: str) -> str:
    """
    Resolve the latest multi-arch manifest digest (`sha256:...`) for an image:tag
    on Docker Hub or Google Container Registry (gcr.io).
    """
    if image.startswith("gcr.io/"):
        path = image.removeprefix("gcr.io/")
        url = f"https://gcr.io/v2/{path}/manifests/{tag}"
        headers = {
            "Accept": _MULTI_ARCH_ACCEPT,
            "User-Agent": "ja4proxy-update-engine/1.0",
        }
        req = urllib.request.Request(url, headers=headers, method="HEAD")
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            digest = str(resp.headers.get("Docker-Content-Digest", ""))
        return _validate_digest(digest, image, tag)

    repo = image if "/" in image else f"library/{image}"
    token = _fetch_docker_hub_token(repo)
    url = f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": _MULTI_ARCH_ACCEPT,
        "User-Agent": "ja4proxy-update-engine/1.0",
    }
    req = urllib.request.Request(url, headers=headers, method="HEAD")
    with urllib.request.urlopen(req, timeout=15) as resp:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        digest = str(resp.headers.get("Docker-Content-Digest", ""))
    return _validate_digest(digest, image, tag)


def _rewrite_file(
    file_path: Path,
    pattern: re.Pattern[str],
    cache: dict[tuple[str, str], str | None],
    dry_run: bool,
) -> list[tuple[str, str, str]]:
    """Scan a single Dockerfile or compose file and update digest pins."""
    raw_lines = file_path.read_text(encoding="utf-8").splitlines(keepends=False)
    new_lines: list[str] = []
    changes: list[tuple[str, str, str]] = []

    for line in raw_lines:
        match = pattern.match(line)
        if not match:
            new_lines.append(line)
            continue

        image = match.group("image")
        raw_tag = match.group("tag")
        lookup_tag = raw_tag if raw_tag is not None else "latest"
        old_digest = match.group("digest")

        if image.startswith("ja4proxy") or image.startswith("mcr.microsoft.com/"):
            new_lines.append(line)
            continue

        key = (image, lookup_tag)
        if key not in cache:
            try:
                cache[key] = resolve_digest(image, lookup_tag)
            except (urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
                print(
                    f"WARNING: digest lookup failed for {image}:{lookup_tag}: {exc}",
                    file=sys.stderr,
                )
                cache[key] = None

        resolved = cache[key]
        if resolved is None or resolved == old_digest:
            new_lines.append(line)
            continue

        tag_part = f":{raw_tag}" if raw_tag is not None else ""
        rewritten = (
            f"{match.group('prefix')}{image}{tag_part}@{resolved}{match.group('suffix')}"
        )
        new_lines.append(rewritten)
        changes.append((f"{image}{tag_part}", old_digest, resolved))

    if changes and not dry_run:
        file_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    return changes


def update_docker_digests(
    dockerfiles: list[Path] | None = None,
    compose_files: list[Path] | None = None,
    repo_root: Path | None = None,
    dry_run: bool = False,
) -> int:
    """Resolve and update multi-arch digests across Dockerfiles and compose files."""
    root = repo_root if repo_root is not None else REPO_ROOT
    df_list = dockerfiles if dockerfiles is not None else _discover_dockerfiles(root)
    cf_list = compose_files if compose_files is not None else _discover_compose_files(root)

    cache: dict[tuple[str, str], str | None] = {}
    total_changes = 0

    work_items: list[tuple[Path, re.Pattern[str]]] = [
        (p, _DOCKERFILE_FROM_RE) for p in df_list
    ] + [(p, _COMPOSE_IMAGE_RE) for p in cf_list]

    for fpath, pattern in work_items:
        if not fpath.exists():
            continue
        changes = _rewrite_file(fpath, pattern, cache, dry_run=dry_run)
        for img_ref, old_d, new_d in changes:
            total_changes += 1
            rel = str(fpath.relative_to(root)) if fpath.is_relative_to(root) else str(fpath)
            prefix = "[dry-run] " if dry_run else "Updated digest: "
            print(f"{prefix}{rel} | {img_ref} {old_d[:19]}.. -> {new_d[:19]}..")

    if total_changes == 0:
        print("All pinned Docker digests are up to date.")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve and update multi-arch Docker digests across Dockerfiles and compose files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned digest updates without modifying files",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return update_docker_digests(dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
