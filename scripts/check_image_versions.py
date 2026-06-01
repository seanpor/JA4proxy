#!/usr/bin/env python3
"""
check_image_versions.py — detect :latest tags and version drift between compose files.

Does NOT call external APIs. Reads compose files and reports:
  - Any :latest tag (error)
  - Any image that appears with different versions in different files (warning)

Exit 0 = no problems.
Exit 1 = :latest tags found or version drift detected.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import NamedTuple

try:
    import yaml
except ImportError:
    print(
        "ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr
    )
    sys.exit(2)


class ImageRef(NamedTuple):
    name: str  # e.g. "grafana/grafana"
    version: str  # e.g. "10.2.0" or "latest"
    source: str  # compose file path


def _extract_images(compose_path: Path) -> list[ImageRef]:
    """Extract all image: values from a Docker Compose file."""
    with compose_path.open() as f:
        data = yaml.safe_load(f)

    refs: list[ImageRef] = []
    services = (data or {}).get("services", {}) or {}
    for _svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        image = svc.get("image")
        if not image:
            continue
        if ":" in image:
            name, version = image.rsplit(":", 1)
        else:
            name, version = image, "latest"
        refs.append(ImageRef(name=name, version=version, source=str(compose_path)))
    return refs


# First-party images are built locally via 'make build' and tagged :latest by convention.
# They have no external registry to pin against, so :latest is expected and correct.
FIRST_PARTY_IMAGES: frozenset[str] = frozenset(
    {
        "ja4proxy",
        "ja4proxy-analytics",
        "ja4proxy-tarpit",
        "ja4proxy-mockbackend",
        "ja4proxy-test",
        "ja4proxy-trafficgen",
    }
)


def check(
    compose_paths: list[Path],
    first_party: frozenset[str] = FIRST_PARTY_IMAGES,
) -> tuple[list[str], list[str]]:
    """
    Check compose files for :latest tags and version drift.

    First-party images (locally built) are exempt from the :latest check.

    Returns:
        errors:   list of error message strings (latest tags)
        warnings: list of warning message strings (version drift)
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Collect all image refs across files
    all_refs: list[ImageRef] = []
    for path in compose_paths:
        if not path.exists():
            warnings.append(f"Compose file not found, skipping: {path}")
            continue
        all_refs.extend(_extract_images(path))

    # Check for :latest — exempt first-party images (locally built, no registry to pin against)
    for ref in all_refs:
        if ref.version == "latest" and ref.name not in first_party:
            errors.append(
                f":latest tag in {ref.source}: {ref.name}:latest — pin to a specific version"
            )

    # Check for version drift (same image name, different versions across files)
    # Group by image name
    by_name: dict[str, list[ImageRef]] = {}
    for ref in all_refs:
        by_name.setdefault(ref.name, []).append(ref)

    for name, refs in by_name.items():
        versions = {r.version for r in refs}
        if len(versions) > 1:
            details = ", ".join(f"{r.version} ({r.source})" for r in refs)
            warnings.append(f"Version drift for {name}: {details}")

    return errors, warnings


def main() -> int:
    repo_root = Path(__file__).parent.parent
    compose_files = [
        repo_root / "deploy" / "docker" / "docker-compose.prod.yml",
        repo_root / "deploy" / "docker" / "docker-compose.monitoring.yml",
        repo_root / "deploy" / "docker" / "docker-compose.poc.yml",
        repo_root / "deploy" / "docker" / "docker-compose.scale.yml",
        repo_root / "deploy" / "docker" / "docker-compose.test.yml",
    ]

    errors, warnings = check(compose_files)

    if warnings:
        print("WARNINGS:")
        for w in warnings:
            print(f"  ⚠  {w}")
        print()

    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  ✗  {e}")
        print()
        print(
            f"✗ check-image-versions failed: {len(errors)} error(s), {len(warnings)} warning(s)"
        )
        return 1

    if warnings:
        print(f"✓ check-image-versions passed with {len(warnings)} warning(s)")
    else:
        print("✓ check-image-versions passed — no :latest tags, no version drift")
    return 0


if __name__ == "__main__":
    sys.exit(main())
