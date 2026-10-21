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

import re
import sys
from pathlib import Path
from typing import NamedTuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


class ImageRef(NamedTuple):
    name: str  # e.g. "grafana/grafana" — never carries a tag or a digest
    version: str  # e.g. "10.2.0", "13.2.4-ubuntu@sha256:…" (digest-pinned), "latest"
    source: str  # compose file path
    # The verbatim `image:` value, so the exact string handed to Trivy can be
    # reconstructed without re-deriving the tag/digest split.
    ref: str = ""


def split_image_ref(image: str) -> tuple[str, str]:
    """`name[:tag][@digest]` -> `(name, version)`, keeping registry ports in name.

    `version` retains the digest when one is present, so two files pinning the
    same tag to different digests are reported as drift instead of agreeing.

    Splitting with `rsplit(":", 1)` — the pre-847c behaviour — put the *digest*
    into `version` and left the tag glued to `name`, giving one image two
    identities depending on how it was pinned: the 847c recorder keyed
    `redis:7.4.11-alpine@sha256:…` as `image:redis` while the gate keyed the same
    image as `image:redis:7.4.11-alpine@sha256`, so every finding on it would
    have counted as new.
    """
    base, _, digest = image.partition("@")
    name, tag = base, ""
    head, sep, tail = base.rpartition(":")
    # A colon with no slash after it is a tag; with a slash it is a registry port.
    if sep and "/" not in tail:
        name, tag = head, tail
    if digest:
        version = f"{tag}@{digest}" if tag else f"@{digest}"
    else:
        version = tag or "latest"
    return name, version


def _extract_images(compose_path: Path) -> list[ImageRef]:
    """Extract all image: values from a Docker Compose file."""
    return extract_images_from_text(compose_path.read_text(), source=str(compose_path))


def extract_images_from_text(text: str, source: str = "<text>") -> list[ImageRef]:
    """Extract all image: values from compose YAML held in *text*.

    Split out of :func:`_extract_images` so the Phase 847c regression gate can
    parse the compose files **at the merge-base** (`git show rev:path`) as well
    as in the working tree — one parser, two revisions, instead of a second
    hand-rolled extractor that could disagree about what an image is.
    """
    data = yaml.safe_load(text)

    refs: list[ImageRef] = []
    services = (data or {}).get("services", {}) or {}
    for _svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        image = svc.get("image")
        if not image:
            continue
        name, version = split_image_ref(image)
        refs.append(ImageRef(name=name, version=version, source=source, ref=image))
    return refs


# First-party images are built locally via 'make build' and tagged :latest by convention.
# They have no external registry to pin against, so :latest is expected and correct.
# MUST stay in sync with `FIRST_PARTY_IMAGES` in the Makefile — the Makefile
# builds and scans this list, while this set decides what `--list-third-party`
# (used by `make scan-images`) hands to Trivy. When the two drifted, a
# locally-built image (ja4proxy-tap) was offered to the *third-party* scan,
# which cannot pull it from a registry. Phase 847b; guarded by
# tests/unit/test_scan_tooling.py::test_first_party_lists_agree_with_the_makefile.
FIRST_PARTY_IMAGES: frozenset[str] = frozenset(
    {
        "ja4proxy",
        "ja4proxy-analytics",
        "ja4proxy-management",
        "ja4proxy-tap",
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
            errors.append(f":latest tag in {ref.source}: {ref.name}:latest — pin to a specific version")

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


# Compose files that make up the deployed production + monitoring stack —
# the surface `make scan-images` (the CVE-gating scan) covers. Kept as its
# own list rather than reusing the 5-file list below: poc/scale/test compose
# files are dev/CI-only, not part of what scan-images is scoping.
SCAN_GATE_COMPOSE_FILES = (
    "docker-compose.prod.yml",
    "docker-compose.monitoring.yml",
)

# The tuple above holds *names only*, and that distinction is load-bearing: the
# files live in COMPOSE_DIR. `third_party_image_refs()` silently skips a compose
# file that does not exist, so a caller that passes
# `Path("docker-compose.prod.yml")` from the repo root gets an empty image list
# and a green gate — no image, no finding, no error. Anything that wants these
# files must go through scan_gate_compose_paths() (filesystem) or
# SCAN_GATE_COMPOSE_REPOS (git).
COMPOSE_DIR = "deploy/docker"


def scan_gate_compose_paths(repo_root: Path | None = None) -> list[Path]:
    """Filesystem paths of the compose files that define the scanned image set."""
    root = repo_root if repo_root is not None else Path(__file__).resolve().parent.parent
    return [root / COMPOSE_DIR / f for f in SCAN_GATE_COMPOSE_FILES]


# The same files as repo-relative paths, for `git show rev:path`.
SCAN_GATE_COMPOSE_REPOS = tuple(f"{COMPOSE_DIR}/{f}" for f in SCAN_GATE_COMPOSE_FILES)

# `-f <dockerfile> -t <image:tag>` pairs, as written in the Makefile's build
# lines. One source for "which image does this Dockerfile produce", shared by the
# regression gate (847c) and the baseline recorder — a second hand-kept mapping
# would drift the moment someone renamed a Dockerfile.
DOCKER_IMAGE_RE = re.compile(r"-f\s+(\S+)\s+-t\s+(\S+)")


def dockerfile_image_map(makefile_text: str) -> dict[str, str]:
    """Parse `{dockerfile path: image:tag}` out of the Makefile's build lines.

    Make's shell loops write `-f "$$df" -t "$$tag"` — the loop's *variables*,
    not their values. Parsed literally those are a Dockerfile path and an image
    name that cannot exist, and the regression gate would try to scan the
    latter and fail closed on a surface that was never real: the gate could
    not pass at all, on any PR that widened its scope.

    `$$` is make's escape for a literal `$`, so a capture containing it is a
    shell variable by definition. A Dockerfile path or image tag is written
    literally in the Makefile's build rules and never contains `$$`.
    """
    out: dict[str, str] = {}
    for dockerfile, image in DOCKER_IMAGE_RE.findall(makefile_text):
        if "$$" in dockerfile or "$$" in image:
            continue
        out[dockerfile] = image
    return out


def third_party_image_refs(
    compose_paths: list[Path],
    first_party: frozenset[str] = FIRST_PARTY_IMAGES,
) -> list[str]:
    """
    Return the deduped, sorted "name:version" third-party image references
    across the given compose files.

    This is the canonical input for `make scan-images`'s image list (Phase
    810): that list used to be a hand-maintained Makefile variable that
    silently drifted from the compose files it was supposed to mirror — one
    image's tag went stale, and three images added to
    docker-compose.monitoring.yml were never added to the scan list at all,
    so they went unscanned indefinitely. Deriving the list here means the
    compose files are the only place a third-party image version is ever
    written down.

    Raises ValueError if the same third-party image name resolves to more
    than one version across the given files — ambiguous; which version would
    even be scanned? Fix the drift (check() above reports it as a warning)
    before this can produce a list.
    """
    all_refs: list[ImageRef] = []
    for path in compose_paths:
        if path.exists():
            all_refs.extend(_extract_images(path))

    by_name: dict[str, dict[str, str]] = {}
    for ref in all_refs:
        if ref.name in first_party:
            continue
        by_name.setdefault(ref.name, {})[ref.version] = ref.ref or f"{ref.name}:{ref.version}"

    conflicts = {name: vers for name, vers in by_name.items() if len(vers) > 1}
    if conflicts:
        details = "; ".join(f"{name}: {sorted(vers)}" for name, vers in sorted(conflicts.items()))
        raise ValueError(f"version drift across compose files — cannot pick one version to scan: {details}")

    return sorted(next(iter(vers.values())) for vers in by_name.values())


def main() -> int:
    repo_root = Path(__file__).parent.parent

    if "--list-third-party" in sys.argv:
        scan_files = scan_gate_compose_paths(repo_root)
        try:
            for ref in third_party_image_refs(scan_files):
                print(ref)
        except ValueError as e:
            print(f"✗ {e}", file=sys.stderr)
            return 1
        return 0

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
        print(f"✗ check-image-versions failed: {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1

    if warnings:
        print(f"✓ check-image-versions passed with {len(warnings)} warning(s)")
    else:
        print("✓ check-image-versions passed — no :latest tags, no version drift")
    return 0


if __name__ == "__main__":
    sys.exit(main())
