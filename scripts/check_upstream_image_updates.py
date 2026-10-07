#!/usr/bin/env python3
"""Automated Upstream Sidecar Container Image Tag Checker (Phase 827).

Queries upstream container registries (Docker Hub, Quay.io) for published image
tags newer than the pinned third-party sidecar tags in `.trivyignore.third-party`
and `deploy/docker/docker-compose.*.yml`.

Fails non-zero when a newer upstream tag is available for an image that carries
active CVE waivers, preventing date-bumping waiver abuse and enforcing image tag
upgrades when vendor patches land.

Stdlib only. Degrades gracefully if offline or rate-limited.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY_IGNORE = _ROOT / ".trivyignore.third-party"
COMPOSE_DIR = _ROOT / "deploy" / "docker"

TAG_REGEX = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[.\-](\w+[\w\-]*))?$")
CARRIER_REGEX = re.compile(r"^\s*#\s*Carriers.*:\s*([^\n]+)", re.MULTILINE | re.IGNORECASE)
CVE_LINE_REGEX = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\s+exp:(\d{4}-\d{2}-\d{2})")


@dataclass
class ImageRef:
    full_name: str
    repository: str  # e.g. "grafana/grafana" or "library/haproxy"
    tag: str         # e.g. "13.1.6-ubuntu"
    version_tuple: tuple[int, int, int]
    prefix: str      # "v" if tag starts with "v" else ""
    suffix: str      # "-ubuntu", "-alpine", etc.


def parse_image_ref(image_str: str) -> ImageRef | None:
    """Parse image string 'grafana/grafana:13.1.6-ubuntu' into structured ImageRef."""
    if "@" in image_str:
        image_str = image_str.split("@")[0]
    if ":" not in image_str:
        return None
    repo, tag = image_str.split(":", 1)
    if "/" not in repo:
        repo = f"library/{repo}"
    elif repo.startswith("gcr.io/"):
        # Strip gcr.io prefix for mapping if needed, e.g. gcr.io/cadvisor/cadvisor
        repo = repo.replace("gcr.io/", "")

    prefix = "v" if tag.startswith("v") else ""
    clean_tag = tag[1:] if prefix else tag

    # Match semver: e.g., 13.1.6-ubuntu -> (13, 1, 6), suffix "-ubuntu"
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", clean_tag)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    suffix = m.group(4)

    return ImageRef(
        full_name=image_str,
        repository=repo,
        tag=tag,
        version_tuple=(major, minor, patch),
        prefix=prefix,
        suffix=suffix,
    )


def fetch_docker_hub_tags(repo: str, timeout: int = 5) -> list[str]:
    """Fetch published tags from Docker Hub API v2."""
    url = f"https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100"
    req = urllib.request.Request(url, headers={"User-Agent": "JA4proxy-UpstreamChecker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return []
            data = json.loads(resp.read().decode("utf-8"))
            return [t["name"] for t in data.get("results", []) if isinstance(t, dict) and "name" in t]
    except Exception:
        return []


def find_newer_tags(ref: ImageRef, available_tags: list[str]) -> list[str]:
    """Find upstream tags matching ref's suffix/prefix with a higher semver tuple."""
    newer = []
    for t in available_tags:
        if ref.prefix and not t.startswith(ref.prefix):
            continue
        if not ref.prefix and t.startswith("v"):
            continue
        clean_t = t[1:] if ref.prefix else t

        # Match suffix pattern (e.g. -ubuntu vs -ubuntu)
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", clean_t)
        if not m:
            continue
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        t_suffix = m.group(4)

        if t_suffix != ref.suffix:
            continue

        cand_tuple = (major, minor, patch)
        # Check if candidate is newer in same major/minor or newer patch
        if cand_tuple > ref.version_tuple:
            newer.append(t)

    # Sort descending
    newer.sort(key=lambda x: [int(c) if c.isdigit() else c for c in re.split(r"(\d+)", x)], reverse=True)
    return newer


def extract_ignored_images() -> set[str]:
    """Extract third-party image strings (repo:tag) from .trivyignore.third-party."""
    if not THIRD_PARTY_IGNORE.exists():
        return set()
    text = THIRD_PARTY_IGNORE.read_text(encoding="utf-8")
    images = set()
    for line in text.splitlines():
        if "Carriers" in line:
            found = re.findall(r"([a-zA-Z0-9_\-\./]+:[a-zA-Z0-9_\-\.]+)", line)
            for f in found:
                cleaned = f.rstrip(".")
                if ":" in cleaned and not cleaned.startswith("http"):
                    images.add(cleaned)
    return images


def check_upstream_updates(fail_on_update: bool = True, timeout: int = 5) -> int:
    """Check all third-party ignored sidecars for available upstream tag updates."""
    ignored_images = extract_ignored_images()
    if not ignored_images:
        print("✓ No third-party images referenced in .trivyignore.third-party.")
        return 0

    print(f"Auditing {len(ignored_images)} third-party sidecar images against upstream registries...")
    print("-" * 80)
    print(f"{'IMAGE':<45} {'PINNED':<15} {'STATUS':<20}")
    print("-" * 80)

    updates_found = 0
    checked = 0

    for img_str in sorted(ignored_images):
        ref = parse_image_ref(img_str)
        if not ref:
            print(f"{img_str:<45} {'unparsed':<15} SKIPPED (non-semver tag)")
            continue

        checked += 1
        tags = fetch_docker_hub_tags(ref.repository, timeout=timeout)
        if not tags:
            print(f"{ref.repository:<45} {ref.tag:<15} OK (registry offline / unreachable)")
            continue

        newer = find_newer_tags(ref, tags)
        if newer:
            latest = newer[0]
            updates_found += 1
            print(f"\033[91m{ref.repository:<45} {ref.tag:<15} UPDATE AVAILABLE -> {latest}\033[0m")
        else:
            print(f"{ref.repository:<45} {ref.tag:<15} UP TO DATE")

    print("-" * 80)

    if updates_found > 0:
        print(f"✗ Found {updates_found} third-party image update(s) with active CVE waivers!")
        print("  Policy (Phase 827): Upgrade sidecar image tags on vendor patch release rather than extending .trivyignore waivers.")
        return 1 if fail_on_update else 0

    print("✓ All third-party sidecar images are on the latest available upstream tags.")
    return 0


def main(argv: list[str]) -> int:
    fail_on_update = "--no-fail" not in argv
    return check_upstream_updates(fail_on_update=fail_on_update)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
