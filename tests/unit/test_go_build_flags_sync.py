"""Unit test verifying that all Go build targets and Dockerfiles stay in sync with the hardened build recipe (Phase 863)."""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Files that build Go binaries
GO_DOCKERFILES = [
    REPO_ROOT / "deploy" / "docker" / "Dockerfile.go-proxy",
    REPO_ROOT / "deploy" / "docker" / "Dockerfile.go-proxy.foss",
    REPO_ROOT / "deploy" / "docker" / "Dockerfile.cli",
    REPO_ROOT / "deploy" / "docker" / "Dockerfile.ja4-tap",
]

MAKEFILE = REPO_ROOT / "Makefile"

# Explicit deferral allowlist: recipes that are intentionally not using scripts/go_build_hardened.sh
# Key: file path relative to repo root, Value: reasoning and tracking issue/phase.
ALLOWLIST = {
    ".goreleaser.yml": "Stale reference to non-existent ./cmd/ja4proxy-cli/ deferred to CLI packaging follow-up",
    "deploy/docker/Dockerfile.mockbackend": "Lightweight mock test backend used only in tests, non-production",
    "deploy/docker/Dockerfile.logtide": "Separate analytics forwarder component",
}


def test_dockerfiles_use_hardened_build_script():
    """All production Go Dockerfiles must call scripts/go_build_hardened.sh."""
    for dockerfile in GO_DOCKERFILES:
        content = dockerfile.read_text(encoding="utf-8")
        assert "./scripts/go_build_hardened.sh" in content, (
            f"{dockerfile.relative_to(REPO_ROOT)} does not invoke scripts/go_build_hardened.sh"
        )
        assert "gcc musl-dev" in content, (
            f"{dockerfile.relative_to(REPO_ROOT)} does not install gcc and musl-dev in builder stage"
        )


def test_makefile_targets_use_hardened_build_script():
    """Makefile Go binary build targets must invoke scripts/go_build_hardened.sh."""
    content = MAKEFILE.read_text(encoding="utf-8")

    # Match recipes for go-build, go-build-foss, cli-build
    for target in ["go-build:", "go-build-foss:", "cli-build:"]:
        idx = content.find(target)
        assert idx != -1, f"Target {target} not found in Makefile"
        # Extract next 10 lines
        target_block = content[idx : idx + 400]
        assert "./scripts/go_build_hardened.sh" in target_block, (
            f"Makefile target {target} does not invoke ./scripts/go_build_hardened.sh"
        )


def test_all_go_build_occurrences_are_hardened_or_allowlisted():
    """Ensure no un-hardened 'go build' calls exist in Dockerfiles without allowlisting."""
    dockerfiles = list(REPO_ROOT.glob("deploy/docker/Dockerfile*"))
    for df in dockerfiles:
        rel = str(df.relative_to(REPO_ROOT))
        content = df.read_text(encoding="utf-8")
        if "go build" in content:
            # Must either call go_build_hardened.sh or be in allowlist
            if "./scripts/go_build_hardened.sh" not in content:
                assert rel in ALLOWLIST, (
                    f"Found un-hardened 'go build' in {rel} that is not in ALLOWLIST"
                )
