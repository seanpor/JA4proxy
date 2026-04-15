"""
tests/integration/test_go_proxy_image.py — Phase 202c TDD (red)

Verifies that `deploy/docker/Dockerfile.go-proxy` is hardened for
production / Pod Security Admission `restricted` profiles:

  * Runs with an EXPLICIT numeric UID 1000 (not a busybox-random low UID).
  * Carries OCI-standard labels for registry discoverability.
  * When actually built, reports `id -u == 1000` at runtime.

The textual tests need no Docker daemon; the build-and-run test is gated on
`docker` being on PATH and is marked `integration` so CI can opt in/out.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = REPO_ROOT / "deploy" / "docker" / "Dockerfile.go-proxy"


# ── Textual (no-daemon) checks ───────────────────────────────────────────────


def test_dockerfile_go_proxy_has_explicit_uid() -> None:
    """`Dockerfile.go-proxy` must switch to an explicit numeric UID.

    `USER ja4proxy` is insufficient: busybox's `adduser -S` assigns a random
    low UID, which Kubernetes PSA `restricted` profiles and `runAsUser: 1000`
    policies reject. Use `USER 1000:1000` (or at minimum `USER 1000`).
    """
    assert DOCKERFILE.exists(), f"missing {DOCKERFILE}"
    text = DOCKERFILE.read_text()

    # Accept either "USER 1000" or "USER 1000:1000" — but reject "USER name".
    explicit_uid = re.search(
        r"^\s*USER\s+1000(?::1000)?\s*$", text, flags=re.MULTILINE
    )
    assert explicit_uid, (
        f"{DOCKERFILE.relative_to(REPO_ROOT)} does not declare an explicit "
        f"numeric UID 1000. Found USER directives:\n"
        + "\n".join(
            f"  {ln}"
            for ln in text.splitlines()
            if re.match(r"\s*USER\s", ln)
        )
        + "\nExpected a line like `USER 1000:1000`."
    )


def test_dockerfile_go_proxy_has_oci_labels() -> None:
    """Dockerfile must declare OCI image-source label for registry traceability.

    At minimum, `org.opencontainers.image.source` must be set to a URL so
    that `ghcr.io` links the image back to the repo.
    """
    assert DOCKERFILE.exists(), f"missing {DOCKERFILE}"
    text = DOCKERFILE.read_text()

    # Match `LABEL ... org.opencontainers.image.source=...` (possibly on a
    # continuation line with a backslash join).
    # We normalise backslash-newline joins first so we can regex across them.
    joined = re.sub(r"\\\n\s*", " ", text)
    label_line = re.search(
        r"LABEL\b[^\n]*\borg\.opencontainers\.image\.source\s*=\s*"
        r"[\"']?(https?://\S+?)[\"']?(?:\s|$)",
        joined,
    )
    assert label_line, (
        f"{DOCKERFILE.relative_to(REPO_ROOT)} lacks an "
        f"`org.opencontainers.image.source=<url>` LABEL. Add an OCI LABEL "
        f"block after `FROM alpine:...` with at minimum a `source` URL."
    )
    url = label_line.group(1)
    assert url.startswith(("http://", "https://")), (
        f"OCI image.source label is not a URL: {url!r}"
    )


# ── Docker-gated build/run check ─────────────────────────────────────────────


_DOCKER_AVAILABLE = shutil.which("docker") is not None


@pytest.mark.integration
@pytest.mark.skipif(not _DOCKER_AVAILABLE, reason="docker CLI not on PATH")
def test_built_image_runs_as_uid_1000() -> None:
    """Actually build the image and verify `id -u` returns 1000.

    This is the ground truth: a Dockerfile can LOOK right yet build to an
    image whose UID isn't what we think. Only a real build/run catches that.
    """
    tag = "ja4proxy-go:phase202-test"
    build = subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(DOCKERFILE),
            "-t",
            tag,
            str(REPO_ROOT),
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert build.returncode == 0, (
        f"docker build failed:\nSTDOUT:\n{build.stdout}\nSTDERR:\n{build.stderr}"
    )

    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            tag,
            "-c",
            "id -u",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, (
        f"docker run failed:\nSTDOUT:\n{run.stdout}\nSTDERR:\n{run.stderr}"
    )
    uid = run.stdout.strip()
    assert uid == "1000", (
        f"Built image runs as UID {uid!r}, expected '1000'. "
        f"Fix the `adduser`/`USER` directives in {DOCKERFILE.name}."
    )
