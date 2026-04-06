"""
tests/integration/test_dockerfile_coverage.py — Phase 89: Dockerfile Coverage

Integration-level tests that validate structural relationships between
Dockerfiles and docker-compose YAML files. These run on the host filesystem
without a Docker daemon but do require filesystem access to the repo root.

These are regression tests written alongside the Phase 89 fixes.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent

COMPOSE_FILES = sorted(REPO_ROOT.glob("docker/docker-compose*.yml"))


def load_compose(path: Path) -> dict:
    """Load a compose YAML file and return as a dict."""
    return yaml.safe_load(path.read_text()) or {}


# ---------------------------------------------------------------------------
# Every Dockerfile in docker/ is referenced by at least one compose file
# ---------------------------------------------------------------------------


def test_every_docker_dockerfile_is_referenced():
    """Every Dockerfile in docker/ must appear in at least one compose build block."""
    dockerfiles = sorted(REPO_ROOT.glob("docker/Dockerfile*"))
    # Collect all dockerfile references from all compose files
    referenced = set()
    for compose_path in COMPOSE_FILES:
        compose = load_compose(compose_path)
        for svc_name, svc in (compose.get("services") or {}).items():
            build = svc.get("build")
            if not isinstance(build, dict):
                continue
            df = build.get("dockerfile")
            ctx = build.get("context", ".")
            if df:
                # Resolve relative to compose file dir or context
                # compose files are in docker/, context is typically ".." (repo root)
                if ctx == "..":
                    resolved = (REPO_ROOT / df).resolve()
                else:
                    ctx_path = (compose_path.parent / ctx).resolve()
                    resolved = (ctx_path / df).resolve()
                referenced.add(resolved)

    for df in dockerfiles:
        resolved = df.resolve()
        assert resolved in referenced, (
            f"{df} is not referenced in any docker-compose build block. "
            f"Either add it to a compose file or remove the unused Dockerfile."
        )


# ---------------------------------------------------------------------------
# Every Dockerfile in tests/docker/ is referenced by at least one compose file
# ---------------------------------------------------------------------------


def test_every_test_dockerfile_is_referenced():
    """Every Dockerfile in tests/docker/ must appear in at least one compose build block."""
    dockerfiles = sorted(REPO_ROOT.glob("tests/docker/Dockerfile*"))
    # Collect all dockerfile references from all compose files
    referenced = set()
    for compose_path in COMPOSE_FILES:
        compose = load_compose(compose_path)
        for svc_name, svc in (compose.get("services") or {}).items():
            build = svc.get("build")
            if not isinstance(build, dict):
                continue
            df = build.get("dockerfile")
            ctx = build.get("context", ".")
            if df:
                if ctx == ".":
                    resolved = (compose_path.parent / df).resolve()
                elif ctx == "..":
                    resolved = (REPO_ROOT / df).resolve()
                else:
                    ctx_path = (compose_path.parent / ctx).resolve()
                    resolved = (ctx_path / df).resolve()
                referenced.add(resolved)

    for df in dockerfiles:
        resolved = df.resolve()
        assert resolved in referenced, (
            f"{df} is not referenced in any docker-compose build block. "
            f"Expected referencing file: docker/docker-compose.test.yml."
        )


# ---------------------------------------------------------------------------
# Every build.context resolves to an existing directory
# ---------------------------------------------------------------------------


def test_all_build_contexts_exist():
    """Every build.context in compose files must resolve to an existing directory."""
    for compose_path in COMPOSE_FILES:
        compose = load_compose(compose_path)
        for svc_name, svc in (compose.get("services") or {}).items():
            build = svc.get("build")
            if not isinstance(build, dict):
                continue
            ctx = build.get("context", ".")
            # Resolve relative to compose file directory
            resolved = (compose_path.parent / ctx).resolve()
            assert resolved.is_dir(), (
                f"{compose_path}: service '{svc_name}' build context "
                f"'{ctx}' resolves to non-existent directory: {resolved}"
            )


# ---------------------------------------------------------------------------
# Every build.dockerfile path resolves to an existing file
# ---------------------------------------------------------------------------


def test_all_build_dockerfiles_exist():
    """Every build.dockerfile in compose files must resolve to an existing file."""
    for compose_path in COMPOSE_FILES:
        compose = load_compose(compose_path)
        for svc_name, svc in (compose.get("services") or {}).items():
            build = svc.get("build")
            if not isinstance(build, dict):
                continue
            df = build.get("dockerfile")
            if not df:
                continue
            ctx = build.get("context", ".")
            # Resolve dockerfile relative to context, then relative to compose dir
            ctx_resolved = (compose_path.parent / ctx).resolve()
            df_resolved = (ctx_resolved / df).resolve()
            assert df_resolved.is_file(), (
                f"{compose_path}: service '{svc_name}' references "
                f"dockerfile '{df}' which does not exist at {df_resolved}"
            )


# ---------------------------------------------------------------------------
# Compose files validate individually (requires docker)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not shutil.which("docker"), reason="Docker not installed")
def test_standalone_compose_files_validate():
    """Standalone compose files must pass docker compose config validation."""
    test_cases = [
        (
            "docker/docker-compose.poc.yml",
            {"REDIS_PASSWORD": "test", "BACKEND_HOST": "lint"},
        ),
        ("docker/docker-compose.test.yml", {}),
        (
            "docker/docker-compose.prod.yml",
            {"BACKEND_HOST": "lint"},
        ),
    ]
    for compose_file, env in test_cases:
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file, "config", "--quiet"],
            env={**os.environ, **env},
            capture_output=True,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, (
            f"{compose_file} failed validation:\n{result.stderr.decode()}"
        )


# ---------------------------------------------------------------------------
# Monitoring overlay references valid POC network names
# ---------------------------------------------------------------------------


def test_monitoring_overlay_references_valid_poc_networks():
    """External network names in monitoring overlay must match explicit name: in poc."""
    poc = load_compose(REPO_ROOT / "docker" / "docker-compose.poc.yml")
    monitoring = load_compose(REPO_ROOT / "docker" / "docker-compose.monitoring.yml")

    # Collect the Docker-level names of all POC networks
    # (uses explicit name: field if present, falls back to the YAML key)
    poc_network_names = set()
    for key, cfg in poc.get("networks", {}).items():
        if isinstance(cfg, dict) and cfg.get("name"):
            poc_network_names.add(cfg["name"])
        else:
            poc_network_names.add(key)

    for key, cfg in monitoring.get("networks", {}).items():
        if isinstance(cfg, dict) and cfg.get("external"):
            declared_name = cfg.get("name", key)
            assert declared_name in poc_network_names, (
                f"docker-compose.monitoring.yml references external network "
                f"'{declared_name}' which is not declared in "
                f"docker-compose.poc.yml. POC networks: {sorted(poc_network_names)}"
            )
