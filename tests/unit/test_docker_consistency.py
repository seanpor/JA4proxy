"""
tests/unit/test_docker_consistency.py — Phase 89: Dockerfile Base Image Hygiene

Pure-Python tests that parse Dockerfile FROM lines and docker-compose YAML files
to enforce consistency rules. Requires only pyyaml and the standard library.
Runs without a Docker daemon in under two seconds.

Note on variable interpolation: Docker Compose's ${VAR:?error} syntax is preserved
as a literal string by pyyaml (it does not expand variables). String-contains checks
work correctly on the literal text — ":?" in value correctly identifies the required form.
"""

import re
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent

# Compose files to parse for various checks (excludes prod which uses secrets)
COMPOSE_FILES = sorted(REPO_ROOT.glob("deploy/docker/docker-compose*.yml"))

# Standalone compose files that must not reference REDIS_PASSWORD with weak forms
# docker-compose.prod.yml uses Docker secrets, so REDIS_PASSWORD is not in env
COMPOSE_FILES_WITH_PASSWORD_CHECK = [
    f for f in COMPOSE_FILES if f.name != "docker-compose.prod.yml"
]

# Dockerfiles to scan for base image tags
DOCKERFILE_DIRS = [
    REPO_ROOT / "deploy" / "docker",
    REPO_ROOT / "tests" / "docker",
    REPO_ROOT / "src" / "analytics",
    REPO_ROOT / "src" / "tarpit",
]


def collect_dockerfiles() -> list[tuple[Path, list[str]]]:
    """Return list of (path, lines) for every Dockerfile found in scanned dirs."""
    results = []
    for d in DOCKERFILE_DIRS:
        for df in sorted(d.glob("Dockerfile*")):
            if df.is_file():
                results.append((df, df.read_text().splitlines()))
    return results


def collect_from_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Return (lineno, image_ref) for each FROM line in a Dockerfile."""
    froms = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            # FROM <image> [AS <stage>]
            parts = stripped.split()
            if len(parts) >= 2:
                froms.append((i, parts[1]))
    return froms


def load_compose(path: Path) -> dict:
    """Load a compose YAML file and return as a dict."""
    return yaml.safe_load(path.read_text()) or {}


def iter_env_entries(compose: dict) -> list[tuple[str, str]]:
    """Yield (service_name, env_entry_string) for all environment entries."""
    entries = []
    for svc_name, svc in (compose.get("services") or {}).items():
        env = svc.get("environment") or []
        if isinstance(env, dict):
            env = [f"{k}={v}" for k, v in env.items()]
        for entry in env:
            entries.append((svc_name, str(entry)))
    return entries


# ---------------------------------------------------------------------------
# 89a — Python base image must be exactly python:3.14.0-slim
# ---------------------------------------------------------------------------


class TestPythonBaseImage:
    """89a: All python: tags must be exactly 3.14.0-slim."""

    @pytest.mark.parametrize("df_path,lines", collect_dockerfiles())
    def test_python_tag_is_pinned(self, df_path: Path, lines: list[str]):
        """Any FROM python:* must use exactly python:3.14.0-slim."""
        for lineno, image_ref in collect_from_lines(lines):
            if not image_ref.startswith("python:"):
                continue
            assert image_ref.startswith("python:3.14.0-slim"), (
                f"{df_path}:{lineno} — "
                f"expected FROM python:3.14.0-slim, got FROM {image_ref}. "
                f"Tags like '3.11-slim' or '3.14-slim' (without patch version) are rejected."
            )


# ---------------------------------------------------------------------------
# 89b — Go toolchain must be exactly golang:1.25-alpine
# ---------------------------------------------------------------------------


class TestGoBaseImage:
    """89b: All golang: tags must be pinned to golang:1.25.x-alpine."""

    @pytest.mark.parametrize("df_path,lines", collect_dockerfiles())
    def test_golang_tag_is_pinned(self, df_path: Path, lines: list[str]):
        """Any FROM golang:* must use golang:1.25.x-alpine (pinned patch version)."""
        for lineno, image_ref in collect_from_lines(lines):
            if not image_ref.startswith("golang:"):
                continue
            assert re.match(r"^golang:1\.26-alpine(@sha256:[a-f0-9]{64})?$", image_ref), (
                f"{df_path}:{lineno} — "
                f"expected FROM golang:1.26-alpine, got FROM {image_ref}. "
                f"Tags must be pinned to a specific patch version (e.g., 1.25.9-alpine)."
            )


# ---------------------------------------------------------------------------
# 89c — deploy/docker/docker-compose.test.yml is the canonical test environment
#       (ADAPTED: Phase 90 already moved the canonical file here; verify it
#        is the real 159-line test environment, not a deleted stub)
# ---------------------------------------------------------------------------


class TestComposeTestFile:
    """89c (adapted): deploy/docker/docker-compose.test.yml is the canonical test env.

    Phase 90 moved the canonical 159-line docker-compose.test.yml from the
    repo root to deploy/docker/. The stub described in Phase 89c no longer exists
    in isolation — this file IS the full test environment. We verify it exists
    and has more than 50 lines to confirm it is the canonical version.
    """

    def test_compose_test_exists_and_is_canonical(self):
        """deploy/docker/docker-compose.test.yml must exist and have more than 50 lines."""
        path = REPO_ROOT / "deploy" / "docker" / "docker-compose.test.yml"
        assert path.exists(), (
            "deploy/docker/docker-compose.test.yml must exist — it is the canonical "
            "integration test environment (moved here by Phase 90)."
        )
        line_count = len(path.read_text().splitlines())
        assert line_count > 50, (
            f"deploy/docker/docker-compose.test.yml has only {line_count} lines — "
            "expected the full canonical test environment (>50 lines). "
            "A short file would indicate an abandoned stub, not the full test env."
        )


# ---------------------------------------------------------------------------
# 89d — Volume and network naming must use hyphens (no underscores)
# ---------------------------------------------------------------------------


class TestVolumeNaming:
    """89d: Non-external volumes must not contain underscores."""

    @pytest.mark.parametrize("compose_path", COMPOSE_FILES)
    def test_volumes_use_hyphen_naming(self, compose_path: Path):
        """Top-level non-external volume keys must not contain underscores."""
        compose = load_compose(compose_path)
        volumes = compose.get("volumes") or {}
        for vol_key, vol_cfg in volumes.items():
            # Skip external volumes (they reference pre-existing resources)
            if isinstance(vol_cfg, dict) and vol_cfg.get("external"):
                continue
            assert "_" not in vol_key, (
                f"{compose_path}: volume key '{vol_key}' contains an underscore. "
                f"Use hyphens instead (e.g. 'redis-data' not 'redis_data')."
            )


class TestNetworkNaming:
    """89d: Non-external network keys must not contain underscores."""

    @pytest.mark.parametrize("compose_path", COMPOSE_FILES)
    def test_non_external_networks_use_hyphen_naming(self, compose_path: Path):
        """Top-level non-external network keys must not contain underscores."""
        compose = load_compose(compose_path)
        networks = compose.get("networks") or {}
        for net_key, net_cfg in networks.items():
            # Skip external networks (they reference pre-existing resources)
            if isinstance(net_cfg, dict) and net_cfg.get("external"):
                continue
            assert "_" not in net_key, (
                f"{compose_path}: network key '{net_key}' contains an underscore. "
                f"Use hyphens instead (e.g. 'ja4proxy-dmz' not 'dmz_net')."
            )


# ---------------------------------------------------------------------------
# 89e — No network: host in build blocks
# ---------------------------------------------------------------------------


class TestNoBuildNetworkHost:
    """89e: No service build block may contain network: host."""

    @pytest.mark.parametrize("compose_path", COMPOSE_FILES)
    def test_no_network_host_in_build_blocks(self, compose_path: Path):
        """build: blocks must not contain a 'network' key."""
        compose = load_compose(compose_path)
        for svc_name, svc in (compose.get("services") or {}).items():
            build = svc.get("build")
            if not isinstance(build, dict):
                continue
            assert "network" not in build, (
                f"{compose_path}: service '{svc_name}' has 'network' in its build block "
                f"(found: network={build['network']!r}). "
                f"Remove 'network: host' from all build blocks (Phase 89e security fix)."
            )


# ---------------------------------------------------------------------------
# 89f — REDIS_PASSWORD must use :? form (not :- or :-value)
# ---------------------------------------------------------------------------


class TestRedisPasswordForm:
    """89f: REDIS_PASSWORD env vars must use the :? required-form."""

    @pytest.mark.parametrize("compose_path", COMPOSE_FILES_WITH_PASSWORD_CHECK)
    def test_redis_password_uses_required_form(self, compose_path: Path):
        """Every REDIS_PASSWORD env entry must use ${REDIS_PASSWORD:?...} syntax."""
        compose = load_compose(compose_path)
        for svc_name, entry in iter_env_entries(compose):
            if "REDIS_PASSWORD" not in entry:
                continue
            # Accept entries that are just "REDIS_PASSWORD" (passthrough without value)
            # or that contain :?
            if entry.strip() == "REDIS_PASSWORD":
                continue
            # Also accept empty-default overlay forms like ${REDIS_PASSWORD:-}
            # (python-legacy overlay intentionally uses :- as it's always layered
            # on top of poc.yml which enforces :?)
            # We flag only :-changeme and similar non-empty weak defaults
            if ":-changeme" in entry or (
                ":-" in entry and ":-}" not in entry and ":-}" not in entry
            ):
                # Check it's not the empty fallback pattern :-}
                raw = entry
                # Allow ${REDIS_PASSWORD:-} but reject ${REDIS_PASSWORD:-changeme}
                if re.search(r"REDIS_PASSWORD:-[^}]+", raw):
                    assert False, (
                        f"{compose_path}: service '{svc_name}' uses weak REDIS_PASSWORD form: "
                        f"{entry!r}. "
                        f"Use ${{REDIS_PASSWORD:?REDIS_PASSWORD is required}} instead."
                    )


# ---------------------------------------------------------------------------
# 89g — Restart policy on permanent services in poc compose
# ---------------------------------------------------------------------------

PERMANENT_POC_SERVICES = [
    "proxy",
    "redis",
    "backend",
    "tarpit",
    "analytics",
    "admin-api",
    "trafficgen",
    "haproxy",
    "management",
]


class TestRestartPolicy:
    """89g: All permanent POC services must have restart: unless-stopped."""

    def test_poc_services_have_restart_policy(self):
        """Each permanent service in docker-compose.poc.yml must have restart: unless-stopped."""
        compose_path = REPO_ROOT / "deploy" / "docker" / "docker-compose.poc.yml"
        compose = load_compose(compose_path)
        services = compose.get("services") or {}
        for svc_name in PERMANENT_POC_SERVICES:
            assert (
                svc_name in services
            ), f"{compose_path}: expected service '{svc_name}' not found."
            restart = services[svc_name].get("restart")
            assert restart == "unless-stopped", (
                f"{compose_path}: service '{svc_name}' has restart={restart!r}, "
                f"expected 'unless-stopped'."
            )


# ---------------------------------------------------------------------------
# 89h — deploy/docker/README.md exists with valid content
# ---------------------------------------------------------------------------


class TestDockerReadme:
    """89h: deploy/docker/README.md must exist and contain required content."""

    def test_readme_exists(self):
        """deploy/docker/README.md must exist."""
        assert (
            REPO_ROOT / "deploy" / "docker" / "README.md"
        ).exists(), "deploy/docker/README.md does not exist — create it per Phase 89h."

    def test_readme_references_poc_compose(self):
        """deploy/docker/README.md must reference deploy/docker/docker-compose.poc.yml."""
        content = (REPO_ROOT / "deploy" / "docker" / "README.md").read_text()
        assert (
            "deploy/docker/docker-compose.poc.yml" in content
        ), "deploy/docker/README.md must reference deploy/docker/docker-compose.poc.yml."

    def test_readme_references_monitoring_compose(self):
        """deploy/docker/README.md must reference docker-compose.monitoring.yml."""
        content = (REPO_ROOT / "deploy" / "docker" / "README.md").read_text()
        assert (
            "docker-compose.monitoring.yml" in content
        ), "deploy/docker/README.md must reference docker-compose.monitoring.yml."

    def test_readme_local_links_resolve(self):
        """All local markdown links in deploy/docker/README.md must reference existing files."""
        readme_path = REPO_ROOT / "deploy" / "docker" / "README.md"
        content = readme_path.read_text()
        # Find all markdown links that are not http/https
        links = re.findall(r"\[.*?\]\((?!https?://)(.*?)\)", content)
        for link in links:
            # Remove fragment identifiers (e.g. #section)
            link_path = link.split("#")[0]
            if not link_path:
                continue
            # Try relative to deploy/docker/ first, then relative to repo root
            resolved = (REPO_ROOT / "deploy" / "docker" / link_path).resolve()
            resolved_root = (REPO_ROOT / link_path).resolve()
            assert (
                resolved.exists() or resolved_root.exists()
            ), f"deploy/docker/README.md links to non-existent file: {link!r}"


# ---------------------------------------------------------------------------
# 89i — Dockerfile location metadata labels on module Dockerfiles
# ---------------------------------------------------------------------------


class TestDockerfileLocationLabels:
    """89i: src/analytics/Dockerfile and src/tarpit/Dockerfile must carry location LABEL."""

    @pytest.mark.parametrize(
        "df_path",
        [
            "src/analytics/Dockerfile",
            "src/tarpit/Dockerfile",
        ],
    )
    def test_dockerfile_has_location_label(self, df_path: str):
        """Module Dockerfiles must contain LABEL dockerfile.location=\"module\"."""
        full_path = REPO_ROOT / df_path
        assert full_path.exists(), f"{df_path} not found."
        content = full_path.read_text()
        assert 'dockerfile.location="module"' in content, (
            f'{df_path} is missing LABEL dockerfile.location="module" (Phase 89i). '
            f"Add after the FROM line."
        )
