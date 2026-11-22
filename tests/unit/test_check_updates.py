"""Unit tests for scripts/check_updates.py and update-checker Dockerfile."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import check_updates

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKERFILE_PATH = REPO_ROOT / "deploy" / "docker" / "update-checker" / "Dockerfile"


class _FakeHTTPResponse:
    """Minimal context-manager mock for urllib.request.urlopen."""

    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class TestFirstPartyImages:
    """First-party internal images must never trigger upstream registry queries."""

    @pytest.mark.parametrize(
        "image_name",
        [
            "ja4proxy",
            "ja4proxy-analytics",
            "ja4proxy-management",
            "ja4proxy-mockbackend",
            "ja4proxy-tarpit",
            "ja4proxy-test",
            "ja4proxy-trafficgen",
            "ja4proxy-tap",
            "ja4proxy-logtide",
            "ja4proxy-attacker",
            "ja4proxy-proxy",
        ],
    )
    def test_first_party_images_excluded_from_registry_lookups(
        self, image_name: str
    ) -> None:
        assert image_name in check_updates.FIRST_PARTY_IMAGES

        with (
            patch.object(check_updates, "_extract_makefile_images", return_value=[]),
            patch.object(
                check_updates,
                "_extract_compose_images",
                return_value=[f"{image_name}:1.0.0"],
            ),
            patch.object(check_updates, "_docker_hub_tags") as mock_dh,
            patch.object(check_updates, "_gcr_tags") as mock_gcr,
        ):
            updates = check_updates.check_docker_images()

        assert updates == []
        mock_dh.assert_not_called()
        mock_gcr.assert_not_called()


class TestDigestStripping:
    """@sha256:... digests must be stripped before tag splitting and registry queries."""

    def test_docker_hub_image_with_digest_stripped(self) -> None:
        digest_ref = (
            "redis:7.4.11-alpine@sha256:"
            "520775a41a63e77e06c73e35d2fd9cc15921a609516818796b4ecbb813078bc7"
        )
        dh_payload = {"results": [{"name": "7.4.11-alpine"}, {"name": "7.4.12-alpine"}]}
        requested_urls: list[str] = []

        def fake_urlopen(req: object, timeout: int = 10) -> _FakeHTTPResponse:
            requested_urls.append(getattr(req, "full_url", str(req)))
            return _FakeHTTPResponse(dh_payload)

        with (
            patch.object(check_updates, "_extract_makefile_images", return_value=[]),
            patch.object(
                check_updates, "_extract_compose_images", return_value=[digest_ref]
            ),
            patch.object(check_updates.urllib.request, "urlopen", side_effect=fake_urlopen),
        ):
            updates = check_updates.check_docker_images()

        assert len(requested_urls) == 1
        assert "@sha256" not in requested_urls[0]
        assert "/repositories/library/redis/tags" in requested_urls[0]
        assert len(updates) == 1
        assert updates[0].name == "redis"
        assert updates[0].current == "7.4.11-alpine"
        assert updates[0].available == "7.4.12-alpine"

    def test_namespaced_docker_hub_image_with_digest_stripped(self) -> None:
        digest_ref = (
            "grafana/alloy:v1.21.2@sha256:"
            "89a5a320168387336b9ac3c850609c3ba7757eadd4ae5f1d819deb35e9854b18"
        )
        dh_payload = {"results": [{"name": "v1.21.2"}, {"name": "v1.21.3"}]}
        requested_urls: list[str] = []

        def fake_urlopen(req: object, timeout: int = 10) -> _FakeHTTPResponse:
            requested_urls.append(getattr(req, "full_url", str(req)))
            return _FakeHTTPResponse(dh_payload)

        with (
            patch.object(check_updates, "_extract_makefile_images", return_value=[]),
            patch.object(
                check_updates, "_extract_compose_images", return_value=[digest_ref]
            ),
            patch.object(check_updates.urllib.request, "urlopen", side_effect=fake_urlopen),
        ):
            updates = check_updates.check_docker_images()

        assert len(requested_urls) == 1
        assert "@sha256" not in requested_urls[0]
        assert "/repositories/grafana/alloy/tags" in requested_urls[0]
        assert len(updates) == 1
        assert updates[0].name == "grafana/alloy"
        assert updates[0].current == "v1.21.2"
        assert updates[0].available == "v1.21.3"

    def test_gcr_image_with_digest_stripped(self) -> None:
        digest_ref = (
            "gcr.io/cadvisor/cadvisor:v0.49.1@sha256:"
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )
        gcr_payload = {"tags": ["v0.49.1", "v0.49.2"]}
        requested_urls: list[str] = []

        def fake_urlopen(req: object, timeout: int = 10) -> _FakeHTTPResponse:
            requested_urls.append(getattr(req, "full_url", str(req)))
            return _FakeHTTPResponse(gcr_payload)

        with (
            patch.object(check_updates, "_extract_makefile_images", return_value=[]),
            patch.object(
                check_updates, "_extract_compose_images", return_value=[digest_ref]
            ),
            patch.object(check_updates.urllib.request, "urlopen", side_effect=fake_urlopen),
        ):
            updates = check_updates.check_docker_images()

        assert len(requested_urls) == 1
        assert "@sha256" not in requested_urls[0]
        assert requested_urls[0] == "https://gcr.io/v2/cadvisor/cadvisor/tags/list"
        assert len(updates) == 1
        assert updates[0].name == "gcr.io/cadvisor/cadvisor"
        assert updates[0].current == "v0.49.1"
        assert updates[0].available == "v0.49.2"

    def test_digest_only_image_without_tag_is_skipped(self) -> None:
        digest_only = (
            "redis@sha256:"
            "520775a41a63e77e06c73e35d2fd9cc15921a609516818796b4ecbb813078bc7"
        )
        with (
            patch.object(check_updates, "_extract_makefile_images", return_value=[]),
            patch.object(
                check_updates, "_extract_compose_images", return_value=[digest_only]
            ),
            patch.object(check_updates, "_docker_hub_tags") as mock_dh,
        ):
            updates = check_updates.check_docker_images()

        assert updates == []
        mock_dh.assert_not_called()


class TestGoListEnvironment:
    """GOROOT must only be overridden to /snap/go/current when that directory exists."""

    def test_does_not_force_snap_goroot_when_absent(self, tmp_path: Path) -> None:
        (tmp_path / "go.mod").write_text("module example.com/test\n")
        captured_env: dict[str, str] = {}

        def fake_run(cmd: list[str], cwd: Path | None = None, timeout: int = 30, env: dict[str, str] | None = None):
            if env is not None:
                captured_env.update(env)
            return ("", "", 0)

        with (
            patch.object(check_updates, "REPO_ROOT", tmp_path),
            patch.object(check_updates, "_run", side_effect=fake_run),
            patch.object(check_updates, "_SNAP_GOROOT", tmp_path / "nonexistent-snap-go"),
        ):
            check_updates._go_list_updates(tmp_path)

        assert captured_env.get("GOROOT") != "/snap/go/current"


class TestJsonOutputFormat:
    """--format json must output valid JSON with no ANSI or text preamble on stdout."""

    def test_main_json_format_outputs_valid_json(self) -> None:
        sample_update = check_updates.Update(
            name="redis",
            current="7.4.11-alpine",
            available="7.4.12-alpine",
            category="docker",
            severity="patch",
        )
        stdout_buf = io.StringIO()

        with (
            patch.object(check_updates, "check_docker_images", return_value=[sample_update]),
            patch.object(check_updates, "check_go_modules", return_value=[]),
            patch.object(check_updates, "check_python_packages", return_value=[]),
            patch.object(check_updates, "check_node_packages", return_value=[]),
            patch("sys.stdout", stdout_buf),
        ):
            rc = check_updates.main(["--format", "json"])

        assert rc == 0
        parsed = json.loads(stdout_buf.getvalue())
        assert isinstance(parsed, dict)
        assert len(parsed["updates"]) == 1
        assert parsed["updates"][0]["name"] == "redis"
        assert parsed["updates"][0]["category"] == "docker"
        assert parsed["summary"]["total"] == 1
        assert parsed["summary"]["patch"] == 1


class TestUpdateCheckerDockerfile:
    """Verify non-root cache environment variables and directory permissions in Dockerfile."""

    def test_dockerfile_sets_non_root_cache_env_and_permissions(self) -> None:
        content = DOCKERFILE_PATH.read_text()

        assert "GOCACHE=/tmp/gocache" in content
        assert "GOPATH=/tmp/gopath" in content
        assert "PIP_CACHE_DIR=/tmp/pip-cache" in content

        user_idx = content.index("USER checker")
        before_user = content[:user_idx]

        assert "/tmp/gocache" in before_user
        assert "/tmp/gopath" in before_user
        assert "/tmp/pip-cache" in before_user
        assert "1777" in before_user
