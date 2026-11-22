"""Unit tests for scripts/apply_updates_docker.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts import apply_updates_docker as mod

DIGEST_OLD = "sha256:" + "a" * 64
DIGEST_NEW = "sha256:" + "b" * 64
DIGEST_GCR = "sha256:" + "c" * 64


class _FakeHTTPResponse:
    """Minimal context-manager mock for urllib.request.urlopen."""

    def __init__(
        self,
        payload: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._body = json.dumps(payload or {}).encode("utf-8")
        self.headers = headers or {}

    def read(self, amt: int | None = None) -> bytes:
        return self._body if amt is None else self._body[:amt]

    def __enter__(self) -> _FakeHTTPResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class TestRegistryDigestResolution:
    """Docker Hub and GCR multi-arch manifest digest resolution."""

    def test_resolve_docker_hub_official_image_digest(self) -> None:
        seen_requests: list[tuple[str, str, dict[str, str]]] = []

        def fake_urlopen(req: object, timeout: int = 15) -> _FakeHTTPResponse:
            url = getattr(req, "full_url", str(req))
            method = getattr(req, "method", "GET") or "GET"
            headers = dict(getattr(req, "headers", {}))
            seen_requests.append((method, url, headers))
            if "auth.docker.io/token" in url:
                return _FakeHTTPResponse({"token": "test-bearer-token"})
            return _FakeHTTPResponse(headers={"Docker-Content-Digest": DIGEST_NEW})

        with patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
            digest = mod.resolve_digest("golang", "1.27.3-alpine")

        assert digest == DIGEST_NEW
        assert len(seen_requests) == 2
        assert "scope=repository:library/golang:pull" in seen_requests[0][1]
        assert seen_requests[1][0] == "HEAD"
        assert (
            seen_requests[1][1]
            == "https://registry-1.docker.io/v2/library/golang/manifests/1.27.3-alpine"
        )
        accept_hdr = seen_requests[1][2].get("Accept", "")
        assert "application/vnd.oci.image.index.v1+json" in accept_hdr
        assert "application/vnd.docker.distribution.manifest.list.v2+json" in accept_hdr

    def test_resolve_gcr_image_digest(self) -> None:
        seen_urls: list[str] = []

        def fake_urlopen(req: object, timeout: int = 15) -> _FakeHTTPResponse:
            seen_urls.append(getattr(req, "full_url", str(req)))
            return _FakeHTTPResponse(headers={"Docker-Content-Digest": DIGEST_GCR})

        with patch.object(mod.urllib.request, "urlopen", side_effect=fake_urlopen):
            digest = mod.resolve_digest("gcr.io/distroless/static-debian12", "latest")

        assert digest == DIGEST_GCR
        assert seen_urls == [
            "https://gcr.io/v2/distroless/static-debian12/manifests/latest"
        ]

    def test_rejects_malformed_digest_header(self) -> None:
        with (
            patch.object(
                mod.urllib.request,
                "urlopen",
                return_value=_FakeHTTPResponse(
                    headers={"Docker-Content-Digest": "sha256:not-a-valid-hex"}
                ),
            ),
            pytest.raises(ValueError, match="Invalid digest"),
        ):
            mod.resolve_digest("gcr.io/distroless/static", "debug")


class TestFileRewriting:
    """Dockerfile and docker-compose*.yml multi-arch digest rewriting."""

    def test_rewrites_dockerfiles_and_compose_preserving_format_and_caching(
        self, tmp_path: Path
    ) -> None:
        df1 = tmp_path / "Dockerfile.proxy"
        df2 = tmp_path / "Dockerfile.cli"
        compose = tmp_path / "docker-compose.prod.yml"

        df1.write_text(
            f"# Builder stage\n"
            f"FROM golang:1.27.3-alpine@{DIGEST_OLD} AS builder\n"
            f"FROM gcr.io/distroless/static-debian12@{DIGEST_OLD}\n"
            f"FROM python:3.11-slim\n"
        )
        df2.write_text(
            f"FROM golang:1.27.3-alpine@{DIGEST_OLD} AS builder\n"
        )
        compose.write_text(
            f"services:\n"
            f"  proxy:\n"
            f"    image: ja4proxy:2.0.0\n"
            f"  redis:\n"
            f"    image: redis:7.4.11-alpine@{DIGEST_OLD}  # pinned\n"
        )

        calls: list[tuple[str, str]] = []

        def fake_resolve(image: str, tag: str) -> str:
            calls.append((image, tag))
            if image.startswith("gcr.io/"):
                return DIGEST_GCR
            return DIGEST_NEW

        with patch.object(mod, "resolve_digest", side_effect=fake_resolve):
            rc = mod.update_docker_digests(
                dockerfiles=[df1, df2],
                compose_files=[compose],
                dry_run=False,
            )

        assert rc == 0
        # golang:1.27.3-alpine appeared in 2 files but must only be queried once
        assert calls.count(("golang", "1.27.3-alpine")) == 1
        assert ("gcr.io/distroless/static-debian12", "latest") in calls
        assert ("redis", "7.4.11-alpine") in calls

        assert f"FROM golang:1.27.3-alpine@{DIGEST_NEW} AS builder\n" in df1.read_text()
        assert f"FROM gcr.io/distroless/static-debian12@{DIGEST_GCR}\n" in df1.read_text()
        assert "FROM python:3.11-slim\n" in df1.read_text()
        assert f"FROM golang:1.27.3-alpine@{DIGEST_NEW} AS builder\n" in df2.read_text()
        assert f"    image: redis:7.4.11-alpine@{DIGEST_NEW}  # pinned\n" in compose.read_text()

    def test_dry_run_makes_no_file_modifications(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile.test"
        orig = f"FROM alpine:3.24.3@{DIGEST_OLD}\n"
        df.write_text(orig)

        with patch.object(mod, "resolve_digest", return_value=DIGEST_NEW):
            rc = mod.update_docker_digests(
                dockerfiles=[df],
                compose_files=[],
                dry_run=True,
            )

        assert rc == 0
        assert df.read_text() == orig
