"""Unit tests for scripts/check_upstream_image_updates.py (Phase 827)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from scripts.check_upstream_image_updates import (
    ImageRef,
    check_upstream_updates,
    extract_ignored_images,
    find_newer_tags,
    parse_image_ref,
)


def test_parse_image_ref_valid():
    ref = parse_image_ref("grafana/grafana:13.1.6-ubuntu")
    assert ref is not None
    assert ref.repository == "grafana/grafana"
    assert ref.tag == "13.1.6-ubuntu"
    assert ref.version_tuple == (13, 1, 6)
    assert ref.suffix == "-ubuntu"
    assert ref.prefix == ""

    ref_v = parse_image_ref("prom/prometheus:v2.54.1")
    assert ref_v is not None
    assert ref_v.repository == "prom/prometheus"
    assert ref_v.tag == "v2.54.1"
    assert ref_v.version_tuple == (2, 54, 1)
    assert ref_v.prefix == "v"
    assert ref_v.suffix == ""


def test_parse_image_ref_official_and_gcr():
    ref_official = parse_image_ref("haproxy:2.8.28-alpine")
    assert ref_official is not None
    assert ref_official.repository == "library/haproxy"

    ref_gcr = parse_image_ref("gcr.io/cadvisor/cadvisor:v0.52.1")
    assert ref_gcr is not None
    assert ref_gcr.repository == "cadvisor/cadvisor"


def test_find_newer_tags():
    ref = parse_image_ref("grafana/grafana:13.1.6-ubuntu")
    tags = [
        "13.1.4-ubuntu",
        "13.1.6-ubuntu",
        "13.1.7-ubuntu",
        "13.2.0-ubuntu",
        "13.1.6-alpine",  # mismatched suffix
        "latest",
    ]
    newer = find_newer_tags(ref, tags)
    assert "13.2.0-ubuntu" in newer
    assert "13.1.7-ubuntu" in newer
    assert "13.1.4-ubuntu" not in newer
    assert "13.1.6-alpine" not in newer


def test_find_newer_tags_with_v_prefix():
    ref = parse_image_ref("prom/prometheus:v2.54.1")
    tags = ["v2.54.0", "v2.54.1", "v2.54.2", "v2.55.0", "2.55.0"]
    newer = find_newer_tags(ref, tags)
    assert "v2.55.0" in newer
    assert "v2.54.2" in newer
    assert "v2.54.0" not in newer
    assert "2.55.0" not in newer  # missing 'v' prefix


def test_extract_ignored_images(tmp_path, monkeypatch):
    mock_file = tmp_path / ".trivyignore.third-party"
    mock_file.write_text(
        "# Carriers: grafana/grafana:13.1.6-ubuntu, grafana/loki:3.7.7\n"
        "# Carriers: prom/alertmanager:v0.34.0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("scripts.check_upstream_image_updates.THIRD_PARTY_IGNORE", mock_file)
    extracted = extract_ignored_images()
    assert "grafana/grafana:13.1.6-ubuntu" in extracted
    assert "grafana/loki:3.7.7" in extracted
    assert "prom/alertmanager:v0.34.0" in extracted


@patch("scripts.check_upstream_image_updates.fetch_docker_hub_tags")
def test_check_upstream_updates(mock_fetch, tmp_path, monkeypatch):
    mock_file = tmp_path / ".trivyignore.third-party"
    mock_file.write_text("# Carriers: grafana/grafana:13.1.6-ubuntu\n", encoding="utf-8")
    monkeypatch.setattr("scripts.check_upstream_image_updates.THIRD_PARTY_IGNORE", mock_file)

    # Test when newer tag exists
    mock_fetch.return_value = ["13.1.6-ubuntu", "13.2.0-ubuntu"]
    res = check_upstream_updates(fail_on_update=True)
    assert res == 1

    # Test when up to date
    mock_fetch.return_value = ["13.1.6-ubuntu", "13.1.4-ubuntu"]
    res_ok = check_upstream_updates(fail_on_update=True)
    assert res_ok == 0
