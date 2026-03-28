"""
tests/unit/test_check_image_versions.py

Unit tests for scripts/check_image_versions.py.
Tests: latest-tag detection, version-drift detection, clean-compose baseline.
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
import yaml

# Add scripts/ to path so we can import the module directly
scripts_dir = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

from check_image_versions import ImageRef, check, _extract_images, FIRST_PARTY_IMAGES  # noqa: E402


def _write_compose(tmp_path: Path, filename: str, content: str) -> Path:
    """Write a minimal compose file and return its path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content))
    return p


class TestExtractImages:
    def test_extracts_versioned_image(self, tmp_path):
        p = _write_compose(tmp_path, "dc.yml", """
            services:
              svc:
                image: prom/prometheus:v2.48.0
        """)
        refs = _extract_images(p)
        assert len(refs) == 1
        assert refs[0].name == "prom/prometheus"
        assert refs[0].version == "v2.48.0"

    def test_extracts_latest_image(self, tmp_path):
        p = _write_compose(tmp_path, "dc.yml", """
            services:
              svc:
                image: redis/redis-stack:latest
        """)
        refs = _extract_images(p)
        assert refs[0].version == "latest"

    def test_image_without_tag_treated_as_latest(self, tmp_path):
        p = _write_compose(tmp_path, "dc.yml", """
            services:
              svc:
                image: myimage
        """)
        refs = _extract_images(p)
        assert refs[0].version == "latest"

    def test_service_without_image_skipped(self, tmp_path):
        p = _write_compose(tmp_path, "dc.yml", """
            services:
              svc:
                build: .
        """)
        refs = _extract_images(p)
        assert refs == []

    def test_multiple_services_extracted(self, tmp_path):
        p = _write_compose(tmp_path, "dc.yml", """
            services:
              a:
                image: grafana/grafana:10.2.0
              b:
                image: prom/prometheus:v2.48.0
        """)
        refs = _extract_images(p)
        assert len(refs) == 2


class TestLatestTagDetection:
    def test_latest_tag_produces_error(self, tmp_path):
        p = _write_compose(tmp_path, "prod.yml", """
            services:
              redis:
                image: redis/redis-stack:latest
        """)
        errors, warnings = check([p])
        assert any("redis/redis-stack:latest" in e for e in errors)
        assert any(":latest tag" in e for e in errors)

    def test_pinned_tag_produces_no_error(self, tmp_path):
        p = _write_compose(tmp_path, "prod.yml", """
            services:
              redis:
                image: redis/redis-stack:7.4.0-v3
        """)
        errors, _ = check([p])
        assert errors == []

    def test_multiple_latest_tags_all_reported(self, tmp_path):
        p = _write_compose(tmp_path, "prod.yml", """
            services:
              a:
                image: foo:latest
              b:
                image: bar:latest
              c:
                image: pinned:1.0.0
        """)
        errors, _ = check([p])
        assert len(errors) == 2

    def test_image_without_tag_treated_as_latest_error(self, tmp_path):
        p = _write_compose(tmp_path, "prod.yml", """
            services:
              svc:
                image: myimage
        """)
        errors, _ = check([p])
        assert any(":latest" in e for e in errors)


class TestVersionDriftDetection:
    def test_same_image_different_versions_produces_warning(self, tmp_path):
        prod = _write_compose(tmp_path, "prod.yml", """
            services:
              grafana:
                image: grafana/grafana:10.2.0
        """)
        monitoring = _write_compose(tmp_path, "monitoring.yml", """
            services:
              grafana:
                image: grafana/grafana:10.2.2
        """)
        _, warnings = check([prod, monitoring])
        assert any("grafana/grafana" in w and "drift" in w for w in warnings)
        assert any("10.2.0" in w for w in warnings)
        assert any("10.2.2" in w for w in warnings)

    def test_same_image_same_version_no_warning(self, tmp_path):
        prod = _write_compose(tmp_path, "prod.yml", """
            services:
              grafana:
                image: grafana/grafana:10.2.0
        """)
        monitoring = _write_compose(tmp_path, "monitoring.yml", """
            services:
              grafana:
                image: grafana/grafana:10.2.0
        """)
        errors, warnings = check([prod, monitoring])
        assert errors == []
        assert not any("grafana/grafana" in w for w in warnings)

    def test_image_only_in_one_file_no_warning(self, tmp_path):
        prod = _write_compose(tmp_path, "prod.yml", """
            services:
              redis:
                image: redis/redis-stack:7.4.0-v3
        """)
        monitoring = _write_compose(tmp_path, "monitoring.yml", """
            services:
              prometheus:
                image: prom/prometheus:v2.48.0
        """)
        errors, warnings = check([prod, monitoring])
        assert errors == []
        assert warnings == []


class TestFirstPartyExemption:
    def test_first_party_latest_not_an_error(self, tmp_path):
        """Locally-built images use :latest by convention — should not be flagged."""
        p = _write_compose(tmp_path, "prod.yml", """
            services:
              proxy:
                image: ja4proxy:latest
              analytics:
                image: ja4proxy-analytics:latest
              tarpit:
                image: ja4proxy-tarpit:latest
        """)
        errors, _ = check([p])
        assert errors == []

    def test_unknown_third_party_latest_still_flagged(self, tmp_path):
        p = _write_compose(tmp_path, "prod.yml", """
            services:
              redis:
                image: redis:latest
              proxy:
                image: ja4proxy:latest
        """)
        errors, _ = check([p])
        assert len(errors) == 1
        assert "redis:latest" in errors[0]

    def test_custom_first_party_set(self, tmp_path):
        """Custom first_party set is respected."""
        p = _write_compose(tmp_path, "prod.yml", """
            services:
              svc:
                image: myapp:latest
        """)
        errors_without_exemption, _ = check([p], first_party=frozenset())
        assert len(errors_without_exemption) == 1

        errors_with_exemption, _ = check([p], first_party=frozenset({"myapp"}))
        assert errors_with_exemption == []


class TestCleanBaseline:
    def test_clean_compose_files_pass(self, tmp_path):
        """Simulate harmonised compose files — should produce no errors or warnings."""
        prod = _write_compose(tmp_path, "prod.yml", """
            services:
              haproxy:
                image: haproxy:2.8-alpine
              redis:
                image: redis/redis-stack:7.4.0-v3
              grafana:
                image: grafana/grafana:10.2.0
              loki:
                image: grafana/loki:2.9.0
              promtail:
                image: grafana/promtail:2.9.0
              prometheus:
                image: prom/prometheus:v2.48.0
        """)
        monitoring = _write_compose(tmp_path, "monitoring.yml", """
            services:
              prometheus:
                image: prom/prometheus:v2.48.0
              grafana:
                image: grafana/grafana:10.2.0
              loki:
                image: grafana/loki:2.9.0
              promtail:
                image: grafana/promtail:2.9.0
              node_exporter:
                image: prom/node-exporter:v1.7.0
        """)
        errors, warnings = check([prod, monitoring])
        assert errors == []
        assert warnings == []

    def test_missing_compose_file_produces_warning_not_error(self, tmp_path):
        prod = _write_compose(tmp_path, "prod.yml", """
            services:
              svc:
                image: foo:1.0
        """)
        missing = tmp_path / "missing.yml"
        errors, warnings = check([prod, missing])
        assert errors == []
        assert any("not found" in w for w in warnings)

    def test_empty_services_produces_no_output(self, tmp_path):
        p = _write_compose(tmp_path, "dc.yml", """
            services: {}
        """)
        errors, warnings = check([p])
        assert errors == []
        assert warnings == []
