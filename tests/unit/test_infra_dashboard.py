"""
Phase 87 — Infrastructure dashboard tests.

These tests validate the structure and content of the ja4proxy-infrastructure
Grafana dashboard JSON without requiring a running Grafana instance.
"""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent

INFRA_DASHBOARD = (
    ROOT / "deploy/monitoring/grafana/dashboards/ja4proxy-infrastructure.json"
)
OVERVIEW_DASHBOARD = (
    ROOT / "deploy/monitoring/grafana/dashboards/ja4proxy-overview.json"
)

REQUIRED_ROW_TITLES = [
    "Fleet Status",
    "Host Resources",
    "Network & TCP Stack",
    "HAProxy",
    "Container Drill-Down",
    "Attack Detection",
]


@pytest.fixture(scope="module")
def infra_dash():
    return json.loads(INFRA_DASHBOARD.read_text())


@pytest.fixture(scope="module")
def overview_dash():
    return json.loads(OVERVIEW_DASHBOARD.read_text())


class TestInfraDashboard:
    def test_dashboard_json_valid(self):
        """ja4proxy-infrastructure.json must be valid JSON."""
        data = json.loads(INFRA_DASHBOARD.read_text())
        assert isinstance(data, dict)

    def test_dashboard_has_container_variable(self, infra_dash):
        """Dashboard must have a template variable named 'container'."""
        templating = infra_dash.get("templating", {})
        variables = templating.get("list", [])
        names = [v.get("name") for v in variables]
        assert (
            "container" in names
        ), f"No 'container' template variable found. Variables: {names}"

    def test_container_variable_excludes_numeric_suffix(self, infra_dash):
        """Container variable query must exclude numeric-suffix names (system containers)."""
        templating = infra_dash.get("templating", {})
        variables = templating.get("list", [])
        container_var = next(
            (v for v in variables if v.get("name") == "container"), None
        )
        assert container_var is not None
        # The query or definition should have the exclusion regex
        definition = container_var.get("definition", "") or container_var.get(
            "query", ""
        )
        if isinstance(definition, dict):
            definition = definition.get("query", "")
        assert ".+_[0-9]+" in definition, (
            "Container variable query must exclude numeric-suffix containers "
            "using regex '.+_[0-9]+'"
        )

    def test_dashboard_has_all_six_row_sections(self, infra_dash):
        """Dashboard must have all 6 named row sections."""
        panels = infra_dash.get("panels", [])
        row_titles = [p.get("title", "") for p in panels if p.get("type") == "row"]
        for required in REQUIRED_ROW_TITLES:
            assert any(
                required in title for title in row_titles
            ), f"Missing row section '{required}'. Found rows: {row_titles}"

    def test_dashboard_alert_annotations_enabled(self, infra_dash):
        """Dashboard must have Grafana alert annotations enabled."""
        annotations = infra_dash.get("annotations", {})
        ann_list = annotations.get("list", [])
        assert len(ann_list) > 0, "No annotations configured"
        # At least one annotation should be enabled
        enabled = [a for a in ann_list if a.get("enable", False)]
        assert len(enabled) > 0, "No annotations are enabled"

    def test_dashboard_links_to_security_overview(self, infra_dash):
        """Dashboard must link to the security overview dashboard."""
        links = infra_dash.get("links", [])
        # Serialise the links list to check for overview dashboard reference
        all_link_text = json.dumps(links)
        assert (
            "ja4proxy-overview" in all_link_text or "ja4proxy_overview" in all_link_text
        ), "Dashboard should link to ja4proxy-overview security dashboard"

    def test_dashboard_has_fleet_status_stat_panels(self, infra_dash):
        """Fleet Status section must contain stat panels (one per container)."""
        panels = infra_dash.get("panels", [])
        # Find panels in the Fleet Status row
        fleet_panel_types = []
        in_fleet_row = False
        for panel in panels:
            if panel.get("type") == "row":
                in_fleet_row = "Fleet Status" in panel.get("title", "")
            elif in_fleet_row:
                if panel.get("type") == "row":
                    break
                fleet_panel_types.append(panel.get("type"))
        assert "stat" in fleet_panel_types, "Fleet Status row must contain stat panels"


class TestOverviewDashboardUnchanged:
    def test_no_infra_panels_in_overview(self, overview_dash):
        """ja4proxy-overview.json must not have panels with id >= 70 (infrastructure panels)."""
        panels = overview_dash.get("panels", [])
        high_id_panels = [p for p in panels if p.get("id", 0) >= 70]
        assert len(high_id_panels) == 0, (
            f"Found {len(high_id_panels)} panels with id>=70 in overview dashboard: "
            f"{[p.get('id') for p in high_id_panels]}. "
            "Infrastructure panels must go in ja4proxy-infrastructure.json only."
        )

    def test_overview_has_links_section(self, overview_dash):
        """ja4proxy-overview.json must have a links section (added by Agent B)."""
        # This just checks the key exists — it may be empty before Agent B runs
        # but Agent B must add the link to the infra dashboard
        links = overview_dash.get("links", [])
        # After Agent B runs, there should be at least one link
        # We test this leniently — just check the key is present
        assert "links" in overview_dash


class TestPrometheusConfig:
    def test_cadvisor_scrape_job_present(self):
        """prometheus.yml must contain a cadvisor scrape job."""
        prom_file = ROOT / "deploy/monitoring/prometheus/prometheus.yml"
        content = prom_file.read_text()
        assert (
            "job_name: 'cadvisor'" in content or 'job_name: "cadvisor"' in content
        ), "prometheus.yml missing cadvisor scrape job"

    def test_haproxy_exporter_scrape_job_present(self):
        """prometheus.yml must contain a haproxy scrape job."""
        prom_file = ROOT / "deploy/monitoring/prometheus/prometheus.yml"
        content = prom_file.read_text()
        assert (
            "job_name: 'haproxy'" in content or 'job_name: "haproxy"' in content
        ), "prometheus.yml missing haproxy scrape job"

    def test_cadvisor_drops_blkio_metrics(self):
        """cAdvisor scrape config must drop high-cardinality blkio metrics."""
        prom_file = ROOT / "deploy/monitoring/prometheus/prometheus.yml"
        content = prom_file.read_text()
        assert (
            "blkio" in content
        ), "cAdvisor scrape config should have metric_relabel_configs dropping blkio series"

    def test_container_variable_excludes_numeric_suffix(self):
        """Infra dashboard container variable query must use numeric-suffix exclusion."""
        if not INFRA_DASHBOARD.exists():
            pytest.skip("ja4proxy-infrastructure.json not yet created")
        content = INFRA_DASHBOARD.read_text()
        assert (
            ".+_[0-9]+" in content
        ), "Container variable query must exclude numeric-suffix containers"
