"""Phase 64f — TDD tests for TLS certificate expiry alert rules and runbook.

Validates:
- deploy/monitoring/alertmanager/rules/tls_alerts.yml exists and is valid YAML
- Alert group and rule structure
- Gauge reference, severity labels, annotations
- Runbook file existence
"""

import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
ALERTS_PATH = ROOT / "monitoring" / "alertmanager" / "rules" / "tls_alerts.yml"
RUNBOOK_PATH = ROOT / "docs" / "runbooks" / "tls_certificate_rotation.md"
GAUGE_NAME = "ja4proxy_tls_cert_expiry_timestamp_seconds"


@pytest.fixture(scope="module")
def alerts_data():
    """Load and parse the TLS alerts YAML file."""
    assert ALERTS_PATH.exists(), f"{ALERTS_PATH} does not exist"
    text = ALERTS_PATH.read_text()
    data = yaml.safe_load(text)
    assert data is not None, "YAML file is empty"
    return data


@pytest.fixture(scope="module")
def tls_group(alerts_data):
    """Extract the tls_certificate_expiry group."""
    groups = alerts_data.get("groups", [])
    matches = [g for g in groups if g["name"] == "tls_certificate_expiry"]
    assert len(matches) == 1, "Expected exactly one group named 'tls_certificate_expiry'"
    return matches[0]


@pytest.fixture(scope="module")
def rules_by_name(tls_group):
    """Map alert names to their rule dicts."""
    return {r["alert"]: r for r in tls_group["rules"]}


class TestAlertsFileStructure:
    """Tests for the alert rules file structure."""

    def test_alerts_file_exists(self):
        assert ALERTS_PATH.exists()

    def test_alerts_file_is_valid_yaml(self):
        data = yaml.safe_load(ALERTS_PATH.read_text())
        assert isinstance(data, dict)

    def test_has_groups_key(self, alerts_data):
        assert "groups" in alerts_data

    def test_group_named_tls_certificate_expiry(self, tls_group):
        assert tls_group["name"] == "tls_certificate_expiry"


class TestWarningAlert:
    """Tests for JA4proxyTLSCertExpiringSoon."""

    ALERT_NAME = "JA4proxyTLSCertExpiringSoon"

    def test_alert_exists(self, rules_by_name):
        assert self.ALERT_NAME in rules_by_name

    def test_references_gauge(self, rules_by_name):
        expr = rules_by_name[self.ALERT_NAME]["expr"]
        assert GAUGE_NAME in expr

    def test_threshold_30_days(self, rules_by_name):
        expr = rules_by_name[self.ALERT_NAME]["expr"]
        assert "30" in expr

    def test_severity_warning(self, rules_by_name):
        labels = rules_by_name[self.ALERT_NAME]["labels"]
        assert labels["severity"] == "warning"

    def test_has_summary_annotation(self, rules_by_name):
        annotations = rules_by_name[self.ALERT_NAME]["annotations"]
        assert "summary" in annotations

    def test_has_description_annotation(self, rules_by_name):
        annotations = rules_by_name[self.ALERT_NAME]["annotations"]
        assert "description" in annotations

    def test_description_references_runbook(self, rules_by_name):
        desc = rules_by_name[self.ALERT_NAME]["annotations"]["description"]
        assert "docs/runbooks/tls_certificate_rotation.md" in desc

    def test_no_absent_over_time(self, rules_by_name):
        expr = rules_by_name[self.ALERT_NAME]["expr"]
        assert "absent_over_time" not in expr


class TestCriticalAlert:
    """Tests for JA4proxyTLSCertExpiryCritical."""

    ALERT_NAME = "JA4proxyTLSCertExpiryCritical"

    def test_alert_exists(self, rules_by_name):
        assert self.ALERT_NAME in rules_by_name

    def test_references_gauge(self, rules_by_name):
        expr = rules_by_name[self.ALERT_NAME]["expr"]
        assert GAUGE_NAME in expr

    def test_threshold_7_days(self, rules_by_name):
        expr = rules_by_name[self.ALERT_NAME]["expr"]
        assert "7" in expr

    def test_severity_critical(self, rules_by_name):
        labels = rules_by_name[self.ALERT_NAME]["labels"]
        assert labels["severity"] == "critical"

    def test_has_summary_annotation(self, rules_by_name):
        annotations = rules_by_name[self.ALERT_NAME]["annotations"]
        assert "summary" in annotations

    def test_has_description_annotation(self, rules_by_name):
        annotations = rules_by_name[self.ALERT_NAME]["annotations"]
        assert "description" in annotations

    def test_description_references_runbook(self, rules_by_name):
        desc = rules_by_name[self.ALERT_NAME]["annotations"]["description"]
        assert "docs/runbooks/tls_certificate_rotation.md" in desc

    def test_no_absent_over_time(self, rules_by_name):
        expr = rules_by_name[self.ALERT_NAME]["expr"]
        assert "absent_over_time" not in expr


class TestRunbook:
    """Tests for the TLS certificate rotation runbook."""

    def test_runbook_exists(self):
        assert RUNBOOK_PATH.exists(), f"Runbook not found at {RUNBOOK_PATH}"

    def test_runbook_references_gauge(self):
        text = RUNBOOK_PATH.read_text()
        assert GAUGE_NAME in text

    def test_runbook_references_alert_rules(self):
        text = RUNBOOK_PATH.read_text()
        assert "tls_alerts.yml" in text
