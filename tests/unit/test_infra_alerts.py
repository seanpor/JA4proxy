"""
Phase 87 — Infrastructure alert rules tests.

These tests validate the structure and content of Prometheus alert rule files
without requiring a running Prometheus instance.
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent.parent

ALERTS_FILE = ROOT / "deploy/monitoring/prometheus/alerts.yml"
RECORDING_FILE = ROOT / "deploy/monitoring/prometheus/recording_rules.yml"

NEW_GROUPS = [
    "ja4proxy_infrastructure",
    "ja4proxy_container",
    "ja4proxy_haproxy",
    "ja4proxy_capacity",
    "ja4proxy_attack_detection",
]

EXISTING_GROUPS = [
    "ja4proxy_proxy",
    "ja4proxy_redis",
    "ja4proxy_security",
    "ja4proxy_analytics",
]


@pytest.fixture(scope="module")
def alerts_data():
    return yaml.safe_load(ALERTS_FILE.read_text())


@pytest.fixture(scope="module")
def recording_data():
    return yaml.safe_load(RECORDING_FILE.read_text())


def _get_group(data, name):
    for group in data["groups"]:
        if group["name"] == name:
            return group
    return None


def _get_all_rules(data, group_names):
    rules = []
    for group in data["groups"]:
        if group["name"] in group_names:
            rules.extend(group.get("rules", []))
    return rules


class TestAlertsYAML:
    def test_alerts_yaml_valid(self):
        """alerts.yml must parse as valid YAML."""
        data = yaml.safe_load(ALERTS_FILE.read_text())
        assert isinstance(data, dict)
        assert "groups" in data

    def test_new_groups_present(self, alerts_data):
        """All 5 new alert groups must be present."""
        group_names = {g["name"] for g in alerts_data["groups"]}
        for name in NEW_GROUPS:
            assert name in group_names, f"Missing group: {name}"

    def test_all_new_alerts_have_runbook_url(self, alerts_data):
        """Every rule in new groups must have a runbook_url annotation."""
        rules = _get_all_rules(alerts_data, NEW_GROUPS)
        for rule in rules:
            if "alert" in rule:  # skip recording rules if any
                annotations = rule.get("annotations", {})
                assert (
                    "runbook_url" in annotations
                ), f"Alert {rule['alert']} missing runbook_url"

    def test_all_new_alerts_have_alert_type(self, alerts_data):
        """Every rule in new groups must have an alert_type label."""
        rules = _get_all_rules(alerts_data, NEW_GROUPS)
        for rule in rules:
            if "alert" in rule:
                labels = rule.get("labels", {})
                assert (
                    "alert_type" in labels
                ), f"Alert {rule['alert']} missing alert_type label"

    def test_existing_groups_present(self, alerts_data):
        """Pre-existing alert groups must still be present."""
        group_names = {g["name"] for g in alerts_data["groups"]}
        for name in EXISTING_GROUPS:
            assert name in group_names, f"Pre-existing group missing: {name}"

    def test_connection_rate_spike_uses_clamp_min(self, alerts_data):
        """ConnectionRateSpike must use clamp_min to prevent startup false positives."""
        group = _get_group(alerts_data, "ja4proxy_attack_detection")
        assert group is not None
        rule = next(
            (r for r in group["rules"] if r.get("alert") == "ConnectionRateSpike"),
            None,
        )
        assert rule is not None, "ConnectionRateSpike alert not found"
        assert (
            "clamp_min" in rule["expr"]
        ), "ConnectionRateSpike expr must use clamp_min to prevent division by zero at startup"

    def test_syn_flood_expr_uses_recording_rule(self, alerts_data):
        """SYNFloodIndicator must reference the ja4proxy:network_avg_pkt_size_bytes recording rule."""
        group = _get_group(alerts_data, "ja4proxy_attack_detection")
        assert group is not None
        rule = next(
            (r for r in group["rules"] if r.get("alert") == "SYNFloodIndicator"),
            None,
        )
        assert rule is not None, "SYNFloodIndicator alert not found"
        assert (
            "ja4proxy:network_avg_pkt_size_bytes" in rule["expr"]
        ), "SYNFloodIndicator must reference ja4proxy:network_avg_pkt_size_bytes recording rule"

    def test_oom_alert_fires_immediately(self, alerts_data):
        """ContainerOOMKilled must have for: 0m — OOM kills should alert immediately."""
        group = _get_group(alerts_data, "ja4proxy_container")
        assert group is not None
        rule = next(
            (r for r in group["rules"] if r.get("alert") == "ContainerOOMKilled"),
            None,
        )
        assert rule is not None, "ContainerOOMKilled alert not found"
        assert (
            rule.get("for") == "0m"
        ), f"ContainerOOMKilled should have 'for: 0m', got {rule.get('for')!r}"

    def test_haproxy_queue_thresholds_are_distinct(self, alerts_data):
        """HAProxyBackendQueueing (>0) and HAProxyQueueSignalsCapacityAttack (>5) must be distinct."""
        haproxy_group = _get_group(alerts_data, "ja4proxy_haproxy")
        attack_group = _get_group(alerts_data, "ja4proxy_attack_detection")
        assert haproxy_group is not None
        assert attack_group is not None

        # HAProxyBackendQueueing should use threshold 0 (early warning)
        queueing = next(
            (
                r
                for r in haproxy_group["rules"]
                if r.get("alert") == "HAProxyBackendQueueing"
            ),
            None,
        )
        assert queueing is not None
        assert "> 0" in queueing["expr"]

        # HAProxyQueueSignalsCapacityAttack should use threshold 5 (attack signal)
        attack = next(
            (
                r
                for r in attack_group["rules"]
                if r.get("alert") == "HAProxyQueueSignalsCapacityAttack"
            ),
            None,
        )
        assert attack is not None
        assert "> 5" in attack["expr"]

    def test_container_restart_loop_fires_immediately(self, alerts_data):
        """ContainerRestartLoop must have for: 0m."""
        group = _get_group(alerts_data, "ja4proxy_container")
        assert group is not None
        rule = next(
            (r for r in group["rules"] if r.get("alert") == "ContainerRestartLoop"),
            None,
        )
        assert rule is not None
        assert rule.get("for") == "0m"


class TestRecordingRules:
    def test_recording_rules_yaml_valid(self):
        """recording_rules.yml must parse as valid YAML."""
        data = yaml.safe_load(RECORDING_FILE.read_text())
        assert isinstance(data, dict)
        assert "groups" in data

    def test_new_recording_rule_group_present(self, recording_data):
        """ja4proxy_infra_aggregations group must be present."""
        group_names = {g["name"] for g in recording_data["groups"]}
        assert "ja4proxy_infra_aggregations" in group_names

    def test_stale_metrics_fixed(self):
        """recording_rules.yml must not reference stale metric names."""
        content = RECORDING_FILE.read_text()
        assert "ja4_requests_total" not in content, (
            "Stale metric 'ja4_requests_total' still in recording_rules.yml — "
            "should be 'ja4proxy_connections_total'"
        )
        assert (
            "ja4_blocked_requests_total" not in content
        ), "Stale metric 'ja4_blocked_requests_total' still in recording_rules.yml"

    def test_infra_recording_rules_have_clamp_min(self, recording_data):
        """Division expressions in infra recording rules must use clamp_min."""
        group = _get_group(recording_data, "ja4proxy_infra_aggregations")
        assert group is not None
        for rule in group["rules"]:
            expr = rule.get("expr", "")
            # Rules that divide by container_spec_memory_limit_bytes or rate() must guard
            if "container_spec_memory_limit_bytes" in expr or (
                "/" in expr and "rate(" in expr
            ):
                assert (
                    "clamp_min" in expr
                ), f"Recording rule {rule['record']!r} divides without clamp_min guard"

    def test_six_infra_recording_rules(self, recording_data):
        """ja4proxy_infra_aggregations must have exactly 6 recording rules."""
        group = _get_group(recording_data, "ja4proxy_infra_aggregations")
        assert group is not None
        rules = [r for r in group["rules"] if "record" in r]
        assert len(rules) == 6, f"Expected 6 infra recording rules, got {len(rules)}"
