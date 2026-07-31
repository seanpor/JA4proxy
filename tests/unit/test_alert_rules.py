"""Unit tests for Phase 14e: alert rule YAML structure validation.

Since `promtool` is not guaranteed to be available in the test environment,
these tests parse the YAML files and assert the required structural properties
that promtool would enforce:
  - Top-level `groups` key is a list
  - Each group has `name` (str) and `rules` (list)
  - Each rule has `alert` (str), `expr` (str), `labels` (dict), `annotations` (dict)
  - No rule expression references old pre-Phase-1 `ja4_*` metric names (bare, no prefix)
  - All four required alert rule files are present and non-empty

Files validated:
  - deploy/monitoring/prometheus/alerts.yml
  - every deploy/monitoring/alertmanager/rules/*.yml file

(deploy/monitoring/prometheus/recording_rules.yml and slo_recording_rules.yml
are deliberately excluded: they hold `record:`/`expr:` recording rules, not
`alert:`/`labels:`/`annotations:` alerting rules, so this file's alert-shape
assertions don't apply. Both are still promtool-syntax-validated by
`make lint-prom`.)

Phase 805: this list used to cover only 5 of the (then) 10 files under
deploy/monitoring/alertmanager/rules/ — the other 5 (tap.yml, ebpf_attack.yml,
management_ui_rules.yml, slo_alerts.yml, ti_feed.yml, tls_alerts.yml) had
never been structurally validated here. Registering all of them together
with this phase's new performance.rules.yml, same as the matching fix to
Makefile's lint-prom/PROM_RULES and (more seriously) the discovery that
Prometheus itself never actually loaded any of them at all — see
docs/phases/complete/PHASE_805.md's design-correction notes and
deploy/docker/docker-compose.monitoring.yml's Phase-805 comment.
"""

import re
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent.parent

RULE_FILES = [
    REPO_ROOT / "deploy/monitoring/prometheus/alerts.yml",
] + sorted((REPO_ROOT / "deploy/monitoring/alertmanager/rules").glob("*.yml"))

# Regex: a bare ja4_ metric (old prefix) — must not appear in any expr field.
# We allow ja4proxy_ (the correct prefix) and ja4: (recording rule names).
_BARE_JA4_METRIC = re.compile(
    r"\bja4_(?!proxy_|requests_total|request_duration|blocked|security_events|errors)"
)


def _load_rules(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _all_rules(data: dict):
    """Yield every alert rule dict from a parsed rule file."""
    for group in data.get("groups", []):
        for rule in group.get("rules", []):
            yield rule


# ---------------------------------------------------------------------------
# Parametrised file-level checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", RULE_FILES, ids=[p.name for p in RULE_FILES])
class TestRuleFileStructure:
    def test_file_exists(self, path):
        assert path.exists(), f"Alert rule file missing: {path}"

    def test_file_is_valid_yaml(self, path):
        data = _load_rules(path)
        assert data is not None

    def test_top_level_groups_is_list(self, path):
        data = _load_rules(path)
        assert isinstance(data.get("groups"), list), "Top-level 'groups' must be a list"
        assert len(data["groups"]) > 0, "Must contain at least one group"

    def test_each_group_has_name_and_rules(self, path):
        data = _load_rules(path)
        for group in data["groups"]:
            assert "name" in group, f"Group missing 'name': {group}"
            assert isinstance(group["name"], str)
            assert "rules" in group, f"Group missing 'rules': {group}"
            assert isinstance(group["rules"], list)

    def test_each_rule_has_required_fields(self, path):
        data = _load_rules(path)
        for rule in _all_rules(data):
            assert "alert" in rule, f"Rule missing 'alert': {rule}"
            assert isinstance(rule["alert"], str)
            assert "expr" in rule, f"Rule '{rule.get('alert')}' missing 'expr'"
            assert isinstance(rule["expr"], str) and rule["expr"].strip()
            assert "labels" in rule, f"Rule '{rule.get('alert')}' missing 'labels'"
            assert isinstance(rule["labels"], dict)
            assert (
                "annotations" in rule
            ), f"Rule '{rule.get('alert')}' missing 'annotations'"
            assert isinstance(rule["annotations"], dict)

    def test_severity_label_present(self, path):
        data = _load_rules(path)
        for rule in _all_rules(data):
            assert (
                "severity" in rule["labels"]
            ), f"Rule '{rule.get('alert')}' missing 'severity' label"
            assert rule["labels"]["severity"] in (
                "critical",
                "warning",
                "info",
            ), f"Rule '{rule.get('alert')}' has unknown severity: {rule['labels']['severity']}"

    def test_no_bare_ja4_metric_names_in_exprs(self, path):
        """Expressions must not reference old pre-Phase-1 ja4_ metric names."""
        data = _load_rules(path)
        for rule in _all_rules(data):
            expr = rule.get("expr", "")
            # Allow ja4proxy_* and ja4:* (recording rule names); flag bare ja4_*
            # Strip ja4proxy_ occurrences first so the regex doesn't false-positive
            expr_stripped = expr.replace("ja4proxy_", "").replace("ja4:", "")
            bad = _BARE_JA4_METRIC.search(expr_stripped)
            assert (
                not bad
            ), f"Rule '{rule.get('alert')}' references old ja4_ metric name in expr: {expr!r}"


# ---------------------------------------------------------------------------
# Content checks for specific files
# ---------------------------------------------------------------------------


class TestPrometheusAlertsContent:
    """Key alerts that must be present in deploy/monitoring/prometheus/alerts.yml."""

    def _alerts(self):
        path = REPO_ROOT / "deploy/monitoring/prometheus/alerts.yml"
        data = _load_rules(path)
        return {r["alert"] for r in _all_rules(data)}

    def test_proxy_instance_down_alert_present(self):
        assert "ProxyInstanceDown" in self._alerts()

    def test_redis_down_alert_present(self):
        assert "RedisDown" in self._alerts()

    def test_abuseipdb_quota_alert_present(self):
        assert "AbuseIPDBQuotaExhausted" in self._alerts()

    def test_spamhaus_stale_alert_present(self):
        assert "SpamhausListStale" in self._alerts()

    def test_tarpit_concurrent_alert_present(self):
        assert "ProxyTarpitConcurrentHigh" in self._alerts()

    def test_score_drift_alert_present(self):
        assert "ScoreDriftDetected" in self._alerts()

    def test_analytics_lag_alert_present(self):
        assert "AnalyticsStreamLagHigh" in self._alerts()


class TestAlertmanagerRuleFiles:
    """Each alertmanager rule file must contain at least its key alerts."""

    def _alerts_in(self, filename: str) -> set:
        path = REPO_ROOT / "deploy/monitoring/alertmanager/rules" / filename
        data = _load_rules(path)
        return {r["alert"] for r in _all_rules(data)}

    def test_proxy_rules_has_proxy_instance_down(self):
        assert "ProxyInstanceDown" in self._alerts_in("proxy.rules.yml")

    def test_proxy_rules_has_high_block_rate(self):
        assert "ProxyHighBlockRate" in self._alerts_in("proxy.rules.yml")

    def test_proxy_rules_has_tarpit_high(self):
        assert "ProxyTarpitConcurrentHigh" in self._alerts_in("proxy.rules.yml")

    def test_redis_rules_has_redis_down(self):
        assert "RedisDown" in self._alerts_in("redis.rules.yml")

    def test_redis_rules_has_memory_high(self):
        assert "RedisMemoryHigh" in self._alerts_in("redis.rules.yml")

    def test_security_rules_has_abuseipdb(self):
        assert "AbuseIPDBQuotaExhausted" in self._alerts_in("security.rules.yml")

    def test_security_rules_has_spamhaus_download(self):
        assert "SpamhausDownloadFailed" in self._alerts_in("security.rules.yml")

    def test_security_rules_has_spamhaus_stale(self):
        assert "SpamhausListStale" in self._alerts_in("security.rules.yml")

    def test_backup_rules_has_backup_failure(self):
        assert "BackupFailureDetected" in self._alerts_in("backup.rules.yml")

    def test_backup_rules_has_backup_stale(self):
        assert "BackupStale" in self._alerts_in("backup.rules.yml")

    def test_backup_rules_has_restore_failure(self):
        assert "RestoreFailureDetected" in self._alerts_in("backup.rules.yml")

    def test_backup_rules_has_backup_duration_high(self):
        assert "BackupDurationHigh" in self._alerts_in("backup.rules.yml")

    def test_backup_rules_has_restore_duration_high(self):
        assert "RestoreDurationHigh" in self._alerts_in("backup.rules.yml")
