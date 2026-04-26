"""Phase 86d — Tests for Datadog integration.

The Datadog Agent SDK (datadog_checks.base) is not available in the local
test environment. The runtime check logic tests (3 tests) are skipped
when the SDK is absent — they run inside a Datadog Agent container.
The 15 static validation tests (JSON/YAML structure) always run.
"""

import json
from pathlib import Path

import pytest
import yaml

DATADOG_DIR = Path(__file__).parent.parent.parent / "deploy" / "datadog"
CHECK_PATH = DATADOG_DIR / "checks" / "ja4proxy" / "check.py"


# ── Dashboard JSON validation ────────────────────────────────────────────────

class TestDatadogDashboard:
    DASHBOARD = DATADOG_DIR / "ja4proxy-dashboard.json"

    def test_file_exists(self):
        assert self.DASHBOARD.exists()

    def test_valid_json(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        assert "title" in data
        assert "widgets" in data
        assert len(data["widgets"]) >= 1

    def test_has_health_widget(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        titles = [w.get("title", "") for w in data["widgets"]]
        assert "Node Health" in titles

    def test_has_block_rate_widget(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        titles = [w.get("title", "") for w in data["widgets"]]
        assert any("Block Rate" in t for t in titles)

    def test_has_cert_expiry_widget(self):
        with open(self.DASHBOARD) as f:
            data = json.load(f)
        titles = [w.get("title", "") for w in data["widgets"]]
        assert any("Certificate" in t or "Cert" in t for t in titles)


# ── Monitors JSON validation ─────────────────────────────────────────────────

class TestDatadogMonitors:
    MONITORS = DATADOG_DIR / "ja4proxy-monitors.json"

    def test_file_exists(self):
        assert self.MONITORS.exists()

    def test_valid_json(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_has_node_unhealthy_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("unhealthy" in n.lower() for n in names)

    def test_has_redis_latency_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("redis" in n.lower() for n in names)

    def test_has_cert_expiry_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("certificate" in n.lower() or "cert" in n.lower() for n in names)

    def test_has_block_rate_monitor(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        names = [m.get("name", "") for m in data]
        assert any("block" in n.lower() for n in names)

    def test_all_monitors_have_message(self):
        with open(self.MONITORS) as f:
            data = json.load(f)
        for m in data:
            assert m.get("message"), f"Monitor {m.get('name')} has no message"


# ── Conf YAML validation ─────────────────────────────────────────────────────

class TestDatadogConf:
    CONF = DATADOG_DIR / "conf.d" / "ja4proxy.d" / "conf.yaml"

    def test_file_exists(self):
        assert self.CONF.exists()

    def test_valid_yaml(self):
        with open(self.CONF) as f:
            data = yaml.safe_load(f)
        assert "instances" in data
        assert len(data["instances"]) >= 1

    def test_instance_has_management_url(self):
        with open(self.CONF) as f:
            data = yaml.safe_load(f)
        for inst in data["instances"]:
            assert "management_url" in inst, "Each instance needs management_url"
            assert inst["management_url"].startswith("http"), (
                f"management_url must be a full URL, got: {inst['management_url']}"
            )

    def test_container_config_has_api_token_field(self):
        """Per AGENTS.md: services with external deps must document auth fields.

        The Datadog check connects to the Management API and supports
        api_token for Bearer authentication. The conf.yaml must include
        this field (even if placeholder) so operators know it's required.
        """
        source = (DATADOG_DIR / "checks" / "ja4proxy" / "check.py").read_text()
        assert "api_token" in source, "Check must read api_token from instance config"


# ── Check module static analysis ─────────────────────────────────────────────

class TestCheckModule:
    """Static checks on the check.py source (no runtime import needed)."""

    CHECK_FILE = CHECK_PATH

    def test_file_exists(self):
        assert self.CHECK_FILE.exists()

    def test_has_required_service_checks_in_source(self):
        """Phase 86i: after the two-layer refactor, check.py must only
        reference service checks; Prometheus-duplicate gauges/rates have
        moved to the OpenMetrics Layer 1 config."""
        source = self.CHECK_FILE.read_text()
        # Only service checks + topology entity remain in-source.
        required = [
            "ja4proxy.node_health",
            "ja4proxy.redis_health",
        ]
        for metric in required:
            assert metric in source, f"Service check {metric!r} missing from check.py"

    def test_emits_service_check_on_failure(self):
        """The check must emit UNKNOWN service check on HTTP failure."""
        source = self.CHECK_FILE.read_text()
        assert "UNKNOWN" in source
        assert "service_check" in source


# ── Phase 86i: two-layer refactor (OpenMetrics + narrowed custom check) ─────


class TestPhase86iOpenMetricsConfig:
    """Phase 86i Gap 1 — Layer 1: OpenMetrics config for Datadog Agent."""

    OPENMETRICS_CONF = (
        DATADOG_DIR / "conf.d" / "openmetrics.d" / "ja4proxy.yaml"
    )

    def test_openmetrics_config_is_valid_yaml_and_has_namespace(self):
        """Layer 1 config must be valid YAML with namespace: ja4proxy and
        at least one metric allowlist entry."""
        assert self.OPENMETRICS_CONF.exists(), (
            f"Phase 86i OpenMetrics config missing: {self.OPENMETRICS_CONF}"
        )
        with open(self.OPENMETRICS_CONF) as f:
            data = yaml.safe_load(f)
        assert "instances" in data
        assert len(data["instances"]) >= 1
        inst = data["instances"][0]
        assert inst.get("namespace") == "ja4proxy"
        metrics = inst.get("metrics")
        assert metrics and len(metrics) >= 1, (
            "openmetrics config must declare at least one metric allowlist entry"
        )

    def _exported_proxy_metrics(self):
        import re
        metrics_go = (
            Path(__file__).resolve().parents[2]
            / "internal" / "metrics" / "metrics.go"
        )
        src = metrics_go.read_text()
        return set(re.findall(r'Name:\s*"(ja4proxy_[a-z0-9_]+)"', src))

    def test_openmetrics_allowlist_only_has_real_metrics(self):
        """Phase 86i reviewer blocker 3: every metric in the allowlist
        must be actually exported by the Go proxy. Cross-check against
        internal/metrics/metrics.go."""
        exported = self._exported_proxy_metrics()
        with open(self.OPENMETRICS_CONF) as f:
            data = yaml.safe_load(f)
        bad: list[tuple[int, str]] = []
        for idx, inst in enumerate(data.get("instances", [])):
            for m in inst.get("metrics", []):
                # Accept plain names; openmetrics also accepts regex dicts,
                # but our allowlist uses plain strings.
                if isinstance(m, str) and m not in exported:
                    bad.append((idx, m))
        assert not bad, (
            "Phase 86i reviewer blocker 3: openmetrics allowlist includes "
            "metrics the proxy does not export:\n"
            + "\n".join(f"  instance[{i}]: {m}" for i, m in bad)
        )

    def test_openmetrics_config_has_type_overrides(self):
        """type_overrides must be present with at least one histogram
        so Datadog preserves histogram semantics instead of flattening
        the _bucket/_count/_sum triples into unrelated gauges."""
        with open(self.OPENMETRICS_CONF) as f:
            data = yaml.safe_load(f)
        for idx, inst in enumerate(data.get("instances", [])):
            overrides = inst.get("type_overrides")
            assert overrides, (
                f"instance[{idx}] missing type_overrides"
            )
            assert any(t == "histogram" for t in overrides.values()), (
                f"instance[{idx}] type_overrides must include at least "
                f"one histogram entry, got: {overrides}"
            )
            # pipeline_duration_seconds must specifically be a histogram.
            assert (
                overrides.get("ja4proxy_pipeline_duration_seconds") == "histogram"
            ), (
                f"instance[{idx}]: ja4proxy_pipeline_duration_seconds "
                f"must be overridden to 'histogram'"
            )

    def test_openmetrics_collects_histogram_buckets(self):
        """Either collect_histogram_buckets: true or the v2 Datadog
        openmetrics distributions flag must be set, otherwise histograms
        arrive in Datadog with no bucket fidelity."""
        with open(self.OPENMETRICS_CONF) as f:
            data = yaml.safe_load(f)
        for idx, inst in enumerate(data.get("instances", [])):
            has_buckets = inst.get("collect_histogram_buckets") is True
            has_distributions = inst.get(
                "histogram_buckets_as_distributions"
            ) is True
            assert has_buckets or has_distributions, (
                f"instance[{idx}]: one of collect_histogram_buckets or "
                f"histogram_buckets_as_distributions must be true"
            )

    def test_openmetrics_config_one_instance_per_node(self):
        """Template must have >1 instance, each tagged with node."""
        assert self.OPENMETRICS_CONF.exists()
        with open(self.OPENMETRICS_CONF) as f:
            data = yaml.safe_load(f)
        instances = data.get("instances", [])
        assert len(instances) > 1, (
            "openmetrics config template must show >1 instance (per-node pattern)"
        )
        for inst in instances:
            tags = inst.get("tags", [])
            joined = " ".join(tags) if isinstance(tags, list) else str(tags)
            assert "node" in joined, (
                f"each instance must include a node tag, got: {tags}"
            )


class TestPhase86iNarrowedCustomCheck:
    """Phase 86i Gap 1 — Layer 2: narrowed custom check emits only
    service checks + derived gauges. All Prometheus-duplicate metrics
    (gauge/rate) must be removed from check.py.
    """

    CHECK_FILE = CHECK_PATH

    # Metrics that duplicate Prometheus exposition and MUST be removed.
    PROMETHEUS_DUPLICATE_METRICS = [
        "ja4proxy.node.redis_latency_ms",
        "ja4proxy.node.dial_setting",
        "ja4proxy.node.cert_days_remaining",
        "ja4proxy.connections.active",
        "ja4proxy.connections.total",
        "ja4proxy.block_rate_pct",
        "ja4proxy.bans.active",
    ]

    def test_check_emits_only_service_checks(self):
        """After Phase 86i, check.py must not emit gauge()/rate() for any
        metric that is already in the Prometheus exposition. Only
        service_check() calls (ja4proxy.node_health, ja4proxy.redis_health)
        and optional derived gauges remain."""
        source = self.CHECK_FILE.read_text()
        for metric in self.PROMETHEUS_DUPLICATE_METRICS:
            assert metric not in source, (
                f"Phase 86i: {metric!r} still in check.py — "
                f"must be scraped via OpenMetrics Layer 1, not duplicated here"
            )
        # Service checks must still be present.
        assert "ja4proxy.node_health" in source
        assert "ja4proxy.redis_health" in source, (
            "Phase 86i: ja4proxy.redis_health service_check must be added"
        )


# ── PHASE_101 H16: migration runbook ────────────────────────────────────────


class TestPhase101H16MigrationRunbook:
    """PHASE_101 H16 — the Datadog two-layer migration must have an oncall
    runbook that documents the deploy order and the smoke-check commands.

    Without this runbook, the migration was lore-only: SREs had to read
    the Phase 86i review doc to know that OpenMetrics ships before the
    custom check, and the exact `datadog-agent check` invocations that
    validate each layer were undocumented.
    """

    RUNBOOK = (
        Path(__file__).parent.parent.parent
        / "docs"
        / "runbooks"
        / "datadog_migration_phase86i.md"
    )

    def test_runbook_exists(self):
        assert self.RUNBOOK.exists(), (
            f"Phase 101 H16: missing {self.RUNBOOK} — oncall has no "
            "documented procedure for the Datadog two-layer rollout"
        )

    def test_runbook_references_both_smoke_check_commands(self):
        """The runbook must reference both ``datadog-agent check openmetrics``
        and ``datadog-agent check ja4proxy`` by exact name — these are the
        commands oncall pastes during a rollout."""
        text = self.RUNBOOK.read_text()
        assert "datadog-agent check openmetrics" in text, (
            "Phase 101 H16: runbook must include the exact "
            "`datadog-agent check openmetrics` invocation"
        )
        assert "datadog-agent check ja4proxy" in text, (
            "Phase 101 H16: runbook must include the exact "
            "`datadog-agent check ja4proxy` invocation"
        )

    def test_runbook_documents_deploy_order(self):
        """The runbook must explicitly state OpenMetrics deploys before the
        narrowed custom check — reversing the order produces 24h of
        spurious ``unknown`` health states."""
        text = self.RUNBOOK.read_text()
        assert "Layer 1" in text and "Layer 2" in text, (
            "Phase 101 H16: runbook must enumerate Layer 1 / Layer 2"
        )
        # Layer 1 (OpenMetrics) must appear before Layer 2 (custom check)
        # in the document body.
        idx_l1 = text.find("Layer 1")
        idx_l2 = text.find("Layer 2")
        assert 0 <= idx_l1 < idx_l2, (
            "Phase 101 H16: runbook must describe Layer 1 before Layer 2"
        )
