"""Phase 829c, outcomes O8/O9/O10 — the swap must not silently break an alert.

Container metrics moved from the standalone cadvisor sidecar to the
``prometheus.exporter.cadvisor`` component already compiled into Alloy.

The failure mode this guards against is specific and has happened here before.
**Phase 820** made an equivalent swap — dropped ``prom/haproxy-exporter`` for
HAProxy's native exporter — and the native one labelled its series ``proxy=``
where the sidecar used ``frontend=``/``backend=``. Every selector had to be
migrated. An alert whose selector no longer matches anything does not error: it
simply never fires, and nothing tells you.

The metric names and label keys were measured on 2026-08-19 by running the
exporter against the live Docker host and diffing its output against every
``container_*`` reference in the rules and dashboards.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ALERTS = ROOT / "deploy/monitoring/prometheus/alerts.yml"
RECORDING = ROOT / "deploy/monitoring/prometheus/recording_rules.yml"
PROM = ROOT / "deploy/monitoring/prometheus/prometheus.yml"
ALLOY = ROOT / "deploy/monitoring/alloy/config.alloy"
DASHBOARD = ROOT / "deploy/monitoring/grafana/dashboards/ja4proxy-infrastructure.json"

# Measured from `prometheus.exporter.cadvisor` with docker_only=true and
# store_container_labels=false, against the live Docker host (2026-08-19).
# 77 metrics were emitted; these are the ones the rules actually reference.
EMITTED = {
    "container_cpu_cfs_throttled_seconds_total",
    "container_cpu_usage_seconds_total",
    "container_fs_reads_bytes_total",
    "container_fs_writes_bytes_total",
    "container_memory_working_set_bytes",
    "container_network_receive_bytes_total",
    "container_network_receive_errors_total",
    "container_network_transmit_bytes_total",
    "container_network_transmit_errors_total",
    "container_oom_events_total",
    "container_spec_memory_limit_bytes",
    "container_start_time_seconds",
}

# Labels the exporter emits with store_container_labels=false. `name` is the
# one the alerts select on.
EMITTED_LABELS = {"id", "image", "name"}

# Produced BY the recording rules, not consumed from the exporter.
RECORDED = {"container_mem_pct", "container_cpu_throttle_ratio"}


def _referenced_metrics() -> set[str]:
    text = "\n".join(
        p.read_text(encoding="utf-8") for p in (ALERTS, RECORDING, DASHBOARD) if p.exists()
    )
    found = set(re.findall(r"\bcontainer_[a-z_]+", text))
    return {m for m in found if m not in RECORDED}


def test_every_referenced_metric_is_emitted() -> None:
    """O8 — a rule referencing a metric nothing emits can never fire."""
    missing = sorted(_referenced_metrics() - EMITTED)
    assert not missing, (
        f"rules reference {missing}, which Alloy's cadvisor exporter does not "
        "emit. Those alerts would silently never fire."
    )


def test_alerts_select_only_on_labels_the_exporter_emits() -> None:
    """O9 — the phase-820 failure mode, as an assertion.

    `store_container_labels = false` drops ~28 `container_label_*` dimensions
    that nothing reads. If a rule ever starts selecting on one, this fails
    rather than the alert quietly matching nothing.
    """
    text = ALERTS.read_text(encoding="utf-8") + RECORDING.read_text(encoding="utf-8")
    # Label selectors appearing inside a container_* metric's braces.
    selectors = set()
    for block in re.findall(r"container_[a-z_]+\{([^}]*)\}", text):
        selectors |= {kv.split("=")[0].strip() for kv in block.split(",") if "=" in kv}
    selectors.discard("")

    unknown = sorted(selectors - EMITTED_LABELS - {"job", "instance"})
    assert not unknown, (
        f"rules select on {unknown}, which the exporter no longer emits. "
        "Either re-enable those labels or migrate the selector."
    )


def test_no_rule_references_a_container_label() -> None:
    """`store_container_labels = false` is only safe while this holds."""
    text = "\n".join(
        p.read_text(encoding="utf-8") for p in (ALERTS, RECORDING, DASHBOARD) if p.exists()
    )
    assert "container_label_" not in text


def test_prometheus_scrapes_alloy_for_container_metrics() -> None:
    """O10 — the job must point somewhere that exists."""
    cfg = yaml.safe_load(PROM.read_text(encoding="utf-8"))
    jobs = {j["job_name"]: j for j in cfg["scrape_configs"]}

    assert "cadvisor" in jobs, "the job name must survive, or every rule needs migrating"
    targets = jobs["cadvisor"]["static_configs"][0]["targets"]
    assert any("alloy" in t for t in targets), f"cadvisor job still targets {targets}"
    assert "prometheus.exporter.cadvisor" in jobs["cadvisor"]["metrics_path"]


def test_job_label_is_unchanged() -> None:
    """Keeping job="cadvisor" is what let every rule survive untouched.

    Phase-820 changed a label in an equivalent swap and had to migrate every
    selector. This asserts we did not repeat that.
    """
    text = ALERTS.read_text(encoding="utf-8")
    if 'job="cadvisor"' in text:
        cfg = yaml.safe_load(PROM.read_text(encoding="utf-8"))
        assert any(j["job_name"] == "cadvisor" for j in cfg["scrape_configs"])


def test_alloy_config_declares_the_exporter() -> None:
    cfg = ALLOY.read_text(encoding="utf-8")
    assert 'prometheus.exporter.cadvisor "containers"' in cfg
    assert "store_container_labels = false" in cfg, (
        "without this the exporter attaches ~28 unused label dimensions to "
        "every series — measured 9.3MB vs 1.1MB per scrape"
    )
    assert "docker_only" in cfg


def test_the_parity_list_is_not_vacuous() -> None:
    """Vacuity guard.

    If `_referenced_metrics()` ever returned nothing — a rules-file rename, a
    broken regex — every assertion above would pass against an empty set while
    the alerts sat broken.
    """
    referenced = _referenced_metrics()
    assert len(referenced) >= 10, f"only {len(referenced)} metrics found; parser broken?"
    assert "container_memory_working_set_bytes" in referenced


def test_dashboard_is_valid_json() -> None:
    """Cheap guard: the dashboard is parsed above and a broken file would make
    the metric scan silently incomplete."""
    if DASHBOARD.exists():
        json.loads(DASHBOARD.read_text(encoding="utf-8"))
