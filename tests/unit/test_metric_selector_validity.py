"""
Phase 820 — metric selector validation.

WHY THIS EXISTS
---------------
Phase 820 found that all four HAProxy alert rules had never been able to fire.
They filtered on ``{proxy="ja4proxy"}``:

  * ``proxy=`` is the label emitted by HAProxy's *native* exporter, but the
    deployed ``prom/haproxy-exporter`` sidecar only ever emitted ``frontend=``
    and ``backend=`` — so the selector matched no series at all; and
  * the value was wrong regardless: the backend is named ``ja4proxy_workers``
    in ``config/haproxy.cfg``, not ``ja4proxy``.

Both faults are invisible to config linting and to a running system: a rule
that matches nothing simply never fires. It went unnoticed for months.

This module is deliberately written as a REUSABLE validator, not a
haproxy-specific test. ``PHASE_821a.md`` regression test #1 is the same check
generalised to ``ja4proxy_*`` metrics and the console metric catalogue; it
consumes :func:`extract_label_selectors` rather than reimplementing it.
See the note in ``docs/phases/complete/PHASE_820.md`` §Test strategy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent

HAPROXY_CFG = ROOT / "config/haproxy.cfg"
ALERTS_YML = ROOT / "deploy/monitoring/prometheus/alerts.yml"
DASHBOARD_DIR = ROOT / "deploy/monitoring/grafana/dashboards"

# metric{label="value", other="value"} — captures metric name and label block.
_SELECTOR_RE = re.compile(r"\b(haproxy_[a-z0-9_]+)\s*\{([^}]*)\}")
_LABEL_RE = re.compile(r'(\w+)\s*=~?\s*"([^"]*)"')


def extract_label_selectors(text: str) -> list[tuple[str, dict[str, str]]]:
    """Return ``[(metric_name, {label: value}), ...]`` for every selector found.

    Reusable across alert rules, recording rules, dashboard JSON, and (via
    Phase 821a) the console metric catalogue.
    """
    out: list[tuple[str, dict[str, str]]] = []
    for match in _SELECTOR_RE.finditer(text):
        metric, label_block = match.group(1), match.group(2)
        labels = dict(_LABEL_RE.findall(label_block))
        out.append((metric, labels))
    return out


def declared_proxy_names(cfg_text: str) -> set[str]:
    """Every frontend/backend/listen name declared in an haproxy.cfg.

    These are exactly the values HAProxy's native exporter emits as ``proxy=``.
    """
    return set(re.findall(r"^(?:frontend|backend|listen)\s+(\S+)", cfg_text, re.M))


def _iter_exprs(node) -> list[str]:
    """Every ``expr`` string in a parsed Grafana dashboard, at any depth."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "expr" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_iter_exprs(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_iter_exprs(item))
    return found


def _consumer_texts() -> list[tuple[str, str]]:
    """(label, text) for every file that may contain haproxy_* selectors.

    Grafana dashboards are parsed as JSON and reduced to their ``expr`` strings
    rather than scanned as raw text: in the file, quotes inside an expression
    are backslash-escaped (``{proxy=\\"x\\"}``), so a regex over raw text sees
    an empty label block and every label-based check silently passes.
    """
    texts = [("alerts.yml", ALERTS_YML.read_text())]
    for path in sorted(DASHBOARD_DIR.glob("*.json")):
        exprs = _iter_exprs(json.loads(path.read_text()))
        texts.append((path.name, "\n".join(exprs)))
    return texts


class TestHAProxySelectorValidity:
    def test_declared_proxy_names_parsed(self):
        """Sanity: the parser finds the real proxies, or every test below is vacuous."""
        names = declared_proxy_names(HAPROXY_CFG.read_text())
        assert "ja4proxy_workers" in names, (
            f"expected backend 'ja4proxy_workers' in config/haproxy.cfg; got {names}"
        )
        assert "tls_in" in names

    def test_every_proxy_label_matches_a_declared_name(self):
        """The Phase 820 bug: a proxy= value that matches no frontend/backend.

        A selector naming a non-existent proxy matches zero series, so the alert
        can never fire and the panel is permanently blank — with no error
        anywhere to reveal it.
        """
        valid = declared_proxy_names(HAPROXY_CFG.read_text())
        bad: list[str] = []
        for source, text in _consumer_texts():
            for metric, labels in extract_label_selectors(text):
                value = labels.get("proxy")
                if value and value not in valid:
                    bad.append(f"{source}: {metric}{{proxy=\"{value}\"}}")
        assert not bad, (
            "selector(s) reference a proxy that does not exist in "
            f"config/haproxy.cfg (valid: {sorted(valid)}):\n  " + "\n  ".join(bad)
        )

    def test_no_selector_uses_the_retired_sidecar_labels(self):
        """prom/haproxy-exporter used frontend=/backend=; native promex uses proxy=."""
        bad: list[str] = []
        for source, text in _consumer_texts():
            for metric, labels in extract_label_selectors(text):
                for stale in ("frontend", "backend"):
                    if stale in labels:
                        bad.append(f'{source}: {metric}{{{stale}="{labels[stale]}"}}')
        assert not bad, (
            "selector(s) use the retired prom/haproxy-exporter label schema; "
            "HAProxy's native exporter emits proxy= instead:\n  " + "\n  ".join(bad)
        )

    def test_server_status_selectors_constrain_state(self):
        """``haproxy_server_status`` is a state machine, not a 0/1 gauge.

        Native promex emits one series per state (UP/DOWN/MAINT/DRAIN/NOLB),
        value 1 for the active state and 0 for the rest. An unconstrained
        ``== 0`` therefore matches the four inactive states permanently and
        pages forever.
        """
        bad: list[str] = []
        for source, text in _consumer_texts():
            for metric, labels in extract_label_selectors(text):
                if metric == "haproxy_server_status" and "state" not in labels:
                    bad.append(f"{source}: {metric}{{{labels}}}")
        assert not bad, (
            "haproxy_server_status used without a state= selector — this matches "
            "every state including the four that are always 0:\n  " + "\n  ".join(bad)
        )

    def test_no_reference_to_metrics_the_native_exporter_never_emits(self):
        """Metrics that existed only in the retired sidecar.

        ``haproxy_frontend_connections_rate`` was a *gauge* the sidecar derived
        from HAProxy's CSV. Native promex does not emit it; the counter
        ``haproxy_frontend_connections_total`` replaces it. (The old dashboard
        panels wrapped the gauge in ``rate()``, which was invalid anyway —
        ``rate()`` is for counters.)
        """
        retired = {"haproxy_up", "haproxy_frontend_connections_rate"}
        bad: list[str] = []
        for source, text in _consumer_texts():
            for name in retired:
                if re.search(rf"\b{re.escape(name)}\b", text):
                    bad.append(f"{source}: {name}")
        assert not bad, (
            "reference(s) to metrics only the retired sidecar emitted:\n  "
            + "\n  ".join(bad)
        )


class TestValidatorItself:
    """The validator is load-bearing; prove it detects what it claims to."""

    def test_extractor_parses_metric_and_labels(self):
        found = extract_label_selectors(
            'haproxy_server_status{proxy="ja4proxy_workers", state="UP"} == 0'
        )
        assert found == [
            ("haproxy_server_status", {"proxy": "ja4proxy_workers", "state": "UP"})
        ]

    def test_extractor_handles_regex_matchers(self):
        found = extract_label_selectors('haproxy_backend_current_queue{proxy=~"ja4.*"}')
        assert found[0][1]["proxy"] == "ja4.*"

    def test_declared_names_ignores_indented_and_comment_lines(self):
        names = declared_proxy_names(
            "frontend tls_in\n    bind *:443\n# backend commented\nbackend be_real\n"
        )
        assert names == {"tls_in", "be_real"}

    def test_dashboard_exprs_are_unescaped_before_matching(self):
        """Regression: raw-text scanning of dashboard JSON hides every label.

        In the file the expression is stored as ``{proxy=\\"x\\"}``. Scanning
        raw text yields an empty label dict, so a bare-``haproxy_server_status``
        check passes vacuously. This asserts the parsed path sees real labels.
        """
        by_source = dict(_consumer_texts())
        infra = by_source["ja4proxy-infrastructure.json"]
        assert '\\"' not in infra, "dashboard exprs must be unescaped before matching"
        statuses = [
            labels
            for metric, labels in extract_label_selectors(infra)
            if metric == "haproxy_server_status"
        ]
        assert statuses, "expected a haproxy_server_status selector in the dashboard"
        assert all("proxy" in lbl for lbl in statuses), (
            f"labels not parsed from dashboard JSON: {statuses}"
        )

    def test_would_have_caught_the_phase_820_bug(self):
        """Regression: the exact pre-820 selector must be rejected."""
        valid = declared_proxy_names(HAPROXY_CFG.read_text())
        metric, labels = extract_label_selectors(
            'haproxy_server_status{proxy="ja4proxy"} == 0'
        )[0]
        assert labels["proxy"] not in valid, (
            "the pre-820 selector proxy=\"ja4proxy\" should NOT match any declared "
            "proxy name — if this passes, the validator cannot catch the bug"
        )
        assert "state" not in labels


@pytest.mark.parametrize(
    "dashboard",
    sorted(p.name for p in DASHBOARD_DIR.glob("*.json")),
)
def test_dashboards_are_valid_json(dashboard):
    """A malformed dashboard silently fails to load in Grafana."""
    json.loads((DASHBOARD_DIR / dashboard).read_text())
