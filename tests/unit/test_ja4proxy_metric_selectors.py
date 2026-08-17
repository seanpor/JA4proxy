"""
Every ``ja4proxy_*`` metric an alert or dashboard references must be emitted.

WHY THIS EXISTS
---------------
Phase 820 found nine HAProxy selectors that had never been able to match a
series: an alert filtering on a label nothing emits never fires and never
errors, so it looked healthy for months. `test_metric_selector_validity.py`
now guards the `haproxy_*` side.

This is that check generalised to our own metrics — and it immediately found
the same class of defect:

  * `ja4proxy_dial_setting` was documented in CLAUDE.md's Prometheus-naming
    section and used by the `ManagementUIDialAtMaximumBlocking` alert, but the
    code emits `ja4proxy_dial_current` (`internal/metrics/metrics.go:23`). The
    alert could never fire. Fixed, and the doc corrected.
  * 19 further references resolve to nothing at all — listed in
    ``KNOWN_DANGLING`` below.

THE BASELINE IS DELIBERATE
--------------------------
Those 19 are frozen rather than fixed here because each needs a judgement that
is not this test's to make: implement the metric, or delete the alert/panel that
consumes it. Freezing them makes the debt visible and stops it growing — the
same pattern `scripts/check_manifest.py` uses for HISTORICAL_CHANGELOG_GAPS.

**Adding to this list is a process failure, not a fix.** A new entry means
someone wrote an alert or panel against a metric that does not exist.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MONITORING = REPO / "deploy" / "monitoring"

# Frozen 2026-08-17. Every one of these is referenced by an alert rule,
# recording rule or dashboard panel and emitted by nothing. Each is either a
# metric that was never implemented or a consumer that outlived it.
# Shrink this list; do not grow it.
KNOWN_DANGLING = frozenset({
    # analytics node — referenced by alerts.yml and dashboards
    "ja4proxy_analytics_last_event_timestamp",
    "ja4proxy_analytics_signals_total",
    "ja4proxy_analytics_unique_ips_seen_total",
    # SLO recording rules referencing inputs that do not exist
    "ja4proxy_availability",
    "ja4proxy_latency_p99_good",
    "ja4proxy_redis_correctness",
    "ja4proxy_false_positive_rate",
    "ja4proxy_connection_duration_seconds_bucket",
    "ja4proxy_errors_total",
    # management API — an entire rules file (management_ui_rules.yml) built on
    # metrics the FastAPI app does not expose
    "ja4proxy_mgmt_actions_total",
    "ja4proxy_mgmt_auth_failures_total",
    "ja4proxy_mgmt_redis_errors_total",
    "ja4proxy_mgmt_request_duration_ms_bucket",
    "ja4proxy_mgmt_requests_total",
    "ja4proxy_mgmt_sse_subscribers_active",
    # proxy metrics referenced by dashboards but never implemented
    "ja4proxy_monitor_counterfactual_total",
    "ja4proxy_static_allowlist_hits_total",
    "ja4proxy_tls_version_total",
    "ja4proxy_workers",
})

_SUFFIX = re.compile(r"_(bucket|sum|count)$")


def _emitted() -> set[str]:
    """Metric names emitted anywhere: Go, Python, shell exporters, or defined
    as a Prometheus recording rule."""
    names: set[str] = set()
    for root in ("internal", "cmd", "src", "management", "scripts"):
        out = subprocess.run(
            ["grep", "-rhoE", r"ja4proxy_[a-z0-9_]+", str(REPO / root)],
            capture_output=True, text=True,
        ).stdout
        names |= set(out.split())
    for p in (MONITORING / "prometheus").rglob("*.yml"):
        names |= set(re.findall(r"record:\s*([\w:]+)", p.read_text(errors="ignore")))
    return names


def _referenced() -> dict[str, set[str]]:
    """ja4proxy_* names used inside an `expr:` — i.e. actually queried."""
    refs: dict[str, set[str]] = {}
    files = list(MONITORING.rglob("*.yml")) + list(MONITORING.rglob("*.json"))
    for p in files:
        for m in re.finditer(r'"?expr"?\s*:\s*[">|]?(.*)', p.read_text(errors="ignore")):
            for name in re.findall(r"\b(ja4proxy_[a-z0-9_]+)", m.group(1)):
                refs.setdefault(name, set()).add(p.name)
    return refs


def test_no_new_dangling_metric_selectors():
    """An alert on a metric nothing emits never fires — and never errors."""
    emitted, refs = _emitted(), _referenced()
    dangling = {
        n: sorted(f)
        for n, f in refs.items()
        if _SUFFIX.sub("", n) not in emitted and n not in emitted
    }
    new = {n: f for n, f in dangling.items() if n not in KNOWN_DANGLING}
    assert not new, (
        "alert/dashboard reference(s) to metric(s) nothing emits — these can "
        "never fire or render, and will fail silently:\n  "
        + "\n  ".join(f"{n}  ({', '.join(f)})" for n, f in sorted(new.items()))
    )


def test_baseline_does_not_contain_fixed_entries():
    """Keep the baseline honest: a fixed metric must leave the list.

    Otherwise the debt looks permanent and nobody can tell what is left.
    """
    emitted, refs = _emitted(), _referenced()
    resolved = sorted(
        n for n in KNOWN_DANGLING
        if _SUFFIX.sub("", n) in emitted or n in emitted or n not in refs
    )
    assert not resolved, (
        "KNOWN_DANGLING lists metric(s) that are now emitted or no longer "
        "referenced — remove them from the baseline:\n  " + "\n  ".join(resolved)
    )


def test_dial_metric_uses_the_emitted_name():
    """Regression: CLAUDE.md documented `dial_setting`; the code emits `dial_current`.

    An alert written to the documented name could never fire. Pinned because the
    doc and the code disagreeing is how it happened.
    """
    go = (REPO / "internal" / "metrics" / "metrics.go").read_text()
    assert "ja4proxy_dial_current" in go, "the dial gauge was renamed again"
    for p in MONITORING.rglob("*.yml"):
        body = p.read_text(errors="ignore")
        assert "ja4proxy_dial_setting" not in body, (
            f"{p.name} uses ja4proxy_dial_setting, which nothing emits — "
            "the gauge is ja4proxy_dial_current"
        )
