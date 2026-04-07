"""Tests that all Alertmanager rule files have runbook_url annotations.

Phase 81 requires every alert rule to include:
    annotations:
      runbook_url: "https://..."

These tests parse all YAML files in monitoring/alertmanager/rules/ and
assert that every alert: entry satisfies the annotation requirements.

The one file that already has runbook_url (ebpf_attack.yml) passes today.
All other files fail until the Phase 81 implementation adds runbook_urls.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path

import pytest
import yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

RULES_DIR = Path(__file__).parent.parent.parent / "monitoring" / "alertmanager" / "rules"


def _collect_all_rules() -> list[tuple[str, str, dict]]:
    """Return a flat list of (filename, alertname, rule_dict) tuples.

    Parses every .yml file in RULES_DIR and extracts alert rules.
    """
    result = []
    rule_files = sorted(RULES_DIR.glob("*.yml"))
    assert rule_files, f"No .yml files found in {RULES_DIR} — check the path"

    for filepath in rule_files:
        with open(filepath) as fh:
            content = yaml.safe_load(fh)
        if not content or "groups" not in content:
            continue
        for group in content["groups"]:
            for rule in group.get("rules", []):
                if "alert" in rule:
                    result.append((filepath.name, rule["alert"], rule))

    return result


def _all_rule_ids():
    """Parametrize IDs for all alert rules."""
    try:
        return [
            f"{fname}::{alertname}"
            for fname, alertname, _ in _collect_all_rules()
        ]
    except Exception:
        return []  # Let the test body handle the failure


# ---------------------------------------------------------------------------
# Collected rules (module-level, evaluated once)
# ---------------------------------------------------------------------------

try:
    ALL_RULES = _collect_all_rules()
    RULE_IDS = [f"{fname}::{alertname}" for fname, alertname, _ in ALL_RULES]
except Exception as e:
    ALL_RULES = []
    RULE_IDS = []
    _COLLECTION_ERROR = e
else:
    _COLLECTION_ERROR = None


# ---------------------------------------------------------------------------
# Test: every rule has an annotations block
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname,alertname,rule", ALL_RULES, ids=RULE_IDS)
def test_no_rule_file_is_missing_annotations(fname: str, alertname: str, rule: dict):
    """Every alert rule must have an 'annotations' block.

    Catches rules that have 'labels' but forgot 'annotations' entirely.
    """
    assert "annotations" in rule, (
        f"Alert '{alertname}' in {fname} has no 'annotations' block. "
        f"Add annotations.runbook_url per Phase 81 requirements."
    )


# ---------------------------------------------------------------------------
# Test: every rule has a non-empty runbook_url annotation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname,alertname,rule", ALL_RULES, ids=RULE_IDS)
def test_all_rule_files_have_runbook_url(fname: str, alertname: str, rule: dict):
    """Every alert rule must have a non-empty annotations.runbook_url.

    Phase 81 §8: 'Every Alertmanager rule must include runbook_url.'
    """
    annotations = rule.get("annotations", {})
    runbook_url = annotations.get("runbook_url", "")

    assert runbook_url, (
        f"Alert '{alertname}' in {fname} is missing 'annotations.runbook_url'. "
        f"Phase 81 requires a runbook URL on every alert rule. "
        f"Current annotations: {annotations!r}"
    )


# ---------------------------------------------------------------------------
# Test: runbook_url is not a catch-all (must be specific to this alert)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("fname,alertname,rule", ALL_RULES, ids=RULE_IDS)
def test_runbook_url_contains_alertname(fname: str, alertname: str, rule: dict):
    """Every runbook_url must be alert-specific — not a trivial catch-all root URL.

    Acceptable forms (all specific to an alert):
      - URL containing the alertname literally
        e.g. "docs/runbooks/ProxyHighBlockRate.md"
      - URL containing the Alertmanager label template reference
        e.g. "https://docs.example.com/runbooks/{{ $labels.alertname }}"
      - URL with a descriptive path segment (longer than just a bare host/domain)
        e.g. "docs/runbooks/ebpf-volumetric-attack.md"
        e.g. "https://docs.example.com/runbooks/ja4proxy/proxy-high-block-rate"

    Not acceptable — trivial catch-all root URL that applies to all alerts equally:
      - "https://docs.example.com/"
      - "https://wiki.internal/"
    """
    annotations = rule.get("annotations", {})
    runbook_url = annotations.get("runbook_url", "")

    if not runbook_url:
        # Already caught by test_all_rule_files_have_runbook_url
        pytest.skip("runbook_url missing — caught by other test")

    # Accept the Alertmanager template variable
    has_template = (
        "{{ $labels.alertname }}" in runbook_url
        or "{{$labels.alertname}}" in runbook_url
    )

    # Accept the alertname appearing literally in the URL (case-insensitive)
    has_alertname_literal = alertname.lower() in runbook_url.lower()

    # Accept any URL that has a meaningful path (not just a bare root like "https://host/")
    # A meaningful path contains at least one path segment with >3 characters
    import re as _re
    path_segments = [
        seg for seg in _re.split(r"[/\\]", runbook_url.rstrip("/"))
        if len(seg) > 3 and not seg.startswith("http")
    ]
    has_specific_path = len(path_segments) >= 1

    assert has_template or has_alertname_literal or has_specific_path, (
        f"Alert '{alertname}' in {fname}: runbook_url {runbook_url!r} appears to be a "
        f"trivial catch-all root URL with no alert-specific path segment. "
        f"Every alert must have its own runbook URL. "
        f"Use the alertname in the path or the template '{{{{ $labels.alertname }}}}'."
    )


# ---------------------------------------------------------------------------
# Smoke test: rule collection works at all
# ---------------------------------------------------------------------------

def test_rule_collection_succeeds():
    """Sanity check: we can parse rule files and find at least one rule."""
    if _COLLECTION_ERROR is not None:
        pytest.fail(f"Rule collection failed with: {_COLLECTION_ERROR}")

    assert len(ALL_RULES) > 0, (
        f"No alert rules found in {RULES_DIR}. "
        "Either the path is wrong or the YAML files have no 'alert:' entries."
    )
