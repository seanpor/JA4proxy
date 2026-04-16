"""Tests for H15 / M25 — Dynatrace plugin robustness.

TDD Tests covering:
- H15: parse_prometheus_text() handles NaN, Inf, non-numeric, control chars, empty body
- M25: scrape_metrics() emits synthetic entity with scrape_failed on HTTP 500 / ConnectionError

These tests will FAIL until the Coder hardens parse_prometheus_text() and
adds the scrape-fail entity emission in plugin.py.
"""

from __future__ import annotations

import importlib.util
import math
import sys
import unittest.mock
from pathlib import Path
from unittest.mock import patch

import pytest

# The plugin lives in a directory with a hyphen so we import via importlib
_PLUGIN_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "dynatrace"
    / "ja4proxy-extension"
    / "plugin.py"
)


@pytest.fixture(scope="module")
def plugin_module():
    """Import plugin.py via importlib (directory has a hyphen)."""
    spec = importlib.util.spec_from_file_location("dynatrace_plugin", _PLUGIN_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── H15: NaN, Inf, -Inf, non-numeric, control chars, empty body ─────────────


class TestParsePrometheusRobustness:
    """parse_prometheus_text must skip bad values without crashing."""

    @pytest.mark.parametrize(
        "bad_value,description",
        [
            ("NaN", "NaN value"),
            ("Nan", "Nan mixed-case"),
            ("nan", "nan lower-case"),
            ("+Inf", "positive Inf"),
            ("-Inf", "negative Inf"),
            ("Inf", "bare Inf"),
        ],
    )
    def test_nan_inf_values_skipped(self, plugin_module, bad_value: str, description: str):
        """Metric lines with NaN or Inf values must be skipped."""
        text = f"ja4proxy_connections_active {bad_value}\n"
        samples = plugin_module.parse_prometheus_text(text)
        # After the fix, NaN/Inf should be skipped entirely
        for name, labels, value in samples:
            assert math.isfinite(value), (
                f"{description}: got non-finite value {value} for {name}"
            )

    @pytest.mark.parametrize(
        "bad_value",
        ["notanumber", "abc", "12.34.56", "true", "null"],
        ids=["alpha", "abc", "double_dot", "bool", "null"],
    )
    def test_non_numeric_values_skipped(self, plugin_module, bad_value: str):
        """Lines with non-numeric value strings must be skipped."""
        text = f"ja4proxy_dial_setting {bad_value}\n"
        samples = plugin_module.parse_prometheus_text(text)
        assert len(samples) == 0, (
            f"Expected 0 samples for non-numeric '{bad_value}', got {len(samples)}"
        )

    def test_control_characters_in_label_values_handled(self, plugin_module):
        """Control characters in label values must be skipped or sanitized."""
        # Label value contains a null byte and bell char
        text = 'ja4proxy_errors{reason="bad\x00\x07value"} 42\n'
        # Should not crash
        samples = plugin_module.parse_prometheus_text(text)
        # If it parses, label values should not contain raw control chars
        for name, labels, value in samples:
            for k, v in labels.items():
                for ch in v:
                    assert ord(ch) >= 32 or ch == "\t", (
                        f"Control character ord({ord(ch)}) in label {k}={v!r}"
                    )

    def test_empty_response_body_returns_empty(self, plugin_module):
        """An empty string must return an empty list, not crash."""
        assert plugin_module.parse_prometheus_text("") == []

    def test_whitespace_only_body_returns_empty(self, plugin_module):
        """Whitespace-only input returns empty list."""
        assert plugin_module.parse_prometheus_text("   \n\n  \t  \n") == []

    def test_valid_samples_still_parsed_alongside_bad(self, plugin_module):
        """Good lines should be kept even when bad lines are present."""
        text = (
            "ja4proxy_dial_setting 42\n"
            "ja4proxy_bad_metric NaN\n"
            "ja4proxy_connections_active 100\n"
            "ja4proxy_inf_metric +Inf\n"
        )
        samples = plugin_module.parse_prometheus_text(text)
        names = [s[0] for s in samples]
        assert "ja4proxy_dial_setting" in names
        assert "ja4proxy_connections_active" in names
        # Bad metrics must NOT be in the output
        assert "ja4proxy_bad_metric" not in names, (
            "NaN metric should have been filtered out"
        )
        assert "ja4proxy_inf_metric" not in names, (
            "Inf metric should have been filtered out"
        )

    def test_comment_and_type_lines_ignored(self, plugin_module):
        """# HELP and # TYPE lines must be ignored."""
        text = (
            "# HELP ja4proxy_dial_setting The current dial value\n"
            "# TYPE ja4proxy_dial_setting gauge\n"
            "ja4proxy_dial_setting 50\n"
        )
        samples = plugin_module.parse_prometheus_text(text)
        assert len(samples) == 1
        assert samples[0][0] == "ja4proxy_dial_setting"
        assert samples[0][2] == 50.0

    def test_metric_with_labels_parsed(self, plugin_module):
        """Lines with labels should parse correctly."""
        text = 'ja4proxy_errors_total{reason="timeout",node="a"} 7\n'
        samples = plugin_module.parse_prometheus_text(text)
        assert len(samples) == 1
        name, labels, value = samples[0]
        assert name == "ja4proxy_errors_total"
        assert labels == {"reason": "timeout", "node": "a"}
        assert value == 7.0


# ── H15: _parse_labels edge cases ────────────────────────────────────────────


class TestParseLabelsRobustness:
    """_parse_labels must handle malformed label strings."""

    def test_empty_string(self, plugin_module):
        assert plugin_module._parse_labels("") == {}

    def test_no_equals(self, plugin_module):
        """A label string with no '=' should produce empty dict or skip the part."""
        result = plugin_module._parse_labels("justkey")
        # Either empty or gracefully degraded — must not crash
        assert isinstance(result, dict)

    def test_quoted_comma_in_value(self, plugin_module):
        """Labels with commas inside quotes should be handled."""
        result = plugin_module._parse_labels('reason="a,b",node="c"')
        assert isinstance(result, dict)


# ── M25: scrape_metrics emits synthetic entity on failure ─────────────────────


class TestScrapeFailSyntheticEntity:
    """When scrape_metrics() hits an error, it should emit a synthetic entity
    with scrape_failed=true."""

    def test_http_500_emits_scrape_failed_entity(self, plugin_module):
        """HTTP 500 from scrape target -> synthetic entity with scrape_failed."""
        import urllib.error

        with patch.object(
            plugin_module.urllib.request,
            "urlopen",
            side_effect=urllib.error.HTTPError(
                url="http://target:8090/metrics",
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=None,
            ),
        ):
            result = plugin_module.scrape_metrics("http://target:8090/metrics")

        # Minimum contract: function does not raise
        assert isinstance(result, list)

        # M25 contract: there should be a synthetic marker indicating failure.
        # Expected: a tuple like ("ja4proxy_scrape_failed", {"reason": "..."}, 1.0)
        failed_samples = [s for s in result if "scrape_failed" in s[0]]
        assert len(failed_samples) >= 1, (
            f"Expected synthetic scrape_failed entity on HTTP 500, got: {result}"
        )

    def test_connection_error_emits_scrape_failed_entity(self, plugin_module):
        """ConnectionError from scrape target -> synthetic entity with scrape_failed."""
        with patch.object(
            plugin_module.urllib.request,
            "urlopen",
            side_effect=ConnectionError("Connection refused"),
        ):
            result = plugin_module.scrape_metrics("http://unreachable:8090/metrics")

        assert isinstance(result, list)

        failed_samples = [s for s in result if "scrape_failed" in s[0]]
        assert len(failed_samples) >= 1, (
            f"Expected synthetic scrape_failed entity on ConnectionError, got: {result}"
        )

    def test_scrape_failed_entity_includes_reason(self, plugin_module):
        """The synthetic scrape_failed entity should include the error reason."""
        with patch.object(
            plugin_module.urllib.request,
            "urlopen",
            side_effect=OSError("Network unreachable"),
        ):
            result = plugin_module.scrape_metrics("http://target:8090/metrics")

        failed_samples = [s for s in result if "scrape_failed" in s[0]]
        assert len(failed_samples) >= 1, "Expected scrape_failed entity"
        _, labels, _ = failed_samples[0]
        assert "reason" in labels, (
            f"scrape_failed entity should include a reason label, got labels: {labels}"
        )
