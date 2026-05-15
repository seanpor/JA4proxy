"""Tests for management.compliance.report_renderer.ReportRenderer.

Quality bar
-----------
- Tests verify actual rendered OUTPUT content, not just "no exception raised".
- Jinja2 injection safety is verified with a hostile period_label.
- The cost section omission is verified in the HTML output.
- Fallback note presence is verified when months_using_fallback is set.
- Custom template path is tested end-to-end.
- PDF test is skipped when WeasyPrint is not installed.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from management.compliance.report_renderer import (
    AvailabilityMetric,
    ReportData,
    ReportRenderer,
    TrendMonth,
    WeasyPrintNotAvailable,
)


def _weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401

        return True
    except Exception:
        return False


def _default_renderer() -> ReportRenderer:
    return ReportRenderer()


def _minimal_data(**kwargs) -> ReportData:
    """Return a ReportData with sensible defaults for testing."""
    defaults = dict(
        period_label="Q1 2026",
        from_iso="2026-01-01T00:00:00+00:00",
        to_iso="2026-03-31T23:59:59+00:00",
        connections_total=1_000_000,
        connections_blocked=10_000,
        fp_incidents=2,
        fp_rate_ppm=2,
        dial_setting=70,
        bans_total=50,
        audit_entry_count=300,
    )
    defaults.update(kwargs)
    return ReportData(**defaults)


# ── Section headers ────────────────────────────────────────────────────────────


def test_html_contains_executive_summary_section():
    html = _default_renderer().render_html(_minimal_data())
    assert "EXECUTIVE SUMMARY" in html


def test_html_contains_value_delivered_section():
    html = _default_renderer().render_html(_minimal_data())
    assert "VALUE DELIVERED" in html


def test_html_contains_dial_configuration_section():
    html = _default_renderer().render_html(_minimal_data())
    assert "DIAL CONFIGURATION" in html


def test_html_contains_security_posture_section():
    html = _default_renderer().render_html(_minimal_data())
    assert "SECURITY POSTURE" in html


def test_html_contains_availability_section():
    html = _default_renderer().render_html(_minimal_data())
    assert "AVAILABILITY" in html


def test_html_contains_compliance_section():
    html = _default_renderer().render_html(_minimal_data())
    assert "COMPLIANCE" in html


# ── Data insertion ─────────────────────────────────────────────────────────────


def test_html_contains_period_label():
    """The configured period label must appear in the rendered output."""
    html = _default_renderer().render_html(_minimal_data(period_label="Q4 2025"))
    assert "Q4 2025" in html


def test_html_contains_blocked_count():
    """The blocked connection count must appear as a formatted number."""
    html = _default_renderer().render_html(_minimal_data(connections_blocked=999_000))
    # Jinja2 formats as "999,000"
    assert "999,000" in html


def test_html_contains_audit_entry_count():
    """audit_entry_count must appear in the Compliance section."""
    html = _default_renderer().render_html(_minimal_data(audit_entry_count=1247))
    assert "1,247" in html


def test_html_cost_section_present_when_cost_nonzero():
    """When cost_per_connection_usd > 0, cost estimate must appear in output."""
    data = _minimal_data(
        connections_blocked=1_000_000,
        cost_per_connection_usd=0.50,
    )
    html = _default_renderer().render_html(data)
    assert "avoided cost" in html.lower()
    # $500,000 at $0.50/connection
    assert "500,000" in html


def test_html_cost_section_absent_when_cost_zero():
    """When cost_per_connection_usd == 0.0, NO cost estimate must appear."""
    data = _minimal_data(cost_per_connection_usd=0.0)
    html = _default_renderer().render_html(data)
    assert "avoided cost" not in html.lower()


def test_html_trend_table_present_when_data_provided():
    """Trend months appear in the output when provided."""
    data = _minimal_data(
        trend_months=[
            TrendMonth(
                month="2026-01",
                connections_blocked=1000,
                fp_rate_ppm=1,
                dial_setting=70,
            ),
            TrendMonth(
                month="2026-02",
                connections_blocked=2000,
                fp_rate_ppm=2,
                dial_setting=70,
            ),
        ]
    )
    html = _default_renderer().render_html(data)
    assert "2026-01" in html
    assert "2026-02" in html
    assert "1,000" in html


def test_html_fallback_note_when_months_using_fallback_set():
    """When months_using_fallback is non-empty, a fallback note must appear."""
    data = _minimal_data(months_using_fallback=["2026-01", "2026-02"])
    html = _default_renderer().render_html(data)
    assert "fallback" in html.lower()
    assert "2026-01" in html
    assert "2026-02" in html


def test_html_no_fallback_note_when_empty():
    """When months_using_fallback is empty, no fallback note should appear."""
    data = _minimal_data(months_using_fallback=[])
    html = _default_renderer().render_html(data)
    assert "fallback" not in html.lower()


# ── Availability metrics ───────────────────────────────────────────────────────


def test_html_availability_metrics_rendered():
    """Availability metric rows must appear in the output."""
    data = _minimal_data(
        availability_metrics=[
            AvailabilityMetric(label="Uptime (all nodes)", value="99.98%"),
            AvailabilityMetric(label="Mean added latency", value="0.3ms"),
        ]
    )
    html = _default_renderer().render_html(data)
    assert "Uptime (all nodes)" in html
    assert "99.98%" in html
    assert "0.3ms" in html


# ── Jinja2 injection safety ────────────────────────────────────────────────────


def test_html_period_label_is_html_escaped():
    """A period_label containing Jinja2 syntax must be escaped, not evaluated."""
    # If auto-escape is broken, "{{ 7*7 }}" would become "49" in the output.
    hostile = "{{ 7*7 }}"
    html = _default_renderer().render_html(_minimal_data(period_label=hostile))
    assert (
        "49" not in html
    ), "Jinja2 template injection via period_label was NOT escaped"


def test_html_xss_in_period_label_escaped():
    """HTML in period_label must be escaped to prevent XSS."""
    xss = '<script>alert("xss")</script>'
    html = _default_renderer().render_html(_minimal_data(period_label=xss))
    assert "<script>" not in html
    assert "&lt;script&gt;" in html or "alert" not in html


# ── render() method ────────────────────────────────────────────────────────────


def test_render_html_returns_bytes_and_content_type():
    """render(fmt='html') returns (bytes, 'text/html')."""
    renderer = _default_renderer()
    content, content_type = renderer.render(_minimal_data(), fmt="html")
    assert isinstance(content, bytes)
    assert content_type == "text/html"
    assert b"EXECUTIVE SUMMARY" in content


@pytest.mark.skipif(
    not _weasyprint_available(),
    reason="WeasyPrint system libraries not installed",
)
def test_render_pdf_returns_pdf_bytes():
    """render(fmt='pdf') returns (bytes, 'application/pdf') with substantial content."""
    renderer = _default_renderer()
    content, content_type = renderer.render(_minimal_data(), fmt="pdf")
    assert content_type == "application/pdf"
    assert len(content) > 1024, "PDF output is suspiciously small"
    # PDF magic bytes
    assert content[:4] == b"%PDF", "Output does not start with PDF magic bytes"


def test_render_pdf_raises_when_weasyprint_missing(monkeypatch):
    """When WeasyPrint cannot be imported, WeasyPrintNotAvailable is raised."""
    import builtins

    original_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise ImportError("mocked: weasyprint not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)

    renderer = _default_renderer()
    with pytest.raises(WeasyPrintNotAvailable):
        renderer.render_pdf(_minimal_data())


# ── Custom template ────────────────────────────────────────────────────────────


def test_custom_template_renders_unique_marker():
    """A custom template with a unique marker produces output containing that marker."""
    unique_marker = "COMPLIANCE_REPORT_MARKER_XYZ_42"

    with tempfile.TemporaryDirectory() as tmpdir:
        template_path = os.path.join(tmpdir, "report_template.html")
        # Use string concatenation, NOT f-string, so {{ }} is not Python-escaped.
        with open(template_path, "w") as f:
            f.write(
                "<html><body>" + unique_marker + " {{ period_label }}</body></html>"
            )

        renderer = ReportRenderer(template_dir=tmpdir)
        html = renderer.render_html(_minimal_data(period_label="test period"))

    assert unique_marker in html
    assert "test period" in html
