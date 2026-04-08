"""Executive compliance report renderer — Phase 84.

Renders the CISO/board executive report as HTML (always) or PDF (requires
WeasyPrint + system libraries).  Called by ``POST /api/v1/compliance/report``.

Template variables are documented in ``docs/compliance/REPORT_TEMPLATE_VARS.md``.

Design decisions
----------------
- Jinja2 auto-escaping is ALWAYS enabled.  User-controlled strings (e.g. period
  labels passed by the operator) go through Jinja2's ``e`` filter or are in a
  context where auto-escape applies.  This prevents template injection.
- PDF format requires WeasyPrint.  If unavailable, raises ``WeasyPrintNotAvailable``
  with a clear message — the route layer converts this to a 503 / 422.
- The report template is loaded from ``config/report_template.html`` by default.
  A custom template path can be set via ``reporting.report_template_path`` in
  proxy.yml.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# Default template location relative to the project root
_DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent.parent / "config"
_DEFAULT_TEMPLATE_NAME = "report_template.html"


class WeasyPrintNotAvailable(RuntimeError):
    """Raised when PDF generation is requested but WeasyPrint is not installed."""


@dataclass
class TrendMonth:
    """One month of trend data for the report trend table."""

    month: str               # "YYYY-MM"
    connections_blocked: int = 0
    fp_rate_ppm: int = 0
    dial_setting: int = 0


@dataclass
class AvailabilityMetric:
    """One row in the availability table."""

    label: str
    value: str


@dataclass
class ReportData:
    """All data fields consumed by the report template.

    All string fields that come from external config or user input are
    rendered through Jinja2 auto-escaping.
    """

    # Metadata
    period_label: str = "Unknown Period"
    from_iso: str = ""
    to_iso: str = ""
    generated_at: str = ""

    # Summary statistics
    connections_total: int = 0
    connections_blocked: int = 0
    fp_incidents: int = 0
    fp_rate_ppm: int = 0

    # Value model
    cost_per_connection_usd: float = 0.0
    category_counts: list[tuple[str, int]] = field(default_factory=list)
    campaigns_detected: int = 0

    # Dial
    dial_setting: int = 0
    shadow_simulations: int = 0
    dial_recommendation: str = ""

    # Security posture
    bans_total: int = 0

    # Availability
    availability_metrics: list[AvailabilityMetric] = field(default_factory=list)

    # Compliance
    audit_entry_count: int = 0

    # Trend
    trend_months: list[TrendMonth] = field(default_factory=list)
    months_using_fallback: list[str] = field(default_factory=list)

    # Optional logo (base64 PNG/SVG data URI)
    logo_data_uri: str = ""

    @property
    def block_rate_pct(self) -> float:
        if self.connections_total == 0:
            return 0.0
        return (self.connections_blocked / self.connections_total) * 100.0


class ReportRenderer:
    """Renders the executive compliance report as HTML or PDF.

    Args:
        template_path: Path to the directory containing the Jinja2 template.
            Defaults to ``config/`` relative to the project root.
        template_name: Name of the template file.
            Defaults to ``report_template.html``.
    """

    def __init__(
        self,
        template_dir: Path | str | None = None,
        template_name: str = _DEFAULT_TEMPLATE_NAME,
    ) -> None:
        template_dir = Path(template_dir) if template_dir else _DEFAULT_TEMPLATE_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html"]),
        )
        self._template_name = template_name

    def render_html(self, data: ReportData) -> str:
        """Render the report as an HTML string.

        Always works — no system library dependencies.
        """
        if not data.generated_at:
            data.generated_at = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%MZ"
            )
        template = self._env.get_template(self._template_name)
        return template.render(**self._build_context(data))

    def render_pdf(self, data: ReportData) -> bytes:
        """Render the report as a PDF byte string.

        Requires WeasyPrint and its system libraries (pango, cairo, fontconfig).

        Raises:
            WeasyPrintNotAvailable: If WeasyPrint cannot be imported.
        """
        try:
            import weasyprint
        except Exception as exc:
            raise WeasyPrintNotAvailable(
                "PDF generation requires WeasyPrint. "
                "Install it with: pip install weasyprint>=60.0 "
                "and ensure libpango, libcairo, libfontconfig are installed. "
                "Use format=html for a CI-friendly alternative."
            ) from exc

        html_str = self.render_html(data)
        return weasyprint.HTML(string=html_str).write_pdf()

    def render(self, data: ReportData, fmt: str = "html") -> tuple[bytes, str]:
        """Render the report and return ``(content_bytes, content_type)``.

        Args:
            data: Report data.
            fmt: ``"html"`` or ``"pdf"``.

        Returns:
            Tuple of (bytes, content_type_string).
        """
        if fmt == "pdf":
            return self.render_pdf(data), "application/pdf"
        return self.render_html(data).encode("utf-8"), "text/html"

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _build_context(data: ReportData) -> dict[str, Any]:
        """Flatten ReportData into a template context dict."""
        return {
            "period_label": data.period_label,
            "from_iso": data.from_iso,
            "to_iso": data.to_iso,
            "generated_at": data.generated_at,
            "connections_total": data.connections_total,
            "connections_blocked": data.connections_blocked,
            "block_rate_pct": data.block_rate_pct,
            "fp_incidents": data.fp_incidents,
            "fp_rate_ppm": data.fp_rate_ppm,
            "cost_per_connection_usd": data.cost_per_connection_usd,
            "category_counts": data.category_counts,
            "campaigns_detected": data.campaigns_detected,
            "dial_setting": data.dial_setting,
            "shadow_simulations": data.shadow_simulations,
            "dial_recommendation": data.dial_recommendation,
            "bans_total": data.bans_total,
            "availability_metrics": data.availability_metrics,
            "audit_entry_count": data.audit_entry_count,
            "trend_months": data.trend_months,
            "months_using_fallback": data.months_using_fallback,
            "logo_data_uri": data.logo_data_uri,
        }
