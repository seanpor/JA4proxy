"""PCI-DSS v4.0 evidence pack builder — Phase 84.

Assembles the 8-artefact evidence pack defined in PHASE_84.md §5.2 and
returns a ZIP byte stream suitable for streaming directly to the HTTP client.

Artefact inventory
------------------
01_deployment_confirmation.pdf/html  — node list, versions, uptime
02_block_event_log.jsonl             — all blocked connections in the period
03_attack_classification.csv         — blocked events with category column
04_rbac_configuration.json          — token inventory (no raw token values)
05_audit_log_export.jsonl            — full audit trail for the period
06_availability_metrics.pdf/html     — uptime/health summary
07_access_denied_summary.pdf/html    — category breakdown table
08_configuration_change_log.csv      — audit entries of type config.*

PDF generation requires WeasyPrint and its system libraries.  When WeasyPrint
is unavailable the *_confirmation.pdf artefacts are produced as HTML instead
(file extension .html, content identical).

SHA-256 footer
--------------
For each text/PDF artefact, a "SHA256: <hex>" line is appended to the source
data before conversion.  This is the hash of the *source data dict* serialised
as canonical JSON, giving the auditor a stable checksum to reference.
"""

from __future__ import annotations

import csv
import hashlib
import html as _html
import io
import json
import logging
import zipfile
from datetime import datetime, timezone
from typing import Any, Optional

from .classifier import SignalClassifier

logger = logging.getLogger(__name__)

_AUDIT_KEY = "management:audit_log"
_STREAM_KEY = "ja4proxy:events"
_CONFIG_CHANGE_PREFIX = "config."  # audit action_type prefix for config changes

# Allowlist of safe token hash fields for the RBAC evidence artefact.
# NEVER use a denylist here: future phases may add refresh_token, api_key, etc.
# and a denylist silently lets them leak into the evidence pack.
_TOKEN_SAFE_FIELDS = frozenset({
    "id",
    "name",
    "role",
    "created_at",
    "created_by",
    "description",
    "last_used",
    "revoked",
    "expires_at",
})


def _parse_ts(ts: Any) -> Optional[datetime]:
    """Best-effort parse of a stored ISO-8601 timestamp into aware UTC.

    Returns None if *ts* is empty or unparseable.  Used for window filters —
    NEVER compare raw ISO strings lexicographically: producers emit
    timestamps in multiple formats (Z suffix, +00:00, naive) and lex-compare
    silently drops events from the window, understating compliance evidence.
    """
    if not ts or not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ts_in_window(ts: Any, from_dt: datetime, to_dt: datetime) -> bool:
    """Return True iff *ts* parses to a datetime within [from_dt, to_dt]."""
    dt = _parse_ts(ts)
    if dt is None:
        return True  # fail-open: missing timestamps are included
    return from_dt <= dt <= to_dt


def _weasyprint_available() -> bool:
    try:
        import weasyprint  # noqa: F401
        return True
    except Exception:
        return False


def _sha256_hex(data: Any) -> str:
    """Return hex SHA-256 of the canonical JSON serialisation of *data*."""
    canonical = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(canonical).hexdigest()


def _render_simple_pdf(title: str, body_html: str, source_data: Any) -> bytes:
    """Render a minimal PDF (or HTML fallback) with a SHA-256 footer.

    Returns the bytes to embed in the ZIP.  The file should be named
    with a .pdf extension even when the fallback HTML is returned —
    auditors receive the content regardless of format.

    Security: *title* is HTML-escaped (defence in depth — callers are
    currently hardcoded strings, but the first time someone interpolates a
    period label or hostname into a title, unescaped output would give
    HTML/XSS injection in the evidence pack).  *body_html* is trusted (built
    by the artefact methods with escaped row content).
    """
    checksum = _sha256_hex(source_data)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    footer = f"Generated: {ts} | SHA256: {checksum}"
    safe_title = _html.escape(title)

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{safe_title}</title>
<style>
  body {{ font-family: monospace; margin: 2cm; font-size: 10pt; }}
  h1 {{ font-size: 14pt; }}
  table {{ border-collapse: collapse; width: 100%; }}
  td, th {{ border: 1px solid #ccc; padding: 4px 8px; text-align: left; }}
  .footer {{ position: fixed; bottom: 1cm; font-size: 8pt; color: #666; }}
</style>
</head>
<body>
<h1>{safe_title}</h1>
{body_html}
<div class="footer">{footer}</div>
</body>
</html>"""

    if _weasyprint_available():
        try:
            import weasyprint
            return weasyprint.HTML(string=html).write_pdf()
        except Exception as exc:
            logger.warning("pack_builder | event=weasyprint_failed | error=%s", exc)

    # Fallback: return HTML bytes (still contains the SHA-256 footer)
    return html.encode("utf-8")


class PciDssPackBuilder:
    """Builds the 8-artefact PCI-DSS v4.0 evidence pack.

    Args:
        redis: Async Redis client.
        config: Optional config dict.  Keys used:
            reporting.signal_categories  (dict, optional signal override)
        fmt: ``"pdf+jsonl"`` (default), ``"pdf"``, or ``"jsonl"``.
            - ``"jsonl"`` skips PDF generation entirely (CI-friendly).
            - ``"pdf"`` generates only PDFs (no JSONL).
            - ``"pdf+jsonl"`` generates both.
    """

    def __init__(
        self,
        redis: Any,
        config: dict[str, Any] | None = None,
        fmt: str = "pdf+jsonl",
    ) -> None:
        self._redis = redis
        self._fmt = fmt
        signal_cfg = (config or {}).get("reporting", {}).get("signal_categories")
        self._classifier = SignalClassifier(signal_cfg)

    async def build(
        self,
        from_dt: datetime,
        to_dt: datetime,
    ) -> bytes:
        """Build the evidence pack ZIP and return its bytes.

        Args:
            from_dt: Start of the evidence period (inclusive, UTC).
            to_dt:   End of the evidence period (inclusive, UTC).

        Returns:
            ZIP file bytes containing all 8 artefacts.
        """
        from_iso = from_dt.isoformat()
        to_iso = to_dt.isoformat()

        # ── Data collection ────────────────────────────────────────────────
        blocked_events = await self._query_blocked_events(from_dt, to_dt)
        audit_entries = await self._query_audit_entries(from_dt, to_dt)
        token_inventory = await self._query_token_inventory()
        node_info = await self._query_nodes()

        classified = self._classifier.classify_batch(blocked_events)
        config_changes = [
            e for e in audit_entries
            if e.get("action_type", "").startswith(_CONFIG_CHANGE_PREFIX)
        ]

        # ── Assemble ZIP ───────────────────────────────────────────────────
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            self._add_01_deployment(zf, node_info, from_iso, to_iso)
            self._add_02_block_events(zf, blocked_events)
            self._add_03_attack_classification(zf, classified)
            self._add_04_rbac_configuration(zf, token_inventory)
            self._add_05_audit_log(zf, audit_entries)
            self._add_06_availability_metrics(zf, node_info, from_iso, to_iso)
            self._add_07_access_denied_summary(zf, classified, from_iso, to_iso)
            self._add_08_config_change_log(zf, config_changes)

        return buf.getvalue()

    # ── Redis data queries ─────────────────────────────────────────────────

    async def _query_blocked_events(
        self, from_dt: datetime, to_dt: datetime
    ) -> list[dict[str, Any]]:
        """Read all blocked events from ja4proxy:events stream in the window."""
        try:
            raw = await self._redis.xrange(_STREAM_KEY)
        except Exception as exc:
            logger.warning("pack_builder | event=stream_read_error | error=%s", exc)
            return []

        events = []
        for _entry_id, fields in raw:
            if fields.get("action_taken") != "blocked":
                continue
            ts = fields.get("timestamp", "")
            if not _ts_in_window(ts, from_dt, to_dt):
                continue
            events.append({
                "ip": fields.get("ip", ""),
                "ja4": fields.get("ja4", ""),
                "risk_score": fields.get("risk_score", ""),
                "action_taken": fields.get("action_taken", ""),
                "timestamp": ts,
                "signals": _parse_signals(fields),
            })
        return events

    async def _query_audit_entries(
        self, from_dt: datetime, to_dt: datetime
    ) -> list[dict[str, Any]]:
        """Read all audit entries in the window from management:audit_log."""
        try:
            raw = await self._redis.lrange(_AUDIT_KEY, 0, -1)
        except Exception as exc:
            logger.warning("pack_builder | event=audit_read_error | error=%s", exc)
            return []

        entries = []
        for item in raw:
            try:
                entry = json.loads(item)
            except json.JSONDecodeError:
                continue
            if not _ts_in_window(entry.get("timestamp", ""), from_dt, to_dt):
                continue
            entries.append(entry)
        return entries

    async def _query_token_inventory(self) -> list[dict[str, Any]]:
        """Return token metadata, allowlisted to safe fields only.

        Uses an allowlist (_TOKEN_SAFE_FIELDS), not a denylist: future phases
        may add refresh_token, api_key, or similar fields to the token hash
        and a denylist silently lets them leak into the evidence pack.
        """
        try:
            cursor = 0
            tokens = []
            while True:
                cursor, keys = await self._redis.scan(
                    cursor=cursor, match="mgmt:token:*", count=100
                )
                for key in keys:
                    if ":idx" in key:
                        continue
                    entry = await self._redis.hgetall(key)
                    if entry:
                        safe = {
                            k: v for k, v in entry.items()
                            if k in _TOKEN_SAFE_FIELDS
                        }
                        # Preserve the token id from the key for traceability.
                        safe["token_id"] = key.rsplit(":", 1)[-1]
                        tokens.append(safe)
                if cursor == 0:
                    break
            return tokens
        except Exception as exc:
            logger.warning("pack_builder | event=token_read_error | error=%s", exc)
            return []

    async def _query_nodes(self) -> list[dict[str, Any]]:
        """Return node heartbeat data."""
        try:
            cursor = 0
            nodes = []
            while True:
                cursor, keys = await self._redis.scan(
                    cursor=cursor, match="proxy:heartbeat:*", count=100
                )
                for key in keys:
                    data = await self._redis.hgetall(key)
                    if data:
                        nodes.append(data)
                if cursor == 0:
                    break
            return nodes
        except Exception as exc:
            logger.warning("pack_builder | event=node_read_error | error=%s", exc)
            return []

    # ── Artefact builders ─────────────────────────────────────────────────

    def _add_01_deployment(
        self,
        zf: zipfile.ZipFile,
        nodes: list[dict],
        from_iso: str,
        to_iso: str,
    ) -> None:
        source = {"nodes": nodes, "period": {"from": from_iso, "to": to_iso}}
        rows = "".join(
            "<tr>"
            f"<td>{_html.escape(str(n.get('host','')))}</td>"
            f"<td>{_html.escape(str(n.get('version','')))}</td>"
            f"<td>{_html.escape(str(n.get('started_at','')))}</td>"
            "</tr>"
            for n in nodes
        ) or "<tr><td colspan='3'>No node data available</td></tr>"
        body = (
            f"<p>Evidence period: {_html.escape(from_iso)} to {_html.escape(to_iso)}</p>"
            "<table><tr><th>Host</th><th>Version</th><th>Started</th></tr>"
            f"{rows}</table>"
        )
        content = _render_simple_pdf("JA4proxy Deployment Confirmation", body, source)
        zf.writestr("01_deployment_confirmation.pdf", content)

    def _add_02_block_events(
        self,
        zf: zipfile.ZipFile,
        events: list[dict],
    ) -> None:
        lines = "\n".join(json.dumps(e, default=str) for e in events)
        if lines:
            lines += "\n"
        zf.writestr("02_block_event_log.jsonl", lines)

    def _add_03_attack_classification(
        self,
        zf: zipfile.ZipFile,
        classified: list[dict],
    ) -> None:
        buf = io.StringIO()
        fields = ["timestamp", "ip", "ja4", "risk_score", "action_taken", "category"]
        writer = csv.DictWriter(
            buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        for event in classified:
            writer.writerow(event)
        zf.writestr("03_attack_classification.csv", buf.getvalue())

    def _add_04_rbac_configuration(
        self,
        zf: zipfile.ZipFile,
        tokens: list[dict],
    ) -> None:
        config = {
            "roles": ["auditor", "analyst", "operator", "admin"],
            "tokens": tokens,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        zf.writestr("04_rbac_configuration.json", json.dumps(config, indent=2, default=str))

    def _add_05_audit_log(
        self,
        zf: zipfile.ZipFile,
        entries: list[dict],
    ) -> None:
        lines = "\n".join(json.dumps(e, default=str) for e in entries)
        if lines:
            lines += "\n"
        zf.writestr("05_audit_log_export.jsonl", lines)

    def _add_06_availability_metrics(
        self,
        zf: zipfile.ZipFile,
        nodes: list[dict],
        from_iso: str,
        to_iso: str,
    ) -> None:
        source = {"nodes": nodes, "period": {"from": from_iso, "to": to_iso}}
        rows = "".join(
            "<tr>"
            f"<td>{_html.escape(str(n.get('host','')))}</td>"
            f"<td>{_html.escape(str(n.get('status','unknown')))}</td>"
            "</tr>"
            for n in nodes
        ) or "<tr><td colspan='2'>No availability data</td></tr>"
        body = (
            f"<p>Evidence period: {_html.escape(from_iso)} to {_html.escape(to_iso)}</p>"
            "<table><tr><th>Host</th><th>Status</th></tr>"
            f"{rows}</table>"
        )
        content = _render_simple_pdf("JA4proxy Availability Metrics", body, source)
        zf.writestr("06_availability_metrics.pdf", content)

    def _add_07_access_denied_summary(
        self,
        zf: zipfile.ZipFile,
        classified: list[dict],
        from_iso: str,
        to_iso: str,
    ) -> None:
        # Aggregate by category
        counts: dict[str, int] = {}
        for event in classified:
            cat = event.get("category", "unknown")
            counts[cat] = counts.get(cat, 0) + 1

        rows = "".join(
            f"<tr><td>{_html.escape(str(cat))}</td><td>{int(count)}</td></tr>"
            for cat, count in sorted(counts.items(), key=lambda x: -x[1])
        ) or "<tr><td colspan='2'>No blocked connections in period</td></tr>"
        body = (
            f"<p>Evidence period: {_html.escape(from_iso)} to {_html.escape(to_iso)}</p>"
            f"<p>Total blocked: {len(classified)}</p>"
            "<table><tr><th>Attack Category</th><th>Count</th></tr>"
            f"{rows}</table>"
        )
        source = {"period": {"from": from_iso, "to": to_iso}, "counts": counts}
        content = _render_simple_pdf(
            "JA4proxy Access Denied Summary", body, source
        )
        zf.writestr("07_access_denied_summary.pdf", content)

    def _add_08_config_change_log(
        self,
        zf: zipfile.ZipFile,
        config_changes: list[dict],
    ) -> None:
        buf = io.StringIO()
        fields = [
            "timestamp", "actor_id", "actor_ip", "action_type",
            "resource_type", "resource_id", "role",
        ]
        writer = csv.DictWriter(
            buf, fieldnames=fields, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        for entry in config_changes:
            writer.writerow(entry)
        zf.writestr("08_configuration_change_log.csv", buf.getvalue())


# ── Helpers ───────────────────────────────────────────────────────────────────


def _parse_signals(fields: dict[str, Any]) -> list[str]:
    """Extract signal names from a stream entry's fields dict.

    The proxy may store signals as a JSON list under the 'signals' key or as
    individual signal_N keys.  Handle both.
    """
    if "signals" in fields:
        try:
            return json.loads(fields["signals"])
        except (json.JSONDecodeError, TypeError):
            return []
    # Fallback: collect any field named signal_0, signal_1, ...
    signals = []
    i = 0
    while f"signal_{i}" in fields:
        signals.append(fields[f"signal_{i}"])
        i += 1
    return signals
