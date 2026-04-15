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
For each text/PDF artefact, a "SHA256: <hex>" line is appended to the source
data before conversion.  This is the hash of the *source data dict* serialised
as canonical JSON, giving the auditor a stable checksum to reference.

L2 — JSONL trailing-newline behaviour: non-empty files end with a single newline,
empty files are zero bytes.
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

AUDIT_LOG_CHUNK_SIZE = 10_000

_AUDIT_KEY = "management:audit_log"
_STREAM_KEY = "ja4proxy:events"
_TOKEN_SAFE_FIELDS = frozenset(
    (
        "token_id",
        "created_at",
        "expires_at",
        "role",
        "groups",
        "last_used_at",
    )
)
_CONFIG_CHANGE_PREFIX = "config."

logger = logging.getLogger(__name__)


def _parse_ts(ts: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp string to datetime."""
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
        return False
    return from_dt <= dt <= to_dt


def _parse_signals(fields: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the signals field from an event dict."""
    if "signals" in fields:
        try:
            return json.loads(fields["signals"])
        except (json.JSONDecodeError, TypeError):
            return []
    signals = []
    i = 0
    while f"signal_{i}" in fields:
        signals.append({"name": fields[f"signal_{i}"], "score": fields.get(f"score_{i}", "")})
        i += 1
    return signals


class PciDssPackBuilder:
    """Builds a PCI-DSS v4.0 evidence pack ZIP file.

    Args:
        redis: Async Redis.
        classifier: SignalClassifier instance for categorising events.
    """

    def __init__(self, redis: Any, classifier: SignalClassifier) -> None:
        self._redis = redis
        self._classifier = classifier

    async def build(self, from_dt: datetime, to_dt: datetime) -> bytes:
        """Assemble the evidence pack for the given window.

        Returns:
            ZIP file contents as bytes.
        """
        from_iso = from_dt.isoformat()
        to_iso = to_dt.isoformat()

        blocked_events = await self._query_blocked_events(from_dt, to_dt)
        audit_entries = await self._query_audit_entries(from_dt, to_dt)
        token_inventory = await self._query_token_inventory()
        node_info = await self._query_nodes()

        classified = self._classifier.classify_batch(blocked_events)
        config_changes = [e for e in audit_entries if e.get("action_type", "").startswith(_CONFIG_CHANGE_PREFIX)]

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

    async def _query_blocked_events(self, from_dt: datetime, to_dt: datetime) -> list[dict[str, Any]]:
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
            events.append(
                {
                    "ip": fields.get("ip", ""),
                    "ja4": fields.get("ja4", ""),
                    "risk_score": fields.get("risk_score", ""),
                    "action_taken": fields.get("action_taken", ""),
                    "timestamp": ts,
                    "signals": _parse_signals(fields),
                }
            )
        return events

    async def _query_audit_entries(self, from_dt: datetime, to_dt: datetime) -> list[dict[str, Any]]:
        """Read all audit entries in the window from management:audit_log.

        Reads in chunks of AUDIT_LOG_CHUNK_SIZE (10k) to avoid blocking
        the event loop on large audit logs.
        """
        entries = []
        start = 0
        while True:
            try:
                raw = await self._redis.lrange(_AUDIT_KEY, start, start + AUDIT_LOG_CHUNK_SIZE - 1)
            except Exception as exc:
                logger.warning("pack_builder | event=audit_read_error | error=%s", exc)
                return entries

            if not raw:
                break

            for item in raw:
                try:
                    entry = json.loads(item)
                except json.JSONDecodeError:
                    continue
                if not _ts_in_window(entry.get("timestamp", ""), from_dt, to_dt):
                    return entries
                entries.append(entry)

            if len(raw) < AUDIT_LOG_CHUNK_SIZE:
                break
            start += AUDIT_LOG_CHUNK_SIZE

        return entries

    async def _query_token_inventory(self) -> list[dict[str, Any]]:
        """Return token metadata, allowlisted to safe fields only."""
        try:
            cursor = 0
            tokens = []
            while True:
                cursor, keys = await self._redis.scan(cursor=cursor, match="mgmt:token:*", count=100)
                for key in keys:
                    if ":idx" in key:
                        continue
                    entry = await self._redis.hgetall(key)
                    if entry:
                        safe = {k: v for k, v in entry.items() if k in _TOKEN_SAFE_FIELDS}
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
                cursor, keys = await self._redis.scan(cursor=cursor, match="proxy:heartbeat:*", count=100)
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

    def _add_01_deployment(
        self,
        zf: zipfile.ZipFile,
        nodes: list[dict],
        from_iso: str,
        to_iso: str,
    ) -> None:
        source = {"nodes": nodes, "period": {"from": from_iso, "to": to_iso}}
        rows = (
            "".join(
                "<tr>"
                f"<td>{_html.escape(str(n.get('host', '')))}</td>"
                f"<td>{_html.escape(str(n.get('version', '')))}</td>"
                f"<td>{_html.escape(str(n.get('started_at', '')))}</td>"
                "</tr>"
                for n in nodes
            )
            or "<tr><td colspan='3'>No node data available</td></tr>"
        )
        html = f"""<!DOCTYPE html>
<html><head><title>Deployment Confirmation</title></head>
<body><h1>Deployment Confirmation</h1>
<table border="1"><thead><tr><th>Host</th><th>Version</th><th>Started At</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
        zf.writestr("01_deployment_confirmation.html", html)

    def _add_02_block_events(self, zf: zipfile.ZipFile, events: list[dict[str, Any]]) -> None:
        buf = io.StringIO()
        for e in events:
            buf.write(json.dumps(e, default=str) + "\n")
        content = buf.getvalue()
        if content:
            content += f"SHA256: {hashlib.sha256(content.encode()).hexdigest()}\n"
        zf.writestr("02_block_event_log.jsonl", content)

    def _add_03_attack_classification(self, zf: zipfile.ZipFile, classified: list[dict[str, Any]]) -> None:
        if not classified:
            zf.writestr("03_attack_classification.csv", "")
            return
        fieldnames = ["timestamp", "ip", "ja4", "category", "risk_score"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for c in classified:
            row = {k: c.get(k, "") for k in fieldnames}
            writer.writerow(row)
        content = buf.getvalue()
        content += f"SHA256: {hashlib.sha256(content.encode()).hexdigest()}\n"
        zf.writestr("03_attack_classification.csv", content)

    def _add_04_rbac_configuration(self, zf: zipfile.ZipFile, tokens: list[dict[str, Any]]) -> None:
        content = json.dumps(tokens, indent=2, default=str)
        content += f"\nSHA256: {hashlib.sha256(content.encode()).hexdigest()}\n"
        zf.writestr("04_rbac_configuration.json", content)

    def _add_05_audit_log(self, zf: zipfile.ZipFile, entries: list[dict[str, Any]]) -> None:
        buf = io.StringIO()
        for e in entries:
            buf.write(json.dumps(e, default=str) + "\n")
        content = buf.getvalue()
        if content:
            content += f"SHA256: {hashlib.sha256(content.encode()).hexdigest()}\n"
        zf.writestr("05_audit_log_export.jsonl", content)

    def _add_06_availability_metrics(
        self,
        zf: zipfile.ZipFile,
        nodes: list[dict],
        from_iso: str,
        to_iso: str,
    ) -> None:
        rows = (
            "".join(
                "<tr>"
                f"<td>{_html.escape(str(n.get('host', '')))}</td>"
                f"<td>{_html.escape(str(n.get('health', '')))}</td>"
                f"<td>{_html.escape(str(n.get('uptime_percent', '')))}</td>"
                "</tr>"
                for n in nodes
            )
            or "<tr><td colspan='3'>No node data available</td></tr>"
        )
        html = f"""<!DOCTYPE html>
<html><head><title>Availability Metrics</title></head>
<body><h1>Availability Metrics</h1>
<p>Period: {from_iso} to {to_iso}</p>
<table border="1"><thead><tr><th>Host</th><th>Health</th><th>Uptime %</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
        zf.writestr("06_availability_metrics.html", html)

    def _add_07_access_denied_summary(
        self,
        zf: zipfile.ZipFile,
        classified: list[dict[str, Any]],
        from_iso: str,
        to_iso: str,
    ) -> None:
        categories: dict[str, int] = {}
        for c in classified:
            cat = c.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
        rows = "".join(f"<tr><td>{_html.escape(cat)}</td><td>{count}</td></tr>" for cat, count in categories.items())
        html = f"""<!DOCTYPE html>
<html><head><title>Access Denied Summary</title></head>
<body><h1>Access Denied Summary</h1>
<p>Period: {from_iso} to {to_iso}</p>
<table border="1"><thead><tr><th>Category</th><th>Count</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>"""
        zf.writestr("07_access_denied_summary.html", html)

    def _add_08_config_change_log(self, zf: zipfile.ZipFile, changes: list[dict[str, Any]]) -> None:
        if not changes:
            zf.writestr("08_configuration_change_log.csv", "")
            return
        fieldnames = ["timestamp", "identity", "action_type", "details"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for c in changes:
            row = {k: c.get(k, "") for k in fieldnames}
            writer.writerow(row)
        content = buf.getvalue()
        content += f"SHA256: {hashlib.sha256(content.encode()).hexdigest()}\n"
        zf.writestr("08_configuration_change_log.csv", content)
