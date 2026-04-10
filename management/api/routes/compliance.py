"""Compliance reporting endpoints — Phase 84.

Routes
------
POST   /api/v1/compliance/pci-dss-pack        — download PCI-DSS evidence pack (ZIP)
POST   /api/v1/compliance/report              — download executive report (PDF or HTML)
GET    /api/v1/compliance/dsar/{ip}           — DSAR: export all data for an IP
DELETE /api/v1/compliance/dsar/{ip}           — DSAR: erase personal data for an IP
POST   /api/v1/compliance/purge-expired       — run GDPR retention purge
GET    /api/v1/compliance/signal-categories   — return configured signal→category mapping

Role requirements
-----------------
Auditor+   : GET DSAR export, POST pci-dss-pack, POST report, GET signal-categories
Admin only : DELETE DSAR erase, POST purge-expired
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

from management.compliance.classifier import SignalClassifier
from management.compliance.pack_builder import PciDssPackBuilder
from management.compliance.purge import GDPRPurge
from management.compliance.report_renderer import (
    AvailabilityMetric,
    ReportData,
    ReportRenderer,
    TrendMonth,
    WeasyPrintNotAvailable,
)

from ..audit_utils import write_audit
from ..auth import require_role
from ..models import Role
from ..redis_client import get_redis

logger = logging.getLogger(__name__)

router = APIRouter(tags=["compliance"])

_STREAM_KEY = "ja4proxy:events"
_AUDIT_KEY = "management:audit_log"

# Logo validation limits — the base64 payload carries ~33% overhead, so
# 1.4MB of base64 ≈ 1MB of binary.  The field docs say "≤1MB"; enforce it.
_LOGO_MAX_BASE64_BYTES = 1_400_000
_LOGO_MAX_DECODED_BYTES = 1_048_576  # 1 MiB

# Magic byte sniffing — covers the formats the report template can actually
# render (PNG, JPEG, GIF, SVG).  Anything else is rejected.
_LOGO_MIME_SNIFF: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
]


def _validate_logo(raw_base64: Optional[str]) -> str:
    """Validate a base64-encoded logo and return a data URI, or "" on failure.

    Enforces:
      * size cap (≤1MB decoded)
      * proper base64 encoding
      * magic-byte sniffing for PNG / JPEG / GIF / SVG (anything else rejected)
      * correct MIME type in the returned data URI

    Failures are logged with a specific reason so operators can diagnose
    missing logos.  Returns "" (empty string) on any validation failure —
    the route continues without a logo rather than failing the whole report.
    """
    if not raw_base64:
        return ""
    if len(raw_base64) > _LOGO_MAX_BASE64_BYTES:
        logger.warning(
            "compliance | event=logo_rejected | reason=too_large | base64_bytes=%d",
            len(raw_base64),
        )
        return ""
    try:
        decoded = base64.b64decode(raw_base64, validate=True)
    except Exception as exc:
        logger.warning(
            "compliance | event=logo_rejected | reason=invalid_base64 | error=%s",
            exc,
        )
        return ""
    if len(decoded) > _LOGO_MAX_DECODED_BYTES:
        logger.warning(
            "compliance | event=logo_rejected | reason=decoded_too_large | decoded_bytes=%d",
            len(decoded),
        )
        return ""
    mime: Optional[str] = None
    for magic, candidate_mime in _LOGO_MIME_SNIFF:
        if decoded.startswith(magic):
            mime = candidate_mime
            break
    if mime is None:
        # SVG is text — sniff for the opening XML or svg tag.
        head = decoded[:512].lstrip()
        if head.startswith(b"<?xml") or head.lower().startswith(b"<svg"):
            mime = "image/svg+xml"
    if mime is None:
        logger.warning(
            "compliance | event=logo_rejected | reason=unknown_format | "
            "head=%r",
            decoded[:16],
        )
        return ""
    return f"data:{mime};base64,{raw_base64}"


# ── Request / response models ─────────────────────────────────────────────────


class PciDssPackRequest(BaseModel):
    from_date: str = Field(..., description="ISO-8601 start of evidence period (e.g. 2026-01-01)")
    to_date: str = Field(..., description="ISO-8601 end of evidence period (e.g. 2026-03-31)")
    format: str = Field(default="pdf+jsonl", description="pdf+jsonl | pdf | jsonl")


class ReportRequest(BaseModel):
    period_label: str = Field(default="", description="Human-readable label (e.g. 'Q1 2026')")
    from_date: str = Field(..., description="ISO-8601 start of report period")
    to_date: str = Field(..., description="ISO-8601 end of report period")
    format: str = Field(default="html", description="html | pdf")
    include_shadow_mode: bool = Field(default=False)
    logo_base64: Optional[str] = Field(default=None, description="Base64-encoded PNG/SVG logo ≤1MB")
    cost_per_connection_usd: float = Field(default=0.50)


class DSARErase(BaseModel):
    ticket: str = Field(..., min_length=1, description="ITSM ticket reference (mandatory)")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _parse_date(date_str: str, field_name: str) -> datetime:
    """Parse ISO-8601 date string into an aware datetime (UTC).

    Raises HTTPException(422) on invalid input.
    """
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # Try full ISO fromisoformat as last resort
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=f"Invalid date format for '{field_name}': {date_str!r}. "
               "Use ISO-8601 (e.g. '2026-01-01' or '2026-01-01T00:00:00Z').",
    )


def _parse_ts(ts: str) -> Optional[datetime]:
    """Best-effort parse of a stored ISO-8601 timestamp into aware UTC.

    Returns None if *ts* is empty or unparseable.  Accepts ``Z`` suffix, naive
    strings (assumed UTC), and offset-aware strings.  Used for window filters
    — NEVER compare raw ISO strings lexicographically: producers emit
    timestamps in multiple formats (``...Z``, ``...+00:00``, naive) and
    lex-compare silently drops events from the window.
    """
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _ts_in_window(ts: str, from_dt: datetime, to_dt: datetime) -> bool:
    """Return True iff *ts* parses to a datetime within [from_dt, to_dt].

    Unparseable or missing timestamps are included (fail-open for compliance
    — a missing timestamp should not silently drop audit evidence)."""
    dt = _parse_ts(ts)
    if dt is None:
        return True
    return from_dt <= dt <= to_dt


def _count_months_in_range(from_dt: datetime, to_dt: datetime) -> int:
    """Return the number of distinct YYYY-MM buckets covered by [from_dt, to_dt].

    Used to detect "every month missing" when deciding whether to fall back
    from monthly aggregates to live-stream data.
    """
    if to_dt < from_dt:
        return 0
    months = (to_dt.year - from_dt.year) * 12 + (to_dt.month - from_dt.month) + 1
    return max(1, months)


# Module-level classifier cache — avoids rebuilding the default mapping on
# every request.  Refreshed on SIGHUP by the config loader in a later phase.
_classifier_instance: SignalClassifier | None = None


def _get_classifier() -> SignalClassifier:
    """Return a cached SignalClassifier loaded with ``reporting.signal_categories``.

    The classifier is cheap to build but even so, creating one per request is
    wasteful and — more importantly — makes the ``/signal-categories`` route
    lie about overrides because it constructs a bare default classifier.
    Load once from the running config.
    """
    global _classifier_instance
    if _classifier_instance is None:
        cfg = _load_signal_categories_config()
        _classifier_instance = SignalClassifier(cfg)
    return _classifier_instance


def _reset_classifier_cache() -> None:
    """Test-only hook: force the classifier to be rebuilt on next access."""
    global _classifier_instance
    _classifier_instance = None


def _load_signal_categories_config() -> dict[str, Any] | None:
    """Load ``reporting.signal_categories`` from proxy.yml, failing open.

    Returns None if the config file cannot be read or the key is absent —
    SignalClassifier then uses pure defaults.
    """
    try:
        from pathlib import Path

        import yaml  # type: ignore

        # config/proxy.yml relative to repo root
        candidate = Path(__file__).resolve().parents[3] / "config" / "proxy.yml"
        if not candidate.exists():
            return None
        with candidate.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        reporting = data.get("reporting") or {}
        sig_cats = reporting.get("signal_categories")
        if isinstance(sig_cats, dict) and sig_cats:
            return sig_cats
        return None
    except Exception as exc:
        logger.warning(
            "compliance | event=signal_categories_load_failed | error=%s", exc
        )
        return None


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/api/v1/compliance/pci-dss-pack")
async def generate_pci_dss_pack(
    body: PciDssPackRequest,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> Response:
    """Generate and download the PCI-DSS v4.0 evidence pack as a ZIP file.

    Returns a ZIP containing 8 artefacts (PHASE_84.md §5.2).
    The ZIP is streamed synchronously; timeout is 120 seconds on the client side.
    """
    from_dt = _parse_date(body.from_date, "from_date")
    to_dt = _parse_date(body.to_date, "to_date")

    if to_dt <= from_dt:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="to_date must be after from_date",
        )

    fmt = body.format if body.format in ("pdf+jsonl", "pdf", "jsonl") else "pdf+jsonl"

    builder = PciDssPackBuilder(redis, fmt=fmt)
    try:
        zip_bytes = await builder.build(from_dt, to_dt)
    except Exception as exc:
        logger.error("compliance | event=pack_build_error | error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to build evidence pack: {exc}",
        ) from exc

    from_label = from_dt.strftime("%Y-%m-%d")
    to_label = to_dt.strftime("%Y-%m-%d")
    filename = f"pci-dss-v4-{from_label}-{to_label}.zip"

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/api/v1/compliance/report")
async def generate_report(
    body: ReportRequest,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> Response:
    """Generate and download the executive compliance report (HTML or PDF).

    PDF format requires WeasyPrint and system libraries in the management
    container.  Use ``format=html`` for CI-friendly generation.
    """
    from_dt = _parse_date(body.from_date, "from_date")
    to_dt = _parse_date(body.to_date, "to_date")

    if to_dt <= from_dt:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="to_date must be after from_date",
        )

    fmt = body.format if body.format in ("html", "pdf") else "html"

    # Build report data from Redis
    data = await _build_report_data(redis, from_dt, to_dt, body)

    # Render
    renderer = ReportRenderer()
    try:
        content, content_type = renderer.render(data, fmt=fmt)
    except WeasyPrintNotAvailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc

    from_label = from_dt.strftime("%Y-%m-%d")
    to_label = to_dt.strftime("%Y-%m-%d")
    ext = "pdf" if fmt == "pdf" else "html"
    filename = f"ja4proxy-report-{from_label}-{to_label}.{ext}"

    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/api/v1/compliance/dsar/{ip:path}")
async def dsar_export(
    ip: str,
    current_user=Depends(require_role(Role.auditor)),
    redis=Depends(get_redis),
) -> Response:
    """GDPR Article 15 — Data Subject Access Request export.

    Returns all stored personal data for the given IP address across all Redis
    data categories.  Never returns 404 — returns empty arrays for categories
    with no data.
    """
    exported_at = datetime.now(timezone.utc).isoformat()

    # Collect data from each category
    connection_history = await _dsar_connection_history(redis, ip)
    ban_history = await _dsar_ban_history(redis, ip)
    watchlist_entries = await _dsar_watchlist_entries(redis, ip)
    beaconing_records = await _dsar_beaconing_records(redis, ip)
    fingerprint_associations = await _dsar_fingerprint_associations(redis, ip)

    payload = {
        "subject_ip": ip,
        "exported_at": exported_at,
        "legal_basis": "GDPR Article 15 — Right of Access",
        "data_categories": {
            "connection_history": connection_history,
            "ban_history": ban_history,
            "watchlist_entries": watchlist_entries,
            "beaconing_records": beaconing_records,
            "fingerprint_associations": fingerprint_associations,
        },
        "retention_periods": {
            "connection_history": "90 days (legitimate interest — security)",
            "ban_history": "365 days after expiry (legitimate interest)",
            "beaconing_records": "24 hours (legitimate interest)",
            "fingerprint_associations": "90 days (legitimate interest)",
            "audit_trail": "7 years (legal obligation — not exportable, not erasable)",
        },
    }

    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
    )


@router.delete("/api/v1/compliance/dsar/{ip:path}")
async def dsar_erase(
    ip: str,
    body: DSARErase,
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    redis=Depends(get_redis),
) -> Response:
    """GDPR Article 17 — Right to Erasure.

    Erases all personal data for the IP except:
    - Active security bans (legitimate interest override while ban is active)
    - Audit log entries (legal obligation — 7 year retention)

    The erasure action itself is written to the audit log.
    """
    identity, role = current_user
    erased_keys: list[str] = []
    skipped: list[dict[str, Any]] = []

    # 1. rv:{ip} — return-visitor hash
    rv_key = f"rv:{ip}"
    if await redis.exists(rv_key):
        await redis.delete(rv_key)
        erased_keys.append(rv_key)

    # 2. beacon:{ip}:* — beaconing sorted sets
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor=cursor, match=f"beacon:{ip}:*", count=100)
        for key in keys:
            await redis.delete(key)
            erased_keys.append(key)
        if cursor == 0:
            break

    # 3. Watchlist entries — scan watchlist:entry:* for ip matches
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor=cursor, match="watchlist:entry:*", count=100)
        for key in keys:
            entry_ip = await redis.hget(key, "entry")
            if entry_ip == ip:
                entry_id = key.split(":")[-1]
                # Remove from index
                await redis.srem("watchlist:idx", entry_id)
                await redis.delete(key)
                erased_keys.append(key)
        if cursor == 0:
            break

    # 4. Active ban — exempt, record as skipped.
    #
    # Fetch reason and TTL together so the ban state is coherent.  A separate
    # TTL-then-GET can race the ban expiring mid-check, producing an audit
    # record that says "skipped" for a key that no longer exists.  Use a
    # pipeline where supported; fall back to sequential and re-fetch TTL only
    # if reason is present.  If reason is None after either path, the ban is
    # absent and we do not record a skip.
    ban_key = f"ban:{ip}"
    ban_reason: Any = None
    ban_ttl: int = -2
    try:
        pipe = redis.pipeline()
        pipe.get(ban_key)
        pipe.ttl(ban_key)
        result = await pipe.execute()
        ban_reason = result[0]
        ban_ttl = result[1]
    except Exception:
        ban_reason = await redis.get(ban_key)
        if ban_reason is not None:
            ban_ttl = await redis.ttl(ban_key)

    if ban_reason is not None and (ban_ttl > 0 or ban_ttl == -1):
        expires_note = f"TTL {ban_ttl}s" if ban_ttl > 0 else "persistent"
        skipped.append({
            "key": ban_key,
            "reason": "active security ban — legitimate interest override",
            "expires_at": expires_note,
        })

    # 5. Write erasure to audit log (exempt from erasure — legal obligation).
    # Preserve the full skipped list — not just its length — so auditors can
    # prove *which* key was skipped and *why* (compliance evidence).
    await write_audit(
        redis,
        actor_id=identity,
        actor_ip=_client_ip(request),
        action_type="compliance.dsar_erasure",
        resource_type="ip",
        resource_id=ip,
        after_value={
            "ticket": body.ticket,
            "erased_keys": erased_keys,
            "skipped": skipped,
        },
        role=role.value,
    )

    payload = {
        "erased_ip": ip,
        "ticket": body.ticket,
        "erased_keys": erased_keys,
        "skipped": skipped,
        "audit_log_note": (
            "Audit entries for this IP are exempt from erasure (legal obligation). "
            "They remain and record this erasure event."
        ),
    }

    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
    )


@router.post("/api/v1/compliance/purge-expired")
async def run_purge(
    request: Request,
    current_user=Depends(require_role(Role.admin)),
    redis=Depends(get_redis),
) -> Response:
    """Run the GDPR data retention purge immediately.

    Designed to be called by the GDPR purge scheduler in the Management API
    background task, by ``ja4proxy-cli compliance purge-expired``, or by a
    system cron job.

    Returns a summary of what was purged.  Exit codes for the CLI:
    - errors list empty → success
    - errors list non-empty → partial errors (CLI exits 2)
    """
    identity, role = current_user
    purge = GDPRPurge(redis)

    try:
        summary = await purge.run()
    except Exception as exc:
        logger.error("compliance | event=purge_failed | error=%s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Purge failed: {exc}",
        ) from exc

    started_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "purged": summary.to_dict(),
    }

    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
    )


@router.get("/api/v1/compliance/signal-categories")
async def get_signal_categories(
    current_user=Depends(require_role(Role.auditor)),
) -> Response:
    """Return the active signal→category mapping used by the classifier.

    Useful for operators to understand what attack categories are produced and
    to verify custom overrides are applied correctly.  Uses the cached
    classifier loaded from ``reporting.signal_categories`` in proxy.yml so
    overrides are reflected (previously this route constructed a bare default
    classifier and silently misreported overrides).
    """
    clf = _get_classifier()
    return Response(
        content=json.dumps(clf.categories, indent=2),
        media_type="application/json",
    )


# ── DSAR data collectors ──────────────────────────────────────────────────────


async def _dsar_connection_history(redis: Any, ip: str) -> list[dict]:
    """Read connection events for this IP from the stream."""
    try:
        raw = await redis.xrange(_STREAM_KEY)
    except Exception:
        return []
    return [
        {
            "timestamp": f.get("timestamp", ""),
            "action": f.get("action_taken", ""),
            "ja4": f.get("ja4", ""),
            "risk_score": f.get("risk_score", ""),
        }
        for _, f in raw
        if f.get("ip") == ip
    ]


async def _dsar_ban_history(redis: Any, ip: str) -> list[dict]:
    """Return active ban info for this IP, if any."""
    ban_key = f"ban:{ip}"
    reason = await redis.get(ban_key)
    if reason is None:
        return []
    ttl = await redis.ttl(ban_key)
    active = ttl > 0 or ttl == -1
    erasure_exempt = active
    return [{
        "active": active,
        "reason": reason,
        "ttl_remaining": ttl if ttl > 0 else None,
        "erasure_exempt": erasure_exempt,
        "erasure_exempt_reason": (
            "Active security ban — legitimate interest override" if active else None
        ),
    }]


async def _dsar_watchlist_entries(redis: Any, ip: str) -> list[dict]:
    """Return watchlist entries for this IP."""
    entries = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor=cursor, match="watchlist:entry:*", count=100)
        for key in keys:
            entry_ip = await redis.hget(key, "entry")
            if entry_ip == ip:
                data = await redis.hgetall(key)
                entries.append(data)
        if cursor == 0:
            break
    return entries


async def _dsar_beaconing_records(redis: Any, ip: str) -> list[dict]:
    """Return beaconing sorted-set entries for this IP."""
    records = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor=cursor, match=f"beacon:{ip}:*", count=100)
        for key in keys:
            members = await redis.zrange(key, 0, -1, withscores=True)
            for member, score in members:
                records.append({"key": key, "timestamp_ms": score, "member": member})
        if cursor == 0:
            break
    return records


async def _dsar_fingerprint_associations(redis: Any, ip: str) -> list[dict]:
    """Return JA4 fingerprints seen for this IP from the event stream."""
    try:
        raw = await redis.xrange(_STREAM_KEY)
    except Exception:
        return []
    seen: dict[str, dict] = {}
    for _, fields in raw:
        if fields.get("ip") != ip:
            continue
        ja4 = fields.get("ja4", "")
        if not ja4:
            continue
        ts = fields.get("timestamp", "")
        if ja4 not in seen:
            seen[ja4] = {"ja4": ja4, "first_seen": ts, "last_seen": ts}
        else:
            if ts < seen[ja4]["first_seen"]:
                seen[ja4]["first_seen"] = ts
            if ts > seen[ja4]["last_seen"]:
                seen[ja4]["last_seen"] = ts
    return list(seen.values())


# ── Report data builder ───────────────────────────────────────────────────────


async def _build_report_data(
    redis: Any,
    from_dt: datetime,
    to_dt: datetime,
    body: ReportRequest,
) -> ReportData:
    """Assemble ReportData from Redis monthly aggregates + live queries."""
    from_iso = from_dt.isoformat()
    to_iso = to_dt.isoformat()

    # Try monthly aggregate first.  Only fall back to live stream when *every*
    # month in the requested range is missing an aggregate — checking
    # `total == 0` would incorrectly fall through on legitimately quiet
    # windows and mix live-stream data with real aggregates elsewhere in the
    # report (see Phase 101 C2).  Counting fallback_months gives us an
    # unambiguous "aggregates completely absent" signal.
    connections_total, connections_blocked, months_using_fallback = (
        await _aggregate_from_monthly_hashes(redis, from_dt, to_dt)
    )

    expected_month_count = _count_months_in_range(from_dt, to_dt)
    if expected_month_count > 0 and len(months_using_fallback) == expected_month_count:
        # No monthly aggregate data at all → use live stream as source of truth.
        connections_total, connections_blocked = await _aggregate_from_stream(
            redis, from_dt, to_dt
        )

    # Audit entry count for the period
    audit_count = await _count_audit_entries(redis, from_dt, to_dt)

    # Category breakdown from the stream
    category_counts = await _build_category_counts(redis, from_dt, to_dt)

    # Dial setting
    dial_val = 0
    try:
        dial_str = await redis.get("config:dial")
        if dial_str:
            dial_val = int(dial_str)
    except Exception:
        pass

    # Logo — validate size, sniff magic bytes to determine MIME type, log
    # failures.  Previous implementation silently swallowed all errors,
    # hardcoded image/png regardless of content, and did not enforce a size
    # cap (allowing a caller to submit a 100MB base64 blob, which would be
    # decoded into memory, dropped, then re-interpolated into the data URI).
    logo_data_uri = _validate_logo(body.logo_base64)

    return ReportData(
        period_label=body.period_label or f"{from_dt.strftime('%Y-%m-%d')} to {to_dt.strftime('%Y-%m-%d')}",
        from_iso=from_iso,
        to_iso=to_iso,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ"),
        connections_total=connections_total,
        connections_blocked=connections_blocked,
        cost_per_connection_usd=body.cost_per_connection_usd,
        category_counts=category_counts,
        dial_setting=dial_val,
        audit_entry_count=audit_count,
        months_using_fallback=months_using_fallback,
        logo_data_uri=logo_data_uri,
    )


async def _aggregate_from_monthly_hashes(
    redis: Any, from_dt: datetime, to_dt: datetime
) -> tuple[int, int, list[str]]:
    """Sum monthly aggregate hashes across the requested period."""
    total = 0
    blocked = 0
    fallback_months: list[str] = []

    current = from_dt.replace(day=1)
    while current <= to_dt:
        month_str = current.strftime("%Y-%m")
        key = f"reporting:monthly:{month_str}"
        try:
            data = await redis.hgetall(key)
        except Exception:
            fallback_months.append(month_str)
            data = None
        if data:
            # Tolerate corrupt / non-numeric hash fields: treat as zero and
            # continue rather than abort the whole report.  A raw int() on a
            # stray "" or "n/a" crashes the entire /compliance/report call.
            try:
                total += int(data.get("connections_total", 0) or 0)
            except (TypeError, ValueError):
                logger.warning(
                    "compliance | event=monthly_aggregate_field_bad | "
                    "key=%s | field=connections_total | value=%r",
                    key, data.get("connections_total"),
                )
            try:
                blocked += int(data.get("connections_blocked", 0) or 0)
            except (TypeError, ValueError):
                logger.warning(
                    "compliance | event=monthly_aggregate_field_bad | "
                    "key=%s | field=connections_blocked | value=%r",
                    key, data.get("connections_blocked"),
                )
        elif data is not None:
            fallback_months.append(month_str)
        # Move to next month
        if current.month == 12:
            current = current.replace(year=current.year + 1, month=1)
        else:
            current = current.replace(month=current.month + 1)

    return total, blocked, fallback_months


async def _aggregate_from_stream(
    redis: Any, from_dt: datetime, to_dt: datetime
) -> tuple[int, int]:
    """Count total and blocked events from the stream (fallback for live data)."""
    try:
        raw = await redis.xrange(_STREAM_KEY)
    except Exception:
        return 0, 0

    total = 0
    blocked = 0
    for _, fields in raw:
        if not _ts_in_window(fields.get("timestamp", ""), from_dt, to_dt):
            continue
        total += 1
        if fields.get("action_taken") == "blocked":
            blocked += 1
    return total, blocked


async def _count_audit_entries(
    redis: Any, from_dt: datetime, to_dt: datetime
) -> int:
    """Count audit entries within the period."""
    try:
        raw = await redis.lrange(_AUDIT_KEY, 0, -1)
    except Exception:
        return 0

    count = 0
    for item in raw:
        try:
            entry = json.loads(item)
        except Exception:
            continue
        if _ts_in_window(entry.get("timestamp", ""), from_dt, to_dt):
            count += 1
    return count


async def _build_category_counts(
    redis: Any, from_dt: datetime, to_dt: datetime
) -> list[tuple[str, int]]:
    """Build sorted category count list from blocked stream events."""
    try:
        raw = await redis.xrange(_STREAM_KEY)
    except Exception:
        return []

    clf = _get_classifier()
    counts: dict[str, int] = {}
    for _, fields in raw:
        if not _ts_in_window(fields.get("timestamp", ""), from_dt, to_dt):
            continue
        if fields.get("action_taken") != "blocked":
            continue
        signals_raw = fields.get("signals", "[]")
        try:
            signals = json.loads(signals_raw)
        except Exception:
            signals = []
        cat = clf.classify(signals)
        counts[cat] = counts.get(cat, 0) + 1

    return sorted(counts.items(), key=lambda x: -x[1])
