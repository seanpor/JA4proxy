"""GDPR data retention purge — Phase 84.

Enforces configurable retention windows across all Redis data stores that
hold personal data (IP addresses).  Designed to be called either:
- On a schedule via the Management API's background task (driven by
  ``gdpr.purge_schedule_cron`` in proxy.yml), or
- On demand via ``POST /api/v1/compliance/purge-expired`` or
  ``ja4proxy-cli compliance purge-expired``.

Fail-open: an error in one data category is recorded in the summary but
does not abort the others.  The caller receives a complete summary with
an ``errors`` list.

Redis keys touched
------------------
Read/trim:
    ja4proxy:events     (Stream)      connection event log
    beacon:*:*          (SortedSet)   beaconing timestamps per IP+JA4
    rv:*                (Hash)        return-visitor records per IP
    reporting:monthly:* (Hash)        monthly aggregates for trend charts

Written:
    gdpr:purge:last_run     (String)  ISO-8601 timestamp of last run
    gdpr:purge:last_summary (String)  JSON of most recent PurgeSummary
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


def _subtract_months(dt: datetime, months: int) -> datetime:
    """Subtract *months* calendar months from *dt*, clamping to end-of-month."""
    year = dt.year
    month = dt.month - months
    while month <= 0:
        month += 12
        year -= 1
    # Clamp day to valid range for the target month (e.g. Mar 31 - 1 month → Feb 28)
    import calendar
    max_day = calendar.monthrange(year, month)[1]
    return dt.replace(year=year, month=month, day=min(dt.day, max_day))

logger = logging.getLogger(__name__)

_STREAM_KEY = "ja4proxy:events"
_LAST_RUN_KEY = "gdpr:purge:last_run"
_LAST_SUMMARY_KEY = "gdpr:purge:last_summary"
_SUMMARY_TTL_SECONDS = 172_800  # 48 h


@dataclass
class PurgeSummary:
    """Summary of a single GDPR purge run."""

    connection_events_deleted: int = 0
    beaconing_records_cleaned: int = 0
    rv_hashes_deleted: int = 0
    monthly_aggregates_deleted: int = 0
    errors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "connection_events_deleted": self.connection_events_deleted,
            "beaconing_records_cleaned": self.beaconing_records_cleaned,
            "rv_hashes_deleted": self.rv_hashes_deleted,
            "monthly_aggregates_deleted": self.monthly_aggregates_deleted,
            "errors": self.errors,
        }


class GDPRPurge:
    """GDPR data retention purge.

    Args:
        redis: Async Redis client (aioredis / fakeredis).
        config: Optional config dict.  Recognised keys (with defaults):
            connection_log_retention_days     (int, default 90)
            analytics_retention_days          (int, default 90)
            monthly_aggregate_retention_months (int, default 24)
    """

    STREAM_KEY = _STREAM_KEY
    LAST_RUN_KEY = _LAST_RUN_KEY
    LAST_SUMMARY_KEY = _LAST_SUMMARY_KEY

    def __init__(self, redis: Any, config: dict[str, Any] | None = None) -> None:
        cfg = config or {}
        self._redis = redis
        self._connection_retention_days: int = int(
            cfg.get("connection_log_retention_days", 90)
        )
        self._analytics_retention_days: int = int(
            cfg.get("analytics_retention_days", 90)
        )
        self._monthly_retention_months: int = int(
            cfg.get("monthly_aggregate_retention_months", 24)
        )

    # ── Public API ────────────────────────────────────────────────────────────

    async def run(self) -> PurgeSummary:
        """Run all purge categories, fail-open per category.

        Always writes ``gdpr:purge:last_run`` and ``gdpr:purge:last_summary``
        to Redis on completion, even if some categories errored.
        """
        now = datetime.now(timezone.utc)
        summary = PurgeSummary()

        conn_cutoff_ms = int(
            (now - timedelta(days=self._connection_retention_days)).timestamp() * 1000
        )
        analytics_cutoff_ms = int(
            (now - timedelta(days=self._analytics_retention_days)).timestamp() * 1000
        )
        analytics_cutoff_dt = now - timedelta(days=self._analytics_retention_days)

        oldest_month = _subtract_months(now, self._monthly_retention_months).strftime(
            "%Y-%m"
        )

        for category, coro in [
            ("stream", self._purge_stream(conn_cutoff_ms)),
            ("beaconing", self._purge_beaconing(analytics_cutoff_ms)),
            ("rv_hashes", self._purge_rv_hashes(analytics_cutoff_dt)),
            ("monthly_aggregates", self._purge_monthly_aggregates(oldest_month)),
        ]:
            try:
                count = await coro
                if category == "stream":
                    summary.connection_events_deleted = count
                elif category == "beaconing":
                    summary.beaconing_records_cleaned = count
                elif category == "rv_hashes":
                    summary.rv_hashes_deleted = count
                elif category == "monthly_aggregates":
                    summary.monthly_aggregates_deleted = count
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "purge | event=category_error | category=%s | error=%s",
                    category,
                    exc,
                )
                summary.errors.append({"category": category, "message": str(exc)})

        await self._write_completion(now, summary)
        return summary

    # ── Private purge methods ─────────────────────────────────────────────────

    async def _purge_stream(self, cutoff_ms: int) -> int:
        """Trim ja4proxy:events stream, removing entries older than cutoff_ms.

        Uses XTRIM with MINID so only entries with an ID older than the cutoff
        are removed.  Returns the number of entries deleted.
        """
        try:
            before = await self._redis.xlen(self.STREAM_KEY)
        except Exception:
            before = 0

        # MINID trims entries whose ID (timestamp part) < cutoff_ms
        minid = f"{cutoff_ms}-0"
        await self._redis.xtrim(self.STREAM_KEY, minid=minid)

        try:
            after = await self._redis.xlen(self.STREAM_KEY)
        except Exception:
            after = before

        deleted = max(0, before - after)
        logger.info("purge | event=stream_trimmed | deleted=%d | minid=%s", deleted, minid)
        return deleted

    async def _purge_beaconing(self, cutoff_ms: int) -> int:
        """Remove beaconing sorted-set members older than cutoff_ms.

        Scans for ``beacon:*`` keys and removes members with score < cutoff_ms.
        Returns total members deleted across all matched keys.
        """
        total = 0
        cursor = 0
        while True:
            cursor, keys = await self._redis.scan(
                cursor=cursor, match="beacon:*", count=100
            )
            for key in keys:
                try:
                    removed = await self._redis.zremrangebyscore(
                        key, "-inf", cutoff_ms - 1
                    )
                    total += removed
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "purge | event=beacon_key_error | key=%s | error=%s", key, exc
                    )
            if cursor == 0:
                break

        logger.info("purge | event=beaconing_cleaned | total=%d", total)
        return total

    async def _purge_rv_hashes(self, cutoff_dt: datetime) -> int:
        """Delete return-visitor hashes whose first_seen predates cutoff_dt.

        Scans ``rv:*`` keys.  Deletes the whole key if the ``first_seen`` Hash
        field (ISO-8601 string) is older than cutoff_dt.  Skips keys with no
        ``first_seen`` field (cannot determine age → preserve them).
        Returns count of keys deleted.
        """
        deleted = 0
        cursor = 0
        while True:
            cursor, keys = await self._redis.scan(
                cursor=cursor, match="rv:*", count=100
            )
            for key in keys:
                try:
                    first_seen_str = await self._redis.hget(key, "first_seen")
                    if first_seen_str is None:
                        continue
                    first_seen = datetime.fromisoformat(
                        first_seen_str.replace("Z", "+00:00")
                    )
                    if first_seen.tzinfo is None:
                        first_seen = first_seen.replace(tzinfo=timezone.utc)
                    if first_seen < cutoff_dt:
                        await self._redis.delete(key)
                        deleted += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "purge | event=rv_key_error | key=%s | error=%s", key, exc
                    )
            if cursor == 0:
                break

        logger.info("purge | event=rv_hashes_deleted | count=%d", deleted)
        return deleted

    async def _purge_monthly_aggregates(self, oldest_allowed: str) -> int:
        """Delete reporting:monthly:{YYYY-MM} hashes older than oldest_allowed.

        Args:
            oldest_allowed: Oldest YYYY-MM string to keep.  Keys with a YYYY-MM
                *strictly less than* this string are deleted.  String comparison
                works correctly for ISO month strings.

        Returns:
            Count of Hash keys deleted.
        """
        deleted = 0
        cursor = 0
        while True:
            cursor, keys = await self._redis.scan(
                cursor=cursor, match="reporting:monthly:*", count=100
            )
            for key in keys:
                # key format: "reporting:monthly:YYYY-MM"
                parts = key.split(":")
                if len(parts) < 3:
                    continue
                month_str = parts[2]  # "YYYY-MM"
                if month_str < oldest_allowed:
                    await self._redis.delete(key)
                    deleted += 1
            if cursor == 0:
                break

        logger.info("purge | event=monthly_aggregates_deleted | count=%d", deleted)
        return deleted

    # ── Completion helpers ────────────────────────────────────────────────────

    async def _write_completion(self, now: datetime, summary: PurgeSummary) -> None:
        """Write last_run and last_summary keys to Redis."""
        ts = now.isoformat()
        try:
            await self._redis.set(self.LAST_RUN_KEY, ts)
            await self._redis.set(
                self.LAST_SUMMARY_KEY,
                json.dumps(summary.to_dict()),
                ex=_SUMMARY_TTL_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "purge | event=completion_write_failed | error=%s", exc
            )
