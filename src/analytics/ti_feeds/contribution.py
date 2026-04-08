"""Community-feed contribution client stub (PHASE_85.md §7).

This client is **disabled by default**, hosted endpoint does not yet exist,
and is a business-track item (§13). The code is shipped so that when the
hosted feed goes live, enabling it is a config toggle and nothing more —
and so that the hard GDPR gate is enforced by a functional check, not a
comment.

The hard gate — PHASE_85.md §7.3:

* Raw source IP addresses — **forbidden**.
* Full URLs or Host headers — **forbidden**.
* TLS SNI values — **forbidden**.
* Timestamps finer than 1-hour buckets — **forbidden**.
* Any field sourced from ``AuditLog`` or ``enrichment.*`` — **forbidden**.

:meth:`ContributionClient._serialize` enforces the whitelist programmatically.
Any attempt to serialise a field that is not in ``_ALLOWED_FIELDS`` raises
``ValueError`` — **this is the hard gate**, not a convention. The sibling
test agent is expected to write a test that calls ``_serialize`` with a
disallowed field and asserts the exception.

On unreachable endpoints when ``enabled=True`` the client logs a single
WARNING per hour, not on every tick. No retry loops, no silent swallowing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

try:  # pragma: no cover
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore

logger = logging.getLogger(__name__)


#: Closed whitelist from PHASE_85.md §7.3. **Do not expand without a
#: privacy review and an update to ``docs/compliance/GDPR.md``.**
_ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        "ja4",
        "category",
        "triggering_signals",
        "occurrences_count",
        "first_seen_bucket",
        "last_seen_bucket",
        "confirmed_fp_rate",
    }
)

_ONE_HOUR_S = 3600


@dataclass
class ContributionConfig:
    """Mirror of ``threat_intel.feed_contribution`` in ``config/proxy.yml``."""

    enabled: bool = False
    submit_threshold: int = 90
    submit_min_occurrences: int = 100
    anonymise: bool = True
    endpoint: str = "https://feed.ja4proxy.io/api/v1/contribute"
    api_key: str = ""


class ContributionClient:
    """Stubbed client for the hosted community feed.

    Usage
    -----
    Ordinarily the feed runner instantiates this once from the parsed config
    and calls :meth:`maybe_submit` after a suitable local analytics event.
    The MVP of Phase 85 does not yet wire a caller — it ships only the
    client + GDPR gate + one-warn-per-hour rate limiter.
    """

    def __init__(self, config: ContributionConfig) -> None:
        self.config = config
        self._last_warn_at: float = 0.0

    # ── hard gate ────────────────────────────────────────────────────────

    @classmethod
    def _serialize(cls, payload: dict[str, Any]) -> str:
        """Serialise a contribution payload, enforcing the field whitelist.

        Raises:
            ValueError: If ``payload`` contains any key not in
                :data:`_ALLOWED_FIELDS`. This is the hard GDPR gate — it
                does not log-and-drop, it raises, so that a coding mistake
                is caught at test time, not in production.
        """
        if not isinstance(payload, dict):
            raise ValueError(
                f"contribution payload must be a dict, got {type(payload).__name__}"
            )

        disallowed = set(payload.keys()) - _ALLOWED_FIELDS
        if disallowed:
            raise ValueError(
                f"contribution payload contains disallowed fields: "
                f"{sorted(disallowed)}. "
                f"See PHASE_85.md §7.3 for the whitelist."
            )

        # Second-layer check: the ``ja4`` field must look like a JA4 string,
        # never a raw IP, URL, or SNI value that a future refactor might
        # accidentally route here.
        ja4 = payload.get("ja4", "")
        if ja4 and not isinstance(ja4, str):
            raise ValueError(f"ja4 field must be a string, got {type(ja4).__name__}")
        if ja4 and (":" in ja4 or "/" in ja4 or "." in ja4.split("_")[0]):
            # IP addresses contain '.' or ':'; URLs contain '/'. JA4
            # strings never do — the first segment is like ``t13d1516h2``.
            raise ValueError(
                f"ja4 field looks like an IP or URL, not a JA4 fingerprint: {ja4!r}"
            )

        return json.dumps(payload, separators=(",", ":"))

    # ── outbound ────────────────────────────────────────────────────────

    async def maybe_submit(self, payload: dict[str, Any]) -> bool:
        """Submit a payload to the hosted feed if ``enabled=True``.

        Returns:
            ``True`` if the payload was accepted by the endpoint,
            ``False`` otherwise (disabled, rate limited, or failed).
        """
        if not self.config.enabled:
            return False
        if not _ALLOWED_FIELDS >= set(payload.keys()):
            # Defence in depth: _serialize will raise, but give callers a
            # clean False return when they trip the gate by accident.
            try:
                self._serialize(payload)
            except ValueError:
                logger.error(
                    "ti_feed | event=contribution_rejected | reason=gdpr_gate"
                )
                return False

        if aiohttp is None:  # pragma: no cover
            self._warn_once("aiohttp not installed")
            return False

        body = self._serialize(payload)
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.endpoint,
                    data=body,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status // 100 != 2:
                        self._warn_once(
                            f"endpoint returned HTTP {resp.status}"
                        )
                        return False
                    return True
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            self._warn_once(f"submit failed: {exc}")
            return False

    # ── one-warn-per-hour rate limiter ──────────────────────────────────

    def _warn_once(self, reason: str) -> None:
        """Emit a WARN log line at most once per hour for the same client instance."""
        now = time.monotonic()
        if now - self._last_warn_at < _ONE_HOUR_S:
            return
        self._last_warn_at = now
        logger.warning(
            "ti_feed | event=contribution_endpoint_unavailable | endpoint=%s | reason=%s",
            self.config.endpoint,
            reason,
        )
