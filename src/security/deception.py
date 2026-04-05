"""Honey-fingerprint and honey-SNI deception detection (Phase 56).

Any client presenting a JA4 fingerprint or SNI hostname that appears in the
configured honey-asset lists is immediately banned.  Legitimate clients never
produce these values — a match is therefore an unambiguous APT/scanner
indicator with zero false-positive rate.

Design
------
- Checks run in the **BLOCK bypass** stage, before the risk scorer.
- A match writes ``ban:{ip}`` to Redis with the configured TTL, then returns
  a sentinel ``PipelineResult(action="silent_drop", ...)`` that tells the
  proxy to close the connection silently (no TCP RST when ``silent_drop: true``).
- If ``silent_drop: false`` is configured, the caller should send an RST.
- The Prometheus counter ``ja4proxy_deception_triggered_total`` is always
  incremented on a match, regardless of the silent_drop setting.
- Config is loaded from ``config/deception.yml`` at startup and on
  :meth:`DeceptionChecker.reload`.  If the file is absent, all checks are
  silently skipped (fail open).
- All errors fail open — a misconfigured deception.yml must not block real
  users.
"""

import logging
import os
from typing import Any

import yaml
from prometheus_client import Counter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_DECEPTION_TRIGGERED = Counter(
    "ja4proxy_deception_triggered_total",
    "Connections that matched a honey-fingerprint or honey-SNI asset",
    ["trigger"],  # "fingerprint" | "sni"
)

# ---------------------------------------------------------------------------
# DeceptionChecker
# ---------------------------------------------------------------------------

_SENTINEL_ACTION = "silent_drop"
_BAN_TAG = "APT:DECEPTION_TRIGGERED"


class DeceptionChecker:
    """Load honey-asset lists and check connections against them.

    Instantiated once per process.  Thread-safe for asyncio use — all state
    is replaced atomically on :meth:`reload`.

    Args:
        proxy_config: Full ``proxy.yml`` config dict.  Reads the
                      ``deception.config_path`` key to locate the asset file.
        redis_client: Async Redis client used to write ``ban:{ip}`` keys.
                      May be ``None`` — bans are skipped (fail open) if Redis
                      is unavailable.
    """

    def __init__(self, proxy_config: dict, redis_client: Any = None) -> None:
        self._redis = redis_client
        self._enabled: bool = False
        self._ban_ttl: int = 604800
        self._silent_drop: bool = True
        self._honey_fingerprints: frozenset[str] = frozenset()
        self._honey_snis: frozenset[str] = frozenset()
        self._config_path: str = proxy_config.get("deception", {}).get(
            "config_path", "config/deception.yml"
        )
        self._load_deception_config()

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    def _load_deception_config(self) -> None:
        """Read the deception asset file and populate in-process sets.

        Fails open on any error (missing file, bad YAML, wrong types).
        """
        try:
            if not os.path.exists(self._config_path):
                logger.debug(
                    "deception | event=config_not_found | path=%s | "
                    "honey checks disabled (fail open)",
                    self._config_path,
                )
                return

            with open(self._config_path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)

            if not isinstance(raw, dict):
                logger.warning(
                    "deception | event=config_parse_error | path=%s | "
                    "expected YAML mapping, got %s — honey checks disabled",
                    self._config_path,
                    type(raw).__name__,
                )
                return

            cfg = raw.get("deception", {})
            if not isinstance(cfg, dict):
                return

            self._enabled = bool(cfg.get("enabled", False))
            self._ban_ttl = int(cfg.get("ban_ttl_seconds", 604800))
            self._silent_drop = bool(cfg.get("silent_drop", True))

            raw_fps = cfg.get("honey_fingerprints") or []
            if not isinstance(raw_fps, list):
                raw_fps = []
            self._honey_fingerprints = frozenset(
                str(fp) for fp in raw_fps if isinstance(fp, str) and fp
            )

            raw_snis = cfg.get("honey_snis") or []
            if not isinstance(raw_snis, list):
                raw_snis = []
            self._honey_snis = frozenset(
                str(sni).lower() for sni in raw_snis if isinstance(sni, str) and sni
            )

            logger.info(
                "deception | event=config_loaded | enabled=%s | "
                "fingerprints=%d | snis=%d",
                self._enabled,
                len(self._honey_fingerprints),
                len(self._honey_snis),
            )

        except Exception as exc:  # noqa: BLE001
            # Fail open — a broken deception config must not block real users.
            logger.warning(
                "deception | event=config_load_error | path=%s | error=%s — "
                "honey checks disabled (fail open)",
                self._config_path,
                exc,
            )
            self._enabled = False
            self._honey_fingerprints = frozenset()
            self._honey_snis = frozenset()

    def reload(self, proxy_config: dict) -> None:
        """Re-read the deception asset file.  Call on SIGHUP / hot reload."""
        new_path = proxy_config.get("deception", {}).get(
            "config_path", "config/deception.yml"
        )
        self._config_path = new_path
        self._load_deception_config()

    # ------------------------------------------------------------------
    # Hot-path check
    # ------------------------------------------------------------------

    async def check(
        self,
        client_ip: str,
        ja4: str | None,
        sni: str | None,
    ) -> dict | None:
        """Check the connection against honey-asset lists.

        Args:
            client_ip: Canonical source IP address string.
            ja4: JA4 fingerprint extracted from the ClientHello, or ``None``.
            sni: SNI hostname from the ClientHello, or ``None``.

        Returns:
            A dict ``{"trigger": "fingerprint"|"sni", "silent_drop": bool}``
            when a honey asset is matched — the caller must ban and drop the
            connection.  Returns ``None`` when no match is found or when the
            checker is disabled / encounters an error (fail open).
        """
        if not self._enabled:
            return None

        try:
            # Check JA4 fingerprint first (O(1) frozenset lookup)
            if ja4 and ja4 in self._honey_fingerprints:
                await self._ban_ip(client_ip, "fingerprint", ja4)
                _DECEPTION_TRIGGERED.labels(trigger="fingerprint").inc()
                logger.warning(
                    "deception | event=deception_triggered | trigger=fingerprint "
                    "| value=%s | ip=%s",
                    ja4,
                    client_ip,
                )
                return {"trigger": "fingerprint", "silent_drop": self._silent_drop}

            # Check SNI (O(1) frozenset lookup after lowercase normalisation)
            if sni:
                sni_clean = sni.rstrip(".").lower()
                if sni_clean in self._honey_snis:
                    await self._ban_ip(client_ip, "sni", sni_clean)
                    _DECEPTION_TRIGGERED.labels(trigger="sni").inc()
                    logger.warning(
                        "deception | event=deception_triggered | trigger=sni "
                        "| value=%s | ip=%s",
                        sni_clean,
                        client_ip,
                    )
                    return {"trigger": "sni", "silent_drop": self._silent_drop}

        except Exception as exc:  # noqa: BLE001
            # Fail open — any error in the deception checker must not block real users.
            logger.error(
                "deception | event=check_error | ip=%s | error=%s",
                client_ip,
                exc,
                exc_info=True,
            )

        return None

    async def _ban_ip(self, ip: str, trigger: str, value: str) -> None:
        """Write ``ban:{ip}`` to Redis with the configured TTL.

        Fails open — if Redis is unavailable the ban is skipped and only the
        Prometheus counter and log entry record the event.
        """
        if self._redis is None:
            logger.warning(
                "deception | event=ban_skipped_no_redis | ip=%s | trigger=%s",
                ip,
                trigger,
            )
            return

        try:
            ban_key = f"ban:{ip}"
            ban_value = f"{_BAN_TAG}:{trigger}:{value}"
            await self._redis.set(ban_key, ban_value, ex=self._ban_ttl)
            logger.warning(
                "deception | event=ip_banned | ip=%s | trigger=%s | ttl=%d",
                ip,
                trigger,
                self._ban_ttl,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "deception | event=ban_write_error | ip=%s | error=%s",
                ip,
                exc,
            )
