"""TLS version and cipher suite enforcement (Phase 3).

Produces :class:`~src.security.risk_scorer.RiskSignal` objects for old or
weak TLS, or returns ``None`` to signal a hard block when the configured
bypass is enabled.

Design
------
- :meth:`TLSEnforcer.check` is called once per connection, between the
  generic BLOCK bypasses and Phase 4+ signal collection.
- Returns ``None`` for hard-block cases (SSLv3 always; TLS 1.0/1.1 when
  ``security_policy.tls_version_bypass.enabled: true``).
- Returns a list (possibly empty) for all other cases — the list is
  prepended to the signals passed to the scorer.
- Weak cipher detection is always a scored signal unless
  ``block_weak_ciphers: true`` is set explicitly.
- All settings are hot-reloadable via :meth:`on_config_reload`.

Signal names
------------
- ``tls_version``  — old or deprecated TLS version
- ``weak_cipher``  — weak or broken cipher suite offered
"""

import logging

from prometheus_client import Counter

from .risk_scorer import RiskSignal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TLS version constants (raw ClientHello integers)
# ---------------------------------------------------------------------------

SSL3 = 0x0300
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304

# ---------------------------------------------------------------------------
# Built-in weak cipher suite IDs (comprehensive; config list extends this)
# ---------------------------------------------------------------------------
# Sources: NIST SP 800-52r2, RFC 9325, Mozilla "Old" security profile.
# RC4, NULL, EXPORT, ANON, DES, 3DES — all considered broken or insecure.

WEAK_CIPHERS: frozenset[int] = frozenset(
    {
        0x0000,  # TLS_NULL_WITH_NULL_NULL
        0x0001,  # TLS_RSA_WITH_NULL_MD5
        0x0002,  # TLS_RSA_WITH_NULL_SHA
        0x0003,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
        0x0004,  # TLS_RSA_WITH_RC4_128_MD5
        0x0005,  # TLS_RSA_WITH_RC4_128_SHA
        0x0006,  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
        0x0007,  # TLS_RSA_WITH_IDEA_CBC_SHA
        0x0008,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0009,  # TLS_RSA_WITH_DES_CBC_SHA
        0x000A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x000B,  # TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x000C,  # TLS_DH_DSS_WITH_DES_CBC_SHA
        0x000D,  # TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
        0x000E,  # TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x000F,  # TLS_DH_RSA_WITH_DES_CBC_SHA
        0x0010,  # TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
        0x0011,  # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
        0x0012,  # TLS_DHE_DSS_WITH_DES_CBC_SHA
        0x0013,  # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        0x0014,  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        0x0015,  # TLS_DHE_RSA_WITH_DES_CBC_SHA
        0x0016,  # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        0x0017,  # TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
        0x0018,  # TLS_DH_anon_WITH_RC4_128_MD5
        0x0019,  # TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
        0x001A,  # TLS_DH_anon_WITH_DES_CBC_SHA
        0x001B,  # TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
        0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA        (no PFS)
        0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA        (no PFS)
        0x003B,  # TLS_RSA_WITH_NULL_SHA256
        0x0041,  # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA   (no PFS)
        0x0084,  # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA   (no PFS)
        0xC007,  # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        0xC011,  # TLS_ECDHE_RSA_WITH_RC4_128_SHA
        0xC015,  # TLS_ECDH_anon_WITH_NULL_SHA
        0xC016,  # TLS_ECDH_anon_WITH_RC4_128_SHA
        0xC017,  # TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
        0xC018,  # TLS_ECDH_anon_WITH_AES_128_CBC_SHA
        0xC019,  # TLS_ECDH_anon_WITH_AES_256_CBC_SHA
    }
)

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

_TLS_VERSION_TOTAL = Counter(
    "ja4proxy_tls_version_total",
    "Connections by TLS version and action taken",
    ["tls_version", "action"],
)

_WEAK_CIPHER_TOTAL = Counter(
    "ja4proxy_weak_cipher_total",
    "Connections by cipher strength and action taken",
    ["cipher_strength", "action"],
)


# ---------------------------------------------------------------------------
# Version label helper
# ---------------------------------------------------------------------------


def _version_label(version: int | str) -> str:
    """Human-readable TLS version label for Prometheus and logs."""
    if isinstance(version, str):
        # Handle string input (e.g. from benchmarks or malformed ClientHello)
        mapping = {
            "SSLv3": SSL3,
            "TLSv1.0": TLS10,
            "TLSv1.1": TLS11,
            "TLSv1.2": TLS12,
            "TLSv1.3": TLS13,
            "TLSv1": TLS10,
        }
        version_int = mapping.get(version)
        if version_int is not None:
            version = version_int
        else:
            return f"unknown_{version}"

    return {
        SSL3: "ssl3",
        TLS10: "tls10",
        TLS11: "tls11",
        TLS12: "tls12",
        TLS13: "tls13",
    }.get(version, f"unknown_0x{version:04x}")


# ---------------------------------------------------------------------------
# Enforcer
# ---------------------------------------------------------------------------


class TLSEnforcer:
    """Enforce TLS version and cipher suite policy.

    Thread-safe (no mutable state after ``__init__``; hot reload via
    :meth:`on_config_reload` uses attribute replacement which is atomic
    under the GIL for CPython).

    Args:
        config: Full proxy.yml config dict. Reads ``tls_enforcer`` and
                ``security_policy.tls_version_bypass`` sub-sections.
    """

    def __init__(self, config: dict) -> None:
        cfg = config.get("tls_enforcer", {})
        self._enabled: bool = bool(cfg.get("enabled", True))
        self._block_ssl3: bool = bool(cfg.get("block_ssl3", True))
        self._block_tls10: bool = bool(cfg.get("block_tls_10", True))
        self._block_tls11: bool = bool(cfg.get("block_tls_11", True))
        self._flag_tls12: bool = bool(cfg.get("flag_tls_12", False))
        self._tls_score: int = int(cfg.get("score", 10))
        self._block_weak_ciphers: bool = bool(cfg.get("block_weak_ciphers", False))
        self._weak_cipher_score: int = int(cfg.get("weak_cipher_score", 20))

        # Config-defined extra ciphers extend the built-in set
        extra = cfg.get("weak_ciphers", [])
        self._weak_ciphers: frozenset[int] = WEAK_CIPHERS | frozenset(
            int(c, 16) if isinstance(c, str) else int(c) for c in extra
        )

        # tls_version_bypass controls hard-block vs. signal for TLS 1.0/1.1
        policy = config.get("security_policy", {})
        self._version_bypass_enabled: bool = bool(
            policy.get("tls_version_bypass", {}).get("enabled", True)
        )

    @classmethod
    def from_config(cls, config: dict) -> "TLSEnforcer":
        """Create a :class:`TLSEnforcer` from the full proxy.yml config dict."""
        return cls(config)

    def on_config_reload(self, new_config: dict) -> None:
        """Apply hot-reloaded config. Safe to call while connections are in flight."""
        self.__init__(new_config)

    def check(
        self,
        tls_version: int | None,
        cipher_list: list[int],
    ) -> list[RiskSignal] | None:
        """Evaluate TLS version and cipher suites for a connection.

        Args:
            tls_version: Integer TLS version from the ClientHello (e.g.
                         ``0x0303`` for TLS 1.2, ``0x0304`` for TLS 1.3),
                         or ``None`` if not available.
            cipher_list: Cipher suite integers from the ClientHello. May
                         be empty — no signal is emitted in that case.

        Returns:
            ``None`` — caller must hard-block this connection (RST).
            ``[]``   — connection is clean; no signals emitted.
            ``[RiskSignal, ...]`` — one or more scored signals; connection
                                    continues to the scorer.
        """
        if not self._enabled:
            return []

        signals: list[RiskSignal] = []

        # ── TLS version check ──────────────────────────────────────────────
        if tls_version is not None:
            label = _version_label(tls_version)

            if tls_version == SSL3 and self._block_ssl3:
                # SSLv3: always hard-block; no bypass option
                _TLS_VERSION_TOTAL.labels(tls_version="ssl3", action="block").inc()
                logger.debug(
                    "tls_enforcer | event=ssl3_blocked | version=0x%04x", tls_version
                )
                return None

            if tls_version in (TLS10, TLS11):
                if self._version_bypass_enabled and (
                    (tls_version == TLS10 and self._block_tls10)
                    or (tls_version == TLS11 and self._block_tls11)
                ):
                    # Hard block
                    _TLS_VERSION_TOTAL.labels(tls_version=label, action="block").inc()
                    logger.debug(
                        "tls_enforcer | event=old_tls_blocked | version=0x%04x",
                        tls_version,
                    )
                    return None
                elif not self._version_bypass_enabled and (
                    (tls_version == TLS10 and self._block_tls10)
                    or (tls_version == TLS11 and self._block_tls11)
                ):
                    # Bypass disabled → scored signal instead
                    _TLS_VERSION_TOTAL.labels(tls_version=label, action="signal").inc()
                    signals.append(
                        RiskSignal(
                            name="tls_version",
                            score=40,
                            reason=f"Deprecated TLS version ({label}); bypass disabled",
                        )
                    )
                else:
                    # block_tls10/11 is false — treat as allowed version
                    _TLS_VERSION_TOTAL.labels(tls_version=label, action="allow").inc()

            elif tls_version == TLS12:
                if self._flag_tls12:
                    _TLS_VERSION_TOTAL.labels(
                        tls_version="tls12", action="signal"
                    ).inc()
                    signals.append(
                        RiskSignal(
                            name="tls_version",
                            score=self._tls_score,
                            reason="TLS 1.2 connection; TLS 1.3 preferred",
                        )
                    )
                else:
                    _TLS_VERSION_TOTAL.labels(tls_version="tls12", action="allow").inc()

            elif tls_version == TLS13:
                _TLS_VERSION_TOTAL.labels(tls_version="tls13", action="allow").inc()

            else:
                # Unknown/future version — no action
                _TLS_VERSION_TOTAL.labels(tls_version=label, action="allow").inc()

        # ── Weak cipher check ──────────────────────────────────────────────
        if cipher_list:
            weak_found = [c for c in cipher_list if c in self._weak_ciphers]
            if weak_found:
                if self._block_weak_ciphers:
                    _WEAK_CIPHER_TOTAL.labels(
                        cipher_strength="weak", action="block"
                    ).inc()
                    logger.debug(
                        "tls_enforcer | event=weak_cipher_blocked | ciphers=%s",
                        [hex(c) for c in weak_found[:5]],
                    )
                    return None
                else:
                    _WEAK_CIPHER_TOTAL.labels(
                        cipher_strength="weak", action="signal"
                    ).inc()
                    signals.append(
                        RiskSignal(
                            name="weak_cipher",
                            score=self._weak_cipher_score,
                            reason=(
                                f"Weak cipher suite(s) offered: "
                                f"{[hex(c) for c in weak_found[:3]]}"
                            ),
                        )
                    )
            else:
                _WEAK_CIPHER_TOTAL.labels(
                    cipher_strength="strong", action="allow"
                ).inc()

        return signals
