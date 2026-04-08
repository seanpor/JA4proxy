"""Signal classifier — maps fired RiskSignal names to attack categories.

Used by PciDssPackBuilder to populate artefact 03_attack_classification.csv
and by the report renderer to build the "Value Delivered" section.

Resolution rules
----------------
- Highest weight among all fired (and known) signals wins.
- Ties are broken alphabetically by *category name* (deterministic).
- Signals not present in the mapping are silently ignored.
- An empty/all-unknown signal list returns FALLBACK_CATEGORY.

Configuration
-------------
Loaded from ``proxy.yml`` under ``reporting.signal_categories``.
Custom entries are *merged over* the defaults: unspecified defaults are preserved.
"""

from __future__ import annotations

import copy
import logging
from typing import Any

logger = logging.getLogger(__name__)


class SignalClassifier:
    """Maps sets of fired risk signal names to attack categories."""

    # Default mapping — mirrors PHASE_84.md §6.1 exactly.
    DEFAULT_SIGNAL_CATEGORIES: dict[str, dict[str, Any]] = {
        "spamhaus_drop":        {"category": "known_malicious_network",   "weight": 100},
        "spamhaus_edrop":       {"category": "known_malicious_network",   "weight": 100},
        "tor_exit":             {"category": "tor_exit_node",             "weight": 95},
        "beaconing_detected":   {"category": "c2_beaconing",              "weight": 90},
        "ja4_blacklist":        {"category": "malicious_tls_fingerprint", "weight": 85},
        "abuseipdb_score_high": {"category": "reported_abuse",            "weight": 70},
        "tls_version_old":      {"category": "obsolete_tls",              "weight": 60},
        "sni_missing":          {"category": "automation_tool",           "weight": 55},
        "sni_ip_literal":       {"category": "automation_tool",           "weight": 55},
        "datacenter":           {"category": "datacenter_scanner",        "weight": 50},
        "asn_datacenter":       {"category": "datacenter_scanner",        "weight": 50},
        "country_blacklist":    {"category": "geo_blocked",               "weight": 40},
    }
    FALLBACK_CATEGORY = "high_risk_score"

    def __init__(self, signal_categories: dict[str, dict[str, Any]] | None = None) -> None:
        """
        Args:
            signal_categories: Optional override dict.  Custom entries are merged
                *over* the defaults — all default entries not mentioned are kept.
                Pass ``{}`` to use pure defaults.  Pass ``None`` for the same.
        """
        merged = copy.deepcopy(self.DEFAULT_SIGNAL_CATEGORIES)
        if signal_categories:
            merged.update(signal_categories)
        self._categories: dict[str, dict[str, Any]] = merged

    @property
    def categories(self) -> dict[str, dict[str, Any]]:
        """Return a defensive copy of the active signal → {category, weight} mapping.

        The returned dict is a fresh copy; mutating it does not affect the classifier.
        """
        return {k: dict(v) for k, v in self._categories.items()}

    def classify(self, signals: list[str]) -> str:
        """Return the attack category for the given fired signals.

        Args:
            signals: List of RiskSignal names that fired for a connection.

        Returns:
            Category string (e.g. ``"known_malicious_network"``).
            Returns ``FALLBACK_CATEGORY`` when signals is empty or all unknown.
        """
        best_weight = -1
        best_category = self.FALLBACK_CATEGORY

        for signal in signals:
            entry = self._categories.get(signal)
            if entry is None:
                continue
            weight = entry["weight"]
            category = entry["category"]
            # Ties broken alphabetically by category name (ascending) so that
            # the result is deterministic regardless of iteration order.
            if weight > best_weight or (
                weight == best_weight and category < best_category
            ):
                best_weight = weight
                best_category = category

        return best_category

    def classify_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return a *new* list of events with a ``category`` field added to each.

        Does not mutate the input dicts.

        Args:
            events: List of connection event dicts.  Each event may have a
                ``signals`` key containing a list of signal name strings.
                Missing or ``None`` signals are treated as ``[]``.

        Returns:
            New list of dicts, each containing all original fields plus
            ``"category"``.
        """
        result = []
        for event in events:
            signals = event.get("signals") or []
            result.append({**event, "category": self.classify(signals)})
        return result
