"""FeedClient ABC, FeedPollResult and FeedConfig dataclasses.

All Phase 85 feed implementations derive from :class:`FeedClient` and return
:class:`FeedPollResult` instances from :meth:`FeedClient.poll`. The runner in
``runner.py`` consumes those results to drive differential cleanup and update
the Redis sidecar index.

No feed implementation writes directly to Redis proxy rule sets. All rule
mutations flow through the Phase 79 Management API via
``mgmt_client.ManagementClient`` — ``FeedClient`` holds a reference to one.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class FeedConfig:
    """Typed view of a single ``threat_intel.feeds[]`` entry from ``config/proxy.yml``.

    Not every field applies to every feed type; unused fields carry their
    defaults. The runner inspects ``type`` to pick the correct subclass.
    """

    id: str
    type: str
    enabled: bool = False
    poll_interval_minutes: int = 60
    min_confidence: int = 70
    ban_ttl_hours: int = 168
    # TAXII 2.1 -----------------------------------------------------------
    url: str = ""
    collection_id: str = ""
    username: str = ""
    password: str = ""
    consume: list[str] = field(default_factory=lambda: ["indicator"])
    # Recorded Future ------------------------------------------------------
    api_token: str = ""
    feeds: list[str] = field(default_factory=list)
    min_rf_risk_score: int = 75
    # CrowdStrike Falcon ---------------------------------------------------
    client_id: str = ""
    client_secret: str = ""
    indicator_types: list[str] = field(default_factory=lambda: ["ip_address"])
    min_malicious_confidence: str = "high"
    # Generic REST ---------------------------------------------------------
    auth: dict[str, Any] = field(default_factory=dict)
    ip_jsonpath: str = ""
    ja4_jsonpath: str = ""
    ttl_jsonpath: str = ""
    confidence_jsonpath: str = ""
    # Raw dict so we can plumb unknown fields through for logging ---------
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FeedConfig":
        """Build a :class:`FeedConfig` from a parsed YAML sub-tree.

        Unknown keys are retained in ``raw`` so that logs can show them without
        causing a ``TypeError`` from the dataclass constructor.
        """
        known: dict[str, Any] = {}
        raw: dict[str, Any] = {}
        fields = {
            "id",
            "type",
            "enabled",
            "poll_interval_minutes",
            "min_confidence",
            "ban_ttl_hours",
            "url",
            "collection_id",
            "username",
            "password",
            "consume",
            "api_token",
            "feeds",
            "min_rf_risk_score",
            "client_id",
            "client_secret",
            "indicator_types",
            "min_malicious_confidence",
            "auth",
            "ip_jsonpath",
            "ja4_jsonpath",
            "ttl_jsonpath",
            "confidence_jsonpath",
        }
        for key, value in data.items():
            if key in fields:
                known[key] = value
            raw[key] = value
        known["raw"] = raw
        # Guard against missing required fields — fail noisy, not silent.
        if "id" not in known or "type" not in known:
            raise ValueError(
                f"feed config missing required 'id'/'type' keys: keys={list(data.keys())}"
            )
        return cls(**known)


@dataclass
class FeedPollResult:
    """Outcome of a single :meth:`FeedClient.poll` invocation.

    Attributes:
        feed_id: The ``FeedConfig.id`` this poll belongs to.
        stix_ids_seen: Indicator ids present in this poll response (used by the
            runner's differential cleanup).
        created: New ``(stix_id, resource_uuid_or_ip)`` pairs added via the
            Management API this cycle.
        skipped_below_confidence: How many indicators were skipped because they
            were under ``FeedConfig.min_confidence``.
        errors: Per-indicator errors — strings in the ECS log style. A non-
            empty list does not mean the poll failed overall.
        poll_duration_s: Wall-clock time from start to finish.
    """

    feed_id: str
    stix_ids_seen: set[str] = field(default_factory=set)
    created: list[tuple[str, str]] = field(default_factory=list)
    skipped_below_confidence: int = 0
    unsupported_pattern: int = 0
    errors: list[str] = field(default_factory=list)
    poll_duration_s: float = 0.0


class FeedClient(abc.ABC):
    """Abstract base class for every Phase 85 feed poller.

    Implementers must:

    * Respect ``config.min_confidence`` (or the feed-type-specific equivalent).
    * Populate ``FeedPollResult.stix_ids_seen`` with *every* indicator id that
      passed confidence in this response — the runner uses the set-difference
      between the previous and current call to decide which rules to remove.
    * Call ``state.mark(...)`` for every rule created this cycle so the sidecar
      index stays consistent.
    * Never delete rules from their own implementation — cleanup is centralised
      in ``runner.py``.
    * Never raise. Return a :class:`FeedPollResult` with ``errors`` populated
      instead. A raised exception bubbles up to the runner's circuit breaker
      and counts as one full-poll failure.

    The runner calls ``poll()`` on the interval declared by
    ``config.poll_interval_minutes``.
    """

    def __init__(
        self,
        config: FeedConfig,
        mgmt: "Any",
        state: "Any",
    ) -> None:
        self.config = config
        self.mgmt = mgmt
        self.state = state

    @abc.abstractmethod
    async def poll(self) -> FeedPollResult:  # pragma: no cover — interface only
        """Poll the upstream feed once and apply its indicators.

        Returns:
            A :class:`FeedPollResult` — never None, never raising.
        """
        raise NotImplementedError

    async def close(self) -> None:
        """Optional cleanup hook, called once on runner shutdown."""
        return None

    # -- shared helpers ----------------------------------------------------

    def feed_label(self) -> str:
        """Return a short identifier for log lines and metric labels."""
        return f"feed:{self.config.id}"

    def ban_ttl_seconds(self) -> int:
        """Return ``ban_ttl_hours`` as seconds, minimum 60s (safety rail)."""
        return max(60, self.config.ban_ttl_hours * 3600)

    def blocklist_expires_at(self) -> Optional[str]:
        """Return the expiry ISO8601 string for blocklist entries.

        Currently returns ``None`` so the Management API treats entries as
        non-expiring; TAXII ``valid_until`` overrides this on a per-indicator
        basis inside the TAXII client.
        """
        return None
