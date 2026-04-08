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
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse


# phase-85 (security review C4): feed_id is used as a Redis key suffix
# (``ti_feed:{feed_id}:*``) and as a metric label. Allowing arbitrary
# characters lets a config author pivot into other key namespaces or
# inflate Prometheus cardinality. Constrain it to a conservative slug.
_FEED_ID_REGEX = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Reserved feed ids that would collide with shared single-key state
# (e.g. ``ti_feed:leader_lock``). Keep in sync with state.py constants.
_RESERVED_FEED_IDS = frozenset({"leader_lock"})


# phase-85 (security review C5): never let a feed-supplied IP turn into a
# ban for the loopback interface, RFC1918, the link-local range, or any
# multicast / broadcast / unspecified address. A compromised or sloppy
# upstream feed must not be able to ban the operator out of their own
# infrastructure.
def is_bannable_ip(ip: str) -> bool:
    """Return True if ``ip`` is a sane public address to apply a ban to.

    phase-85 (architect C6): a feed-supplied IP can sneak past the
    loopback / RFC1918 guard by encoding the address in an alternate
    form that ``ipaddress.IPv6Address.is_loopback`` does not flag:

    * ``::ffff:127.0.0.1`` — IPv4-mapped IPv6, ``ipv4_mapped`` is set
    * ``2002:7f00:0001::`` — 6to4 wrapping 127.0.0.1, ``sixtofour`` is set
    * ``2001::...`` — Teredo wrapping 192.168.x.y, ``teredo`` is set

    Each of those wrappers carries an embedded IPv4 address that the
    upstream feed control plane *cannot* see is private, but which the
    operator's egress / NAT *can* — banning such an address is
    indistinguishable from banning the unwrapped form. Recurse on the
    embedded v4 so the inner-loopback / inner-RFC1918 / inner-multicast
    is caught.
    """
    if not isinstance(ip, str) or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return is_bannable_ip(str(addr.ipv4_mapped))
        if addr.sixtofour is not None:
            return is_bannable_ip(str(addr.sixtofour))
        teredo = addr.teredo
        if teredo is not None:
            # teredo returns (server, client); the client is what would
            # actually receive traffic.
            return is_bannable_ip(str(teredo[1]))
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return False
    return True


# phase-85 (security review C1): SSRF guard. The feed runner makes
# outbound HTTP calls to URLs sourced from operator config — but config
# changes flow through the Management API which Operators can drive
# without an out-of-band review, so we still treat the URL as untrusted
# and refuse to dial loopback / link-local / private / CGNAT / ULA /
# multicast destinations.
def validate_feed_url(url: str) -> None:
    """Reject feed URLs that point at local or private network space.

    Raises ``ValueError`` on any of:

    * non-``https`` scheme (we never want to dial plaintext HTTP for a
      feed that ships indicators we will turn into ban rules)
    * missing host
    * host that resolves to a literal address inside loopback,
      link-local, RFC1918, CGNAT (100.64/10), ULA (fc00::/7),
      multicast, or unspecified ranges

    DNS-based bypasses (a public hostname that resolves to 127.0.0.1)
    are out of scope here — those are caught at connection time by
    ``aiohttp``'s ``TCPConnector`` ``family``/``ssl`` settings and the
    operator-tier network egress controls.
    """
    if not isinstance(url, str) or not url:
        raise ValueError("feed url is empty")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(
            f"feed url must use https scheme (got {parsed.scheme!r})"
        )
    if not parsed.hostname:
        raise ValueError("feed url has no host")
    host = parsed.hostname
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname — DNS-time guard happens elsewhere
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        raise ValueError(
            f"feed url host {host} is in a forbidden network range"
        )


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
        # phase-85 (security review C4): refuse feed ids that would let an
        # operator pivot the Redis key namespace or inflate metric cardinality.
        feed_id = known["id"]
        if not isinstance(feed_id, str) or not _FEED_ID_REGEX.match(feed_id):
            raise ValueError(
                "feed id must match ^[a-z0-9][a-z0-9_-]{0,63}$ "
                f"(got {feed_id!r})"
            )
        if feed_id in _RESERVED_FEED_IDS:
            raise ValueError(
                f"feed id {feed_id!r} is reserved (collides with shared state)"
            )
        # phase-85 (security review C1): SSRF guard for feed types that
        # carry a URL. We validate here so a bad URL is rejected at config
        # parse time, before any aiohttp client is instantiated.
        url = known.get("url", "") or ""
        if known.get("type") in {"taxii2", "rest"} and url:
            validate_feed_url(url)
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
