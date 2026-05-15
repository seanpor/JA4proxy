"""Phase 85 — Threat Intelligence Feed runner.

This package lives alongside the existing analytics daemons
(`src/analytics/stream_consumer.py`, `src/analytics/drift_detector.py`)
and is explicitly *not* part of the hot-path proxy pipeline.

Architecture summary (see `docs/phases/PHASE_85.md` for the full spec):

- ``base`` — ``FeedClient`` ABC, ``FeedPollResult`` dataclass, ``FeedConfig`` dataclass
- ``state`` — Redis sidecar index (the six ``ti_feed:*`` keys from §2.2)
- ``circuit_breaker`` — per-feed CLOSED / HALF-OPEN / OPEN state machine
- ``mgmt_client`` — async client for the MFA/SSO Hardening Management API
- ``taxii`` — hand-rolled TAXII 2.1 poller
- ``recorded_future`` — wrapper over ``taxii`` with the RF token-exchange flow
- ``crowdstrike`` — Falcon Intel OAuth2 client
- ``rest_generic`` — JSONPath-driven REST client
- ``seed_file`` — loader for ``config/known_bad_fingerprints.yml``
- ``stix_ja4`` — STIX 2.1 ``x-ja4-fingerprint`` extension helpers
- ``contribution`` — stubbed community-feed contribution client (disabled by default)
- ``runner`` — asyncio scheduler that owns the per-feed poll tasks

All rule mutations go through the Management API — the feed runner never
touches proxy rule sets in Redis directly. The sidecar ``ti_feed:*`` keys are
internal bookkeeping for differential cleanup and per-feed status.
"""

from .base import FeedClient, FeedConfig, FeedPollResult

__all__ = ["FeedClient", "FeedConfig", "FeedPollResult"]
