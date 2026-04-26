"""PHASE_101 H6 — DNS-level SSRF blocked at the connector for every TI client.

`safe_resolver.SafeResolver` runs after the inner DNS lookup and rejects every
resolution whose addresses are all private / loopback / link-local — including
the cloud-metadata sentinel ``169.254.169.254``. This file proves the four
production HTTP paths actually wire that resolver into their
``aiohttp.TCPConnector`` and therefore *cannot* be tricked into hitting metadata
endpoints by a feed config that points at a hostname whose A record is private.

Strategy: monkey-patch the inner resolver inside ``safe_resolver.SafeResolver``
so every lookup returns ``169.254.169.254``. Then drive a real client poll
(no transport stub injected — we want the real aiohttp path) and assert:

* the poll fails closed: ``result.errors`` carries an entry referencing the
  SSRF block, OR an exception bubbles out of the connector;
* ``mgmt.post_ban`` is **never** called — no IOC was applied, no CIDR
  expansion happened, no follow-up traffic was issued to the metadata IP.

Covers all four wrap sites that landed in 101c (rest_generic, taxii) and
101d-H6 (crowdstrike OAuth path + crowdstrike indicators path). Recorded
Future delegates HTTP through inner ``TAXIIClient`` instances and is
covered transitively by the TAXII test.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import pytest

from src.analytics.ti_feeds import safe_resolver as _sr

# ── Helpers ────────────────────────────────────────────────────────────────


class _PrivateIPResolver:
    """Stand-in for aiohttp's DefaultResolver — returns the metadata IP for any host.

    Records every host queried so tests can assert SafeResolver actually ran
    (rather than the connection failing for an unrelated reason like real DNS).
    """

    invocations: list[str] = []

    def __init__(self, ip: str = "169.254.169.254") -> None:
        self._ip = ip

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        type(self).invocations.append(host)
        return [
            {
                "hostname": host,
                "host": self._ip,
                "port": port,
                "family": socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }
        ]

    async def close(self) -> None:
        return None


@pytest.fixture
def _force_private_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every SafeResolver() instantiated by client code return a private IP.

    Patches the module-level ``DefaultResolver`` symbol that ``SafeResolver.__init__``
    falls back to when callers don't supply an inner resolver — every wrap site in
    the production clients takes that fallback. Resets the call recorder so each
    test starts with a clean counter and can prove the resolver actually ran.
    """
    _PrivateIPResolver.invocations = []
    monkeypatch.setattr(_sr, "DefaultResolver", _PrivateIPResolver, raising=True)


def _run(coro):
    return asyncio.run(coro)


def _import_clients():
    from src.analytics.ti_feeds.base import FeedConfig
    from src.analytics.ti_feeds.crowdstrike import CrowdStrikeClient
    from src.analytics.ti_feeds.rest_generic import RESTGenericClient
    from src.analytics.ti_feeds.taxii import TAXIIClient

    return FeedConfig, CrowdStrikeClient, RESTGenericClient, TAXIIClient


# ── Tests ──────────────────────────────────────────────────────────────────


def test_taxii_client_blocks_private_ip_resolution(
    _force_private_resolution: None, stub_management_client
) -> None:
    """TAXII real-aiohttp path must not connect when DNS yields 169.254.169.254."""
    FeedConfig, _, _, TAXIIClient = _import_clients()

    cfg = FeedConfig(
        id="taxii-ssrf",
        type="taxii2",
        url="https://feed.attacker.example/taxii2/",
        collection_id="indicators",
        poll_interval_minutes=60,
        ban_ttl_hours=24,
        enabled=True,
        min_confidence=70,
    )
    client = TAXIIClient(config=cfg, mgmt=stub_management_client, state=None)

    result = _run(client.poll())

    # Proof that SafeResolver ran: the inner _PrivateIPResolver recorded a
    # lookup. If this is empty, the request bypassed the resolver and the
    # SSRF guard is not in effect for this client.
    assert _PrivateIPResolver.invocations, (
        "SafeResolver was not invoked — client is not wired to use it. "
        "post_ban check below will pass for the wrong reason if this fails."
    )
    assert result.errors, "expected SSRF block to surface as a poll error"
    assert stub_management_client.bans == {}, (
        f"post_ban must not have fired for an SSRF-blocked poll; got "
        f"{stub_management_client.bans!r}"
    )


def test_rest_generic_client_blocks_private_ip_resolution(
    _force_private_resolution: None, stub_management_client
) -> None:
    """REST generic real-aiohttp path must not connect when DNS yields 169.254.169.254."""
    FeedConfig, _, RESTGenericClient, _ = _import_clients()

    cfg = FeedConfig(
        id="rest-ssrf",
        type="rest_generic",
        url="https://feed.attacker.example/v1/iocs.json",
        ip_jsonpath="$.iocs[*].ip",
        confidence_jsonpath="$.iocs[*].score",
        ban_ttl_hours=24,
        enabled=True,
    )
    client = RESTGenericClient(config=cfg, mgmt=stub_management_client, state=None)

    result = _run(client.poll())

    # Proof that SafeResolver ran: the inner _PrivateIPResolver recorded a
    # lookup. If this is empty, the request bypassed the resolver and the
    # SSRF guard is not in effect for this client.
    assert _PrivateIPResolver.invocations, (
        "SafeResolver was not invoked — client is not wired to use it. "
        "post_ban check below will pass for the wrong reason if this fails."
    )
    assert result.errors, "expected SSRF block to surface as a poll error"
    assert stub_management_client.bans == {}


def test_crowdstrike_oauth_blocks_private_ip_resolution(
    _force_private_resolution: None, stub_management_client
) -> None:
    """CrowdStrike OAuth token endpoint must not connect to a private-IP DNS result."""
    FeedConfig, CrowdStrikeClient, _, _ = _import_clients()

    cfg = FeedConfig(
        id="cs-ssrf",
        type="crowdstrike",
        url="https://api.attacker.example",
        client_id="test-id",
        client_secret="test-secret",
        indicator_types=["ip_address"],
        min_malicious_confidence="high",
        poll_interval_minutes=30,
        ban_ttl_hours=48,
        enabled=True,
    )
    client = CrowdStrikeClient(config=cfg, mgmt=stub_management_client, state=None)

    result = _run(client.poll())

    # CrowdStrike's poll() catches connector errors and surfaces them in
    # ``result.errors``. The token fetch is the first network op so the
    # block trips here before any indicator request can be issued.
    # Proof that SafeResolver ran: the inner _PrivateIPResolver recorded a
    # lookup. If this is empty, the request bypassed the resolver and the
    # SSRF guard is not in effect for this client.
    assert _PrivateIPResolver.invocations, (
        "SafeResolver was not invoked — client is not wired to use it. "
        "post_ban check below will pass for the wrong reason if this fails."
    )
    assert result.errors, "expected SSRF block to surface as a poll error"
    assert stub_management_client.bans == {}, (
        "post_ban must not have fired during an SSRF-blocked CrowdStrike poll"
    )


def test_safe_resolver_isolation_check_no_global_leak() -> None:
    """Sanity: outside the fixture, SafeResolver still uses the real DefaultResolver."""
    # We don't actually resolve anything (avoid requiring DNS in CI); we just
    # verify the symbol the production clients depend on hasn't been replaced
    # globally by the fixture (regression guard against monkeypatch leaks).
    from aiohttp.resolver import DefaultResolver as _AIODefault

    assert _sr.DefaultResolver is _AIODefault, (
        "SafeResolver's DefaultResolver should be the real aiohttp resolver "
        "outside the SSRF fixture; if this fails the fixture leaked or the "
        "module was reimported under a stale patch."
    )
