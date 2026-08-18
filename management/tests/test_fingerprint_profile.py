"""The fingerprint detail page's data endpoint must actually return data.

WHY THIS EXISTS
---------------
The page at /fingerprint/<ja4> renders its decoded-JA4 section server-side from
Jinja, and everything else — Total Events, Unique IPs, Associated IPs, Action
Breakdown, the risk timeline — from Alpine bound to
GET /api/v1/fingerprints/{ja4}/profile.

That split means the page can look half-alive: the server-rendered half is
correct while every number is blank, and nothing errors visibly. It was
reported from the browser as "I don't get the detail we discussed", with real
matching events sitting in the stream.

The endpoint had no test at all. These seed the stream with an event in exactly
the shape the Go proxy writes — including the RFC3339Nano `@timestamp` with
NINE fractional digits, which is the detail most likely to break parsing and
silently drop every event.
"""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient

JA4 = "t13d1212h2_eac1b15b5477_8e6e362c5eac"


def proxy_event(ja4: str = JA4, ip: str = "203.0.113.9", action: str = "allow",
                score: int = 35, ts: str = "") -> dict:
    """One entry exactly as cmd/ja4pd writes it to events:connection.

    Note the timestamp: Go's time.RFC3339Nano emits nine fractional digits.
    datetime.fromisoformat rejected that before Python 3.11, so this fixture is
    the guard against a runtime downgrade silently emptying the page.
    """
    from datetime import datetime, timedelta, timezone

    if not ts:
        ts = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f000Z"
        )
    return {
        "event": json.dumps({
            "@timestamp": ts,
            "source.ip": ip,
            "source.port": 44321,
            "event.action": action,
            "event.risk_score": score,
            "ja4proxy.fingerprint.ja4": ja4,
            "ja4proxy.sni": "forms.example.ie",
            "client.geo.country_iso": "IE",
            "client.as.number": 15502,
            "client.as.organization.name": "Vodafone Ireland Limited",
            "service.name": "ja4proxy",
        })
    }


@pytest.mark.asyncio
async def test_profile_returns_populated_data(authenticated_client: AsyncClient, fake_redis):
    for i in range(5):
        await fake_redis.xadd("events:connection", proxy_event(ip=f"203.0.113.{i}"))

    r = await authenticated_client.get(f"/api/v1/fingerprints/{JA4}/profile")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["total_events"] == 5, (
        f"the page shows this number; got {body['total_events']} from 5 seeded "
        "events. A blank page is what the operator actually sees."
    )
    assert body["unique_ips"] == 5
    assert len(body["ips_sample"]) == 5, "Associated IPs renders from this list"
    assert body["action_counts"].get("allow") == 5


@pytest.mark.asyncio
async def test_every_field_the_template_binds_is_present(authenticated_client: AsyncClient, fake_redis):
    """A missing key leaves an Alpine binding blank with no error anywhere."""
    await fake_redis.xadd("events:connection", proxy_event())

    body = (await authenticated_client.get(f"/api/v1/fingerprints/{JA4}/profile")).json()
    for field in ("total_events", "unique_ips", "ips_sample", "action_counts",
                  "is_banned", "is_allowlisted", "hourly_scores"):
        assert field in body, f"fingerprint.html binds profile.{field}; endpoint omits it"


@pytest.mark.asyncio
async def test_nanosecond_timestamps_are_not_dropped(authenticated_client: AsyncClient, fake_redis):
    """Nine fractional digits is what Go emits. Six is what older Python takes.

    If this ever regresses, EVERY event is skipped and the page goes blank while
    the endpoint returns 200 — the exact shape of a bug nobody notices.
    """
    from datetime import datetime, timedelta, timezone

    ts = (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime(
        "%Y-%m-%dT%H:%M:%S.%f"
    ) + "675Z"
    assert len(ts.split(".")[1]) == 10, "fixture must carry 9 digits + Z"

    await fake_redis.xadd("events:connection", proxy_event(ts=ts))
    body = (await authenticated_client.get(f"/api/v1/fingerprints/{JA4}/profile")).json()
    assert body["total_events"] == 1, (
        "an RFC3339Nano timestamp was dropped — every real proxy event carries "
        "one, so the page would be empty for all fingerprints"
    )


@pytest.mark.asyncio
async def test_other_fingerprints_are_not_counted(authenticated_client: AsyncClient, fake_redis):
    await fake_redis.xadd("events:connection", proxy_event())
    await fake_redis.xadd("events:connection", proxy_event(ja4="t13d091100_other_hash"))

    body = (await authenticated_client.get(f"/api/v1/fingerprints/{JA4}/profile")).json()
    assert body["total_events"] == 1, "profile leaked events from a different fingerprint"
