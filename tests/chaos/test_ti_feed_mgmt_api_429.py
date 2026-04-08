"""Phase 85 — chaos test: Management API returns 429.

When the Phase 79 rate limiter rejects a write, the feed must:
- back off per §2.5 (50 ms inter-batch sleep escalates) without losing
  the indicators queued behind it
- retry the rejected batch until it succeeds or hits max_retries
- NOT lose any indicator from the poll

These tests are RED until the mgmt_client exists.
"""

from __future__ import annotations

import asyncio
import itertools
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

# phase-85: H1 closed (commit 5223cdc) — feed clients now expose
# HTTP-layer DI seams; the shared stub fixture is exposed via
# tests/chaos/conftest.py.
_ = pytest  # noqa: F841 — keep import marker active


def _run(coro):
    return asyncio.run(coro)


def _import_client():
    from src.analytics.ti_feeds.mgmt_client import ManagementClient

    return ManagementClient


class _RespondingSession:
    """Session that returns a scripted sequence of status codes per POST."""

    def __init__(self, statuses: list[int]) -> None:
        self._statuses = list(statuses)
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, json=None, headers=None, **kwargs):
        self.calls.append({"method": "POST", "url": url, "json": json, "headers": headers})
        status = self._statuses.pop(0) if self._statuses else 201

        class _Resp:
            def __init__(self, status):
                self.status = status

            async def json(self):
                return {"id": "x", "entry": (json or {}).get("entry", ""), "managed_by": "feed", "note": ""}

            async def text(self):
                return str(status)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return None

        return _Resp(status)

    def delete(self, url: str, headers=None, **kwargs):
        self.calls.append({"method": "DELETE", "url": url, "headers": headers})

        class _Resp:
            status = 204

            async def json(self):
                return {}

            async def text(self):
                return ""

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return None

        return _Resp()


@pytest.mark.chaos
def test_batch_retried_on_429_no_loss():
    ManagementClient = _import_client()

    # First POST → 429, subsequent → 201. Six indicators in one batch.
    statuses = [429, 201, 201, 201, 201, 201, 201]
    sess = _RespondingSession(statuses=statuses)

    client = ManagementClient(
        base_url="http://testserver",
        token="tok",
        session=sess,
        max_retries=4,
        backoff_initial_s=0.0,
        batch_size=10,
        inter_batch_sleep_s=0.0,
    )

    entries = [
        {"entry": f"ja4-{i}", "managed_by": "feed", "note": f"feed:x:ind{i}"}
        for i in range(6)
    ]

    async def _fake_sleep(_s):
        return None

    with patch("src.analytics.ti_feeds.mgmt_client.asyncio.sleep", _fake_sleep):
        _run(client.bulk_post_blocklist(entries))

    # Six indicators must have been POSTed at least once each — but one
    # extra POST happens because of the 429 retry → total ≥ 7
    posts = [c for c in sess.calls if c["method"] == "POST"]
    assert len(posts) >= 7
    entries_seen = {(c.get("json") or {}).get("entry") for c in posts}
    assert entries_seen == {f"ja4-{i}" for i in range(6)}


@pytest.mark.chaos
def test_429_backoff_increases_inter_call_sleep():
    ManagementClient = _import_client()

    # Three 429s then success
    statuses = [429, 429, 429, 201]
    sess = _RespondingSession(statuses=statuses)

    client = ManagementClient(
        base_url="http://testserver",
        token="tok",
        session=sess,
        max_retries=5,
        backoff_initial_s=0.01,
    )

    sleeps: list[float] = []

    async def _fake_sleep(s):
        sleeps.append(s)

    with patch("src.analytics.ti_feeds.mgmt_client.asyncio.sleep", _fake_sleep):
        _run(client.post_blocklist(entry="x", managed_by="feed", note=""))

    # Exponential backoff: 0.01 → 0.02 → 0.04
    assert len(sleeps) == 3
    assert sleeps[0] == pytest.approx(0.01, rel=0.1)
    assert sleeps[1] == pytest.approx(0.02, rel=0.1)
    assert sleeps[2] == pytest.approx(0.04, rel=0.1)
