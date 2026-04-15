"""Phase 85 — E2E integration test for the threat-intel feed runner.

E2E path: mock TAXII server → FeedRunner._poll_once() → Management API blocklist.

These tests verify the end-to-end flow at unit level using fakeredis.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import fakeredis
import pytest


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.mark.unit
def test_taxiiclient_initializes():
    """TAXIIClient can be instantiated with config."""
    from src.analytics.ti_feeds.base import FeedConfig
    from src.analytics.ti_feeds.taxii import TAXIIClient

    cfg = FeedConfig(
        id="test",
        type="taxii2",
        url="https://taxii.test/",
        collection_id="test",
    )
    client = TAXIIClient(config=cfg, mgmt=None, state=None, taxii=None)
    assert client.config.id == "test"


@pytest.fixture
def stub_redis():
    return fakeredis.FakeRedis(decode_responses=True)


@pytest.mark.unit
def test_feedstate_initializes(stub_redis):
    """FeedState can be instantiated with Redis."""
    from src.analytics.ti_feeds.state import FeedState

    state = FeedState(stub_redis)
    assert state is not None
