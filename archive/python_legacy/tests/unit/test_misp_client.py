"""
Unit tests for src/tap/export/misp_client.py — Phase 20, Group 9.
"""

import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.tap.export.misp_client import MISPClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> dict:
    cfg = {
        "base_url": "https://misp.example.com",
        "api_key": "test-api-key",
        "verify_tls": True,
        "event_distribution": 0,
        "event_threat_level": 1,
    }
    cfg.update(overrides)
    return cfg


def _make_response(status: int = 200, data: dict | None = None) -> MagicMock:
    resp = AsyncMock()
    resp.status = status
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    if data is not None:
        resp.json = AsyncMock(return_value=data)
    else:
        resp.json = AsyncMock(return_value={})
    return resp


def _make_session(event_response=None, attr_response=None) -> MagicMock:
    """Build a mock session.

    event_response: response for POST /events
    attr_response: response for POST /attributes/add/...
    """
    session = MagicMock()
    if event_response is None:
        event_response = _make_response(200, {"Event": {"id": "42"}})
    if attr_response is None:
        attr_response = _make_response(200, {})

    post_calls = [0]

    def post_side_effect(url, **kwargs):
        if "/events" in url and "/attributes" not in url:
            return event_response
        else:
            return attr_response

    session.post.side_effect = post_side_effect
    return session


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPushBan:
    @pytest.mark.asyncio
    async def test_push_ban_creates_attribute_with_ip_dst_type(self):
        """push_ban must add an ip-dst attribute."""
        session = _make_session()
        client = MISPClient(_make_config(), session)

        # Capture _add_attribute calls
        add_calls = []

        async def capture_add(event_id, type_, value, comment):
            add_calls.append((type_, value))

        client._add_attribute = capture_add

        await client.push_ban("1.2.3.4", 80, "high_score")

        assert any(
            t == "ip-dst" for t, _ in add_calls
        ), f"Expected ip-dst attribute, got: {add_calls}"

    @pytest.mark.asyncio
    async def test_ja4_attribute_added_as_other_type(self):
        """push_ban with ja4 must add an 'other' type attribute for the fingerprint."""
        session = _make_session()
        client = MISPClient(_make_config(), session)

        add_calls = []

        async def capture_add(event_id, type_, value, comment):
            add_calls.append((type_, value))

        client._add_attribute = capture_add

        await client.push_ban("1.2.3.4", 80, "high_score", ja4="t13d_abc")

        assert any(
            t == "other" for t, _ in add_calls
        ), f"Expected 'other' type for JA4, got: {add_calls}"

    @pytest.mark.asyncio
    async def test_daily_event_reused_for_same_day(self):
        """Calling push_ban twice on the same day should not create two events."""
        event_resp = _make_response(200, {"Event": {"id": "42"}})
        session = _make_session(event_response=event_resp)
        client = MISPClient(_make_config(), session)

        # Track how many times the event creation POST is called
        create_count = [0]
        original_get_or_create = client._get_or_create_daily_event

        async def patched():
            result = await original_get_or_create()
            # Prevent a second creation on second call
            return result

        # Simulate two bans on same day
        async def noop_add(event_id, type_, value, comment):
            pass

        client._add_attribute = noop_add

        await client.push_ban("1.2.3.4", 80, "reason1")
        await client.push_ban("5.6.7.8", 70, "reason2")

        # Event creation should have been attempted once per unique date
        # The POST /events endpoint should only be called once
        post_to_events = [c for c in session.post.call_args_list if "/events" in str(c)]
        assert (
            len(post_to_events) <= 1
        ), f"Event should be created only once, got {len(post_to_events)} calls to /events"

    @pytest.mark.asyncio
    async def test_duplicate_attribute_not_created(self):
        """When _add_attribute gets a 409, no exception should be raised."""
        attr_409 = _make_response(409, {})
        session = _make_session(attr_response=attr_409)
        client = MISPClient(_make_config(), session)

        # Must not raise
        await client._add_attribute("42", "ip-dst", "1.2.3.4", "comment")

    @pytest.mark.asyncio
    async def test_misp_api_error_logs_warn_not_crash(self):
        """When session.post raises, push_ban must not propagate the error."""
        session = MagicMock()
        session.post.side_effect = ConnectionError("connection refused")
        client = MISPClient(_make_config(), session)

        # Must not raise
        await client.push_ban("1.2.3.4", 80, "reason")

    @pytest.mark.asyncio
    async def test_push_ban_without_ja4_only_adds_ip_attribute(self):
        """When ja4 is None, only the ip-dst attribute should be added."""
        session = _make_session()
        client = MISPClient(_make_config(), session)

        add_calls = []

        async def capture_add(event_id, type_, value, comment):
            add_calls.append((type_, value))

        client._add_attribute = capture_add

        await client.push_ban("1.2.3.4", 80, "reason")

        types = [t for t, _ in add_calls]
        assert "ip-dst" in types
        assert "other" not in types


class TestGetOrCreateDailyEvent:
    @pytest.mark.asyncio
    async def test_caches_event_id_for_today(self):
        """_get_or_create_daily_event must cache the event_id for today."""
        event_resp = _make_response(200, {"Event": {"id": "99"}})
        session = _make_session(event_response=event_resp)
        client = MISPClient(_make_config(), session)

        id1 = await client._get_or_create_daily_event()
        id2 = await client._get_or_create_daily_event()

        assert id1 == id2 == "99"
        # Only one POST to create event
        event_posts = [c for c in session.post.call_args_list if "/events" in str(c)]
        assert len(event_posts) == 1


# ---------------------------------------------------------------------------
# Additional tests targeting previously uncovered lines
# ---------------------------------------------------------------------------


class TestPushBanExceptionPath:
    """Lines 71-72: outer exception handler in push_ban logs WARNING and does not raise."""

    @pytest.mark.asyncio
    async def test_push_ban_logs_warning_on_unexpected_error(self, caplog):
        # Lines 71-72: any unexpected exception in push_ban is caught and logged.
        # Without this catch, a MISP outage would propagate and block the proxy pipeline.
        session = _make_session()
        client = MISPClient(_make_config(), session)

        async def explode(event_id, type_, value, comment):
            raise RuntimeError("unexpected error")

        client._add_attribute = explode

        with caplog.at_level(logging.WARNING, logger="src.tap.export.misp_client"):
            await client.push_ban("1.2.3.4", 80, "reason")

        assert any("push_ban_failed" in r.message for r in caplog.records)


class TestGetOrCreateDailyEventCreateFails:
    """Line 112: create_event_failed log path when session.post raises."""

    @pytest.mark.asyncio
    async def test_create_event_failure_returns_empty_string(self, caplog):
        # Line 112 (and surrounding exception block): when event creation POST raises,
        # event_id is set to "" and a WARNING is logged.
        # An empty event_id must not crash _add_attribute (line 136 guards it).
        session = MagicMock()
        session.post.side_effect = ConnectionError("misp unreachable")
        client = MISPClient(_make_config(), session)

        with caplog.at_level(logging.WARNING, logger="src.tap.export.misp_client"):
            event_id = await client._get_or_create_daily_event()

        assert event_id == ""
        assert any("create_event_failed" in r.message for r in caplog.records)


class TestAddAttributeEdgeCases:
    """Lines 159-180: _add_attribute HTTP error and non-context-manager paths."""

    @pytest.mark.asyncio
    async def test_add_attribute_skips_when_event_id_empty(self):
        # Line 136: _add_attribute must return immediately if event_id is "".
        # This guards against POSTing attributes to an invalid MISP event.
        session = MagicMock()
        client = MISPClient(_make_config(), session)
        await client._add_attribute("", "ip-dst", "1.2.3.4", "comment")
        session.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_add_attribute_logs_warning_on_400_error(self, caplog):
        # Lines 159-166: HTTP 4xx (not 409) must log a WARNING but not raise.
        # A rejected attribute must not abort the entire push_ban flow.
        attr_resp = _make_response(400, {})
        session = _make_session(attr_response=attr_resp)
        client = MISPClient(_make_config(), session)

        with caplog.at_level(logging.WARNING, logger="src.tap.export.misp_client"):
            await client._add_attribute("42", "ip-dst", "1.2.3.4", "comment")

        assert any("add_attribute_failed" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_add_attribute_exception_is_caught_and_logged(self, caplog):
        # Lines 179-183: if session.post() raises, _add_attribute logs a WARNING.
        # Network errors must never propagate up to crash push_ban.
        session = MagicMock()
        session.post.side_effect = ConnectionError("MISP unreachable")
        client = MISPClient(_make_config(), session)

        with caplog.at_level(logging.WARNING, logger="src.tap.export.misp_client"):
            await client._add_attribute("42", "ip-dst", "1.2.3.4", "comment")

        assert any("add_attribute_error" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_add_attribute_non_aenter_path_handles_409(self):
        # Lines 168-170: when resp_ctx has no __aenter__ (plain response object),
        # a 409 status must be silently swallowed (duplicate attribute).
        resp_mock = MagicMock()
        resp_mock.status = 409
        # No __aenter__ — simulates a non-context-manager response
        del resp_mock.__aenter__
        session = MagicMock()
        session.post.return_value = resp_mock

        client = MISPClient(_make_config(), session)
        await client._add_attribute(
            "42", "ip-dst", "1.2.3.4", "comment"
        )  # must not raise

    @pytest.mark.asyncio
    async def test_add_attribute_non_aenter_path_logs_warning_on_error(self, caplog):
        # Lines 171-178: non-context-manager response with status >= 400 (not 409) logs WARNING.
        resp_mock = MagicMock()
        resp_mock.status = 500
        del resp_mock.__aenter__
        session = MagicMock()
        session.post.return_value = resp_mock

        client = MISPClient(_make_config(), session)

        with caplog.at_level(logging.WARNING, logger="src.tap.export.misp_client"):
            await client._add_attribute("42", "ip-dst", "1.2.3.4", "comment")

        assert any("add_attribute_failed" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_get_or_create_non_aenter_response_calls_json_directly(self):
        # Line 112: when resp_ctx has no __aenter__, data = await resp_ctx.json() is called.
        # This non-context-manager path must correctly extract the event_id.
        resp_mock = AsyncMock()
        resp_mock.json = AsyncMock(return_value={"Event": {"id": "77"}})
        # Remove __aenter__ so the else branch is taken in _get_or_create_daily_event
        del resp_mock.__aenter__
        session = MagicMock()
        session.post.return_value = resp_mock

        client = MISPClient(_make_config(), session)
        event_id = await client._get_or_create_daily_event()
        assert event_id == "77"
