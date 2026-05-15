"""Unit tests for deploy/integrations/splunk-ta/ja4proxy-ta/bin/ja4proxy_ban_action.py.

Verifies that the Splunk alert action script constructs the correct URL and
request body to match the Phase 79 Management API shape:
  - POST /api/v1/bans/{ip:path}  (IP in path, URL-encoded for IPv6 safety)
  - Body: {"ttl": <int>, "reason": <str>}  (BanCreateRequest fields)
  - Body must NOT contain "ip" or "ttl_seconds"
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
import unittest.mock
from pathlib import Path
from urllib.parse import quote as urlquote

import pytest

# ---------------------------------------------------------------------------
# Load the module without executing main()
# ---------------------------------------------------------------------------

_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "integrations"
    / "splunk-ta"
    / "ja4proxy-ta"
    / "bin"
    / "ja4proxy_ban_action.py"
)


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("ja4proxy_ban_action", _SCRIPT_PATH)
    assert spec is not None, f"Could not load spec from {_SCRIPT_PATH}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


mod = _load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_response(status_code: int = 200, body: str = '{"message": "ok"}'):
    """Return a context-manager mock that mimics urllib.request.urlopen()."""
    fake = unittest.mock.MagicMock()
    fake.__enter__ = unittest.mock.Mock(return_value=fake)
    fake.__exit__ = unittest.mock.Mock(return_value=False)
    fake.getcode.return_value = status_code
    fake.read.return_value = body.encode("utf-8")
    return fake


# ---------------------------------------------------------------------------
# URL shape tests
# ---------------------------------------------------------------------------


class TestUrlShape:
    """IP must appear in the path, not just in the body."""

    def test_ipv4_appears_in_path(self):
        """IPv4 address is embedded in the URL path segment."""
        captured: list = []

        def fake_urlopen(req, timeout=None, **kwargs):
            # JA4PROXY-2026-0055 (phase-118aa): real _post_ban now passes
            # context=<ssl context>. Accept **kwargs so future hardening
            # kwargs do not silently break this mock.
            captured.append(req)
            return _make_fake_response()

        with unittest.mock.patch("urllib.request.urlopen", fake_urlopen):
            mod._post_ban(
                mgmt_url="https://mgmt.example.com",
                api_token="tok",
                src_ip="203.0.113.42",
                ttl_seconds=3600,
                reason="test",
            )

        assert captured, "urlopen was not called"
        req = captured[0]
        assert (
            "/api/v1/bans/203.0.113.42" in req.full_url
        ), f"Expected IP in URL path; got {req.full_url!r}"

    def test_ipv6_is_url_encoded_in_path(self):
        """IPv6 colons are percent-encoded so they don't break URL parsing."""
        captured: list = []

        def fake_urlopen(req, timeout=None, **kwargs):
            # JA4PROXY-2026-0055 (phase-118aa): real _post_ban now passes
            # context=<ssl context>. Accept **kwargs so future hardening
            # kwargs do not silently break this mock.
            captured.append(req)
            return _make_fake_response()

        with unittest.mock.patch("urllib.request.urlopen", fake_urlopen):
            mod._post_ban(
                mgmt_url="https://mgmt.example.com",
                api_token="tok",
                src_ip="2001:db8::1",
                ttl_seconds=3600,
                reason="test",
            )

        assert captured, "urlopen was not called"
        req = captured[0]
        encoded_ipv6 = urlquote("2001:db8::1", safe="")
        assert (
            encoded_ipv6 in req.full_url
        ), f"Expected URL-encoded IPv6 in path; got {req.full_url!r}"
        # Confirm colons are NOT bare in the path
        # (the base URL may still contain ://, so check the path component only)
        path_part = req.full_url.split("/api/v1/bans/")[-1]
        assert (
            ":" not in path_part
        ), f"Bare colon found in IP path segment; got {path_part!r}"

    def test_url_does_not_end_with_bare_bans(self):
        """URL must NOT be /api/v1/bans with no IP segment (old broken shape)."""
        captured: list = []

        def fake_urlopen(req, timeout=None, **kwargs):
            # JA4PROXY-2026-0055 (phase-118aa): real _post_ban now passes
            # context=<ssl context>. Accept **kwargs so future hardening
            # kwargs do not silently break this mock.
            captured.append(req)
            return _make_fake_response()

        with unittest.mock.patch("urllib.request.urlopen", fake_urlopen):
            mod._post_ban(
                mgmt_url="https://mgmt.example.com",
                api_token="tok",
                src_ip="198.51.100.7",
                ttl_seconds=3600,
                reason="test",
            )

        req = captured[0]
        assert not req.full_url.rstrip("/").endswith(
            "/api/v1/bans"
        ), f"URL must not be /api/v1/bans with no IP; got {req.full_url!r}"


# ---------------------------------------------------------------------------
# Request body shape tests
# ---------------------------------------------------------------------------


class TestRequestBodyShape:
    """Body must match BanCreateRequest: {ttl, reason}.  No ip or ttl_seconds."""

    def _capture_body(self, src_ip: str, ttl_seconds: int, reason: str) -> dict:
        captured: list = []

        def fake_urlopen(req, timeout=None, **kwargs):
            # JA4PROXY-2026-0055 (phase-118aa): real _post_ban now passes
            # context=<ssl context>. Accept **kwargs so future hardening
            # kwargs do not silently break this mock.
            captured.append(req)
            return _make_fake_response()

        with unittest.mock.patch("urllib.request.urlopen", fake_urlopen):
            mod._post_ban(
                mgmt_url="https://mgmt.example.com",
                api_token="tok",
                src_ip=src_ip,
                ttl_seconds=ttl_seconds,
                reason=reason,
            )

        req = captured[0]
        return json.loads(req.data.decode("utf-8"))

    def test_body_contains_ttl_field(self):
        body = self._capture_body("10.0.0.1", 7200, "pentest")
        assert "ttl" in body, f"Expected 'ttl' key in body; got {list(body.keys())}"

    def test_body_contains_reason_field(self):
        body = self._capture_body("10.0.0.1", 7200, "pentest")
        assert (
            "reason" in body
        ), f"Expected 'reason' key in body; got {list(body.keys())}"

    def test_body_ttl_value_matches_ttl_seconds_param(self):
        body = self._capture_body("10.0.0.1", 7200, "pentest")
        assert body["ttl"] == 7200, f"Expected ttl=7200; got {body['ttl']}"

    def test_body_reason_value_is_correct(self):
        body = self._capture_body("10.0.0.1", 7200, "pentest")
        assert (
            body["reason"] == "pentest"
        ), f"Expected reason='pentest'; got {body['reason']}"

    def test_body_does_not_contain_ip_field(self):
        """IP must be in the URL path, not the body."""
        body = self._capture_body("10.0.0.1", 3600, "test")
        assert (
            "ip" not in body
        ), f"'ip' field must not appear in request body (IP goes in path); body={body}"

    def test_body_does_not_contain_ttl_seconds_field(self):
        """Old field name 'ttl_seconds' must not appear — API expects 'ttl'."""
        body = self._capture_body("10.0.0.1", 3600, "test")
        assert (
            "ttl_seconds" not in body
        ), f"Old field 'ttl_seconds' must not appear in body; body={body}"

    def test_body_does_not_contain_source_field(self):
        """Extraneous 'source' field from Sentinel playbook must not be in Splunk script."""
        body = self._capture_body("10.0.0.1", 3600, "test")
        assert "source" not in body, f"Unexpected 'source' field in body; body={body}"


# ---------------------------------------------------------------------------
# Sentinel playbook JSON shape test
# ---------------------------------------------------------------------------

_PLAYBOOK_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy"
    / "integrations"
    / "sentinel"
    / "playbooks"
    / "Block-IP-Playbook.json"
)


class TestSentinelPlaybook:
    """Block-IP-Playbook.json must match Phase 79 API shape."""

    @pytest.fixture(scope="class")
    def playbook(self):
        with open(_PLAYBOOK_PATH) as f:
            return json.load(f)

    def _find_ban_action(self, playbook: dict) -> dict:
        """Locate the Call_JA4proxy_ban_API action in the playbook."""
        for action_group in playbook.get("actions", {}).values():
            if not isinstance(action_group, dict):
                continue
            inner_actions = action_group.get("actions", {})
            for inner in inner_actions.values():
                if not isinstance(inner, dict):
                    continue
                nested = inner.get("actions", {})
                ban_action = nested.get("Call_JA4proxy_ban_API")
                if ban_action:
                    return ban_action
        pytest.fail("Could not locate Call_JA4proxy_ban_API action in playbook")

    def test_ban_action_uri_contains_bans_path_with_ip(self, playbook):
        """URI must include IP as a path segment, not just /api/v1/bans."""
        ban_action = self._find_ban_action(playbook)
        uri: str = ban_action["inputs"]["uri"]
        assert (
            "/api/v1/bans/" in uri
        ), f"Expected '/api/v1/bans/<ip>' in URI; got {uri!r}"

    def test_ban_action_uri_does_not_end_with_bare_bans(self, playbook):
        """URI must not be bare /api/v1/bans (old broken shape)."""
        ban_action = self._find_ban_action(playbook)
        uri: str = ban_action["inputs"]["uri"]
        # Strip trailing whitespace/slashes before checking
        assert not uri.rstrip("/ ").endswith(
            "/api/v1/bans"
        ), f"URI must not end at /api/v1/bans with no IP segment; got {uri!r}"

    def test_ban_action_body_has_ttl_not_ttl_seconds(self, playbook):
        """Body must use 'ttl', not 'ttl_seconds' (BanCreateRequest field name)."""
        ban_action = self._find_ban_action(playbook)
        body: dict = ban_action["inputs"]["body"]
        body_str = json.dumps(body)
        assert "ttl" in body_str, f"Expected 'ttl' in body; got {body_str!r}"
        assert (
            "ttl_seconds" not in body_str
        ), f"Old field 'ttl_seconds' must not appear in body; got {body_str!r}"

    def test_ban_action_body_has_no_ip_field(self, playbook):
        """IP must be in the path, not a top-level body field."""
        ban_action = self._find_ban_action(playbook)
        body: dict = ban_action["inputs"]["body"]
        assert (
            "ip" not in body
        ), f"'ip' field must not appear in body (IP goes in URL path); body keys: {list(body.keys())}"

    def test_ban_action_body_has_reason(self, playbook):
        """Body must contain 'reason' field (BanCreateRequest field)."""
        ban_action = self._find_ban_action(playbook)
        body: dict = ban_action["inputs"]["body"]
        assert "reason" in body, f"Expected 'reason' in body; got {list(body.keys())}"
