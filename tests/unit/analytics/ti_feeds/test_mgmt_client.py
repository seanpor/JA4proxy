"""Phase 85 — unit tests for ``analytics.ti_feeds.mgmt_client.ManagementClient``.

Verifies:
- Bans are written to ``POST /api/v1/bans/{ip:path}`` (URL-encoded path),
  with the IP in the URL not the body. **This is the canonical form** —
  the historical wrong-doc form ``POST /api/v1/bans`` with an ``ip`` body
  field must never be reintroduced.
- Blocklist entries are written to ``POST /api/v1/blocklist`` with a
  ``ResourceCreate``-shaped body.
- 5xx responses are retried with exponential backoff.
- 4xx responses are NOT retried (the request is malformed; retry won't help).
- Bulk ingest respects the §2.5 rate limit: batches of 50, 50 ms inter-batch
  sleep.

These tests are RED until ``src/analytics/ti_feeds/mgmt_client.py`` exists.
"""

from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest  # noqa: F401


def _run(coro):
    return asyncio.run(coro)


def _import_client():
    from src.analytics.ti_feeds.mgmt_client import ManagementClient

    return ManagementClient


class _RecordingResponse:
    """Minimal aiohttp.ClientResponse stand-in."""

    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self._body = body

    async def json(self) -> Any:
        return self._body

    async def text(self) -> str:
        return str(self._body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None


class _RecordingSession:
    """Captures every HTTP call and returns the next queued response."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._post_responses: list[_RecordingResponse] = []
        self._delete_responses: list[_RecordingResponse] = []

    def queue_post(self, status: int, body: Any) -> None:
        self._post_responses.append(_RecordingResponse(status, body))

    def queue_delete(self, status: int, body: Any) -> None:
        self._delete_responses.append(_RecordingResponse(status, body))

    def post(self, url: str, json=None, headers=None, **kwargs):
        self.calls.append(
            {
                "method": "POST",
                "url": url,
                "json": json,
                "headers": headers,
                "kwargs": kwargs,
            }
        )
        if not self._post_responses:
            return _RecordingResponse(500, {"error": "no response queued"})
        return self._post_responses.pop(0)

    def delete(self, url: str, headers=None, **kwargs):
        self.calls.append(
            {"method": "DELETE", "url": url, "headers": headers, "kwargs": kwargs}
        )
        if not self._delete_responses:
            return _RecordingResponse(204, {})
        return self._delete_responses.pop(0)


# ── URL contract ──────────────────────────────────────────────────────────────


def test_post_ban_calls_correct_url_with_ip_in_path():
    """The ban endpoint is /api/v1/bans/{ip:path}, not /api/v1/bans."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(201, {"ip": "1.2.3.4", "ttl": 3600, "reason": "feed:rf"})

    client = ManagementClient(
        base_url="https://mgmt.test", token="bearer-tok", session=sess
    )
    _run(client.post_ban("1.2.3.4", ttl=3600, reason="feed:rf"))

    call = sess.calls[-1]
    assert call["method"] == "POST"
    assert call["url"].endswith("/api/v1/bans/1.2.3.4")
    # Critical regression guard: must NOT POST to /api/v1/bans bare
    assert not call["url"].endswith("/api/v1/bans")
    # Body must NOT contain an "ip" field — that was the wrong-doc form
    body = call["json"] or {}
    assert "ip" not in body
    assert body.get("reason") == "feed:rf"
    assert body.get("ttl") == 3600


def test_post_ban_url_encodes_ipv6():
    """IPv6 addresses contain colons and must be URL-encoded into the path."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(201, {"ip": "2606:4700::1", "ttl": 3600, "reason": "feed:rf"})

    client = ManagementClient(
        base_url="https://mgmt.test", token="bearer-tok", session=sess
    )
    _run(client.post_ban("2606:4700::1", ttl=3600, reason="feed:rf"))

    call = sess.calls[-1]
    decoded = urllib.parse.unquote(call["url"])
    assert decoded.endswith("/api/v1/bans/2606:4700::1")


def test_post_blocklist_uses_resource_create_body():
    """Blocklist POST body matches the ResourceCreate model."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(
        201,
        {
            "id": "uuid-1",
            "entry": "t10d_aaaa_bbbb",
            "managed_by": "feed",
            "note": "feed:rf:indicator--xxx",
        },
    )

    client = ManagementClient(
        base_url="https://mgmt.test", token="bearer-tok", session=sess
    )
    _run(
        client.post_blocklist(
            entry="t10d_aaaa_bbbb",
            managed_by="feed",
            note="feed:rf:indicator--xxx",
            expires_at="2027-01-01T00:00:00Z",
        )
    )

    call = sess.calls[-1]
    assert call["url"].endswith("/api/v1/blocklist")
    body = call["json"]
    assert body["entry"] == "t10d_aaaa_bbbb"
    assert body["managed_by"] == "feed"
    assert body["note"] == "feed:rf:indicator--xxx"
    assert body["expires_at"] == "2027-01-01T00:00:00Z"


# ── Auth header ───────────────────────────────────────────────────────────────


def test_authorization_header_is_set_on_every_call():
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(
        201, {"id": "uuid-1", "entry": "x", "managed_by": "feed", "note": ""}
    )

    client = ManagementClient(
        base_url="https://mgmt.test", token="my-secret-token", session=sess
    )
    _run(client.post_blocklist(entry="x", managed_by="feed", note=""))

    headers = sess.calls[-1]["headers"] or {}
    assert headers.get("Authorization") == "Bearer my-secret-token"


# ── Retry semantics ───────────────────────────────────────────────────────────


def test_retries_on_5xx():
    """A 503 followed by a 200 succeeds; the call is retried."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(503, {"error": "transient"})
    sess.queue_post(503, {"error": "transient"})
    sess.queue_post(
        201, {"id": "uuid-1", "entry": "x", "managed_by": "feed", "note": ""}
    )

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        max_retries=3,
        backoff_initial_s=0.0,
    )
    _run(client.post_blocklist(entry="x", managed_by="feed", note=""))
    # Three POSTs total: two failed + one success
    assert sum(1 for c in sess.calls if c["method"] == "POST") == 3


def test_does_not_retry_on_4xx():
    """A 422 (validation error) is final — retry would just fail again."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(422, {"detail": "entry too long"})

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        max_retries=3,
        backoff_initial_s=0.0,
    )
    with pytest.raises(Exception):
        _run(client.post_blocklist(entry="x", managed_by="feed", note=""))
    assert sum(1 for c in sess.calls if c["method"] == "POST") == 1


def test_retries_use_exponential_backoff():
    """Backoff doubles between attempts (initial=0.01 → 0.02 → 0.04)."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(503, {"error": "transient"})
    sess.queue_post(503, {"error": "transient"})
    sess.queue_post(
        201, {"id": "uuid-1", "entry": "x", "managed_by": "feed", "note": ""}
    )

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        max_retries=3,
        backoff_initial_s=0.01,
    )

    sleeps: list[float] = []

    async def _fake_sleep(s: float) -> None:
        sleeps.append(s)

    with patch("src.analytics.ti_feeds.mgmt_client.asyncio.sleep", _fake_sleep):
        _run(client.post_blocklist(entry="x", managed_by="feed", note=""))

    assert len(sleeps) == 2
    assert sleeps[0] == pytest.approx(0.01, rel=0.01)
    assert sleeps[1] == pytest.approx(0.02, rel=0.01)


# ── Bulk ingest pacing (§2.5) ──────────────────────────────────────────────────


def test_bulk_blocklist_paces_50_per_batch():
    """When called with >50 entries, the client batches them in groups of 50."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    for i in range(120):
        sess.queue_post(
            201,
            {
                "id": f"uuid-{i}",
                "entry": f"ja4-{i}",
                "managed_by": "feed",
                "note": "feed:rf:indicator--{i}",
            },
        )

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        batch_size=50,
        inter_batch_sleep_s=0.05,
    )
    entries = [
        {"entry": f"ja4-{i}", "managed_by": "feed", "note": f"feed:rf:i{i}"}
        for i in range(120)
    ]

    sleeps: list[float] = []

    async def _fake_sleep(s: float) -> None:
        sleeps.append(s)

    with patch("src.analytics.ti_feeds.mgmt_client.asyncio.sleep", _fake_sleep):
        _run(client.bulk_post_blocklist(entries))

    # 120 entries → 3 batches of 50/50/20 → 2 inter-batch sleeps of 50 ms
    inter_batch_sleeps = [s for s in sleeps if s == pytest.approx(0.05, rel=0.01)]
    assert len(inter_batch_sleeps) == 2
    assert sum(1 for c in sess.calls if c["method"] == "POST") == 120


def test_bulk_blocklist_uses_return_exceptions_per_batch():
    """One bad indicator in a batch must not stall the rest."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    for i in range(50):
        if i == 7:
            sess.queue_post(422, {"detail": "entry malformed"})
        else:
            sess.queue_post(
                201,
                {"id": f"uuid-{i}", "entry": f"x{i}", "managed_by": "feed", "note": ""},
            )

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        batch_size=50,
        inter_batch_sleep_s=0.0,
    )
    entries = [{"entry": f"x{i}", "managed_by": "feed", "note": ""} for i in range(50)]

    async def _fake_sleep(s: float) -> None:
        return None

    with patch("src.analytics.ti_feeds.mgmt_client.asyncio.sleep", _fake_sleep):
        results = _run(client.bulk_post_blocklist(entries))

    # 50 results — at least one is an exception, the rest are dicts
    assert len(results) == 50
    failed = [r for r in results if isinstance(r, Exception)]
    assert len(failed) == 1


# ── Session management (coverage lines 167-194) ─────────────────────────────


def test_connect_noop_with_injected_session():
    """connect() is a no-op when session was injected via constructor."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )
    _run(client.connect())
    # Session should still be the injected one
    assert client._session is sess


def test_close_noop_with_injected_session():
    """close() is a no-op when session was injected via constructor."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )
    _run(client.close())
    # Session should still be set (not cleared)
    assert client._session is sess


def test_close_swallows_session_close_error():
    """close() swallows errors from session.close()."""
    ManagementClient = _import_client()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
    )
    # Manually set a session that raises on close
    mock_session = MagicMock()
    mock_session.close = AsyncMock(side_effect=RuntimeError("close failed"))
    client._session = mock_session
    client._injected_session = False

    _run(client.close())
    assert client._session is None


def test_close_clears_session():
    """close() sets session to None after closing."""
    ManagementClient = _import_client()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
    )
    mock_session = MagicMock()
    mock_session.close = AsyncMock()
    client._session = mock_session
    client._injected_session = False

    _run(client.close())
    assert client._session is None


# ── _open_request unsupported method (coverage line 229) ────────────────────


def test_open_request_unsupported_method_raises():
    """_open_request raises on unsupported HTTP method with injected session."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )
    with pytest.raises(RuntimeError, match="unsupported method"):
        client._open_request("PATCH", "https://mgmt.test/api/v1/test")


# ── No token raises 401 (coverage lines 256-257) ───────────────────────────


def test_no_token_raises_401():
    """When no token is set, _request raises ManagementAPIError(401)."""
    ManagementClient = _import_client()
    from src.analytics.ti_feeds.mgmt_client import ManagementAPIError

    sess = _RecordingSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="",
        session=sess,
    )

    with pytest.raises(ManagementAPIError) as exc_info:
        _run(client.post_blocklist(entry="x", note="test"))
    assert exc_info.value.status_code == 401


# ── Network exception triggers retry (coverage lines 303-311) ──────────────


def test_network_error_retries_and_exhausts():
    """Network errors are retried and eventually raise ManagementAPIError(503)."""
    ManagementClient = _import_client()
    from src.analytics.ti_feeds.mgmt_client import ManagementAPIError

    class FailingSession:
        def post(self, url, json=None, headers=None, **kwargs):
            raise ConnectionError("network down")

        def delete(self, url, headers=None, **kwargs):
            raise ConnectionError("network down")

        def get(self, url, headers=None, **kwargs):
            raise ConnectionError("network down")

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=FailingSession(),
        max_retries=2,
        backoff_initial_s=0.0,
    )

    with pytest.raises(ManagementAPIError) as exc_info:
        _run(client.post_blocklist(entry="x", note="test"))
    assert exc_info.value.status_code == 503
    assert "exhausted retries" in exc_info.value.message


# ── post_ban unsafe IP (coverage lines 344, 350-355) ───────────────────────


def test_post_ban_rejects_private_ip():
    """post_ban rejects RFC1918 addresses."""
    ManagementClient = _import_client()
    from src.analytics.ti_feeds.mgmt_client import ManagementAPIError

    sess = _RecordingSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )

    with pytest.raises(ManagementAPIError) as exc_info:
        _run(client.post_ban("192.168.1.1", ttl=3600, reason="test"))
    assert exc_info.value.status_code == 400
    assert "non-public" in exc_info.value.message


def test_post_ban_rejects_loopback():
    """post_ban rejects loopback addresses."""
    ManagementClient = _import_client()
    from src.analytics.ti_feeds.mgmt_client import ManagementAPIError

    sess = _RecordingSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )

    with pytest.raises(ManagementAPIError) as exc_info:
        _run(client.post_ban("127.0.0.1", ttl=3600, reason="test"))
    assert exc_info.value.status_code == 400


# ── delete_ban 404 swallow (coverage lines 366-374) ────────────────────────


def test_delete_ban_swallows_404():
    """delete_ban silently swallows 404 (ban already expired)."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_delete(404, {"detail": "not found"})
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )
    # Should not raise
    _run(client.delete_ban("1.2.3.4"))


def test_delete_ban_raises_on_non_404_error():
    """delete_ban re-raises non-404 errors."""
    ManagementClient = _import_client()
    from src.analytics.ti_feeds.mgmt_client import ManagementAPIError

    sess = _RecordingSession()
    sess.queue_delete(403, {"detail": "forbidden"})
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )

    with pytest.raises(ManagementAPIError) as exc_info:
        _run(client.delete_ban("1.2.3.4"))
    assert exc_info.value.status_code == 403


# ── delete_blocklist 404 swallow (coverage lines 416-422) ──────────────────


def test_delete_blocklist_swallows_404():
    """delete_blocklist silently swallows 404."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_delete(404, {"detail": "not found"})
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )
    # Should not raise
    _run(client.delete_blocklist("uuid-does-not-exist"))


def test_delete_blocklist_raises_on_non_404():
    """delete_blocklist re-raises non-404 errors."""
    ManagementClient = _import_client()
    from src.analytics.ti_feeds.mgmt_client import ManagementAPIError

    sess = _RecordingSession()
    sess.queue_delete(500, {"detail": "server error"})
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        max_retries=0,
        backoff_initial_s=0.0,
    )

    with pytest.raises(ManagementAPIError):
        _run(client.delete_blocklist("uuid-x"))


# ── bulk_post_blocklist inter-batch sleep (coverage line 456) ──────────────


def test_bulk_post_single_batch_no_sleep():
    """A single batch (<=50) does not trigger inter-batch sleep."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    for i in range(10):
        sess.queue_post(
            201, {"id": f"u-{i}", "entry": f"x{i}", "managed_by": "feed", "note": ""}
        )

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        batch_size=50,
        inter_batch_sleep_s=0.05,
    )
    entries = [{"entry": f"x{i}", "note": ""} for i in range(10)]

    sleeps = []

    async def _fake_sleep(s):
        sleeps.append(s)

    with patch("src.analytics.ti_feeds.mgmt_client.asyncio.sleep", _fake_sleep):
        _run(client.bulk_post_blocklist(entries))

    # Only 10 entries / 50 batch = 1 batch, no inter-batch sleep
    assert len(sleeps) == 0


# ── _open_request GET method (coverage line 228) ───────────────────────────


def test_open_request_get_method():
    """_open_request routes GET through session.get()."""
    ManagementClient = _import_client()

    class GetSession:
        def __init__(self):
            self.calls = []

        def get(self, url, headers=None, **kwargs):
            self.calls.append(("GET", url))
            return _RecordingResponse(200, {})

    sess = GetSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )
    ctx = client._open_request("GET", "https://mgmt.test/api/v1/test")
    # Just verify it returns without error
    assert ctx is not None


# ── post_ban ttl_s alias ───────────────────────────────────────────────────


def test_post_ban_requires_ttl():
    """post_ban raises TypeError when neither ttl nor ttl_s is provided."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
    )
    with pytest.raises(TypeError, match="ttl_s"):
        _run(client.post_ban("1.2.3.4", reason="test"))


# ── 429 triggers retry (coverage line 276) ─────────────────────────────────


def test_429_rate_limit_triggers_retry():
    """A 429 response triggers retry like 5xx."""
    ManagementClient = _import_client()
    sess = _RecordingSession()
    sess.queue_post(429, {"detail": "rate limited"})
    sess.queue_post(201, {"id": "u-1", "entry": "x", "managed_by": "feed", "note": ""})

    client = ManagementClient(
        base_url="https://mgmt.test",
        token="tok",
        session=sess,
        max_retries=3,
        backoff_initial_s=0.0,
    )

    async def _noop_sleep(s):
        pass

    with patch("src.analytics.ti_feeds.mgmt_client.asyncio.sleep", _noop_sleep):
        _run(client.post_blocklist(entry="x", note="test"))

    assert sum(1 for c in sess.calls if c["method"] == "POST") == 2
