"""
Minimal aiohttp-compatible mock for the AbuseIPDB v2 /check endpoint.

Usage::

    mock = AbuseIPDBMock()
    mock.set_score("1.2.3.4", 85)
    mock.set_error("2.3.4.5", status=500)
    mock.set_quota_exhausted()   # next call returns 429
    session = mock.make_session()
    # Pass session to AbuseIPDBChecker(config, redis, local_cache, session)

The mock provides a fake aiohttp.ClientSession-like object via make_session().
All HTTP calls go through AsyncMock objects that simulate the AbuseIPDB API.

It records which IPs were requested (accessible via mock.requested_ips).
"""

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock


class _FakeResponse:
    """Simulates an aiohttp.ClientResponse with the /check endpoint format."""

    def __init__(self, ip: str, score: int, status: int = 200) -> None:
        self._ip = ip
        self._score = score
        self.status = status

    async def json(self) -> dict:
        return {"data": {"abuseConfidenceScore": self._score, "ipAddress": self._ip}}

    def raise_for_status(self) -> None:
        if self.status >= 400:
            err = MagicMock()
            err.status = self.status
            exc = Exception(f"HTTP {self.status}")
            exc.status = self.status  # type: ignore[attr-defined]
            raise exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class _TimeoutResponse:
    """Simulates a response that never arrives (asyncio.TimeoutError)."""

    async def json(self) -> dict:  # pragma: no cover
        raise asyncio.TimeoutError()

    def raise_for_status(self) -> None:  # pragma: no cover
        raise asyncio.TimeoutError()

    async def __aenter__(self):
        raise asyncio.TimeoutError()

    async def __aexit__(self, *args):
        pass


class AbuseIPDBMock:
    """Test double for the AbuseIPDB v2 API.

    Provides a fake aiohttp session via make_session(). Configure per-IP
    behaviour before passing the session to AbuseIPDBChecker.

    Attributes:
        requested_ips: List of IP strings that were requested, in call order.
    """

    def __init__(self) -> None:
        self._scores: dict[str, int] = {}
        self._errors: dict[str, int] = {}
        self._timeouts: set[str] = set()
        self._quota_exhausted: bool = False
        self.requested_ips: list[str] = []

    def set_score(self, ip: str, score: int) -> None:
        """Configure the confidence score returned for this IP."""
        self._scores[ip] = score
        self._errors.pop(ip, None)
        self._timeouts.discard(ip)

    def set_error(self, ip: str, status: int = 500) -> None:
        """Configure an HTTP error status for this IP."""
        self._errors[ip] = status
        self._scores.pop(ip, None)
        self._timeouts.discard(ip)

    def set_quota_exhausted(self) -> None:
        """Make all subsequent requests return HTTP 429."""
        self._quota_exhausted = True

    def set_timeout(self, ip: str) -> None:
        """Simulate a timeout (asyncio.TimeoutError) for this IP."""
        self._timeouts.add(ip)
        self._scores.pop(ip, None)
        self._errors.pop(ip, None)

    def reset(self) -> None:
        """Reset all configured behaviours and recorded requests."""
        self._scores.clear()
        self._errors.clear()
        self._timeouts.clear()
        self._quota_exhausted = False
        self.requested_ips.clear()

    def make_session(self) -> MagicMock:
        """Return a MagicMock that behaves like aiohttp.ClientSession.

        The returned object has a .get() method that returns an async context
        manager yielding a fake response object.
        """
        mock_session = MagicMock()
        mock_self = self  # Capture for closure

        @asynccontextmanager
        async def _fake_get(url, params=None, headers=None, timeout=None, **kwargs):
            ip = (params or {}).get("ipAddress", "unknown")
            mock_self.requested_ips.append(ip)

            if mock_self._quota_exhausted:
                yield _FakeResponse(ip, 0, status=429)
                return

            if ip in mock_self._timeouts:
                raise asyncio.TimeoutError()

            if ip in mock_self._errors:
                yield _FakeResponse(ip, 0, status=mock_self._errors[ip])
                return

            score = mock_self._scores.get(ip, 0)
            yield _FakeResponse(ip, score, status=200)

        mock_session.get = _fake_get
        return mock_session
