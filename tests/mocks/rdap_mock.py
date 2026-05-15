"""
Minimal aiohttp-compatible mock for RDAP registry API responses.

Usage::

    mock = RDAPMock()
    mock.set_result("1.2.3.4", rdap_result)
    mock.set_not_found("2.3.4.5")
    mock.set_error("3.4.5.6", status=500)
    mock.set_timeout("4.5.6.7")
    mock.set_redirect("5.6.7.8", hops=2)
    session = mock.make_session()
    # Pass session to RDAPEnricher(config, redis, local_cache, session)

The mock records which IPs were requested (accessible via mock.requested_ips).
It also simulates IANA bootstrap responses so the enricher can route correctly.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from unittest.mock import MagicMock


@dataclass
class _FakeRDAPResponse:
    """Simulates a minimal RDAP IP response body."""

    ip: str
    netblock: str = "1.2.3.0/24"
    org_name: str = "Test Org"
    org_handle: str = "TEST-1"
    registration_date: str = "2020-01-01"
    country: str = "US"

    def as_rdap_json(self) -> dict:
        """Return a minimal RDAP JSON response body."""
        return {
            "startAddress": self.netblock.split("/")[0],
            "cidrLength": int(self.netblock.split("/")[1]),
            "country": self.country,
            "events": [
                {
                    "eventAction": "registration",
                    "eventDate": f"{self.registration_date}T00:00:00Z",
                }
            ],
            "entities": [
                {
                    "handle": self.org_handle,
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", self.org_name],
                        ],
                    ],
                }
            ],
        }


class _FakeHTTPResponse:
    """Simulates an aiohttp.ClientResponse for RDAP calls."""

    def __init__(
        self,
        status: int = 200,
        body: dict | None = None,
        location: str | None = None,
    ) -> None:
        self.status = status
        self._body = body or {}
        self.headers: dict = {}
        if location:
            self.headers["Location"] = location

    async def json(self, content_type=None) -> dict:
        return self._body

    def raise_for_status(self) -> None:
        if self.status >= 400:
            exc = Exception(f"HTTP {self.status}")
            exc.status = self.status  # type: ignore[attr-defined]
            raise exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class _TimeoutResponse:
    """Simulates a request that times out."""

    async def json(self, content_type=None):  # pragma: no cover
        raise asyncio.TimeoutError()

    def raise_for_status(self):  # pragma: no cover
        raise asyncio.TimeoutError()

    async def __aenter__(self):
        raise asyncio.TimeoutError()

    async def __aexit__(self, *args):
        pass


class RDAPMock:
    """Test double for RDAP registry HTTP responses.

    Provides a fake aiohttp session via make_session(). Configure per-IP
    behaviour before passing the session to RDAPEnricher.

    Attributes:
        requested_ips: List of IP strings that were requested, in call order.
    """

    def __init__(self) -> None:
        self._results: dict[str, _FakeRDAPResponse] = {}
        self._not_found: set[str] = set()
        self._errors: dict[str, int] = {}  # ip → HTTP status
        self._timeouts: set[str] = set()
        self._redirects: dict[str, int] = {}  # ip → number of redirect hops
        self._redirect_counts: dict[str, int] = {}  # ip → current hop count
        self.requested_ips: list[str] = []

        # Bootstrap data: maps IP prefix to RIR URL
        self._bootstrap_v4: list[dict] = [
            {
                "prefixes": ["0.0.0.0/0"],
                "urls": ["https://rdap.arin.net/registry/"],
            }
        ]
        self._bootstrap_v6: list[dict] = [
            {
                "prefixes": ["::/0"],
                "urls": ["https://rdap.arin.net/registry/"],
            }
        ]

    def set_result(
        self, ip: str, rdap_result: "_FakeRDAPResponse | None" = None
    ) -> None:
        """Configure a successful RDAP result for this IP."""
        if rdap_result is None:
            rdap_result = _FakeRDAPResponse(ip=ip)
        self._results[ip] = rdap_result
        self._not_found.discard(ip)
        self._errors.pop(ip, None)
        self._timeouts.discard(ip)
        self._redirects.pop(ip, None)

    def set_not_found(self, ip: str) -> None:
        """Simulate HTTP 404 for this IP (IP not in RDAP database)."""
        self._not_found.add(ip)
        self._results.pop(ip, None)
        self._errors.pop(ip, None)
        self._timeouts.discard(ip)

    def set_error(self, ip: str, status: int = 500) -> None:
        """Simulate an HTTP error status for this IP."""
        self._errors[ip] = status
        self._results.pop(ip, None)
        self._not_found.discard(ip)
        self._timeouts.discard(ip)

    def set_timeout(self, ip: str) -> None:
        """Simulate a network timeout for this IP."""
        self._timeouts.add(ip)
        self._results.pop(ip, None)
        self._not_found.discard(ip)
        self._errors.pop(ip, None)

    def set_redirect(self, ip: str, hops: int = 1) -> None:
        """Simulate N redirect hops before the final response for this IP."""
        self._redirects[ip] = hops
        self._redirect_counts[ip] = 0

    def set_bootstrap(
        self,
        v4_entries: list[dict] | None = None,
        v6_entries: list[dict] | None = None,
    ) -> None:
        """Override bootstrap data. Each entry: {prefixes: [...], urls: [...]}"""
        if v4_entries is not None:
            self._bootstrap_v4 = v4_entries
        if v6_entries is not None:
            self._bootstrap_v6 = v6_entries

    def reset(self) -> None:
        """Reset all configured behaviours and recorded requests."""
        self._results.clear()
        self._not_found.clear()
        self._errors.clear()
        self._timeouts.clear()
        self._redirects.clear()
        self._redirect_counts.clear()
        self.requested_ips.clear()

    def make_session(self) -> MagicMock:
        """Return a MagicMock behaving like aiohttp.ClientSession.

        The .get() method returns an async context manager yielding fake
        responses. IANA bootstrap URLs return bootstrap JSON; RDAP IP
        lookup URLs return the configured response.
        """
        mock_session = MagicMock()
        mock_self = self

        @asynccontextmanager
        async def _fake_get(url: str, timeout=None, allow_redirects=True, **kwargs):
            # Handle IANA bootstrap requests
            if "iana.org/rdap/ipv4" in url:
                yield _FakeHTTPResponse(
                    status=200,
                    body={
                        "services": [
                            [entry["prefixes"], entry["urls"]]
                            for entry in mock_self._bootstrap_v4
                        ]
                    },
                )
                return
            if "iana.org/rdap/ipv6" in url:
                yield _FakeHTTPResponse(
                    status=200,
                    body={
                        "services": [
                            [entry["prefixes"], entry["urls"]]
                            for entry in mock_self._bootstrap_v6
                        ]
                    },
                )
                return

            # Extract IP from URL pattern: .../ip/{ip}
            ip = "unknown"
            if "/ip/" in url:
                ip = url.split("/ip/")[-1].rstrip("/")

            mock_self.requested_ips.append(ip)

            # Timeout
            if ip in mock_self._timeouts:
                raise asyncio.TimeoutError()

            # Redirect simulation
            if ip in mock_self._redirects:
                count = mock_self._redirect_counts.get(ip, 0)
                max_hops = mock_self._redirects[ip]
                if count < max_hops:
                    mock_self._redirect_counts[ip] = count + 1
                    redirect_url = (
                        f"https://rdap-redirect.example.com/ip/{ip}?hop={count + 1}"
                    )
                    yield _FakeHTTPResponse(
                        status=301,
                        body={},
                        location=redirect_url,
                    )
                    return
                else:
                    # Final response after redirects
                    mock_self._redirect_counts[ip] = 0

            # Not found
            if ip in mock_self._not_found:
                yield _FakeHTTPResponse(status=404, body={})
                return

            # HTTP error
            if ip in mock_self._errors:
                yield _FakeHTTPResponse(status=mock_self._errors[ip], body={})
                return

            # Configured result
            result = mock_self._results.get(ip)
            if result is not None:
                yield _FakeHTTPResponse(status=200, body=result.as_rdap_json())
                return

            # Default: return a basic result
            default = _FakeRDAPResponse(ip=ip)
            yield _FakeHTTPResponse(status=200, body=default.as_rdap_json())

        mock_session.get = _fake_get
        return mock_session


def make_rdap_result(
    ip: str,
    netblock: str = "1.2.3.0/24",
    org_name: str = "Test Org",
    org_handle: str = "TEST-1",
    registration_date: str = "2020-01-01",
    country: str = "US",
) -> _FakeRDAPResponse:
    """Convenience factory for test setup."""
    return _FakeRDAPResponse(
        ip=ip,
        netblock=netblock,
        org_name=org_name,
        org_handle=org_handle,
        registration_date=registration_date,
        country=country,
    )
