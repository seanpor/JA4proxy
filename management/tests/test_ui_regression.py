"""Phase 826 — UI regression tests that fail when a panel is actually broken.

WHY THIS EXISTS
---------------
test_pages.py asserts that page routes return 200 and contain a landmark
string. That is necessary but it cannot catch the failure mode this console
actually has: the console is a shell plus htmx partials fetched AFTER page
load, so the shell renders identically whether the panels behind it work or
are all 500ing. Every page test passed throughout the period when the
Intelligence panel had never once displayed a finding, the dial could not be
moved, and /api/v1/tls-health was returning 500 on every poll.

Three tiers here, cheapest first:

  Tier 1  Every hx-get URL referenced by a template resolves to a real route.
          Extracted FROM the templates, so it covers new panels automatically
          rather than needing a human to remember to add them.

  Tier 2  Each partial returns 200 AND is not rendering an error state. A
          panel that 200s with "Unavailable" in it is not a working panel.

  Tier 3  Content assertions for the pages a demo actually walks through —
          the fingerprint drill-down must contain its decoded explanation, not
          just a heading.

Not covered here: real browser rendering (Playwright). Tracked in Phase 824.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from httpx import AsyncClient

TEMPLATES = Path(__file__).resolve().parents[1] / "templates"

# Fingerprints observed on the POC stack; the browser one must stay
# distinguishable from the tool ones or the drill-down is not saying anything.
BROWSER_JA4 = "t13d1212h2_eac1b15b5477_8e6e362c5eac"
TOOL_JA4 = "t13d091100_f91f431d341e_8e6e362c5eac"

# Substrings that mean a panel rendered its failure branch rather than content.
_ERROR_MARKERS = ("Unavailable", "unavailable", "Traceback", "Internal Server Error")


def _hx_urls() -> list[str]:
    """Every hx-get URL literal referenced across the templates.

    Self-maintaining on purpose: a new panel is covered the moment its template
    lands, without anyone remembering to extend a list here.
    """
    urls: set[str] = set()
    for tpl in TEMPLATES.rglob("*.html"):
        for m in re.finditer(r"""hx-get=["']([^"'{}]+)["']""", tpl.read_text()):
            url = m.group(1).strip()
            if url.startswith("/"):
                urls.add(url)
    return sorted(urls)


class TestTier1RouteResolution:
    """Every panel the UI fetches must exist. A 404 blanks a panel silently."""

    def test_templates_reference_at_least_one_partial(self):
        """Guard the guard: a broken extractor would vacuously pass everything."""
        assert len(_hx_urls()) >= 5, (
            f"only found {_hx_urls()} — the hx-get extractor is probably broken, "
            "which would make every assertion below pass vacuously"
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", _hx_urls())
    async def test_hx_get_url_resolves(
        self, authenticated_client: AsyncClient, url: str
    ):
        resp = await authenticated_client.get(url)
        assert resp.status_code != 404, (
            f"{url} is fetched by a template but resolves to nothing — the panel "
            "using it renders permanently blank, with no error anywhere"
        )
        assert resp.status_code < 500, (
            f"{url} returned {resp.status_code}; the panel using it shows an "
            f"error state to the operator. Body: {resp.text[:300]}"
        )


class TestTier2PanelContent:
    """A 200 is not enough — the panel must not be rendering its error branch."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", _hx_urls())
    async def test_panel_is_not_in_an_error_state(
        self, authenticated_client: AsyncClient, url: str
    ):
        resp = await authenticated_client.get(url)
        if resp.status_code != 200:
            pytest.skip(f"{url} returned {resp.status_code}; covered by tier 1")
        body = resp.text
        hit = [m for m in _ERROR_MARKERS if m in body]
        assert not hit, (
            f"{url} returned 200 but its body contains {hit} — it is rendering a "
            "failure state, which looks like a working page to a status-code-only "
            "assertion"
        )


class TestTier3FingerprintDrillDown:
    """The drill-down must interpret the fingerprint, not just echo it.

    Before phase-826 this page received only the raw JA4 string and displayed
    it verbatim, so clicking a fingerprint led to a screen that told the
    operator nothing they did not already know.
    """

    @pytest.mark.asyncio
    async def test_page_renders(self, authenticated_client: AsyncClient):
        resp = await authenticated_client.get(f"/fingerprint/{BROWSER_JA4}")
        assert resp.status_code == 200
        assert BROWSER_JA4 in resp.text

    @pytest.mark.asyncio
    async def test_page_decodes_the_fingerprint(
        self, authenticated_client: AsyncClient
    ):
        body = (await authenticated_client.get(f"/fingerprint/{BROWSER_JA4}")).text
        # The decoded facts, not the raw string.
        for expected in ("TLS 1.3", "12 ciphers", "HTTP/2", "SNI"):
            assert expected in body, f"decoded value {expected!r} missing from page"

    @pytest.mark.asyncio
    async def test_tool_fingerprint_is_labelled_differently_from_a_browser(
        self, authenticated_client: AsyncClient
    ):
        """The decode must actually discriminate, or it is decoration."""
        tool = (await authenticated_client.get(f"/fingerprint/{TOOL_JA4}")).text
        browser = (await authenticated_client.get(f"/fingerprint/{BROWSER_JA4}")).text
        assert "not browser-shaped" in tool
        assert "browser-shaped" in browser and "not browser-shaped" not in browser

    @pytest.mark.asyncio
    async def test_alpn_row_warns_it_is_attacker_controlled(
        self, authenticated_client: AsyncClient
    ):
        """The page must not let an operator read ALPN as proof."""
        body = (await authenticated_client.get(f"/fingerprint/{TOOL_JA4}")).text
        assert "attacker-controlled" in body.lower()

    @pytest.mark.asyncio
    async def test_malformed_fingerprint_does_not_500(
        self, authenticated_client: AsyncClient
    ):
        """This path takes user-controlled input straight into a template."""
        resp = await authenticated_client.get("/fingerprint/not-a-real-ja4")
        assert resp.status_code == 200
        assert "Not a JA4 client fingerprint" in resp.text

    @pytest.mark.asyncio
    async def test_fingerprint_is_escaped_not_injected(
        self, authenticated_client: AsyncClient
    ):
        resp = await authenticated_client.get("/fingerprint/%3Cscript%3Ealert(1)%3C/script%3E")
        assert resp.status_code in (200, 404)
        assert "<script>alert(1)</script>" not in resp.text


class TestPagesRequireAuth:
    """A 500 here means the route crashed BEFORE the auth check ran."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "path",
        [
            "/",
            "/lists",
            "/bans",
            "/audit",
            "/threat-intel",
            "/security-policy",
            "/intelligence-review",
            "/under-attack",
            f"/fingerprint/{BROWSER_JA4}",
            "/ip/1.2.3.4",
        ],
    )
    async def test_unauthenticated_does_not_crash(
        self, test_client: AsyncClient, path: str
    ):
        resp = await test_client.get(path)
        assert resp.status_code < 500, (
            f"{path} returned {resp.status_code} unauthenticated — the handler "
            "crashed before authentication was enforced"
        )


class TestObservabilityLink:
    """The console must expose Grafana, and must not render a dead link.

    Before phase-826 there were zero references to Grafana anywhere in the
    console: the metrics and logs were reachable only by knowing a URL and a
    lane-specific port, which is a bad moment in a demo and worse during an
    incident.
    """

    @pytest.mark.asyncio
    async def test_link_absent_when_not_configured(
        self, authenticated_client: AsyncClient, monkeypatch
    ):
        """A deployment without monitoring must not show a link to nowhere."""
        from management.api import main as mgmt_main

        templates = mgmt_main._get_templates() if hasattr(mgmt_main, "_get_templates") else None
        if templates is None:
            from management.api.routes import pages as pages_mod

            templates = pages_mod._get_templates()
        original = templates.env.globals.get("grafana_url", "")
        templates.env.globals["grafana_url"] = ""
        try:
            body = (await authenticated_client.get("/")).text
            assert "Metrics &amp; Logs" not in body and "Metrics & Logs" not in body
        finally:
            templates.env.globals["grafana_url"] = original

    @pytest.mark.asyncio
    async def test_link_rendered_when_configured(
        self, authenticated_client: AsyncClient
    ):
        from management.api.routes import pages as pages_mod

        configured = "https://grafana.example:3000"
        templates = pages_mod._get_templates()
        original = templates.env.globals.get("grafana_url", "")
        templates.env.globals["grafana_url"] = configured
        try:
            body = (await authenticated_client.get("/")).text
            # Extract the anchor and compare the href EXACTLY rather than
            # asking whether the URL appears somewhere in the page. A substring
            # check would pass on a link to
            # https://grafana.example:3000.attacker.test, and CodeQL flags the
            # pattern (py/incomplete-url-substring-sanitization) for that
            # reason. Exact comparison is both safe and a stronger assertion.
            anchors = re.findall(r'<a\s+href="([^"]+)"([^>]*)>', body)
            hrefs = [h for h, _ in anchors]
            assert configured in hrefs, (
                f"sidebar has no link whose href is exactly {configured!r}; "
                f"found: {hrefs}"
            )
            attrs = next(a for h, a in anchors if h == configured)
            # External app with its own session — must not steal the tab, and
            # must not leak the console URL via the referrer.
            assert 'target="_blank"' in attrs
            assert 'rel="noopener noreferrer"' in attrs
        finally:
            templates.env.globals["grafana_url"] = original
