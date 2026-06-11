"""Phase-230: integrity + hardening guard for the Management UI front-end assets.

Vendored third-party JS is a supply-chain surface, so we pin each blob's SHA-256
in management/static/SHA256SUMS and fail the build if a committed asset drifts
(tamper / accidental edit). We also assert the console makes no external asset
calls (no CDN / Google Fonts) and uses the pre-built Tailwind CSS, not the
407 KB browser/runtime Play build.
"""
import hashlib
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STATIC = REPO / "management" / "static"
SUMS = STATIC / "SHA256SUMS"
BASE_HTML = REPO / "management" / "templates" / "base.html"


def _parse_sums():
    pairs = []
    for line in SUMS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        h, _, name = line.partition("  ")
        pairs.append((h.strip(), name.strip()))
    return pairs


def test_sha256sums_present_and_nonempty():
    assert SUMS.exists(), "management/static/SHA256SUMS missing"
    assert _parse_sums(), "SHA256SUMS has no entries"


def test_vendored_assets_match_pinned_hashes():
    for expected, name in _parse_sums():
        f = STATIC / name
        assert f.exists(), f"pinned asset missing: {name}"
        actual = hashlib.sha256(f.read_bytes()).hexdigest()
        assert actual == expected, (
            f"{name} drifted from its pinned SHA-256 (supply-chain guard). "
            f"If this was an intentional update, refresh SHA256SUMS + VENDOR.md."
        )


def test_no_external_asset_fetches_in_base_html():
    """The console must not pull assets from the public internet (DMZ/offline)."""
    html = BASE_HTML.read_text()
    bad = re.findall(r'(?:src|href)\s*=\s*["\']https?://[^"\']+', html)
    assert not bad, f"base.html fetches external assets (use self-hosted): {bad}"


def test_uses_prebuilt_tailwind_not_play_build():
    html = BASE_HTML.read_text()
    assert "tailwind.min.js" not in html, "still references the Tailwind Play/runtime build"
    assert "/static/tailwind.css" in html, "should load the pre-built tailwind.css"


def test_csp_present():
    html = BASE_HTML.read_text()
    assert "Content-Security-Policy" in html, "base.html should declare a CSP"
    assert "default-src 'self'" in html, "CSP should default to same-origin"
