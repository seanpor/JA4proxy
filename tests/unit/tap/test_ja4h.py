"""
Unit tests for src/tap/fingerprints/ja4h.py (Phase 20 Group 5-D).
"""
import pytest

from src.tap.fingerprints.ja4h import JA4HResult, extract_ja4h


def _req(method="GET", path="/", version="1.1", headers=None, body=b""):
    """Build minimal HTTP/1.1 request bytes."""
    hdrs = headers or {}
    lines = [f"{method} {path} HTTP/{version}"]
    for k, v in hdrs.items():
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class TestJA4H:
    def test_get_request_with_standard_browser_headers(self):
        data = _req(
            headers={
                "Host": "example.com",
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/html",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )
        result = extract_ja4h(data)
        assert result is not None
        assert result.method == "GET"
        assert result.http_version == "11"
        assert result.user_agent == "Mozilla/5.0"
        assert result.accept_language == "en-US,en;q=0.9"

    def test_post_request_with_cookie(self):
        data = _req(
            method="POST",
            headers={
                "Host": "api.example.com",
                "Cookie": "session=abc123; pref=dark",
                "Content-Type": "application/json",
            },
        )
        result = extract_ja4h(data)
        assert result is not None
        assert result.method == "POST"
        assert result.cookie_count == 2
        assert "c" in result.fingerprint  # cookie present flag

    def test_referer_present_in_fingerprint(self):
        data = _req(
            headers={
                "Host": "example.com",
                "Referer": "https://search.example.com/",
            }
        )
        result = extract_ja4h(data)
        assert result is not None
        assert result.referer == "https://search.example.com/"
        assert "r" in result.fingerprint

    def test_returns_none_on_incomplete_headers(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n"  # no \r\n\r\n
        result = extract_ja4h(data)
        assert result is None

    def test_returns_none_on_non_http_bytes(self):
        result = extract_ja4h(b"\x16\x03\x01\x00\x00")
        assert result is None

    def test_header_order_preserved_in_hash(self):
        """Two requests with same headers in different order → different name hash."""
        data1 = _req(headers={"Host": "x", "Accept": "text/html", "Connection": "keep-alive"})
        data2 = _req(headers={"Connection": "keep-alive", "Accept": "text/html", "Host": "x"})
        r1 = extract_ja4h(data1)
        r2 = extract_ja4h(data2)
        assert r1 is not None and r2 is not None
        # Header order affects the name hash portion
        parts1 = r1.fingerprint.split("_")
        parts2 = r2.fingerprint.split("_")
        assert parts1[1] != parts2[1]

    def test_language_hash_included(self):
        data = _req(headers={"Host": "x", "Accept-Language": "de-DE,de;q=0.9"})
        result = extract_ja4h(data)
        assert result is not None
        assert result.accept_language == "de-DE,de;q=0.9"

    def test_no_cookie_flag(self):
        data = _req(headers={"Host": "example.com"})
        result = extract_ja4h(data)
        assert result is not None
        assert "n" in result.fingerprint  # no-cookie flag
        assert result.cookie_count == 0

    def test_http10_version(self):
        data = _req(version="1.0", headers={"Host": "example.com"})
        result = extract_ja4h(data)
        assert result is not None
        assert result.http_version == "10"

    def test_fingerprint_is_deterministic(self):
        data = _req(
            headers={
                "Host": "example.com",
                "Accept": "*/*",
                "Accept-Language": "en",
            }
        )
        r1 = extract_ja4h(data)
        r2 = extract_ja4h(data)
        assert r1 is not None and r2 is not None
        assert r1.fingerprint == r2.fingerprint


# ── Missing-coverage tests ────────────────────────────────────────────────────

class TestJA4HEdgeCases:
    """Cover boundary paths in _parse() and helpers (lines 40-41, 58, 64, 68, 76-81, 88, 141).

    So what: every unchecked parse path is a crash vector when the HTTP fingerprinter
    receives attacker-controlled bytes from the reassembler.
    """

    def test_exception_in_parse_returns_none(self):
        """_parse() raising → None (line 40-41).
        So what: unexpected internal error must not crash the capture loop."""
        from unittest.mock import patch
        import src.tap.fingerprints.ja4h as _mod
        with patch.object(_mod, "_parse", side_effect=RuntimeError("injected")):
            result = _mod.extract_ja4h(b"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n")
        assert result is None

    def test_request_line_too_few_parts_returns_none(self):
        """Request line with < 3 space-separated tokens → None (line 63-64).
        So what: malformed first line must not IndexError when accessing parts[2]."""
        data = b"GET /path\r\n\r\n"
        assert extract_ja4h(data) is None

    def test_method_with_digits_returns_none(self):
        """Non-alpha method (contains digit) → None (line 67-68).
        So what: injection attempt using a digit-padded method must not produce a fingerprint."""
        data = b"G3T / HTTP/1.1\r\n\r\n"
        assert extract_ja4h(data) is None

    def test_very_long_method_returns_none(self):
        """Method > 20 chars → None (line 67-68).
        So what: oversized method field must not produce a garbage fingerprint."""
        method = "A" * 21
        data = f"{method} / HTTP/1.1\r\n\r\n".encode()
        assert extract_ja4h(data) is None

    def test_non_http_version_returns_none(self):
        """Version string not starting with 'HTTP/' → None (line 80-81).
        So what: SPDY/WebSocket upgrade must not be fingerprinted as HTTP."""
        data = b"GET / SPDY/3.1\r\n\r\n"
        assert extract_ja4h(data) is None

    def test_http2_version_parsed(self):
        """HTTP/2 version → http_version='20' (line 76-77).
        So what: h2 cleartext frames must not produce '00' version in fingerprint."""
        data = b"GET / HTTP/2\r\n\r\n"
        result = extract_ja4h(data)
        assert result is not None
        assert result.http_version == "20"

    def test_unknown_http_version_truncated(self):
        """Non-1.0/1.1/2 version → version chars stripped to 2 (line 78-79).
        So what: future HTTP versions must not crash the fingerprinter."""
        data = b"GET / HTTP/3.0\r\n\r\n"
        result = extract_ja4h(data)
        assert result is not None
        # version is ver.replace(".", "")[:2] for "3.0" → "30"
        assert result.http_version == "30"

    def test_header_line_without_colon_skipped(self):
        """A header line without ':' is skipped (line 87-88).
        So what: malformed header line must not cause a partition error or wrong parse."""
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\nBadLine\r\n\r\n"
        result = extract_ja4h(data)
        assert result is not None
        assert "host" in result.headers
        assert "badline" not in result.headers

    def test_hash_header_names_only_cookie_and_referer(self):
        """Header list with only cookie/referer → '000000000000' (line 141).
        So what: cookie-only requests must produce a valid (zero) name hash, not crash."""
        from src.tap.fingerprints.ja4h import _hash_header_names
        result = _hash_header_names(["cookie", "referer"])
        assert result == "000000000000"

    def test_referrer_alternate_spelling(self):
        """'Referrer' header (double-r) is also captured as referer (line 97).
        So what: both spellings of the header must set has_referer='r' in fingerprint."""
        data = _req(headers={"Host": "x.com", "Referrer": "https://prev.example.com/"})
        result = extract_ja4h(data)
        assert result is not None
        assert result.referer == "https://prev.example.com/"
        assert "r" in result.fingerprint


# ---------------------------------------------------------------------------
# Coverage gap additions — lines 48-49, 58
# ---------------------------------------------------------------------------

class TestJA4HCoverageGaps:
    """Lines 48-49: decode exception; line 58: empty lines guard (defensive)."""

    def test_parse_decode_exception_returns_none(self):
        """Lines 48-49: data.decode() raises → _parse returns None.
        So what: without this except, a non-bytes input (e.g. from a mocked stream)
        propagates an AttributeError out of extract_ja4h, crashing the TAP pipeline
        for the entire flow instead of safely skipping the fingerprint."""
        from src.tap.fingerprints.ja4h import _parse

        class _BadBytes:
            def decode(self, *a, **kw):
                raise RuntimeError("cannot decode")

        result = _parse(_BadBytes())
        assert result is None
