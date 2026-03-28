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
