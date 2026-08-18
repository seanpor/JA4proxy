"""Phase 826 — JA4 decomposition must stay correct and must stay a hint.

WHY THIS EXISTS
---------------
The console displayed JA4 fingerprints as opaque strings, so a blocked
connection could only be explained with a score. The first segment is in fact a
structured description of the ClientHello, and decoding it is free.

Two risks are guarded here:

1. Field offsets. The a-segment is fixed-width and positional; an off-by-one in
   the regex silently mislabels every fingerprint (e.g. reading the extension
   count as the cipher count) while still "working". The live fixtures below
   are real fingerprints observed on the POC stack, with the profile that
   produced each one.

2. The heuristic hardening into a verdict. `is_browser_like` reads ALPN, which
   is ATTACKER-CONTROLLED — a bot can send h2. This project deliberately keeps
   alpn_browser_bypass off by default for exactly that reason
   (JA4PROXY-2026-0004). The property may caption a UI hint; if it ever starts
   driving an allow/block decision, that is a security regression.
"""

from __future__ import annotations

import pytest

from management.api.ja4_decode import decode

# Real fingerprints observed on the running POC stack, 2026-08-17, with the
# tls-traffic-generator profile that produced each.
BROWSER = "t13d1212h2_eac1b15b5477_8e6e362c5eac"  # Chrome/Firefox/Safari profiles
SLIVER = "t13d091100_f91f431d341e_8e6e362c5eac"  # Sliver_C2 / Evilginx / Masscan
COBALT = "t12d020800_04659ec43a24_36cef8aed422"  # CobaltStrike / Credential_Stuffer
PYBOT = "t13d301100_1d37bd780c83_8e6e362c5eac"  # Python_Requests_Bot


class TestFieldOffsets:
    """Positional parsing — an off-by-one mislabels everything, silently."""

    def test_browser_fingerprint_decodes_exactly(self):
        d = decode(BROWSER)
        assert d.valid
        assert d.parts["transport"] == "t"
        assert d.parts["version"] == "13"
        assert d.parts["sni"] == "d"
        assert d.parts["ciphers"] == "12"
        assert d.parts["extensions"] == "12"
        assert d.parts["alpn"] == "h2"
        assert d.parts["cipher_hash"] == "eac1b15b5477"
        assert d.parts["extension_hash"] == "8e6e362c5eac"

    def test_cipher_and_extension_counts_are_not_swapped(self):
        """The two adjacent 2-digit fields are the easiest pair to transpose."""
        d = decode(PYBOT)  # 30 ciphers, 11 extensions — deliberately asymmetric
        assert d.parts["ciphers"] == "30"
        assert d.parts["extensions"] == "11"
        assert "30 offered" in [f.value for f in d.fields if f.label == "Cipher suites"][0]
        assert "11 offered" in [f.value for f in d.fields if f.label == "Extensions"][0]

    def test_tls_12_is_read_as_12_not_13(self):
        assert "TLS 1.2" in decode(COBALT).summary

    def test_summary_mentions_every_decoded_dimension(self):
        s = decode(BROWSER).summary
        for expected in ("TCP", "TLS 1.3", "SNI", "12 ciphers", "12 extensions", "HTTP/2"):
            assert expected in s, f"{expected!r} missing from summary: {s}"


class TestAlpn:
    def test_no_alpn_decoded_as_none_offered(self):
        assert "none offered" in decode(SLIVER).summary

    @pytest.mark.parametrize("fp", [SLIVER, COBALT, PYBOT])
    def test_tool_fingerprints_are_not_browser_shaped(self, fp):
        assert decode(fp).is_browser_like is False

    def test_browser_fingerprint_is_browser_shaped(self):
        assert decode(BROWSER).is_browser_like is True

    def test_alpn_note_always_warns_it_is_attacker_controlled(self):
        """The UI must never present ALPN as proof of anything."""
        for fp in (BROWSER, SLIVER):
            note = [f.note for f in decode(fp).fields if f.label == "ALPN"][0]
            assert "attacker-controlled" in note.lower(), (
                "the ALPN row must state that a bot can send this too — "
                "alpn_browser_bypass is off by default for this exact reason"
            )


class TestRobustness:
    """Never raise: this decodes untrusted input rendered into a page."""

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "garbage",
            "t13d1212h2",  # a-segment only, no hashes
            "t13d1212h2_short_8e6e362c5eac",  # wrong hash length
            "t13d12x2h2_eac1b15b5477_8e6e362c5eac",  # non-digit in a count
            "x" * 500,
            "t13d1212h2_eac1b15b5477_8e6e362c5eac_extra",
            "../../etc/passwd",
            "<script>alert(1)</script>",
        ],
    )
    def test_invalid_input_reports_rather_than_raises(self, bad):
        d = decode(bad)
        assert d.valid is False
        assert d.error
        assert d.is_browser_like is None

    def test_none_is_handled(self):
        assert decode(None).valid is False  # type: ignore[arg-type]

    def test_whitespace_is_tolerated(self):
        assert decode(f"  {BROWSER}  ").valid


class TestQuic:
    def test_quic_transport_decoded(self):
        d = decode("q13d1212h3_eac1b15b5477_8e6e362c5eac")
        assert d.valid
        assert "QUIC" in d.summary
