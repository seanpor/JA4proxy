"""
tests/adversarial/test_ja4_adversarial.py
Purpose: Verify JA4 generation handles degenerate inputs without crashing
Coverage: Empty lists, max-length fields, GREASE values
Owner: Phase 16
"""

import pytest
from proxy import JA4Generator


@pytest.mark.parametrize(
    "cipher_list,ext_list,sni",
    [
        ([], [], None),  # All empty
        ([0x0A0A], [], "example.com"),  # Single GREASE cipher only
        (list(range(256)), [], ""),  # 256-entry cipher list (max)
        ([0xC02B], [0x0A0A, 0x0A0A], "a" * 255),  # Max-length SNI (255 chars)
        ([0xC02B], list(range(65)), None),  # 65 extension types
        # All 16 GREASE cipher values — JA4 must filter them all out
        (
            [
                0x0A0A,
                0x1A1A,
                0x2A2A,
                0x3A3A,
                0x4A4A,
                0x5A5A,
                0x6A6A,
                0x7A7A,
                0x8A8A,
                0x9A9A,
                0xAAAA,
                0xBABA,
                0xCACA,
                0xDADA,
                0xEAEA,
                0xFAFA,
            ],
            [],
            None,
        ),  # All-GREASE cipher list
        ([], [], "\x00evil"),  # SNI with leading null byte
        ([0xC02B, 0xC02B, 0xC02B], [], "dup.example.com"),  # Duplicate cipher values
        ([0xFFFF], [0xFFFF], None),  # Unknown cipher + ext type
        (
            list(range(0x0000, 0x0010)),
            list(range(0x0000, 0x0010)),
            "",
        ),  # Low-range values
    ],
)
def test_ja4_does_not_crash(cipher_list, ext_list, sni):
    """JA4 generator must handle degenerate inputs without crashing."""
    generator = JA4Generator()

    # Create minimal client_hello_fields dict
    client_hello_fields = {
        "cipher_suites": cipher_list,
        "extensions": ext_list,
        "sni": sni,
        "tls_version": 0x0304,  # TLS 1.3
    }

    result = generator.generate_ja4(client_hello_fields)
    assert isinstance(result, str)
    assert len(result) > 0
