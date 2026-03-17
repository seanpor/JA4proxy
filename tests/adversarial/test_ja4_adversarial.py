"""
tests/adversarial/test_ja4_adversarial.py
Purpose: Verify JA4 generation handles degenerate inputs without crashing
Coverage: Empty lists, max-length fields, GREASE values
Owner: Phase 16
"""
import pytest
from proxy import JA4Generator

@pytest.mark.parametrize("cipher_list,ext_list,sni", [
    ([], [], None),                    # All empty
    ([0x0A0A], [], "example.com"),     # All-GREASE ciphers
    (list(range(256)), [], ""),        # Max cipher list
    ([0xC02B], [0x0A0A, 0x0A0A], "a" * 255),  # Max SNI
    ([0xC02B], list(range(65)), None), # 65 extension types
])
def test_ja4_does_not_crash(cipher_list, ext_list, sni):
    """JA4 generator must handle degenerate inputs without crashing."""
    generator = JA4Generator()
    
    # Create minimal client_hello_fields dict
    client_hello_fields = {
        'cipher_suites': cipher_list,
        'extensions': ext_list,
        'sni': sni,
        'tls_version': 0x0304  # TLS 1.3
    }
    
    result = generator.generate_ja4(client_hello_fields)
    assert isinstance(result, str)
    assert len(result) > 0
