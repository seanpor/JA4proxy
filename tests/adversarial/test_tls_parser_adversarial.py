"""
tests/adversarial/test_tls_parser_adversarial.py
Purpose: Verify TLS parser handles adversarial inputs without crashing
Coverage: All files in tests/adversarial/corpus/
Owner: Phase 16
"""

import struct
from pathlib import Path

import pytest

# Import from proxy.py where TLSParser is defined
from proxy import TLSParser

CORPUS_DIR = Path(__file__).parent / "corpus"


@pytest.mark.parametrize("corpus_file", list(CORPUS_DIR.glob("*.bin")))
def test_parser_does_not_crash(corpus_file):
    """Every corpus file must parse without raising an uncaught exception."""
    raw = corpus_file.read_bytes()
    try:
        # Create parser instance and parse
        parser = TLSParser()
        result = parser.parse_client_hello(raw)
        # Either a valid parse result (dict) or None — both acceptable
        assert result is None or isinstance(result, dict)
    except (ValueError, struct.error, AttributeError):
        pass  # Expected parse failures are fine
    # Uncaught exceptions (IndexError, KeyError, etc.) fail the test
