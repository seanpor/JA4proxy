"""Regression tests for the GDPR erasure key catalogue in scripts/gdpr_delete.py.

Phase 309 R4 — the erasure script previously targeted the *deleted Python proxy's*
Redis key names (`session:ip:{ip}:ja4:*`, bare `visitor:{ip}`) and omitted keys the
Go proxy actually writes (`session:{ip}`, `return_visitor:{ip}`, `dns:fcrdns:{ip}`,
`audit:last_score:{ip}`). That made a "complete" erasure silently leave live PII in
Redis. These tests pin the catalogue to the current Go-proxy schema so the gap cannot
regress. Key names are cross-checked against docs/reference/REDIS_SCHEMA.md.
"""

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "gdpr_delete.py"


@pytest.fixture(scope="module")
def gdpr():
    spec = importlib.util.spec_from_file_location("gdpr_delete", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Keys the Go proxy / TAP sensor actively writes, keyed by client IP. Every one of
# these MUST be in the erasure catalogue or a data-subject request leaves PII behind.
LIVE_IP_KEYS = [
    "ban:{ip}",
    "session:{ip}",
    "concurrent:{ip}",
    "return_visitor:{ip}",
    "dns:fcrdns:{ip}",
    "audit:last_score:{ip}",
    "rdap:ip:{ip}",
    "abuseipdb:{ip}",
    "beacon:{ip}:*",
    "fp:os:ip:{ip}",
    "fp:ja4t:ip:{ip}",
    "fp:ban_intent:ip:{ip}",
    "fp:ip:{ip}",
]

# Stale Python-proxy key forms that must NOT reappear — they never match anything
# the Go proxy writes, so their presence is a false sense of completeness.
STALE_IP_KEYS = [
    "session:ip:{ip}:ja4:*",
    "visitor:{ip}",
]


@pytest.mark.parametrize("key", LIVE_IP_KEYS)
def test_live_go_proxy_keys_are_erased(gdpr, key):
    assert key in gdpr._IP_KEY_PATTERNS, (
        f"{key!r} is written by the Go proxy but is missing from the GDPR "
        f"erasure catalogue — erasure would leave it behind"
    )


@pytest.mark.parametrize("key", STALE_IP_KEYS)
def test_stale_python_proxy_keys_are_gone(gdpr, key):
    assert key not in gdpr._IP_KEY_PATTERNS, (
        f"{key!r} is a deleted-Python-proxy key form and must not be in the "
        f"erasure catalogue"
    )


def test_zset_member_pattern_uses_correct_spelling(gdpr):
    globs = [g for g, _ in gdpr._ZSET_MEMBER_PATTERNS]
    assert "behavioral:burst:*" in globs, "ZSET erasure must target behavioral:burst:*"
    assert "behavioural:burst:*" not in globs, (
        "the British 'behavioural' spelling never matched the real "
        "'behavioral:burst:' key and must not return"
    )


def test_scan_and_exact_partition_is_consistent(gdpr):
    # Every pattern is classified exactly once, and wildcards go to SCAN.
    for p in gdpr._IP_KEY_PATTERNS:
        in_scan = p in gdpr._SCAN_PATTERNS
        in_exact = p in gdpr._EXACT_PATTERNS
        assert in_scan != in_exact, f"{p!r} must be in exactly one of SCAN/EXACT"
        assert in_scan == ("*" in p), f"{p!r} wildcard classification is wrong"
