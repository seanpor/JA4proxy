"""Phase 104 — coverage tests for ``analytics.ti_feeds.ja4_safety``.

Covers file-not-found, load exceptions, empty corpus fallback, and
the is_known_browser_ja4 cached check.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest


def _reset_corpus():
    """Reset the module-level corpus cache so each test starts fresh."""
    import src.analytics.ti_feeds.ja4_safety as mod
    mod._JA4_FP_CORPUS = None
    mod.is_known_browser_ja4.cache_clear()


# ── File not found / empty corpus fallback ──────────────────────────────────


def test_corpus_file_not_found_returns_empty_frozenset():
    """When corpus file does not exist, _load_corpus returns empty frozenset."""
    _reset_corpus()
    from src.analytics.ti_feeds.ja4_safety import _load_corpus

    with patch.dict(os.environ, {"JA4PROXY_FP_CORPUS_PATH": "/nonexistent/path/corpus.txt"}):
        result = _load_corpus(Path("/nonexistent/path/corpus.txt"))

    assert result == frozenset()
    _reset_corpus()


def test_corpus_load_exception_returns_empty_frozenset():
    """When corpus loading raises an exception, returns empty frozenset."""
    _reset_corpus()
    from src.analytics.ti_feeds.ja4_safety import _load_corpus

    with patch.dict(os.environ, {"JA4PROXY_FP_CORPUS_PATH": "/tmp/test_corpus.txt"}):
        with patch("builtins.open", side_effect=PermissionError("no access")):
            with patch.object(Path, "exists", return_value=True):
                result = _load_corpus(Path("/tmp/test_corpus.txt"))

    assert result == frozenset()
    _reset_corpus()


def test_ja4_safe_to_block_empty_string():
    """Empty ja4 string returns (True, '')."""
    _reset_corpus()
    from src.analytics.ti_feeds.ja4_safety import ja4_safe_to_block

    safe, reason = ja4_safe_to_block("")
    assert safe is True
    assert reason == ""
    _reset_corpus()


def test_ja4_safe_to_block_unknown_ja4():
    """Unknown JA4 (not in corpus) returns (True, '')."""
    _reset_corpus()
    # Force empty corpus
    import src.analytics.ti_feeds.ja4_safety as mod
    from src.analytics.ti_feeds.ja4_safety import ja4_safe_to_block
    mod._JA4_FP_CORPUS = frozenset()

    safe, reason = ja4_safe_to_block("t13d191000_aaaaaaaaaa_bbbbbbbbbb")
    assert safe is True
    assert reason == ""
    _reset_corpus()


def test_ja4_safe_to_block_known_browser():
    """Known browser JA4 returns (False, 'known_browser')."""
    _reset_corpus()
    import src.analytics.ti_feeds.ja4_safety as mod
    from src.analytics.ti_feeds.ja4_safety import ja4_safe_to_block
    mod._JA4_FP_CORPUS = frozenset({"t13d191000_known_browser"})

    safe, reason = ja4_safe_to_block("t13d191000_known_browser")
    assert safe is False
    assert reason == "known_browser"
    _reset_corpus()


def test_is_known_browser_ja4_returns_bool():
    """is_known_browser_ja4 returns a bool via the cached check."""
    _reset_corpus()
    import src.analytics.ti_feeds.ja4_safety as mod
    from src.analytics.ti_feeds.ja4_safety import is_known_browser_ja4
    mod._JA4_FP_CORPUS = frozenset({"t13d191000_known_browser"})

    # Unknown JA4 - safe to block, so is_known_browser returns the safe value
    result = is_known_browser_ja4("t13d191000_unknown")
    assert isinstance(result, bool)

    _reset_corpus()


def test_corpus_loads_from_file(tmp_path):
    """Corpus loads JA4s from a text file, skipping comments."""
    _reset_corpus()
    from src.analytics.ti_feeds.ja4_safety import _load_corpus

    corpus_file = tmp_path / "corpus.txt"
    corpus_file.write_text(
        "# comment line\n"
        "t13d191000_aaaa_bbbb\n"
        "\n"
        "t13d191000_cccc_dddd\n"
        "# another comment\n"
    )

    with patch.dict(os.environ, {"JA4PROXY_FP_CORPUS_PATH": str(corpus_file)}):
        result = _load_corpus(corpus_file)

    assert "t13d191000_aaaa_bbbb" in result
    assert "t13d191000_cccc_dddd" in result
    assert len(result) == 2
    _reset_corpus()
