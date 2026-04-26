"""JA4 false-positive blocking for threat-intel feeds.

C6 (PHASE_101): Check new JA4 fingerprints against a known-good
corpus before adding to blocklists. Chrome, Firefox, Safari, and other
major browsers must never be blocked by automated feeds.

The FP corpus is loaded once at module import time and cached.
Configure the corpus path via JA4PROXY_FP_CORPUS_PATH env var.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Default corpus location — repo-root ``fixtures/ti_feeds/ja4_fp_corpus.txt``.
# parents[3] walks ja4_safety.py → ti_feeds → analytics → src → repo root.
_DEFAULT_CORPUS_PATH = Path(__file__).parents[3] / "fixtures" / "ti_feeds" / "ja4_fp_corpus.txt"

# Load corpus once at import
_JA4_FP_CORPUS: Optional[frozenset[str]] = None


def _load_corpus(path: Path) -> frozenset[str]:
    """Load JA4 FP corpus from file.

    Expected format: one JA4 per line, comments start with #.
    """
    global _JA4_FP_CORPUS
    if _JA4_FP_CORPUS is not None:
        return _JA4_FP_CORPUS

    corpus_path = os.environ.get("JA4PROXY_FP_CORPUS_PATH", str(_DEFAULT_CORPUS_PATH))
    try:
        path = Path(corpus_path)
        if path.exists():
            with open(path) as f:
                ja4s = {line.strip() for line in f if line.strip() and not line.startswith("#")}
            _JA4_FP_CORPUS = frozenset(ja4s)
            logger.info(
                "ti_feed | event=ja4_corpus_loaded | path=%s | count=%d",
                path,
                len(_JA4_FP_CORPUS),
            )
            return _JA4_FP_CORPUS
    except Exception as exc:
        logger.warning(
            "ti_feed | event=ja4_corpus_load_failed | path=%s | error=%s",
            corpus_path,
            exc,
        )

    # Return empty set if load fails
    _JA4_FP_CORPUS = frozenset()
    return _JA4_FP_CORPUS


def ja4_safe_to_block(ja4: str) -> tuple[bool, str]:
    """Return (safe_to_block, reason).

    If the JA4 is in the FP corpus, return (False, "known_browser").
    Otherwise return (True, "") - unknown JA4s are allowed by default.
    """
    if not ja4:
        return True, ""

    # Load corpus if not yet loaded
    corpus = _load_corpus(_DEFAULT_CORPUS_PATH)

    if ja4 in corpus:
        return False, "known_browser"
    return True, ""


@lru_cache(maxsize=10000)
def is_known_browser_ja4(ja4: str) -> bool:
    """Cached check for known browser JA4.

    Returns True if the JA4 is in the FP corpus.
    """
    safe, _ = ja4_safe_to_block(ja4)
    return safe
