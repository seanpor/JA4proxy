"""Known-browser JA4 corpus and label lookup for the management API (Phase 250).

This module is intentionally separate from src/analytics/ti_feeds/ja4_safety.py —
src/ and management/ are separate packages on different PYTHONPATH roots.
Do NOT import across package boundaries.
"""

import json
import logging
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

# Resolve paths relative to this file so the module works regardless of cwd.
# management/api/ja4_corpus.py → .parents[3] = repo root.
_CORPUS_PATH = Path(__file__).parents[3] / "fixtures" / "ti_feeds" / "ja4_fp_corpus.txt"
_LABELS_PATH = Path(__file__).parents[3] / "fixtures" / "ti_feeds" / "ja4_browser_labels.json"


def _load_corpus() -> frozenset:
    try:
        lines = _CORPUS_PATH.read_text().splitlines()
        corpus = frozenset(
            line.strip()
            for line in lines
            if line.strip() and not line.startswith("#")
        )
        logger.debug("ja4_corpus: loaded %d entries from %s", len(corpus), _CORPUS_PATH)
        return corpus
    except Exception as exc:
        logger.warning("ja4_corpus: failed to load corpus from %s: %s", _CORPUS_PATH, exc)
        return frozenset()


def _load_labels() -> dict:
    try:
        raw = json.loads(_LABELS_PATH.read_text())
        # Strip metadata keys starting with underscore.
        return {k: v for k, v in raw.items() if not k.startswith("_")}
    except Exception as exc:
        logger.warning("ja4_corpus: failed to load labels from %s: %s", _LABELS_PATH, exc)
        return {}


# Load at module import time — these files are small and static.
_CORPUS: frozenset = _load_corpus()
_LABELS: dict = _load_labels()


@lru_cache(maxsize=10000)
def is_known_browser(ja4: str) -> bool:
    """Return True if ja4 is a verified browser fingerprint in the safe corpus."""
    return ja4 in _CORPUS


def browser_label(ja4: str) -> str:
    """Return a human-readable label for ja4, or '' if unknown."""
    return _LABELS.get(ja4, "")


def corpus_size() -> int:
    """Return the number of entries in the corpus (for diagnostics)."""
    return len(_CORPUS)
