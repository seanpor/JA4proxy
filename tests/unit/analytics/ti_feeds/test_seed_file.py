"""Phase 85 — unit tests for ``analytics.ti_feeds.seed_file``.

The seed file is ``config/known_bad_fingerprints.yml`` and must:
- contain at least 10 vetted entries (acceptance criterion §12.5)
- have all required fields per entry: ja4, name, category, source, confidence
- reject malformed entries at load time (no silent skipping)

These tests are RED until ``src/analytics/ti_feeds/seed_file.py`` exists. The
``config/known_bad_fingerprints.yml`` file is also expected to ship with the
implementation; the test that asserts ≥10 entries reads it directly.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def _import_seed():
    from src.analytics.ti_feeds.seed_file import SeedFileLoader

    return SeedFileLoader


_REPO_ROOT = Path(__file__).resolve().parents[4]
_SEED_PATH = _REPO_ROOT / "config" / "known_bad_fingerprints.yml"


# ── ≥10 entries acceptance criterion ──────────────────────────────────────────


def test_seed_file_ships_with_at_least_10_entries():
    """``config/known_bad_fingerprints.yml`` must contain ≥10 fingerprints."""
    SeedFileLoader = _import_seed()

    if not _SEED_PATH.exists():
        pytest.fail(
            f"Seed file missing: {_SEED_PATH}. "
            "Phase 85 acceptance criterion §12.5 requires ≥10 vetted fingerprints."
        )

    loader = SeedFileLoader(_SEED_PATH)
    entries = loader.load()
    assert len(entries) >= 10, (
        f"known_bad_fingerprints.yml has {len(entries)} entries; "
        "acceptance criterion requires ≥10."
    )


def test_seed_file_entries_have_required_fields(tmp_path):
    """Each entry must have ja4, name, category, source, confidence."""
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "Cobalt Strike"
    category: "c2_framework"
    source: "https://example.test/research"
    confidence: 95
  - ja4: "t13d301100_5b57614c22b0_3d5424432f57"
    name: "Sliver"
    category: "c2_framework"
    source: "https://example.test/sliver"
    confidence: 90
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    loader = SeedFileLoader(p)
    entries = loader.load()
    assert len(entries) == 2
    for e in entries:
        assert "ja4" in e
        assert "name" in e
        assert "category" in e
        assert "source" in e
        assert "confidence" in e


# ── Validation ────────────────────────────────────────────────────────────────


def test_seed_file_rejects_missing_ja4(tmp_path):
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - name: "no-ja4"
    category: "c2"
    source: "https://example.test/x"
    confidence: 50
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    loader = SeedFileLoader(p)
    with pytest.raises((ValueError, KeyError, Exception)):
        loader.load()


def test_seed_file_rejects_malformed_ja4_string(tmp_path):
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: "not-a-valid-ja4"
    name: "bad"
    category: "c2"
    source: "https://example.test/x"
    confidence: 50
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    loader = SeedFileLoader(p)
    with pytest.raises((ValueError, Exception)):
        loader.load()


def test_seed_file_rejects_confidence_out_of_range(tmp_path):
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "x"
    category: "c2"
    source: "https://example.test/x"
    confidence: 150
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    loader = SeedFileLoader(p)
    with pytest.raises((ValueError, Exception)):
        loader.load()


def test_seed_file_empty_fingerprints_section_is_an_error(tmp_path):
    """An empty 'fingerprints:' list is suspicious — load should refuse."""
    SeedFileLoader = _import_seed()
    yaml_text = "fingerprints: []\n"
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    loader = SeedFileLoader(p)
    with pytest.raises((ValueError, Exception)):
        loader.load()
