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


# ══════════════════════════════════════════════════════════════════════════════
# Phase 104 — coverage gap closure tests
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# ── _parse_entries validation ────────────────────────────────────────────────


def _import_parse_entries():
    from src.analytics.ti_feeds.seed_file import _parse_entries
    return _parse_entries


def _import_load_seed_file():
    from src.analytics.ti_feeds.seed_file import load_seed_file
    return load_seed_file


def _import_run_once():
    from src.analytics.ti_feeds.seed_file import run_once
    return run_once


def test_parse_entries_fingerprints_not_list():
    """When fingerprints is not a list, returns empty."""
    parse = _import_parse_entries()
    result = parse({"fingerprints": "not-a-list"})
    assert result == []


def test_parse_entries_entry_not_dict():
    """Non-dict entries are skipped."""
    parse = _import_parse_entries()
    result = parse({"fingerprints": ["not-a-dict", 42]})
    assert result == []


def test_parse_entries_invalid_ja4():
    """Entry with invalid JA4 is skipped."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "invalid-ja4",
                "name": "test",
                "category": "c2",
                "source": "https://example.test",
                "confidence": 90,
            }
        ]
    })
    assert result == []


def test_parse_entries_non_string_ja4():
    """Entry with non-string JA4 is skipped."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": 12345,
                "name": "test",
                "category": "c2",
                "source": "https://example.test",
                "confidence": 90,
            }
        ]
    })
    assert result == []


def test_parse_entries_missing_metadata():
    """Entry with empty name/category/source is skipped."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
                "name": "",
                "category": "c2",
                "source": "https://example.test",
                "confidence": 90,
            }
        ]
    })
    assert result == []


def test_parse_entries_non_string_metadata():
    """Entry with non-string name is skipped."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
                "name": 123,
                "category": "c2",
                "source": "https://example.test",
                "confidence": 90,
            }
        ]
    })
    assert result == []


def test_parse_entries_bad_confidence_type():
    """Entry with non-numeric confidence is skipped."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
                "name": "test",
                "category": "c2",
                "source": "https://example.test",
                "confidence": "not-a-number",
            }
        ]
    })
    assert result == []


def test_parse_entries_confidence_out_of_range_negative():
    """Entry with negative confidence is skipped."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
                "name": "test",
                "category": "c2",
                "source": "https://example.test",
                "confidence": -5,
            }
        ]
    })
    assert result == []


def test_parse_entries_confidence_out_of_range_high():
    """Entry with confidence > 100 is skipped."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
                "name": "test",
                "category": "c2",
                "source": "https://example.test",
                "confidence": 150,
            }
        ]
    })
    assert result == []


def test_parse_entries_valid_entry_passes():
    """A valid entry is parsed and returned."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
                "name": "Cobalt Strike",
                "category": "c2_framework",
                "source": "https://example.test",
                "confidence": 95,
            }
        ]
    })
    assert len(result) == 1
    assert result[0].ja4 == "t10d170900_9dc949161b6c_b64c0ad42cb7"
    assert result[0].confidence == 95


def test_parse_entries_mixed_valid_and_invalid():
    """Valid entries pass, invalid are skipped — no crash."""
    parse = _import_parse_entries()
    result = parse({
        "fingerprints": [
            {
                "ja4": "t10d170900_9dc949161b6c_b64c0ad42cb7",
                "name": "Valid",
                "category": "c2",
                "source": "https://example.test",
                "confidence": 80,
            },
            "not-a-dict",
            {
                "ja4": "invalid",
                "name": "Bad",
                "category": "c2",
                "source": "https://example.test",
                "confidence": 80,
            },
        ]
    })
    assert len(result) == 1


# ── SeedFileLoader strict validation ─────────────────────────────────────────


def test_loader_file_not_found():
    """SeedFileLoader raises FileNotFoundError for missing files."""
    SeedFileLoader = _import_seed()
    loader = SeedFileLoader("/nonexistent/path/seed.yml")
    with pytest.raises(FileNotFoundError):
        loader.load()


def test_loader_non_mapping_root(tmp_path):
    """SeedFileLoader raises ValueError if root is not a mapping."""
    SeedFileLoader = _import_seed()
    p = tmp_path / "seed.yml"
    p.write_text("- just\n- a\n- list\n")
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="root must be a mapping"):
        loader.load()


def test_loader_fingerprints_not_list(tmp_path):
    """SeedFileLoader raises ValueError if fingerprints is not a list."""
    SeedFileLoader = _import_seed()
    p = tmp_path / "seed.yml"
    p.write_text("fingerprints: not-a-list\n")
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="non-empty list"):
        loader.load()


def test_loader_fingerprints_none(tmp_path):
    """SeedFileLoader raises ValueError if fingerprints key is missing."""
    SeedFileLoader = _import_seed()
    p = tmp_path / "seed.yml"
    p.write_text("other_key: value\n")
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="non-empty list"):
        loader.load()


def test_loader_entry_not_dict(tmp_path):
    """SeedFileLoader raises ValueError for non-dict entry."""
    SeedFileLoader = _import_seed()
    p = tmp_path / "seed.yml"
    p.write_text('fingerprints:\n  - "just-a-string"\n')
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="must be a mapping"):
        loader.load()


def test_loader_missing_required_field(tmp_path):
    """SeedFileLoader raises ValueError for missing required field."""
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "test"
    category: "c2"
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="missing required field"):
        loader.load()


def test_loader_invalid_ja4(tmp_path):
    """SeedFileLoader raises ValueError for invalid JA4."""
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: "not-valid"
    name: "test"
    category: "c2"
    source: "https://example.test"
    confidence: 90
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="invalid JA4"):
        loader.load()


def test_loader_non_string_ja4(tmp_path):
    """SeedFileLoader raises ValueError for non-string JA4."""
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: 12345
    name: "test"
    category: "c2"
    source: "https://example.test"
    confidence: 90
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="invalid JA4"):
        loader.load()


def test_loader_non_int_confidence(tmp_path):
    """SeedFileLoader raises ValueError for non-int confidence."""
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "test"
    category: "c2"
    source: "https://example.test"
    confidence: "abc"
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="not an int"):
        loader.load()


def test_loader_confidence_out_of_range(tmp_path):
    """SeedFileLoader raises ValueError for confidence out of [0,100]."""
    SeedFileLoader = _import_seed()
    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "test"
    category: "c2"
    source: "https://example.test"
    confidence: 200
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)
    loader = SeedFileLoader(p)
    with pytest.raises(ValueError, match="out of range"):
        loader.load()


# ── load_seed_file ───────────────────────────────────────────────────────────


def test_load_seed_file_missing_path():
    """load_seed_file returns [] for a missing file."""
    load = _import_load_seed_file()
    result = load("/nonexistent/path/seed.yml")
    assert result == []


def test_load_seed_file_empty_file(tmp_path):
    """load_seed_file returns [] for an empty file."""
    load = _import_load_seed_file()
    p = tmp_path / "seed.yml"
    p.write_text("")
    result = load(p)
    assert result == []


def test_load_seed_file_whitespace_only(tmp_path):
    """load_seed_file returns [] for whitespace-only file."""
    load = _import_load_seed_file()
    p = tmp_path / "seed.yml"
    p.write_text("   \n  \n  ")
    result = load(p)
    assert result == []


def test_load_seed_file_non_dict_root(tmp_path):
    """load_seed_file returns [] for non-dict YAML root."""
    load = _import_load_seed_file()
    p = tmp_path / "seed.yml"
    p.write_text("- just\n- a\n- list\n")
    result = load(p)
    assert result == []


def test_load_seed_file_valid(tmp_path):
    """load_seed_file returns parsed entries for valid input."""
    load = _import_load_seed_file()
    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "Cobalt Strike"
    category: "c2_framework"
    source: "https://example.test"
    confidence: 95
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)
    result = load(p)
    assert len(result) == 1
    assert result[0].ja4 == "t10d170900_9dc949161b6c_b64c0ad42cb7"


# ── run_once ─────────────────────────────────────────────────────────────────


def _mock_seed_metric():
    """Return a mock that silences the Prometheus label mismatch in tests."""
    m = MagicMock()
    m.labels.return_value = MagicMock()
    return m


@pytest.mark.asyncio
async def test_run_once_short_entries_warning(tmp_path):
    """run_once logs warning when entries < min_entries."""
    from src.analytics.ti_feeds.seed_file import run_once
    from tests._helpers.ti_feed_stubs import StubManagementClient

    import fakeredis
    from src.analytics.ti_feeds.state import FeedState

    mgmt = StubManagementClient()
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    state = FeedState(redis_client)

    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "Test"
    category: "c2"
    source: "https://example.test"
    confidence: 90
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    with patch("src.analytics.ti_feeds.seed_file._SEED_ENTRIES_LOADED", _mock_seed_metric()):
        result = await run_once(mgmt=mgmt, state=state, path=p, min_entries=10)
    assert result["loaded"] == 1
    assert result["created"] == 1


@pytest.mark.asyncio
async def test_run_once_api_error(tmp_path):
    """run_once counts ManagementAPIError as errors."""
    from src.analytics.ti_feeds.mgmt_client import ManagementAPIError
    from src.analytics.ti_feeds.seed_file import run_once
    from src.analytics.ti_feeds.state import FeedState

    import fakeredis

    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    state = FeedState(redis_client)

    mgmt = AsyncMock()
    mgmt.post_blocklist = AsyncMock(side_effect=ManagementAPIError(status_code=500, message="server error"))

    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "Test"
    category: "c2"
    source: "https://example.test"
    confidence: 90
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    with patch("src.analytics.ti_feeds.seed_file._SEED_ENTRIES_LOADED", _mock_seed_metric()):
        result = await run_once(mgmt=mgmt, state=state, path=p, min_entries=1)
    assert result["errors"] == 1
    assert result["created"] == 0


@pytest.mark.asyncio
async def test_run_once_generic_exception(tmp_path):
    """run_once counts generic exceptions as errors."""
    from src.analytics.ti_feeds.seed_file import run_once
    from src.analytics.ti_feeds.state import FeedState

    import fakeredis

    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    state = FeedState(redis_client)

    mgmt = AsyncMock()
    mgmt.post_blocklist = AsyncMock(side_effect=RuntimeError("network error"))

    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "Test"
    category: "c2"
    source: "https://example.test"
    confidence: 90
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    with patch("src.analytics.ti_feeds.seed_file._SEED_ENTRIES_LOADED", _mock_seed_metric()):
        result = await run_once(mgmt=mgmt, state=state, path=p, min_entries=1)
    assert result["errors"] == 1
    assert result["created"] == 0


@pytest.mark.asyncio
async def test_run_once_success_calls_state_mark(tmp_path):
    """run_once calls state.mark for each successful entry."""
    from src.analytics.ti_feeds.seed_file import run_once
    from src.analytics.ti_feeds.state import FeedState
    from tests._helpers.ti_feed_stubs import StubManagementClient

    import fakeredis

    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    state = FeedState(redis_client)
    mgmt = StubManagementClient()

    yaml_text = """
fingerprints:
  - ja4: "t10d170900_9dc949161b6c_b64c0ad42cb7"
    name: "CS"
    category: "c2"
    source: "https://example.test"
    confidence: 95
  - ja4: "t13d301100_5b57614c22b0_3d5424432f57"
    name: "Sliver"
    category: "c2"
    source: "https://example.test"
    confidence: 90
"""
    p = tmp_path / "seed.yml"
    p.write_text(yaml_text)

    with patch("src.analytics.ti_feeds.seed_file._SEED_ENTRIES_LOADED", _mock_seed_metric()):
        result = await run_once(mgmt=mgmt, state=state, path=p, min_entries=1)
    assert result["created"] == 2
    assert result["errors"] == 0

    # Verify state was marked
    stix_ids = await state.get_active_stix_ids("seed_file")
    assert "t10d170900_9dc949161b6c_b64c0ad42cb7" in stix_ids
    assert "t13d301100_5b57614c22b0_3d5424432f57" in stix_ids


@pytest.mark.asyncio
async def test_run_once_empty_file(tmp_path):
    """run_once with 0 entries still returns a valid summary."""
    from src.analytics.ti_feeds.seed_file import run_once
    from src.analytics.ti_feeds.state import FeedState
    from tests._helpers.ti_feed_stubs import StubManagementClient

    import fakeredis

    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    state = FeedState(redis_client)
    mgmt = StubManagementClient()

    p = tmp_path / "seed.yml"
    p.write_text("")

    result = await run_once(mgmt=mgmt, state=state, path=p, min_entries=10)
    assert result["loaded"] == 0
    assert result["created"] == 0
