"""
tests/unit/test_waivers_registry.py

Phase 847a — `security/waivers.yaml` is the single source of truth for CVE
waivers; `.trivyignore.{first,third}-party` and `.pip-audit-ignores` are
GENERATED from it.

This module is the guard. It fails when a generated file does not match what the
renderer produces from the registry, so hand-editing a derived file (or
forgetting to re-run the renderer after editing the registry) fails CI rather
than silently drifting. Same discipline the repo applies to TODO.md /
PROJECT_STATUS.md (Phase 332).
"""
from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from scripts import render_waivers

REPO_ROOT = Path(__file__).resolve().parents[2]


# ── The guard ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "attr",
    ["THIRD_PARTY_IGNORE", "FIRST_PARTY_IGNORE", "PIP_AUDIT_IGNORES"],
)
def test_derived_file_matches_registry(attr: str) -> None:
    registry = render_waivers.load_registry()
    assert render_waivers.validate(registry) == []
    expected = render_waivers.render_all(registry)[getattr(render_waivers, attr)]
    actual = getattr(render_waivers, attr).read_text(encoding="utf-8")
    assert actual == expected, (
        f"{getattr(render_waivers, attr).name} is stale — it does not match "
        "security/waivers.yaml. Run `python3 scripts/render_waivers.py` and commit "
        "the result. Never hand-edit a generated file."
    )


def test_check_mode_passes_on_the_committed_tree() -> None:
    assert render_waivers.main(["--check"]) == 0


# ── Schema enforcement ───────────────────────────────────────────────────────

def _valid_registry() -> dict:
    return {
        "version": 1,
        "policy": {"max_window_days": 90, "default_owner": "security-oncall"},
        "waivers": [
            {
                "id": "CVE-2026-00001",
                "scope": "third-party",
                "severity": "HIGH",
                "source": "trivy",
                "carriers": ["img:1.0"],
                "rationale": "because",
                "created": "2026-10-17",
                "expires": "2027-01-15",
            }
        ],
    }


def test_valid_registry_has_no_errors() -> None:
    assert render_waivers.validate(_valid_registry()) == []


def test_empty_waiver_list_is_valid() -> None:
    """Zero waivers is the *goal*, not an error (Phase 847d). Deleting the last
    dead waiver must not make the registry unvalidatable — otherwise a repo that
    fixed everything would be blocked from recording that fact."""
    reg = _valid_registry()
    reg["waivers"] = []
    assert render_waivers.validate(reg) == []


def test_missing_waivers_key_is_still_rejected() -> None:
    reg = _valid_registry()
    del reg["waivers"]
    assert render_waivers.validate(reg) == ["`waivers:` must be a list"]


def test_load_registry_refuses_a_file_with_no_waivers_key(tmp_path) -> None:
    """A file that lost its `waivers:` key is not an empty registry.

    Coercing it to `[]` would read as "zero waivers", and the derived
    ignorefiles would then be regenerated EMPTY — every live exemption
    dropped, silently. The dict-level check in `validate()` cannot catch it
    once `load_registry` has normalised the value away, so the refusal has to
    happen at load time.
    """
    path = tmp_path / "waivers.yaml"
    path.write_text(
        "version: 1\npolicy:\n  max_window_days: 90\n  default_owner: security-oncall\n",
        encoding="utf-8",
    )

    with pytest.raises(render_waivers.RegistryError) as excinfo:
        render_waivers.load_registry(path)

    assert "waivers" in str(excinfo.value)


def test_load_registry_accepts_an_empty_waivers_list(tmp_path) -> None:
    """The goal state: zero waivers, with the key still present."""
    path = tmp_path / "waivers.yaml"
    path.write_text(
        "version: 1\npolicy:\n  max_window_days: 90\n  default_owner: security-oncall\n"
        "waivers:\n",
        encoding="utf-8",
    )

    registry = render_waivers.load_registry(path)

    assert registry["waivers"] == []
    assert render_waivers.validate(registry) == []


def test_missing_rationale_is_rejected() -> None:
    reg = _valid_registry()
    del reg["waivers"][0]["rationale"]
    errors = render_waivers.validate(reg)
    assert any("rationale" in e for e in errors)


def test_missing_carriers_is_rejected() -> None:
    reg = _valid_registry()
    reg["waivers"][0]["carriers"] = []
    errors = render_waivers.validate(reg)
    assert any("carriers" in e for e in errors)


def test_window_longer_than_policy_is_rejected() -> None:
    reg = _valid_registry()
    reg["waivers"][0]["created"] = "2026-10-17"
    reg["waivers"][0]["expires"] = "2027-06-17"  # ~8 months
    errors = render_waivers.validate(reg)
    assert any("exceeds policy max" in e for e in errors)


def test_expiry_before_creation_is_rejected() -> None:
    reg = _valid_registry()
    reg["waivers"][0]["created"] = "2026-10-17"
    reg["waivers"][0]["expires"] = "2026-10-01"
    errors = render_waivers.validate(reg)
    assert any("is before created" in e for e in errors)


def test_fix_available_false_requires_recheck_trigger() -> None:
    reg = _valid_registry()
    reg["waivers"][0]["fix_available"] = False
    errors = render_waivers.validate(reg)
    assert any("recheck_trigger" in e for e in errors)

    reg["waivers"][0]["recheck_trigger"] = "image ships a newer tag"
    assert render_waivers.validate(reg) == []


def test_bad_severity_is_rejected() -> None:
    reg = _valid_registry()
    reg["waivers"][0]["severity"] = "SEVERE"
    assert any("severity" in e for e in render_waivers.validate(reg))


def test_bad_scope_is_rejected() -> None:
    reg = _valid_registry()
    reg["waivers"][0]["scope"] = "fourth-party"
    assert any("scope" in e for e in render_waivers.validate(reg))


def test_duplicate_id_is_rejected() -> None:
    reg = _valid_registry()
    reg["waivers"].append(dict(reg["waivers"][0]))
    assert any("duplicate id" in e for e in render_waivers.validate(reg))


def test_malformed_id_is_rejected() -> None:
    reg = _valid_registry()
    reg["waivers"][0]["id"] = "not-a-cve"
    assert any("malformed id" in e for e in render_waivers.validate(reg))


def test_unquoted_yaml_dates_are_normalised() -> None:
    """Unquoted YYYY-MM-DD loads as datetime.date; the loader normalises it."""
    raw = yaml.safe_load(
        "waivers:\n"
        "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        "    carriers: [x:1]\n"
        "    rationale: y\n"
        "    created: 2026-10-17\n"
        "    expires: 2027-01-15\n"
    )
    assert isinstance(raw["waivers"][0]["created"], date)
    render_waivers._normalise_dates(raw)
    assert raw["waivers"][0]["created"] == "2026-10-17"
    assert raw["waivers"][0]["expires"] == "2027-01-15"


# ── Rendering properties ─────────────────────────────────────────────────────

def test_render_is_deterministic() -> None:
    registry = render_waivers.load_registry()
    a = render_waivers.render_all(registry)
    b = render_waivers.render_all(registry)
    assert {p.name: t for p, t in a.items()} == {p.name: t for p, t in b.items()}


def test_entries_are_sorted_by_id() -> None:
    reg = _valid_registry()
    reg["waivers"].append(
        {**reg["waivers"][0], "id": "CVE-2026-00000"}
    )
    out = render_waivers.render_trivy(reg, "third-party")
    ids = [ln.split()[0] for ln in out.splitlines() if ln.startswith("CVE-")]
    assert ids == sorted(ids)


def test_pip_audit_render_lists_every_source_id() -> None:
    registry = render_waivers.load_registry()
    ids = {
        w["id"]
        for w in registry["waivers"]
        if w.get("source") == "pip-audit"
    }
    rendered = render_waivers.render_pip_audit(registry)
    for wid in ids:
        assert f"--ignore-vuln {wid}" in rendered


def test_first_party_render_is_empty_but_valid() -> None:
    """The first-party ignorefile is intentionally empty; the gate still reads it."""
    registry = render_waivers.load_registry()
    out = render_waivers.render_trivy(registry, "first-party")
    assert "No waivers for this scope" in out
    assert not any(ln.startswith("CVE-") for ln in out.splitlines())


def test_render_line_length_is_bounded() -> None:
    """Comment wrapping must keep every line readable."""
    registry = render_waivers.load_registry()
    for text in render_waivers.render_all(registry).values():
        for line in text.splitlines():
            assert len(line) <= 100, line


# ── save_registry: comments survive a rewrite ────────────────────────────────

_REGISTRY_PROLOGUE = (
    "version: 1\n"
    "policy:\n"
    "  max_window_days: 90\n"
    "  default_owner: security-oncall\n"
    "waivers:\n"
)


def test_save_registry_preserves_comments_and_rationale_style(tmp_path: Path) -> None:
    """Regression guard for a real bug.

    `save_registry` originally used `yaml.safe_dump`, which strips every comment
    — including the whole file header — and reflows the hand-authored `>-`
    rationale blocks into quoted strings. A single `--refresh-carriers` run
    produced a 1346-line diff of pure destruction, and the same would happen on
    every renewal. Only the mutable scalars may change.
    """
    path = tmp_path / "waivers.yaml"
    path.write_text(
        "# HEADER: do not lose me\n"
        + _REGISTRY_PROLOGUE
        + "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img:1.0"]\n'
        "    rationale: >-\n"
        "      because the thing\n"
        "      is internal only\n"
        "    created: 2026-10-17\n"
        "    expires: 2027-01-15\n",
        encoding="utf-8",
    )
    registry = render_waivers.load_registry(path)
    registry["waivers"][0]["carriers"] = ["img:2.0"]
    registry["waivers"][0]["expires"] = "2027-02-01"

    render_waivers.save_registry(registry, path)

    saved = path.read_text(encoding="utf-8")
    assert "# HEADER: do not lose me" in saved
    assert "    rationale: >-" in saved
    assert "      is internal only" in saved
    assert '    carriers: ["img:2.0"]' in saved
    assert "    expires: 2027-02-01" in saved
    # The mutated values round-trip back out.
    reloaded = render_waivers.load_registry(path)
    assert reloaded["waivers"][0]["carriers"] == ["img:2.0"]
    assert reloaded["waivers"][0]["expires"] == "2027-02-01"


def test_save_registry_collapses_a_block_carrier_list(tmp_path: Path) -> None:
    """A block-form `carriers:` collapses to one inline line, with no orphans."""
    path = tmp_path / "waivers.yaml"
    path.write_text(
        _REGISTRY_PROLOGUE
        + "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        "    carriers:\n"
        "      - img:1.0\n"
        "      - img:2.0\n"
        "    rationale: y\n"
        "    created: 2026-10-17\n"
        "    expires: 2027-01-15\n",
        encoding="utf-8",
    )
    registry = render_waivers.load_registry(path)
    registry["waivers"][0]["carriers"] = ["img:3.0"]

    render_waivers.save_registry(registry, path)

    text = path.read_text(encoding="utf-8")
    assert '    carriers: ["img:3.0"]' in text
    assert "- img:1.0" not in text
    assert "- img:2.0" not in text
    assert render_waivers.validate(render_waivers.load_registry(path)) == []


def test_save_registry_leaves_unrelated_prose_untouched(tmp_path: Path) -> None:
    """A `rationale:` line that merely looks like a field is not rewritten."""
    path = tmp_path / "waivers.yaml"
    path.write_text(
        _REGISTRY_PROLOGUE
        + "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img:1.0"]\n'
        "    rationale: >-\n"
        "      carriers: this is prose, not a field\n"
        "    created: 2026-10-17\n"
        "    expires: 2027-01-15\n",
        encoding="utf-8",
    )
    registry = render_waivers.load_registry(path)
    registry["waivers"][0]["carriers"] = ["img:2.0"]

    render_waivers.save_registry(registry, path)

    saved = path.read_text(encoding="utf-8")
    assert "      carriers: this is prose, not a field" in saved
    assert '    carriers: ["img:2.0"]' in saved


def test_save_registry_handles_a_quoted_id(tmp_path: Path) -> None:
    """A quoted `- id:` still round-trips (the entry regex tolerates quotes)."""
    path = tmp_path / "waivers.yaml"
    path.write_text(
        _REGISTRY_PROLOGUE
        + '  - id: "CVE-2026-00001"\n'
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img:1.0"]\n'
        "    rationale: y\n"
        "    created: 2026-10-17\n"
        "    expires: 2027-01-15\n",
        encoding="utf-8",
    )
    registry = render_waivers.load_registry(path)
    registry["waivers"][0]["expires"] = "2027-02-01"

    render_waivers.save_registry(registry, path)

    reloaded = render_waivers.load_registry(path)
    assert reloaded["waivers"][0]["expires"] == "2027-02-01"


def test_save_registry_refuses_to_drop_an_entry(tmp_path: Path) -> None:
    """An entry the writer cannot locate must abort the write, not vanish.

    Silently skipping it would leave its dates/carriers stale with no signal, so
    the failure is loud.
    """
    path = tmp_path / "waivers.yaml"
    path.write_text(
        _REGISTRY_PROLOGUE
        + "  - id: CVE-2026-00001\n"
        "    scope: third-party\n"
        "    severity: HIGH\n"
        "    source: trivy\n"
        '    carriers: ["img:1.0"]\n'
        "    rationale: y\n"
        "    created: 2026-10-17\n"
        "    expires: 2027-01-15\n",
        encoding="utf-8",
    )
    registry = render_waivers.load_registry(path)
    orphan = dict(registry["waivers"][0])
    orphan["id"] = "CVE-2026-99999"
    registry["waivers"].append(orphan)

    with pytest.raises(ValueError, match="CVE-2026-99999"):
        render_waivers.save_registry(registry, path)

    # And the file is untouched.
    assert "CVE-2026-99999" not in path.read_text(encoding="utf-8")


# ── Phase 847d: fix-metadata splice (the fix-forward bot's write path) ───────

_FIX_META_ENTRY = (
    "  - id: CVE-2026-90001\n"
    "    scope: third-party\n"
    "    severity: HIGH\n"
    "    source: trivy\n"
    '    carriers: ["img:1.0"]\n'
    "    rationale: synthetic entry for the 847d splice tests\n"
    "    created: 2026-10-17\n"
    "    expires: 2027-01-15\n"
)


def _write_fix_meta_registry(
    tmp_path: Path, extra_lines: str = ""
) -> tuple[Path, dict]:
    path = tmp_path / "waivers.yaml"
    path.write_text(
        _REGISTRY_PROLOGUE + _FIX_META_ENTRY + extra_lines, encoding="utf-8"
    )
    return path, render_waivers.load_registry(path)


def test_bot_splice_appends_fix_metadata_missing_from_text(tmp_path: Path) -> None:
    """A registry record the splice silently dropped must not be possible: a
    key the waiver carries but the text lacks is appended after the last
    field."""
    path, registry = _write_fix_meta_registry(tmp_path)
    entry = registry["waivers"][0]
    entry["fix_available"] = False
    entry["recheck_trigger"] = "upstream publishes a fixed tag"
    render_waivers.save_registry(
        registry, path, mutable_keys=render_waivers.BOT_MUTABLE_KEYS
    )
    text = path.read_text(encoding="utf-8")
    assert "    fix_available: false" in text
    assert '    recheck_trigger: "upstream publishes a fixed tag"' in text
    reloaded = render_waivers.load_registry(path)
    assert reloaded["waivers"][0]["fix_available"] is False
    assert reloaded["waivers"][0]["recheck_trigger"] == "upstream publishes a fixed tag"
    assert render_waivers.validate(reloaded) == []


def test_default_splice_preserves_fix_metadata_byte_for_byte(tmp_path: Path) -> None:
    """The existing mutators must keep rewriting only created/expires/carriers
    even when fix metadata is present in both text and dict."""
    path, registry = _write_fix_meta_registry(
        tmp_path,
        '    fix_available: false\n'
        '    recheck_trigger: "when upstream ships the fix"\n',
    )
    before = path.read_text(encoding="utf-8")
    registry["waivers"][0]["expires"] = "2027-02-15"
    render_waivers.save_registry(registry, path)  # default mutable keys
    after = path.read_text(encoding="utf-8")
    assert after == before.replace(
        "expires: 2027-01-15", "expires: 2027-02-15"
    )


def test_bot_splice_drops_stale_trigger_when_fix_lands(tmp_path: Path) -> None:
    """fix_available: true supersedes a recheck_trigger the waiver no longer
    carries — the line must be dropped, not left stale."""
    path, registry = _write_fix_meta_registry(
        tmp_path,
        '    fix_available: false\n    recheck_trigger: "when"\n',
    )
    entry = registry["waivers"][0]
    entry["fix_available"] = True
    entry.pop("recheck_trigger")
    render_waivers.save_registry(
        registry, path, mutable_keys=render_waivers.BOT_MUTABLE_KEYS
    )
    text = path.read_text(encoding="utf-8")
    block = text.split("waivers:\n", 1)[1]
    assert "    fix_available: true" in block
    assert "recheck_trigger" not in block


def test_bot_splice_quoted_trigger_round_trips(tmp_path: Path) -> None:
    """A trigger with `: `/quotes/`#` survives JSON-quoting round-trip."""
    trigger = 'when semgrep allows mcp >= 1.30.0: re-check "#1" (v2)'
    path, registry = _write_fix_meta_registry(tmp_path)
    entry = registry["waivers"][0]
    entry["fix_available"] = False
    entry["recheck_trigger"] = trigger
    render_waivers.save_registry(
        registry, path, mutable_keys=render_waivers.BOT_MUTABLE_KEYS
    )
    line = next(
        ln
        for ln in path.read_text(encoding="utf-8").splitlines()
        if "recheck_trigger" in ln
    )
    assert line.startswith("    recheck_trigger: ")
    reloaded = render_waivers.load_registry(path)
    assert reloaded["waivers"][0]["recheck_trigger"] == trigger
