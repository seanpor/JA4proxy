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


# ── Renewal helper (used by renew_trivyignore.py) ────────────────────────────

def test_renew_expiring_bumps_only_trivy_within_window() -> None:
    today = date(2026, 10, 17)
    reg = {
        "policy": {"max_window_days": 90},
        "waivers": [
            {**_valid_registry()["waivers"][0], "expires": "2026-10-19"},  # in window
            {**_valid_registry()["waivers"][0], "id": "CVE-2026-00002",
             "expires": "2027-01-15"},  # out of window
            {**_valid_registry()["waivers"][0], "id": "CVE-2026-00003",
             "source": "pip-audit", "expires": "2026-10-18"},  # pip-audit: skipped
        ],
    }
    n = render_waivers.renew_expiring(reg, within_days=5, days=90, today=today)
    assert n == 1
    bumped = reg["waivers"][0]
    assert bumped["expires"] == (today + timedelta(days=90)).isoformat()
    assert bumped["created"] == today.isoformat()
    # Renewed window is still within policy.
    assert render_waivers.validate(reg) == []


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
