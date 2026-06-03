"""Phase 86h — guard tests for the runbook URL fixup.

These tests cover the two URL-correctness bugs shipped by Phase 86:
    Bug 1 (Flavor A): `docs.ja4proxy.example.com` placeholder URLs.
    Bug 1 (Flavor B): wrong-owner/wrong-case github.com URLs.
    Bug 2: runbook_url format inconsistency (relative vs absolute).

They also exercise `scripts/fix_runbook_urls.py` and the mapping file
`docs/phases/PHASE_86h_runbook_mapping.yml`. Both artefacts do not yet exist
at TDD red-state time — the tests must fail (or error) until the Coder
creates them.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
RULES_DIR = REPO_ROOT / "deploy" / "monitoring" / "alertmanager" / "rules"
RUNBOOKS_DIR = REPO_ROOT / "docs" / "runbooks"
MAPPING_PATH = REPO_ROOT / "docs" / "phases" / "PHASE_86h_runbook_mapping.yml"
FIXER_SCRIPT = REPO_ROOT / "scripts" / "fix_runbook_urls.py"

CANONICAL_PREFIX = "https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_rule_files() -> list[Path]:
    files = sorted(RULES_DIR.glob("*.yml"))
    assert files, f"No rule files found in {RULES_DIR}"
    return files


def _iter_runbook_urls() -> list[tuple[Path, str, str]]:
    """Yield (filepath, alertname, runbook_url) for every alert rule."""
    out: list[tuple[Path, str, str]] = []
    for filepath in _iter_rule_files():
        content = yaml.safe_load(filepath.read_text())
        if not content or "groups" not in content:
            continue
        for group in content["groups"]:
            for rule in group.get("rules", []):
                if "alert" not in rule:
                    continue
                url = rule.get("annotations", {}).get("runbook_url", "")
                out.append((filepath, rule["alert"], url))
    return out


def _iter_alert_names() -> list[str]:
    return sorted({alert for _, alert, _ in _iter_runbook_urls()})


# ---------------------------------------------------------------------------
# Bug 1 Flavor A — no example.com placeholders
# ---------------------------------------------------------------------------


def test_no_dead_example_com_urls_in_rules():
    offenders: list[str] = []
    for filepath in _iter_rule_files():
        text = filepath.read_text()
        if "docs.ja4proxy.example.com" in text:
            offenders.append(str(filepath.relative_to(REPO_ROOT)))
    assert not offenders, (
        "Found dead docs.ja4proxy.example.com URLs in rule files: "
        f"{offenders}. Phase 86h Bug 1 Flavor A must be fixed."
    )


# ---------------------------------------------------------------------------
# Bug 1 Flavor B — no wrong owner / wrong case github URLs
# ---------------------------------------------------------------------------


def test_no_wrong_owner_github_urls_in_rules():
    offenders: list[tuple[str, str]] = []
    for filepath in _iter_rule_files():
        text = filepath.read_text()
        # wrong owner (seanoriordain — typo of seanpor)
        if "github.com/seanoriordain" in text:
            offenders.append((str(filepath.relative_to(REPO_ROOT)), "seanoriordain"))
        # wrong repo case (lowercase ja4proxy under seanpor)
        if "github.com/seanpor/ja4proxy" in text:
            offenders.append(
                (str(filepath.relative_to(REPO_ROOT)), "seanpor/ja4proxy (lowercase)")
            )
    assert not offenders, (
        "Found wrong-owner or wrong-case github.com URLs in rule files: "
        f"{offenders}. Phase 86h Bug 1 Flavor B must be fixed. "
        "Use github.com/seanpor/JA4proxy (capital J, capital P)."
    )


# ---------------------------------------------------------------------------
# Bug 2 — all runbook_url values are absolute github URLs
# ---------------------------------------------------------------------------


def test_all_runbook_urls_are_absolute_github():
    offenders: list[tuple[str, str, str]] = []
    for filepath, alert, url in _iter_runbook_urls():
        if not url:
            offenders.append((str(filepath.relative_to(REPO_ROOT)), alert, "<empty>"))
            continue
        if not url.startswith(CANONICAL_PREFIX):
            offenders.append((str(filepath.relative_to(REPO_ROOT)), alert, url))
    assert (
        not offenders
    ), f"Every runbook_url must start with {CANONICAL_PREFIX!r}. Offenders: {offenders}"


# ---------------------------------------------------------------------------
# Bug 2 — every URL resolves to a real file in docs/runbooks/
# ---------------------------------------------------------------------------


def test_all_runbook_urls_point_to_existing_files():
    missing: list[tuple[str, str, str]] = []
    for filepath, alert, url in _iter_runbook_urls():
        if not url.startswith(CANONICAL_PREFIX):
            missing.append((str(filepath.relative_to(REPO_ROOT)), alert, url))
            continue
        rel = url[len(CANONICAL_PREFIX) :]
        # strip any anchor / query
        rel = rel.split("#", 1)[0].split("?", 1)[0]
        target = RUNBOOKS_DIR / rel
        if not target.is_file():
            missing.append((str(filepath.relative_to(REPO_ROOT)), alert, url))
    assert not missing, f"runbook_url values reference non-existent files: {missing}"


# ---------------------------------------------------------------------------
# Mapping file coverage
# ---------------------------------------------------------------------------


def test_runbook_mapping_covers_every_alert():
    assert MAPPING_PATH.exists(), (
        f"Mapping file {MAPPING_PATH.relative_to(REPO_ROOT)} does not exist. "
        "Phase 86h Step 2 must create it."
    )
    mapping = yaml.safe_load(MAPPING_PATH.read_text()) or {}
    assert isinstance(
        mapping, dict
    ), f"Mapping file must be a YAML dict, got {type(mapping).__name__}"
    missing = [name for name in _iter_alert_names() if name not in mapping]
    assert not missing, f"Mapping file is missing entries for alerts: {missing}"
    # Every mapped runbook filename must exist on disk
    bad_targets: list[tuple[str, str]] = []
    for alert, runbook_name in mapping.items():
        if not isinstance(runbook_name, str):
            bad_targets.append((alert, repr(runbook_name)))
            continue
        target = RUNBOOKS_DIR / runbook_name
        if not target.is_file():
            bad_targets.append((alert, runbook_name))
    assert (
        not bad_targets
    ), f"Mapping entries point to missing runbook files: {bad_targets}"


# ---------------------------------------------------------------------------
# fix_runbook_urls.py — idempotence and --check mode
# ---------------------------------------------------------------------------

_DIRTY_RULE_FIXTURE = """\
groups:
  - name: phase86h-fixture
    rules:
      - alert: FixtureAlertOne
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Fixture alert one"
          runbook_url: "https://docs.ja4proxy.example.com/runbooks/{{ $labels.alertname }}"
      - alert: FixtureAlertTwo
        expr: up == 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Fixture alert two"
          runbook_url: "https://github.com/seanoriordain/ja4proxy/blob/main/docs/runbooks/ja4proxy_node_unhealthy.md"
"""

_CLEAN_RULE_FIXTURE = """\
groups:
  - name: phase86h-fixture-clean
    rules:
      - alert: FixtureAlertOne
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Fixture alert one"
          runbook_url: "https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/ja4proxy_node_unhealthy.md"
      - alert: FixtureAlertTwo
        expr: up == 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Fixture alert two"
          runbook_url: "https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/ja4proxy_node_unhealthy.md"
"""

_MAPPING_FIXTURE = """\
FixtureAlertOne: ja4proxy_node_unhealthy.md
FixtureAlertTwo: ja4proxy_node_unhealthy.md
"""


def _write_fixture(tmp_path: Path, rule_text: str) -> tuple[Path, Path]:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "fixture.yml"
    rule_file.write_text(rule_text)

    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text(_MAPPING_FIXTURE)
    return rules_dir, mapping_file


def _run_fixer(*args: str) -> subprocess.CompletedProcess:
    assert FIXER_SCRIPT.exists(), (
        f"{FIXER_SCRIPT.relative_to(REPO_ROOT)} does not exist. "
        "Phase 86h Step 4 must create it."
    )
    return subprocess.run(
        [sys.executable, str(FIXER_SCRIPT), *args],
        capture_output=True,
        text=True,
    )


def test_fix_runbook_urls_idempotent(tmp_path: Path):
    rules_dir, mapping_file = _write_fixture(tmp_path, _DIRTY_RULE_FIXTURE)

    first = _run_fixer(
        "--rules-dir",
        str(rules_dir),
        "--mapping",
        str(mapping_file),
    )
    assert (
        first.returncode == 0
    ), f"fixer first run failed: stdout={first.stdout!r} stderr={first.stderr!r}"
    after_first = (rules_dir / "fixture.yml").read_text()

    second = _run_fixer(
        "--rules-dir",
        str(rules_dir),
        "--mapping",
        str(mapping_file),
    )
    assert (
        second.returncode == 0
    ), f"fixer second run failed: stdout={second.stdout!r} stderr={second.stderr!r}"
    after_second = (rules_dir / "fixture.yml").read_text()

    assert (
        after_first == after_second
    ), "fix_runbook_urls.py is not idempotent — second run produced different output"
    # Sanity: the dead URLs are gone after rewrite.
    assert "docs.ja4proxy.example.com" not in after_first
    assert "github.com/seanoriordain" not in after_first


def test_fix_runbook_urls_check_mode_exits_nonzero_when_dirty(tmp_path: Path):
    rules_dir, mapping_file = _write_fixture(tmp_path, _DIRTY_RULE_FIXTURE)
    result = _run_fixer(
        "--rules-dir",
        str(rules_dir),
        "--mapping",
        str(mapping_file),
        "--check",
    )
    assert result.returncode != 0, (
        "fix_runbook_urls.py --check must exit non-zero on dirty files. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # --check must not mutate files
    assert "docs.ja4proxy.example.com" in (rules_dir / "fixture.yml").read_text()


def test_fix_runbook_urls_check_mode_exits_zero_when_clean(tmp_path: Path):
    rules_dir, mapping_file = _write_fixture(tmp_path, _CLEAN_RULE_FIXTURE)
    result = _run_fixer(
        "--rules-dir",
        str(rules_dir),
        "--mapping",
        str(mapping_file),
        "--check",
    )
    assert result.returncode == 0, (
        "fix_runbook_urls.py --check must exit 0 on clean files. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Review-round guards: mapping target validation + atomic-on-error
# ---------------------------------------------------------------------------


def test_fix_runbook_urls_rejects_mapping_with_nonexistent_target(tmp_path: Path):
    """MAJOR 1: a mapping whose target file does not exist under
    --runbooks-dir must cause the fixer to exit non-zero WITHOUT writing any
    rule file.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "fixture.yml"
    rule_file.write_text(_DIRTY_RULE_FIXTURE)
    original_bytes = rule_file.read_bytes()

    runbooks_dir = tmp_path / "runbooks"
    runbooks_dir.mkdir()
    # Create only one of the two targets so the mapping has both valid and
    # invalid entries.
    (runbooks_dir / "ja4proxy_node_unhealthy.md").write_text("# stub\n")

    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text(
        "FixtureAlertOne: this_runbook_does_not_exist.md\n"
        "FixtureAlertTwo: ja4proxy_node_unhealthy.md\n"
    )

    # Apply mode
    result = _run_fixer(
        "--rules-dir",
        str(rules_dir),
        "--mapping",
        str(mapping_file),
        "--runbooks-dir",
        str(runbooks_dir),
    )
    assert result.returncode != 0, (
        "Fixer must exit non-zero when a mapping target does not exist "
        f"under --runbooks-dir. stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert (
        "this_runbook_does_not_exist.md" in result.stderr
    ), f"Error message must name the missing target. stderr={result.stderr!r}"
    assert (
        rule_file.read_bytes() == original_bytes
    ), "Fixer must NOT modify the rule file when the mapping is invalid."

    # --check mode: same invariant
    result_check = _run_fixer(
        "--rules-dir",
        str(rules_dir),
        "--mapping",
        str(mapping_file),
        "--runbooks-dir",
        str(runbooks_dir),
        "--check",
    )
    assert result_check.returncode != 0
    assert rule_file.read_bytes() == original_bytes


def test_fix_runbook_urls_no_partial_writes_on_error(tmp_path: Path):
    """MAJOR 3: when a rule file has both a mappable alert and an unmapped
    alert, the fixer must NOT rewrite the mappable lines. Operator should
    never see a half-rewritten file on disk.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rule_file = rules_dir / "fixture.yml"
    rule_file.write_text(_DIRTY_RULE_FIXTURE)
    original_bytes = rule_file.read_bytes()

    runbooks_dir = tmp_path / "runbooks"
    runbooks_dir.mkdir()
    (runbooks_dir / "ja4proxy_node_unhealthy.md").write_text("# stub\n")

    # Mapping covers FixtureAlertOne only; FixtureAlertTwo is unmapped.
    mapping_file = tmp_path / "mapping.yml"
    mapping_file.write_text("FixtureAlertOne: ja4proxy_node_unhealthy.md\n")

    result = _run_fixer(
        "--rules-dir",
        str(rules_dir),
        "--mapping",
        str(mapping_file),
        "--runbooks-dir",
        str(runbooks_dir),
    )
    assert result.returncode != 0, (
        "Fixer must exit non-zero when any alert is unmapped. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert rule_file.read_bytes() == original_bytes, (
        "Fixer must NOT rewrite ANY line in a rule file if any alert in it "
        "is unmapped. Got partial write."
    )
    # And the error must name the unmapped alert.
    assert (
        "FixtureAlertTwo" in result.stderr
    ), f"Error must name the unmapped alert. stderr={result.stderr!r}"
