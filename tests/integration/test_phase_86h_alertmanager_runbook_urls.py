"""Phase 86h integration tests for Alertmanager runbook URLs.

These run against the on-disk rule files (not a tmpdir fixture) and verify
that the real rule files Phase 86h rewrites are both syntactically valid
(via promtool if available) and that every runbook_url resolves to a real
file on disk.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
RULES_DIR = REPO_ROOT / "deploy" / "monitoring" / "alertmanager" / "rules"
RUNBOOKS_DIR = REPO_ROOT / "docs" / "runbooks"
CANONICAL_PREFIX = "https://github.com/seanpor/JA4proxy/blob/main/docs/runbooks/"


def _rule_files() -> list[Path]:
    files = sorted(RULES_DIR.glob("*.yml"))
    assert files, f"no rule files in {RULES_DIR}"
    return files


# ---------------------------------------------------------------------------
# promtool check rules
# ---------------------------------------------------------------------------

def test_promtool_check_rules_all_files():
    promtool = shutil.which("promtool")
    if promtool is None:
        pytest.skip("promtool not installed on this host")

    failures: list[tuple[str, str]] = []
    for rf in _rule_files():
        result = subprocess.run(
            [promtool, "check", "rules", str(rf)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            failures.append((rf.name, (result.stdout + result.stderr).strip()))
    assert not failures, f"promtool check rules failed: {failures}"


# ---------------------------------------------------------------------------
# Sanity: every runbook_url in every real rule file points at a real runbook
# ---------------------------------------------------------------------------

def test_every_url_resolves_to_real_file():
    missing: list[tuple[str, str, str]] = []
    for rf in _rule_files():
        content = yaml.safe_load(rf.read_text())
        if not content or "groups" not in content:
            continue
        for group in content["groups"]:
            for rule in group.get("rules", []):
                if "alert" not in rule:
                    continue
                url = rule.get("annotations", {}).get("runbook_url", "")
                if not url:
                    missing.append((rf.name, rule["alert"], "<empty>"))
                    continue
                if not url.startswith(CANONICAL_PREFIX):
                    missing.append((rf.name, rule["alert"], url))
                    continue
                rel = url[len(CANONICAL_PREFIX):].split("#", 1)[0].split("?", 1)[0]
                target = RUNBOOKS_DIR / rel
                if not target.is_file():
                    missing.append((rf.name, rule["alert"], url))
    assert not missing, (
        f"runbook_url values do not resolve to on-disk files: {missing}"
    )
